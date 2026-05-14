package postgres

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
)

const (
	longQueryDuration = 100 * time.Millisecond
	longTxnDuration   = time.Second
)

type (
	// A scanner wraps the Scan method of pgx.Rows and pgx.Row to simplify
	// scanning a single row or many rows uniformly.
	scanner interface {
		Scan(dest ...any) error
	}

	// A txn wraps a pgx.Tx and carries the context for all underlying calls.
	// `?` placeholders in queries are automatically converted to `$N`, so query
	// strings can be written in the same style as the SQLite store.
	txn struct {
		pgx.Tx
		ctx context.Context
		log *zap.Logger
	}

	// A stmt mimics the SQLite store's *stmt type. pgx caches statements
	// automatically per connection, so Prepare simply stores the converted
	// query and Exec/Query/QueryRow execute it through the underlying tx.
	stmt struct {
		tx    *txn
		query string
		log   *zap.Logger
	}

	// A row wraps a pgx.Row, logging slow scans.
	row struct {
		pgx.Row
		log *zap.Logger
	}

	// rows wraps pgx.Rows, logging slow iteration.
	rows struct {
		pgx.Rows
		log *zap.Logger
	}
)

// Close releases iteration resources. pgx.Rows has a Close that returns no
// error, but we expose an error-returning Close to match database/sql's API.
func (r *rows) Close() error {
	r.Rows.Close()
	return nil
}

// Err returns any error encountered during iteration.
func (r *rows) Err() error {
	return r.Rows.Err()
}

func (r *rows) Next() bool {
	start := time.Now()
	next := r.Rows.Next()
	if dur := time.Since(start); dur > longQueryDuration {
		r.log.Debug("slow next", zap.Duration("elapsed", dur), zap.Stack("stack"))
	}
	return next
}

func (r *rows) Scan(dest ...any) error {
	start := time.Now()
	err := r.Rows.Scan(dest...)
	if dur := time.Since(start); dur > longQueryDuration {
		r.log.Debug("slow scan", zap.Duration("elapsed", dur), zap.Stack("stack"))
	}
	return err
}

func (r *row) Scan(dest ...any) error {
	start := time.Now()
	err := r.Row.Scan(dest...)
	if dur := time.Since(start); dur > longQueryDuration {
		r.log.Debug("slow scan", zap.Duration("elapsed", dur), zap.Stack("stack"))
	}
	return err
}

// Exec executes a query without returning any rows.
func (tx *txn) Exec(query string, args ...any) (pgconn.CommandTag, error) {
	q := convertPlaceholders(query)
	args = normalizeArgs(args)
	start := time.Now()
	result, err := tx.Tx.Exec(tx.ctx, q, args...)
	if dur := time.Since(start); dur > longQueryDuration {
		tx.log.Debug("slow exec", zap.String("query", q), zap.Duration("elapsed", dur), zap.Stack("stack"))
	}
	return result, err
}

// Query executes a query that returns rows, typically a SELECT.
func (tx *txn) Query(query string, args ...any) (*rows, error) {
	q := convertPlaceholders(query)
	args = normalizeArgs(args)
	start := time.Now()
	r, err := tx.Tx.Query(tx.ctx, q, args...)
	if dur := time.Since(start); dur > longQueryDuration {
		tx.log.Debug("slow query", zap.String("query", q), zap.Duration("elapsed", dur), zap.Stack("stack"))
	}
	return &rows{r, tx.log.Named("rows")}, err
}

// QueryRow executes a query that is expected to return at most one row.
// Errors are deferred until row's Scan method is called.
func (tx *txn) QueryRow(query string, args ...any) *row {
	q := convertPlaceholders(query)
	args = normalizeArgs(args)
	start := time.Now()
	r := tx.Tx.QueryRow(tx.ctx, q, args...)
	if dur := time.Since(start); dur > longQueryDuration {
		tx.log.Debug("slow query row", zap.String("query", q), zap.Duration("elapsed", dur), zap.Stack("stack"))
	}
	return &row{r, tx.log.Named("row")}
}

// Prepare returns a stmt that captures the query for repeated execution.
// pgx caches statements automatically per connection; the returned stmt does
// not hold any database resources directly, so Close is a no-op.
func (tx *txn) Prepare(query string) (*stmt, error) {
	return &stmt{
		tx:    tx,
		query: convertPlaceholders(query),
		log:   tx.log.Named("statement"),
	}, nil
}

// Close is a no-op kept for API parity with database/sql.
func (s *stmt) Close() error { return nil }

// Exec executes the prepared statement with the given args.
func (s *stmt) Exec(args ...any) (pgconn.CommandTag, error) {
	args = normalizeArgs(args)
	start := time.Now()
	result, err := s.tx.Tx.Exec(s.tx.ctx, s.query, args...)
	if dur := time.Since(start); dur > longQueryDuration {
		s.log.Debug("slow exec", zap.String("query", s.query), zap.Duration("elapsed", dur), zap.Stack("stack"))
	}
	return result, err
}

// Query executes the prepared statement, returning rows.
func (s *stmt) Query(args ...any) (*rows, error) {
	args = normalizeArgs(args)
	start := time.Now()
	r, err := s.tx.Tx.Query(s.tx.ctx, s.query, args...)
	if dur := time.Since(start); dur > longQueryDuration {
		s.log.Debug("slow query", zap.String("query", s.query), zap.Duration("elapsed", dur), zap.Stack("stack"))
	}
	return &rows{r, s.log.Named("rows")}, err
}

// QueryRow executes the prepared statement, returning a single row.
func (s *stmt) QueryRow(args ...any) *row {
	args = normalizeArgs(args)
	start := time.Now()
	r := s.tx.Tx.QueryRow(s.tx.ctx, s.query, args...)
	if dur := time.Since(start); dur > longQueryDuration {
		s.log.Debug("slow query row", zap.String("query", s.query), zap.Duration("elapsed", dur), zap.Stack("stack"))
	}
	return &row{r, s.log.Named("row")}
}

// normalizeArgs widens Go integer types that pgx cannot directly encode into
// int64 so callers can pass `int`, `uint64`, etc. through transparently.
func normalizeArgs(args []any) []any {
	for i, a := range args {
		switch v := a.(type) {
		case int:
			args[i] = int64(v)
		case uint64:
			args[i] = int64(v)
		}
	}
	return args
}

// convertPlaceholders rewrites `?` placeholders to `$N`. Queries that already
// use `$N` placeholders are returned unmodified.
func convertPlaceholders(q string) string {
	if !strings.ContainsRune(q, '?') {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 8)
	n := 0
	for i := 0; i < len(q); i++ {
		c := q[i]
		if c == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// queryPlaceHolders builds a comma-separated list of n `?` placeholders. The
// result is intended to be embedded in a query string that is later run through
// convertPlaceholders, which renumbers all `?` into `$N`.
func queryPlaceHolders(n int) string {
	if n == 0 {
		return ""
	} else if n == 1 {
		return "?"
	}
	var b strings.Builder
	b.Grow(((n - 1) * 2) + 1) // ?,?
	for i := 0; i < n-1; i++ {
		b.WriteString("?,")
	}
	b.WriteString("?")
	return b.String()
}

func queryArgs[T any](args []T) []any {
	if len(args) == 0 {
		return nil
	}
	out := make([]any, len(args))
	for i, arg := range args {
		out[i] = arg
	}
	return out
}
