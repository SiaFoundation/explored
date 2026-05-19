package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"lukechampine.com/frand"
)

const (
	factor           = 1.8              // factor ^ retryAttempts = backoff time in milliseconds
	maxBackoff       = 15 * time.Second // max backoff time
	maxRetryAttempts = 30               // max number of retry attempts
)

type (
	// ConnectionInfo contains the information needed to connect to a PostgreSQL
	// database.
	ConnectionInfo struct {
		Host        string `json:"host" yaml:"host"`
		Port        int    `json:"port" yaml:"port"`
		User        string `json:"user" yaml:"user"`
		Password    string `json:"password" yaml:"password"`
		Database    string `json:"database" yaml:"database"`
		SSLMode     string `json:"sslmode" yaml:"sslmode"`
		SSLRootCert string `json:"sslrootcert" yaml:"sslrootcert"`
	}

	// A Store is a persistent store that uses a PostgreSQL database as its
	// backend.
	Store struct {
		pool *pgxpool.Pool
		log  *zap.Logger
	}
)

// String returns a connection string for the given ConnectionInfo.
func (ci ConnectionInfo) String() string {
	params := []string{
		fmt.Sprintf("host='%s'", ci.Host),
		fmt.Sprintf("port='%d'", ci.Port),
		fmt.Sprintf("user='%s'", ci.User),
		fmt.Sprintf("password='%s'", ci.Password),
		fmt.Sprintf("dbname='%s'", ci.Database),
		fmt.Sprintf("sslmode='%s'", ci.SSLMode),
	}
	if ci.SSLRootCert != "" {
		params = append(params, fmt.Sprintf("sslrootcert='%s'", ci.SSLRootCert))
	}
	return strings.Join(params, " ")
}

// transaction executes a function within a database transaction. If the
// function returns an error, the transaction is rolled back. Otherwise, the
// transaction is committed. If the transaction fails due to a serialization or
// deadlock error, it is retried up to maxRetryAttempts times before returning.
func (s *Store) transaction(fn func(*txn) error) error {
	var err error
	txnID := hex.EncodeToString(frand.Bytes(4))
	log := s.log.Named("transaction").With(zap.String("id", txnID))
	start := time.Now()
	attempt := 1
	for ; attempt <= maxRetryAttempts; attempt++ {
		attemptStart := time.Now()
		log := log.With(zap.Int("attempt", attempt))
		err = s.doTransaction(log, fn)
		if err == nil {
			return nil
		}

		// retry on serialization failures, deadlocks and lock-not-available
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if !(pgErr.Code == "40001" || // serialization_failure
				pgErr.Code == "40P01" || // deadlock_detected
				pgErr.Code == "55P03") { // lock_not_available
				return err
			}
		} else {
			return err
		}

		if attempt == maxRetryAttempts {
			// no more retries; don't waste a backoff before reporting failure.
			break
		}
		sleep := min(time.Duration(math.Pow(factor, float64(attempt)))*time.Millisecond, maxBackoff)
		log.Debug("retryable database error", zap.Duration("elapsed", time.Since(attemptStart)), zap.Duration("totalElapsed", time.Since(start)), zap.Duration("retry", sleep), zap.Error(err))
		time.Sleep(sleep + time.Duration(rand.Int63n(int64(sleep/2))))
	}
	return fmt.Errorf("transaction failed (attempt %d): %w", maxRetryAttempts, err)
}

func (s *Store) doTransaction(log *zap.Logger, fn func(*txn) error) error {
	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	failed := true
	start := time.Now()
	defer func() {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			log.Error("failed to rollback transaction", zap.Error(rollbackErr))
		}
		if time.Since(start) > longTxnDuration {
			log.Debug("long transaction", zap.Duration("elapsed", time.Since(start)), zap.Stack("stack"), zap.Bool("failed", failed))
		}
	}()

	if err := fn(&txn{Tx: tx, ctx: ctx, log: log}); err != nil {
		return err
	} else if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	failed = false
	return nil
}

// Close closes the underlying database connection pool.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// NewStore creates a new Store instance, initializing the database if
// necessary. ctx is used only for the initial connection; migrations run on
// context.Background.
func NewStore(ctx context.Context, ci ConnectionInfo, log *zap.Logger) (*Store, error) {
	if err := ensureDatabase(ctx, ci); err != nil {
		return nil, fmt.Errorf("failed to ensure database %q exists: %w", ci.Database, err)
	}

	pool, err := pgxpool.New(ctx, ci.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	} else if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	log.Info("connected", zap.String("database", ci.Database), zap.String("host", ci.Host), zap.Int("port", ci.Port))

	s := &Store{
		pool: pool,
		log:  log,
	}

	if err := s.init(); err != nil {
		s.Close()
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	return s, nil
}

func ensureDatabase(ctx context.Context, ci ConnectionInfo) error {
	if ci.Database == "postgres" {
		return nil
	}
	db := ci.Database
	ci.Database = "postgres"

	pool, err := pgxpool.New(ctx, ci.String())
	if err != nil {
		return fmt.Errorf("failed to connect to postgres database: %w", err)
	}
	defer pool.Close()

	var exists bool
	if err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_database WHERE datname = $1)", db).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check if database exists: %w", err)
	} else if exists {
		return nil
	}

	query := "CREATE DATABASE " + pgx.Identifier{db}.Sanitize()
	_, err = pool.Exec(ctx, query)
	return err
}
