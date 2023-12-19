package exploreutil

import (
	"context"
	"database/sql"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements explorer.Store using a SQLite database.
type SQLiteStore struct {
	db    *sql.DB
	tx    *sql.Tx
	txErr error
}

func (s *SQLiteStore) beginTx() {
	if s.tx == nil {
		s.tx, s.txErr = s.db.BeginTx(context.Background(), nil)
	}
}

// Commit implements explorer.Store.
func (s *SQLiteStore) Commit() (err error) {
	if s.txErr != nil {
		s.tx.Rollback() // TODO: return this error?
		err = s.txErr
	} else {
		err = s.tx.Commit()
	}
	s.tx = nil
	return
}

func createTables(db *sql.DB) error {
	// create tables...
	query := ``
	_, err := db.Exec(query)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		err = nil
	}
	return err
}

// NewStore creates a new SQLiteStore for storing explorer data.
func NewStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	} else if err := createTables(db); err != nil {
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

// NewEphemeralStore returns a new in-memory SQLiteStore.
func NewEphemeralStore() *SQLiteStore {
	s, err := NewStore(":memory:")
	if err != nil {
		panic(err)
	}
	return s
}
