package postgres

import (
	"context"
	_ "embed" // for init.sql
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// init queries are run when the database is first created.
//
//go:embed init.sql
var initDatabase string

func initializeSettings(tx *txn, target int64) error {
	_, err := tx.Exec(`INSERT INTO global_settings (id, db_version) VALUES (0, $1)`, target)
	return err
}

func initNewDatabase(tx *txn, target int64) error {
	if _, err := tx.Exec(initDatabase); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	} else if err := initializeSettings(tx, target); err != nil {
		return fmt.Errorf("failed to initialize global settings: %w", err)
	}
	return nil
}

// getDBVersion returns the current version of the database.
func getDBVersion(ctx context.Context, pool *pgxpool.Pool) (version int64) {
	// error is ignored -- the database may not have been initialized yet.
	pool.QueryRow(ctx, `SELECT db_version FROM global_settings;`).Scan(&version)
	return
}

// setDBVersion sets the current version of the database.
func setDBVersion(tx *txn, version int64) error {
	const query = `UPDATE global_settings SET db_version=$1 RETURNING id;`
	var dbID int64
	return tx.QueryRow(query, version).Scan(&dbID)
}

func (s *Store) upgradeDatabase(current, target int64) error {
	log := s.log.Named("migrations").With(zap.Int64("target", target))
	for ; current < target; current++ {
		version := current + 1 // initial schema is version 1, migration 0 is version 2, etc.
		log := log.With(zap.Int64("version", version))
		start := time.Now()
		fn := migrations[current-1]
		err := s.transaction(func(tx *txn) error {
			if err := fn(tx, log); err != nil {
				return err
			}
			return setDBVersion(tx, version)
		})
		if err != nil {
			return fmt.Errorf("migration %d failed: %w", version, err)
		}
		log.Info("migration complete", zap.Duration("elapsed", time.Since(start)))
	}
	return nil
}

func (s *Store) init() error {
	target := int64(len(migrations) + 1)

	version := getDBVersion(context.Background(), s.pool)
	switch {
	case version == 0:
		return s.transaction(func(tx *txn) error {
			return initNewDatabase(tx, target)
		})
	case version < target:
		return s.upgradeDatabase(version, target)
	case version > target:
		return fmt.Errorf("database version %v is newer than expected %v. database downgrades are not supported", version, target)
	}
	return nil
}
