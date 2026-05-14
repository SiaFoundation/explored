package postgres

import (
	"context"

	"go.sia.tech/explored/explorer"
)

// SeedHosts is a test-only helper that inserts the given hosts directly into
// the host_info table, bypassing the chain state machine. It is exported for
// use by the shared store test suite in internal/storetest.
func (s *Store) SeedHosts(hosts []explorer.Host) error {
	return s.transaction(func(tx *txn) error {
		return addHosts(tx, hosts)
	})
}

// ResetForTesting drops and recreates the `public` schema, returning the store
// to a fresh state. It is intended for use only by the shared store test
// suite, which re-runs migrations afterwards via the Store's own init path on
// the next openStore call.
func (s *Store) ResetForTesting(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
	return err
}
