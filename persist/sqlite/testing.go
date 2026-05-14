package sqlite

import "go.sia.tech/explored/explorer"

// SeedHosts is a test-only helper that inserts the given hosts directly into
// the host_info table, bypassing the chain state machine. It is exported for
// use by the shared store test suite in internal/storetest.
func (s *Store) SeedHosts(hosts []explorer.Host) error {
	return s.transaction(func(tx *txn) error {
		return addHosts(tx, hosts)
	})
}
