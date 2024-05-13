package sqlite

import (
	"fmt"

	"go.sia.tech/explored/explorer"
)

// Metrics implements explorer.Store
func (s *Store) Metrics() (result explorer.Metrics, err error) {
	err = s.transaction(func(tx *txn) error {
		totalHosts := func() (count uint64, err error) {
			err = tx.QueryRow("SELECT COUNT(*) FROM (SELECT DISTINCT public_key FROM host_announcements);").Scan(&count)
			return
		}

		tip, err := s.Tip()
		if err != nil {
			return fmt.Errorf("failed to get tip: %w", err)
		}
		result.Height = tip.Height

		hosts, err := totalHosts()
		if err != nil {
			return fmt.Errorf("failed to get tip: %w", err)
		}
		result.TotalHosts = hosts
		return nil
	})
	return
}
