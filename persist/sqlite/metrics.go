package sqlite

import (
	"fmt"

	"go.sia.tech/explored/explorer"
)

// Metrics implements explorer.Store
func (s *Store) Metrics() (result explorer.Metrics, err error) {
	err = s.transaction(func(tx *txn) error {
		totalHosts := func() (count uint64, err error) {
			err = tx.QueryRow(`SELECT COUNT(*) FROM (SELECT DISTINCT public_key FROM host_announcements);`).Scan(&count)
			return
		}
		storageUtilization := func() (count uint64, err error) {
			err = tx.QueryRow(`SELECT SUM(fce.filesize)
FROM file_contract_elements fce
LEFT JOIN last_contract_revision rev ON (rev.contract_element_id = fce.id)
WHERE fce.valid = TRUE AND fce.resolved = FALSE`).Scan(&count)
			return
		}

		tip, err := s.Tip()
		if err != nil {
			return fmt.Errorf("failed to get tip: %w", err)
		}
		result.Height = tip.Height

		hosts, err := totalHosts()
		if err != nil {
			return fmt.Errorf("failed to get total hosts: %w", err)
		}
		result.TotalHosts = hosts

		bytes, err := storageUtilization()
		if err != nil {
			return fmt.Errorf("failed to get storage utilization: %w", err)
		}
		result.StorageUtilization = bytes
		return nil
	})
	return
}
