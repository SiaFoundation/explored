package sqlite

import (
	"fmt"

	"go.sia.tech/explored/explorer"
)

// Metrics implements explorer.Store
func (s *Store) Metrics() (result explorer.Metrics, err error) {
	err = s.transaction(func(tx *txn) error {
		heightDifficulty := func() error {
			return tx.QueryRow(`SELECT height, difficulty FROM blocks ORDER BY height DESC LIMIT 1`).Scan(&result.Height, decode(&result.Difficulty))
		}
		totalHosts := func() error {
			return tx.QueryRow(`SELECT COUNT(*) FROM (SELECT DISTINCT public_key FROM host_announcements);`).Scan(&result.TotalHosts)
		}
		storageUtilization := func() error {
			return tx.QueryRow(`SELECT SUM(fce.filesize)
FROM file_contract_elements fce
LEFT JOIN last_contract_revision rev ON (rev.contract_element_id = fce.id)
WHERE fce.valid = TRUE AND fce.resolved = FALSE`).Scan(&result.StorageUtilization)
		}

		if err := heightDifficulty(); err != nil {
			return fmt.Errorf("failed to get height and difficulty: %w", err)
		} else if err := totalHosts(); err != nil {
			return fmt.Errorf("failed to get total hosts: %w", err)
		} else if err := storageUtilization(); err != nil {
			return fmt.Errorf("failed to get storage utilization: %w", err)
		}
		return nil
	})
	return
}
