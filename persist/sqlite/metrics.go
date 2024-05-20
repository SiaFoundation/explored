package sqlite

import (
	"fmt"

	"go.sia.tech/explored/explorer"
)

// Metrics implements explorer.Store
func (s *Store) Metrics() (result explorer.Metrics, err error) {
	err = s.transaction(func(tx *txn) error {
		err = tx.QueryRow(`SELECT height, difficulty FROM blocks ORDER BY height DESC LIMIT 1`).Scan(&result.Height, decode(&result.Difficulty))
		if err != nil {
			return fmt.Errorf("failed to get height and difficulty: %w", err)
		}

		err = tx.QueryRow(`SELECT COUNT(*), SUM(fce.filesize)
FROM file_contract_elements fce
INNER JOIN last_contract_revision rev ON (rev.contract_element_id = fce.id)
WHERE fce.resolved = FALSE`).Scan(&result.ActiveContracts, &result.StorageUtilization)
		if err != nil {
			return fmt.Errorf("failed to get active contracts and storage utilization: %w", err)
		}

		err = tx.QueryRow(`SELECT COUNT(*) FROM (SELECT DISTINCT public_key FROM host_announcements);`).Scan(&result.TotalHosts)
		if err != nil {
			return fmt.Errorf("failed to get total hosts: %w", err)
		}

		return nil
	})
	return
}
