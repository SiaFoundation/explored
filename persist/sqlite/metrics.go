package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// Metrics implements explorer.Store
func (s *Store) Metrics(id types.BlockID) (result explorer.Metrics, err error) {
	err = s.transaction(func(tx *txn) error {
		err = tx.QueryRow(`SELECT height, difficulty, total_hosts, active_contracts, failed_contracts, successful_contracts, storage_utilization FROM blocks WHERE id = ?`, encode(id)).Scan(&result.Height, decode(&result.Difficulty), &result.TotalHosts, &result.ActiveContracts, &result.FailedContracts, &result.SuccessfulContracts, &result.StorageUtilization)
		if err != nil {
			return fmt.Errorf("failed to get height and difficulty: %w", err)
		}
		return nil
	})
	return
}
