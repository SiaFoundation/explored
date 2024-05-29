package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// Metrics implements explorer.Store
func (s *Store) Metrics(id types.BlockID) (result explorer.Metrics, err error) {
	err = s.transaction(func(tx *txn) error {
		err = tx.QueryRow(`SELECT height, difficulty, total_hosts, active_contracts, failed_contracts, successful_contracts, storage_utilization, circulating_supply, contract_revenue FROM network_metrics WHERE block_id = ?`, encode(id)).Scan(&result.Height, decode(&result.Difficulty), &result.TotalHosts, &result.ActiveContracts, &result.FailedContracts, &result.SuccessfulContracts, &result.StorageUtilization, decode(&result.CirculatingSupply), decode(&result.ContractRevenue))
		if err != nil {
			return fmt.Errorf("failed to get metrics: %w", err)
		}
		return nil
	})
	return
}
