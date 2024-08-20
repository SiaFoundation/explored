package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// Metrics implements explorer.Store
func (s *Store) Metrics(id types.BlockID) (result explorer.Metrics, err error) {
	err = s.transaction(func(tx *txn) error {
		err = tx.QueryRow(`SELECT block_id, height, difficulty, total_hosts, active_contracts, failed_contracts, successful_contracts, storage_utilization, circulating_supply, contract_revenue FROM network_metrics WHERE block_id = ?`, encode(id)).Scan(decode(&result.Index.ID), &result.Index.Height, decode(&result.Difficulty), &result.TotalHosts, &result.ActiveContracts, &result.FailedContracts, &result.SuccessfulContracts, &result.StorageUtilization, decode(&result.CirculatingSupply), decode(&result.ContractRevenue))
		if err != nil {
			return fmt.Errorf("failed to get metrics: %w", err)
		}
		return nil
	})
	return
}

// HostMetrics implements explorer.Store
func (s *Store) HostMetrics() (result explorer.HostMetrics, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT price_table_host_block_height,price_table_update_price_table_cost,price_table_account_balance_cost,price_table_fund_account_cost,price_table_latest_revision_cost,price_table_subscription_memory_cost,price_table_subscription_notification_cost,price_table_init_base_cost,price_table_memory_time_cost,price_table_download_bandwidth_cost,price_table_upload_bandwidth_cost,price_table_drop_sectors_base_cost,price_table_drop_sectors_unit_cost,price_table_has_sector_base_cost,price_table_read_base_cost,price_table_read_length_cost,price_table_renew_contract_cost,price_table_revision_base_cost,price_table_swap_sector_base_cost,price_table_write_base_cost,price_table_write_length_cost,price_table_write_store_cost,price_table_txn_fee_min_recommended,price_table_txn_fee_max_recommended,price_table_contract_price,price_table_collateral_cost,price_table_max_collateral,price_table_max_duration,price_table_window_size,price_table_registry_entries_left,price_table_registry_entries_total FROM host_info WHERE last_scan_successful = 1`)
		if err != nil {
			return fmt.Errorf("failed to get hosts: %w", err)
		}

		var count uint64
		for rows.Next() {
			var host explorer.Host
			if err := rows.Scan(decode(&host.PriceTable.UpdatePriceTableCost), decode(&host.PriceTable.AccountBalanceCost), decode(&host.PriceTable.FundAccountCost), decode(&host.PriceTable.LatestRevisionCost), decode(&host.PriceTable.SubscriptionMemoryCost), decode(&host.PriceTable.SubscriptionNotificationCost), decode(&host.PriceTable.InitBaseCost), decode(&host.PriceTable.MemoryTimeCost), decode(&host.PriceTable.DownloadBandwidthCost), decode(&host.PriceTable.UploadBandwidthCost), decode(&host.PriceTable.DropSectorsBaseCost), decode(&host.PriceTable.DropSectorsUnitCost), decode(&host.PriceTable.HasSectorBaseCost), decode(&host.PriceTable.ReadBaseCost), decode(&host.PriceTable.ReadLengthCost), decode(&host.PriceTable.RenewContractCost), decode(&host.PriceTable.RevisionBaseCost), decode(&host.PriceTable.SwapSectorBaseCost), decode(&host.PriceTable.WriteBaseCost), decode(&host.PriceTable.WriteLengthCost), decode(&host.PriceTable.WriteStoreCost), decode(&host.PriceTable.TxnFeeMinRecommended), decode(&host.PriceTable.TxnFeeMaxRecommended), decode(&host.PriceTable.ContractPrice), decode(&host.PriceTable.CollateralCost), decode(&host.PriceTable.MaxCollateral), decode(&host.PriceTable.MaxDuration), decode(&host.PriceTable.WindowSize), decode(&host.PriceTable.RegistryEntriesLeft), decode(&host.PriceTable.RegistryEntriesTotal)); err != nil {
				return fmt.Errorf("failed to scan host: %w", err)
			}

			result.PriceTable.UpdatePriceTableCost = result.PriceTable.UpdatePriceTableCost.Add(host.PriceTable.UpdatePriceTableCost)
			result.PriceTable.AccountBalanceCost = result.PriceTable.AccountBalanceCost.Add(host.PriceTable.AccountBalanceCost)
			result.PriceTable.FundAccountCost = result.PriceTable.FundAccountCost.Add(host.PriceTable.FundAccountCost)
			result.PriceTable.LatestRevisionCost = result.PriceTable.LatestRevisionCost.Add(host.PriceTable.LatestRevisionCost)
			result.PriceTable.SubscriptionMemoryCost = result.PriceTable.SubscriptionMemoryCost.Add(host.PriceTable.SubscriptionMemoryCost)
			result.PriceTable.SubscriptionNotificationCost = result.PriceTable.SubscriptionNotificationCost.Add(host.PriceTable.SubscriptionNotificationCost)
			result.PriceTable.InitBaseCost = result.PriceTable.InitBaseCost.Add(host.PriceTable.InitBaseCost)
			result.PriceTable.MemoryTimeCost = result.PriceTable.MemoryTimeCost.Add(host.PriceTable.MemoryTimeCost)
			result.PriceTable.DownloadBandwidthCost = result.PriceTable.DownloadBandwidthCost.Add(host.PriceTable.DownloadBandwidthCost)
			result.PriceTable.UploadBandwidthCost = result.PriceTable.UploadBandwidthCost.Add(host.PriceTable.UploadBandwidthCost)
			result.PriceTable.DropSectorsBaseCost = result.PriceTable.DropSectorsBaseCost.Add(host.PriceTable.DropSectorsBaseCost)
			result.PriceTable.DropSectorsUnitCost = result.PriceTable.DropSectorsUnitCost.Add(host.PriceTable.DropSectorsUnitCost)
			result.PriceTable.HasSectorBaseCost = result.PriceTable.HasSectorBaseCost.Add(host.PriceTable.HasSectorBaseCost)
			result.PriceTable.ReadBaseCost = result.PriceTable.ReadBaseCost.Add(host.PriceTable.ReadBaseCost)
			result.PriceTable.ReadLengthCost = result.PriceTable.ReadLengthCost.Add(host.PriceTable.ReadLengthCost)
			result.PriceTable.RenewContractCost = result.PriceTable.RenewContractCost.Add(host.PriceTable.RenewContractCost)
			result.PriceTable.RevisionBaseCost = result.PriceTable.RevisionBaseCost.Add(host.PriceTable.RevisionBaseCost)
			result.PriceTable.SwapSectorBaseCost = result.PriceTable.SwapSectorBaseCost.Add(host.PriceTable.SwapSectorBaseCost)
			result.PriceTable.WriteBaseCost = result.PriceTable.WriteBaseCost.Add(host.PriceTable.WriteBaseCost)
			result.PriceTable.WriteLengthCost = result.PriceTable.WriteLengthCost.Add(host.PriceTable.WriteLengthCost)
			result.PriceTable.WriteStoreCost = result.PriceTable.WriteStoreCost.Add(host.PriceTable.WriteStoreCost)
			result.PriceTable.TxnFeeMinRecommended = result.PriceTable.TxnFeeMinRecommended.Add(host.PriceTable.TxnFeeMinRecommended)
			result.PriceTable.TxnFeeMaxRecommended = result.PriceTable.TxnFeeMaxRecommended.Add(host.PriceTable.TxnFeeMaxRecommended)
			result.PriceTable.ContractPrice = result.PriceTable.ContractPrice.Add(host.PriceTable.ContractPrice)
			result.PriceTable.CollateralCost = result.PriceTable.CollateralCost.Add(host.PriceTable.CollateralCost)
			result.PriceTable.MaxCollateral = result.PriceTable.MaxCollateral.Add(host.PriceTable.MaxCollateral)
			result.PriceTable.MaxDuration += host.PriceTable.MaxDuration
			result.PriceTable.WindowSize += host.PriceTable.WindowSize
			result.PriceTable.RegistryEntriesLeft += host.PriceTable.RegistryEntriesLeft
			result.PriceTable.RegistryEntriesTotal = host.PriceTable.RegistryEntriesTotal

			count++
		}

		if count > 0 {
			result.PriceTable.UpdatePriceTableCost = result.PriceTable.UpdatePriceTableCost.Div64(count)
			result.PriceTable.AccountBalanceCost = result.PriceTable.AccountBalanceCost.Div64(count)
			result.PriceTable.FundAccountCost = result.PriceTable.FundAccountCost.Div64(count)
			result.PriceTable.LatestRevisionCost = result.PriceTable.LatestRevisionCost.Div64(count)
			result.PriceTable.SubscriptionMemoryCost = result.PriceTable.SubscriptionMemoryCost.Div64(count)
			result.PriceTable.SubscriptionNotificationCost = result.PriceTable.SubscriptionNotificationCost.Div64(count)
			result.PriceTable.InitBaseCost = result.PriceTable.InitBaseCost.Div64(count)
			result.PriceTable.MemoryTimeCost = result.PriceTable.MemoryTimeCost.Div64(count)
			result.PriceTable.DownloadBandwidthCost = result.PriceTable.DownloadBandwidthCost.Div64(count)
			result.PriceTable.UploadBandwidthCost = result.PriceTable.UploadBandwidthCost.Div64(count)
			result.PriceTable.DropSectorsBaseCost = result.PriceTable.DropSectorsBaseCost.Div64(count)
			result.PriceTable.DropSectorsUnitCost = result.PriceTable.DropSectorsUnitCost.Div64(count)
			result.PriceTable.HasSectorBaseCost = result.PriceTable.HasSectorBaseCost.Div64(count)
			result.PriceTable.ReadBaseCost = result.PriceTable.ReadBaseCost.Div64(count)
			result.PriceTable.ReadLengthCost = result.PriceTable.ReadLengthCost.Div64(count)
			result.PriceTable.RenewContractCost = result.PriceTable.RenewContractCost.Div64(count)
			result.PriceTable.RevisionBaseCost = result.PriceTable.RevisionBaseCost.Div64(count)
			result.PriceTable.SwapSectorBaseCost = result.PriceTable.SwapSectorBaseCost.Div64(count)
			result.PriceTable.WriteBaseCost = result.PriceTable.WriteBaseCost.Div64(count)
			result.PriceTable.WriteLengthCost = result.PriceTable.WriteLengthCost.Div64(count)
			result.PriceTable.WriteStoreCost = result.PriceTable.WriteStoreCost.Div64(count)
			result.PriceTable.TxnFeeMinRecommended = result.PriceTable.TxnFeeMinRecommended.Div64(count)
			result.PriceTable.TxnFeeMaxRecommended = result.PriceTable.TxnFeeMaxRecommended.Div64(count)
			result.PriceTable.ContractPrice = result.PriceTable.ContractPrice.Div64(count)
			result.PriceTable.CollateralCost = result.PriceTable.CollateralCost.Div64(count)
			result.PriceTable.MaxCollateral = result.PriceTable.MaxCollateral.Div64(count)
			result.PriceTable.MaxDuration /= count
			result.PriceTable.WindowSize /= count
			result.PriceTable.RegistryEntriesLeft /= count
			result.PriceTable.RegistryEntriesTotal /= count
		}

		return nil
	})
	return
}
