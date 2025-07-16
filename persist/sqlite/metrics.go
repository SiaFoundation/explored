package sqlite

import (
	"fmt"
	"slices"
	"time"

	proto4 "go.sia.tech/core/rhp/v4"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// Metrics implements explorer.Store
func (s *Store) Metrics(id types.BlockID) (result explorer.Metrics, err error) {
	err = s.transaction(func(tx *txn) error {
		err = tx.QueryRow(`SELECT block_id, height, difficulty, siafund_tax_revenue, num_leaves, total_hosts, active_contracts, failed_contracts, successful_contracts, storage_utilization, circulating_supply, contract_revenue FROM network_metrics WHERE block_id = ?`, encode(id)).Scan(decode(&result.Index.ID), &result.Index.Height, decode(&result.Difficulty), decode(&result.SiafundTaxRevenue), decode(&result.NumLeaves), &result.TotalHosts, &result.ActiveContracts, &result.FailedContracts, &result.SuccessfulContracts, &result.StorageUtilization, decode(&result.CirculatingSupply), decode(&result.ContractRevenue))
		if err != nil {
			return fmt.Errorf("failed to get metrics: %w", err)
		}
		return nil
	})
	return
}

// HostMetrics implements explorer.Store
func (s *Store) HostMetrics() (result explorer.HostMetrics, err error) {
	medianUint64 := func(x []uint64) uint64 {
		if len(x) == 0 {
			return 0
		}

		slices.Sort(x)
		if len(x)%2 == 1 {
			return x[len(x)/2]
		}
		return (x[(len(x)/2)-1] + x[(len(x)/2)]) / 2
	}

	medianCurrency := func(x []types.Currency) types.Currency {
		if len(x) == 0 {
			return types.ZeroCurrency
		}

		slices.SortFunc(x, func(a, b types.Currency) int {
			return a.Cmp(b)
		})
		if len(x)%2 == 1 {
			return x[len(x)/2]
		}
		return (x[(len(x)/2)-1].Add(x[(len(x) / 2)])).Div64(2)
	}

	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT v2,settings_max_download_batch_size,settings_max_duration,settings_max_revise_batch_size,settings_remaining_storage,settings_sector_size,settings_total_storage,settings_window_size,settings_collateral,settings_max_collateral,settings_base_rpc_price,settings_contract_price,settings_download_bandwidth_price,settings_sector_access_price,settings_storage_price,settings_upload_bandwidth_price,settings_ephemeral_account_expiry,settings_max_ephemeral_account_balance,settings_revision_number,price_table_validity,price_table_host_block_height,price_table_update_price_table_cost,price_table_account_balance_cost,price_table_fund_account_cost,price_table_latest_revision_cost,price_table_subscription_memory_cost,price_table_subscription_notification_cost,price_table_init_base_cost,price_table_memory_time_cost,price_table_download_bandwidth_cost,price_table_upload_bandwidth_cost,price_table_drop_sectors_base_cost,price_table_drop_sectors_unit_cost,price_table_has_sector_base_cost,price_table_read_base_cost,price_table_read_length_cost,price_table_renew_contract_cost,price_table_revision_base_cost,price_table_swap_sector_base_cost,price_table_write_base_cost,price_table_write_length_cost,price_table_write_store_cost,price_table_txn_fee_min_recommended,price_table_txn_fee_max_recommended,price_table_contract_price,price_table_collateral_cost,price_table_max_collateral,price_table_max_duration,price_table_window_size,price_table_registry_entries_left,price_table_registry_entries_total,v2_settings_max_collateral,v2_settings_max_contract_duration,v2_settings_remaining_storage,v2_settings_total_storage,v2_prices_contract_price,v2_prices_collateral_price,v2_prices_storage_price,v2_prices_ingress_price,v2_prices_egress_price,v2_prices_free_sector_price,v2_prices_tip_height,v2_prices_valid_until FROM host_info WHERE last_scan_successful = 1`)
		if err != nil {
			return fmt.Errorf("failed to get hosts: %w", err)
		}
		defer rows.Close()

		var count uint64
		var settingsMaxDownloadBatchSize, settingsMaxDuration, settingsMaxReviseBatchSize, settingsRemainingStorage, settingsSectorSize, settingsTotalStorage, settingsWindowSize, settingsRevisionNumber, priceTableHostBlockHeight, priceTableMaxDuration, priceTableWindowSize, priceTableRegistryEntriesLeft, priceTableRegistryEntriesTotal, settingsEphemeralAccountExpiry, priceTableValidity, v2MaxContractDuration, v2RemainingStorage, v2TotalStorage, v2PricesTipHeight, v2PricesValidUntil []uint64
		var settingsCollateral, settingsMaxCollateral, settingsBaseRPCPrice, settingsContractPrice, settingsDownloadBandwidthPrice, settingsSectorAccessPrice, settingsStoragePrice, settingsUploadBandwidthPrice, settingsMaxEphemeralAccountBalance, priceTableUpdatePriceTableCost, priceTableAccountBalanceCost, priceTableFundAccountCost, priceTableLatestRevisionCost, priceTableSubscriptionMemoryCost, priceTableSubscriptionNotificationCost, priceTableInitBaseCost, priceTableMemoryTimeCost, priceTableDownloadBandwidthCost, priceTableUploadBandwidthCost, priceTableDropSectorsBaseCost, priceTableDropSectorsUnitCost, priceTableHasSectorBaseCost, priceTableReadBaseCost, priceTableReadLengthCost, priceTableRenewContractCost, priceTableRevisionBaseCost, priceTableSwapSectorBaseCost, priceTableWriteBaseCost, priceTableWriteLengthCost, priceTableWriteStoreCost, priceTableTxnFeeMinRecommended, priceTableTxnFeeMaxRecommended, priceTableContractPrice, priceTableCollateralCost, priceTableMaxCollateral, v2MaxCollateral, v2PricesContractPrice, v2PricesCollateral, v2PricesStoragePrice, v2PricesIngressPrice, v2PricesEgressPrice, v2PricesFreeSectorPrice []types.Currency
		for rows.Next() {
			var host explorer.Host
			if err := rows.Scan(&host.V2, decode(&host.Settings.MaxDownloadBatchSize), decode(&host.Settings.MaxDuration), decode(&host.Settings.MaxReviseBatchSize), decode(&host.Settings.RemainingStorage), decode(&host.Settings.SectorSize), decode(&host.Settings.TotalStorage), decode(&host.Settings.WindowSize), decode(&host.Settings.Collateral), decode(&host.Settings.MaxCollateral), decode(&host.Settings.BaseRPCPrice), decode(&host.Settings.ContractPrice), decode(&host.Settings.DownloadBandwidthPrice), decode(&host.Settings.SectorAccessPrice), decode(&host.Settings.StoragePrice), decode(&host.Settings.UploadBandwidthPrice), decode(&host.Settings.EphemeralAccountExpiry), decode(&host.Settings.MaxEphemeralAccountBalance), decode(&host.Settings.RevisionNumber), decode(&host.PriceTable.Validity), decode(&host.PriceTable.HostBlockHeight), decode(&host.PriceTable.UpdatePriceTableCost), decode(&host.PriceTable.AccountBalanceCost), decode(&host.PriceTable.FundAccountCost), decode(&host.PriceTable.LatestRevisionCost), decode(&host.PriceTable.SubscriptionMemoryCost), decode(&host.PriceTable.SubscriptionNotificationCost), decode(&host.PriceTable.InitBaseCost), decode(&host.PriceTable.MemoryTimeCost), decode(&host.PriceTable.DownloadBandwidthCost), decode(&host.PriceTable.UploadBandwidthCost), decode(&host.PriceTable.DropSectorsBaseCost), decode(&host.PriceTable.DropSectorsUnitCost), decode(&host.PriceTable.HasSectorBaseCost), decode(&host.PriceTable.ReadBaseCost), decode(&host.PriceTable.ReadLengthCost), decode(&host.PriceTable.RenewContractCost), decode(&host.PriceTable.RevisionBaseCost), decode(&host.PriceTable.SwapSectorBaseCost), decode(&host.PriceTable.WriteBaseCost), decode(&host.PriceTable.WriteLengthCost), decode(&host.PriceTable.WriteStoreCost), decode(&host.PriceTable.TxnFeeMinRecommended), decode(&host.PriceTable.TxnFeeMaxRecommended), decode(&host.PriceTable.ContractPrice), decode(&host.PriceTable.CollateralCost), decode(&host.PriceTable.MaxCollateral), decode(&host.PriceTable.MaxDuration), decode(&host.PriceTable.WindowSize), decode(&host.PriceTable.RegistryEntriesLeft), decode(&host.PriceTable.RegistryEntriesTotal), decode(&host.V2Settings.MaxCollateral), decode(&host.V2Settings.MaxContractDuration), decode(&host.V2Settings.RemainingStorage), decode(&host.V2Settings.TotalStorage), decode(&host.V2Settings.Prices.ContractPrice), decode(&host.V2Settings.Prices.Collateral), decode(&host.V2Settings.Prices.StoragePrice), decode(&host.V2Settings.Prices.IngressPrice), decode(&host.V2Settings.Prices.EgressPrice), decode(&host.V2Settings.Prices.FreeSectorPrice), decode(&host.V2Settings.Prices.TipHeight), decode(&host.V2Settings.Prices.ValidUntil)); err != nil {
				return fmt.Errorf("failed to scan host: %w", err)
			}

			if host.V2 {
				result.TotalStorage += proto4.SectorSize * host.V2Settings.TotalStorage
				result.RemainingStorage += proto4.SectorSize * host.V2Settings.RemainingStorage

				v2MaxCollateral = append(v2MaxCollateral, host.V2Settings.MaxCollateral)
				v2MaxContractDuration = append(v2MaxContractDuration, host.V2Settings.MaxContractDuration)
				v2RemainingStorage = append(v2RemainingStorage, host.V2Settings.RemainingStorage)
				v2TotalStorage = append(v2TotalStorage, host.V2Settings.TotalStorage)

				v2PricesContractPrice = append(v2PricesContractPrice, host.V2Settings.Prices.ContractPrice)
				v2PricesCollateral = append(v2PricesCollateral, host.V2Settings.Prices.Collateral)
				v2PricesStoragePrice = append(v2PricesStoragePrice, host.V2Settings.Prices.StoragePrice)
				v2PricesIngressPrice = append(v2PricesIngressPrice, host.V2Settings.Prices.IngressPrice)
				v2PricesEgressPrice = append(v2PricesEgressPrice, host.V2Settings.Prices.EgressPrice)
				v2PricesFreeSectorPrice = append(v2PricesFreeSectorPrice, host.V2Settings.Prices.FreeSectorPrice)
				v2PricesTipHeight = append(v2PricesTipHeight, host.V2Settings.Prices.TipHeight)
				v2PricesValidUntil = append(v2PricesValidUntil, uint64(host.V2Settings.Prices.ValidUntil.Unix()))
			} else {
				result.TotalStorage += host.Settings.TotalStorage
				result.RemainingStorage += host.Settings.RemainingStorage

				settingsMaxDownloadBatchSize = append(settingsMaxDownloadBatchSize, host.Settings.MaxDownloadBatchSize)
				settingsMaxDuration = append(settingsMaxDuration, host.Settings.MaxDuration)
				settingsMaxReviseBatchSize = append(settingsMaxReviseBatchSize, host.Settings.MaxReviseBatchSize)
				settingsRemainingStorage = append(settingsRemainingStorage, host.Settings.RemainingStorage)
				settingsSectorSize = append(settingsSectorSize, host.Settings.SectorSize)
				settingsTotalStorage = append(settingsTotalStorage, host.Settings.TotalStorage)
				settingsWindowSize = append(settingsWindowSize, host.Settings.WindowSize)
				settingsCollateral = append(settingsCollateral, host.Settings.Collateral)
				settingsMaxCollateral = append(settingsMaxCollateral, host.Settings.MaxCollateral)
				settingsBaseRPCPrice = append(settingsBaseRPCPrice, host.Settings.BaseRPCPrice)
				settingsContractPrice = append(settingsContractPrice, host.Settings.ContractPrice)
				settingsDownloadBandwidthPrice = append(settingsDownloadBandwidthPrice, host.Settings.DownloadBandwidthPrice)
				settingsSectorAccessPrice = append(settingsSectorAccessPrice, host.Settings.SectorAccessPrice)
				settingsStoragePrice = append(settingsStoragePrice, host.Settings.StoragePrice)
				settingsUploadBandwidthPrice = append(settingsUploadBandwidthPrice, host.Settings.UploadBandwidthPrice)
				settingsEphemeralAccountExpiry = append(settingsEphemeralAccountExpiry, uint64(host.Settings.EphemeralAccountExpiry))
				settingsMaxEphemeralAccountBalance = append(settingsMaxEphemeralAccountBalance, host.Settings.MaxEphemeralAccountBalance)
				settingsRevisionNumber = append(settingsRevisionNumber, host.Settings.RevisionNumber)

				priceTableValidity = append(priceTableValidity, uint64(host.PriceTable.Validity))
				priceTableHostBlockHeight = append(priceTableHostBlockHeight, host.PriceTable.HostBlockHeight)
				priceTableUpdatePriceTableCost = append(priceTableUpdatePriceTableCost, host.PriceTable.UpdatePriceTableCost)
				priceTableAccountBalanceCost = append(priceTableAccountBalanceCost, host.PriceTable.AccountBalanceCost)
				priceTableFundAccountCost = append(priceTableFundAccountCost, host.PriceTable.FundAccountCost)
				priceTableLatestRevisionCost = append(priceTableLatestRevisionCost, host.PriceTable.LatestRevisionCost)
				priceTableSubscriptionMemoryCost = append(priceTableSubscriptionMemoryCost, host.PriceTable.SubscriptionMemoryCost)
				priceTableSubscriptionNotificationCost = append(priceTableSubscriptionNotificationCost, host.PriceTable.SubscriptionNotificationCost)
				priceTableInitBaseCost = append(priceTableInitBaseCost, host.PriceTable.InitBaseCost)
				priceTableMemoryTimeCost = append(priceTableMemoryTimeCost, host.PriceTable.MemoryTimeCost)
				priceTableDownloadBandwidthCost = append(priceTableDownloadBandwidthCost, host.PriceTable.DownloadBandwidthCost)
				priceTableUploadBandwidthCost = append(priceTableUploadBandwidthCost, host.PriceTable.UploadBandwidthCost)
				priceTableDropSectorsBaseCost = append(priceTableDropSectorsBaseCost, host.PriceTable.DropSectorsBaseCost)
				priceTableDropSectorsUnitCost = append(priceTableDropSectorsUnitCost, host.PriceTable.DropSectorsUnitCost)
				priceTableHasSectorBaseCost = append(priceTableHasSectorBaseCost, host.PriceTable.HasSectorBaseCost)
				priceTableReadBaseCost = append(priceTableReadBaseCost, host.PriceTable.ReadBaseCost)
				priceTableReadLengthCost = append(priceTableReadLengthCost, host.PriceTable.ReadLengthCost)
				priceTableRenewContractCost = append(priceTableRenewContractCost, host.PriceTable.RenewContractCost)
				priceTableRevisionBaseCost = append(priceTableRevisionBaseCost, host.PriceTable.RevisionBaseCost)
				priceTableSwapSectorBaseCost = append(priceTableSwapSectorBaseCost, host.PriceTable.SwapSectorBaseCost)
				priceTableWriteBaseCost = append(priceTableWriteBaseCost, host.PriceTable.WriteBaseCost)
				priceTableWriteLengthCost = append(priceTableWriteLengthCost, host.PriceTable.WriteLengthCost)
				priceTableWriteStoreCost = append(priceTableWriteStoreCost, host.PriceTable.WriteStoreCost)
				priceTableTxnFeeMinRecommended = append(priceTableTxnFeeMinRecommended, host.PriceTable.TxnFeeMinRecommended)
				priceTableTxnFeeMaxRecommended = append(priceTableTxnFeeMaxRecommended, host.PriceTable.TxnFeeMaxRecommended)
				priceTableContractPrice = append(priceTableContractPrice, host.PriceTable.ContractPrice)
				priceTableCollateralCost = append(priceTableCollateralCost, host.PriceTable.CollateralCost)
				priceTableMaxCollateral = append(priceTableMaxCollateral, host.PriceTable.MaxCollateral)
				priceTableMaxDuration = append(priceTableMaxDuration, host.PriceTable.MaxDuration)
				priceTableWindowSize = append(priceTableWindowSize, host.PriceTable.WindowSize)
				priceTableRegistryEntriesLeft = append(priceTableRegistryEntriesLeft, host.PriceTable.RegistryEntriesLeft)
				priceTableRegistryEntriesTotal = append(priceTableRegistryEntriesTotal, host.PriceTable.RegistryEntriesTotal)
			}

			count++
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to retrieve rows: %w", err)
		}

		if count > 0 {
			result.ActiveHosts = count

			result.Settings.MaxDownloadBatchSize = medianUint64(settingsMaxDownloadBatchSize)
			result.Settings.MaxDuration = medianUint64(settingsMaxDuration)
			result.Settings.MaxReviseBatchSize = medianUint64(settingsMaxReviseBatchSize)
			result.Settings.RemainingStorage = medianUint64(settingsRemainingStorage)
			result.Settings.SectorSize = medianUint64(settingsSectorSize)
			result.Settings.TotalStorage = medianUint64(settingsTotalStorage)
			result.Settings.WindowSize = medianUint64(settingsWindowSize)
			result.Settings.Collateral = medianCurrency(settingsCollateral)
			result.Settings.MaxCollateral = medianCurrency(settingsMaxCollateral)
			result.Settings.BaseRPCPrice = medianCurrency(settingsBaseRPCPrice)
			result.Settings.ContractPrice = medianCurrency(settingsContractPrice)
			result.Settings.DownloadBandwidthPrice = medianCurrency(settingsDownloadBandwidthPrice)
			result.Settings.SectorAccessPrice = medianCurrency(settingsSectorAccessPrice)
			result.Settings.StoragePrice = medianCurrency(settingsStoragePrice)
			result.Settings.UploadBandwidthPrice = medianCurrency(settingsUploadBandwidthPrice)
			result.Settings.EphemeralAccountExpiry = time.Duration(medianUint64(settingsEphemeralAccountExpiry))
			result.Settings.MaxEphemeralAccountBalance = medianCurrency(settingsMaxEphemeralAccountBalance)
			result.Settings.RevisionNumber = medianUint64(settingsRevisionNumber)

			result.PriceTable.Validity = time.Duration(medianUint64(priceTableValidity))
			result.PriceTable.HostBlockHeight = medianUint64(priceTableHostBlockHeight)
			result.PriceTable.UpdatePriceTableCost = medianCurrency(priceTableUpdatePriceTableCost)
			result.PriceTable.AccountBalanceCost = medianCurrency(priceTableAccountBalanceCost)
			result.PriceTable.FundAccountCost = medianCurrency(priceTableFundAccountCost)
			result.PriceTable.LatestRevisionCost = medianCurrency(priceTableLatestRevisionCost)
			result.PriceTable.SubscriptionMemoryCost = medianCurrency(priceTableSubscriptionMemoryCost)
			result.PriceTable.SubscriptionNotificationCost = medianCurrency(priceTableSubscriptionNotificationCost)
			result.PriceTable.InitBaseCost = medianCurrency(priceTableInitBaseCost)
			result.PriceTable.MemoryTimeCost = medianCurrency(priceTableMemoryTimeCost)
			result.PriceTable.DownloadBandwidthCost = medianCurrency(priceTableDownloadBandwidthCost)
			result.PriceTable.UploadBandwidthCost = medianCurrency(priceTableUploadBandwidthCost)
			result.PriceTable.DropSectorsBaseCost = medianCurrency(priceTableDropSectorsBaseCost)
			result.PriceTable.DropSectorsUnitCost = medianCurrency(priceTableDropSectorsUnitCost)
			result.PriceTable.HasSectorBaseCost = medianCurrency(priceTableHasSectorBaseCost)
			result.PriceTable.ReadBaseCost = medianCurrency(priceTableReadBaseCost)
			result.PriceTable.ReadLengthCost = medianCurrency(priceTableReadLengthCost)
			result.PriceTable.RenewContractCost = medianCurrency(priceTableRenewContractCost)
			result.PriceTable.RevisionBaseCost = medianCurrency(priceTableRevisionBaseCost)
			result.PriceTable.SwapSectorBaseCost = medianCurrency(priceTableSwapSectorBaseCost)
			result.PriceTable.WriteBaseCost = medianCurrency(priceTableWriteBaseCost)
			result.PriceTable.WriteLengthCost = medianCurrency(priceTableWriteLengthCost)
			result.PriceTable.WriteStoreCost = medianCurrency(priceTableWriteStoreCost)
			result.PriceTable.TxnFeeMinRecommended = medianCurrency(priceTableTxnFeeMinRecommended)
			result.PriceTable.TxnFeeMaxRecommended = medianCurrency(priceTableTxnFeeMaxRecommended)
			result.PriceTable.ContractPrice = medianCurrency(priceTableContractPrice)
			result.PriceTable.CollateralCost = medianCurrency(priceTableCollateralCost)
			result.PriceTable.MaxCollateral = medianCurrency(priceTableMaxCollateral)
			result.PriceTable.MaxDuration = medianUint64(priceTableMaxDuration)
			result.PriceTable.WindowSize = medianUint64(priceTableWindowSize)
			result.PriceTable.RegistryEntriesLeft = medianUint64(priceTableRegistryEntriesLeft)
			result.PriceTable.RegistryEntriesTotal = medianUint64(priceTableRegistryEntriesTotal)

			result.V2Settings.MaxCollateral = medianCurrency(v2MaxCollateral)
			result.V2Settings.MaxContractDuration = medianUint64(v2MaxContractDuration)
			result.V2Settings.RemainingStorage = medianUint64(v2RemainingStorage)
			result.V2Settings.TotalStorage = medianUint64(v2TotalStorage)

			result.V2Settings.Prices.ContractPrice = medianCurrency(v2PricesContractPrice)
			result.V2Settings.Prices.Collateral = medianCurrency(v2PricesCollateral)
			result.V2Settings.Prices.StoragePrice = medianCurrency(v2PricesStoragePrice)
			result.V2Settings.Prices.IngressPrice = medianCurrency(v2PricesIngressPrice)
			result.V2Settings.Prices.EgressPrice = medianCurrency(v2PricesEgressPrice)
			result.V2Settings.Prices.FreeSectorPrice = medianCurrency(v2PricesFreeSectorPrice)
			result.V2Settings.Prices.TipHeight = medianUint64(v2PricesTipHeight)
			result.V2Settings.Prices.ValidUntil = time.Unix(int64(medianUint64(v2PricesValidUntil)), 0)
		}

		return nil
	})
	return
}
