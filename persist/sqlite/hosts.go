package sqlite

import (
	"fmt"
	"strings"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

// Hosts returns the hosts with the given public keys.
func (st *Store) Hosts(pks []types.PublicKey) (result []explorer.Host, err error) {
	err = st.transaction(func(tx *txn) error {
		var encoded []any
		for _, pk := range pks {
			encoded = append(encoded, encode(pk))
		}

		rows, err := tx.Query(`SELECT public_key,v2,net_address,country_code,known_since,last_scan,last_scan_successful,last_announcement,total_scans,successful_interactions,failed_interactions,settings_accepting_contracts,settings_max_download_batch_size,settings_max_duration,settings_max_revise_batch_size,settings_net_address,settings_remaining_storage,settings_sector_size,settings_total_storage,settings_address,settings_window_size,settings_collateral,settings_max_collateral,settings_base_rpc_price,settings_contract_price,settings_download_bandwidth_price,settings_sector_access_price,settings_storage_price,settings_upload_bandwidth_price,settings_ephemeral_account_expiry,settings_max_ephemeral_account_balance,settings_revision_number,settings_version,settings_release,settings_sia_mux_port,price_table_uid,price_table_validity,price_table_host_block_height,price_table_update_price_table_cost,price_table_account_balance_cost,price_table_fund_account_cost,price_table_latest_revision_cost,price_table_subscription_memory_cost,price_table_subscription_notification_cost,price_table_init_base_cost,price_table_memory_time_cost,price_table_download_bandwidth_cost,price_table_upload_bandwidth_cost,price_table_drop_sectors_base_cost,price_table_drop_sectors_unit_cost,price_table_has_sector_base_cost,price_table_read_base_cost,price_table_read_length_cost,price_table_renew_contract_cost,price_table_revision_base_cost,price_table_swap_sector_base_cost,price_table_write_base_cost,price_table_write_length_cost,price_table_write_store_cost,price_table_txn_fee_min_recommended,price_table_txn_fee_max_recommended,price_table_contract_price,price_table_collateral_cost,price_table_max_collateral,price_table_max_duration,price_table_window_size,price_table_registry_entries_left,price_table_registry_entries_total,rhp4_settings_protocol_version,rhp4_settings_release,rhp4_settings_wallet_address,rhp4_settings_accepting_contracts,rhp4_settings_max_collateral,rhp4_settings_max_contract_duration,rhp4_settings_remaining_storage,rhp4_settings_total_storage,rhp4_prices_contract_price,rhp4_prices_collateral_price,rhp4_prices_storage_price,rhp4_prices_ingress_price,rhp4_prices_egress_price,rhp4_prices_free_sector_price,rhp4_prices_tip_height,rhp4_prices_valid_until,rhp4_prices_signature FROM host_info WHERE public_key IN (`+queryPlaceHolders(len(pks))+`)`, encoded...)
		if err != nil {
			return err
		}
		defer rows.Close()

		v2AddrStmt, err := tx.Prepare(`SELECT protocol,address FROM host_info_v2_netaddresses WHERE public_key = ? ORDER BY netaddress_order`)
		if err != nil {
			return err
		}
		defer v2AddrStmt.Close()

		for rows.Next() {
			if err := func() error {
				var host explorer.Host
				var protocolVersion []uint8

				s, p := &host.Settings, &host.PriceTable
				sV4, pV4 := &host.RHPV4Settings, &host.RHPV4Settings.Prices
				if err := rows.Scan(decode(&host.PublicKey), &host.V2, &host.NetAddress, &host.CountryCode, decode(&host.KnownSince), decode(&host.LastScan), &host.LastScanSuccessful, decode(&host.LastAnnouncement), &host.TotalScans, &host.SuccessfulInteractions, &host.FailedInteractions, &s.AcceptingContracts, decode(&s.MaxDownloadBatchSize), decode(&s.MaxDuration), decode(&s.MaxReviseBatchSize), &s.NetAddress, decode(&s.RemainingStorage), decode(&s.SectorSize), decode(&s.TotalStorage), decode(&s.Address), decode(&s.WindowSize), decode(&s.Collateral), decode(&s.MaxCollateral), decode(&s.BaseRPCPrice), decode(&s.ContractPrice), decode(&s.DownloadBandwidthPrice), decode(&s.SectorAccessPrice), decode(&s.StoragePrice), decode(&s.UploadBandwidthPrice), &s.EphemeralAccountExpiry, decode(&s.MaxEphemeralAccountBalance), decode(&s.RevisionNumber), &s.Version, &s.Release, &s.SiaMuxPort, decode(&p.UID), &p.Validity, decode(&p.HostBlockHeight), decode(&p.UpdatePriceTableCost), decode(&p.AccountBalanceCost), decode(&p.FundAccountCost), decode(&p.LatestRevisionCost), decode(&p.SubscriptionMemoryCost), decode(&p.SubscriptionNotificationCost), decode(&p.InitBaseCost), decode(&p.MemoryTimeCost), decode(&p.DownloadBandwidthCost), decode(&p.UploadBandwidthCost), decode(&p.DropSectorsBaseCost), decode(&p.DropSectorsUnitCost), decode(&p.HasSectorBaseCost), decode(&p.ReadBaseCost), decode(&p.ReadLengthCost), decode(&p.RenewContractCost), decode(&p.RevisionBaseCost), decode(&p.SwapSectorBaseCost), decode(&p.WriteBaseCost), decode(&p.WriteLengthCost), decode(&p.WriteStoreCost), decode(&p.TxnFeeMinRecommended), decode(&p.TxnFeeMaxRecommended), decode(&p.ContractPrice), decode(&p.CollateralCost), decode(&p.MaxCollateral), decode(&p.MaxDuration), decode(&p.WindowSize), decode(&p.RegistryEntriesLeft), decode(&p.RegistryEntriesTotal), &protocolVersion, &sV4.Release, decode(&sV4.WalletAddress), &sV4.AcceptingContracts, decode(&sV4.MaxCollateral), decode(&sV4.MaxContractDuration), decode(&sV4.RemainingStorage), decode(&sV4.TotalStorage), decode(&pV4.ContractPrice), decode(&pV4.Collateral), decode(&pV4.StoragePrice), decode(&pV4.IngressPrice), decode(&pV4.EgressPrice), decode(&pV4.FreeSectorPrice), decode(&pV4.TipHeight), decode(&pV4.ValidUntil), decode(&pV4.Signature)); err != nil {
					return err
				}
				sV4.ProtocolVersion = [3]uint8(protocolVersion)

				if host.V2 {
					v2AddrRows, err := v2AddrStmt.Query(encode(host.PublicKey))
					if err != nil {
						return err
					}
					defer v2AddrRows.Close()
					for v2AddrRows.Next() {
						var netAddr chain.NetAddress
						if err := v2AddrRows.Scan(&netAddr.Protocol, &netAddr.Address); err != nil {
							return err
						}
						host.V2NetAddresses = append(host.V2NetAddresses, netAddr)
					}
				}

				result = append(result, host)
				return nil
			}(); err != nil {
				return err
			}
		}
		return nil
	})
	return
}

// HostsForScanning returns hosts ordered by the transaction they were created in.
// Note that only the PublicKey, V2, NetAddress, and V2NetAddresses fields are
// populated.
func (s *Store) HostsForScanning(maxLastScan, minLastAnnouncement time.Time, offset, limit uint64) (result []explorer.Host, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT public_key, v2, net_address FROM host_info WHERE last_scan <= ? AND last_announcement >= ? ORDER BY last_scan ASC LIMIT ? OFFSET ?`, encode(maxLastScan), encode(minLastAnnouncement), limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()

		v2AddrStmt, err := tx.Prepare(`SELECT protocol,address FROM host_info_v2_netaddresses WHERE public_key = ? ORDER BY netaddress_order`)
		if err != nil {
			return err
		}
		defer v2AddrStmt.Close()

		for rows.Next() {
			var host explorer.Host
			if err := rows.Scan(decode(&host.PublicKey), &host.V2, &host.NetAddress); err != nil {
				return err
			}

			if host.V2 {
				err := func() error {
					v2AddrRows, err := v2AddrStmt.Query(encode(host.PublicKey))
					if err != nil {
						return err
					}
					defer v2AddrRows.Close()
					for v2AddrRows.Next() {
						var netAddr chain.NetAddress
						if err := v2AddrRows.Scan(&netAddr.Protocol, &netAddr.Address); err != nil {
							return err
						}
						host.V2NetAddresses = append(host.V2NetAddresses, netAddr)
					}
					return nil
				}()
				if err != nil {
					return err
				}
			}
			result = append(result, host)
		}
		return nil
	})
	return
}

// QueryHosts returns the hosts matching the query parameters in the order
// specified by dir.
func (st *Store) QueryHosts(params explorer.HostQuery, sortBy explorer.HostSortColumn, dir explorer.HostSortDir, offset, limit uint64) (result []explorer.Host, err error) {
	var args []any
	var filters []string

	if params.V2 {
		filters = append(filters, `v2 = 1`)
	} else {
		filters = append(filters, `v2 = 0`)
	}

	const uptimeValue = `(successful_interactions * 1.0 / MAX(1, total_scans))`
	if params.MinUptime > 0 {
		filters = append(filters, uptimeValue+" >= ?")
		args = append(args, params.MinUptime/100.0)
	}
	if params.MinDuration > 0 {
		if params.V2 {
			filters = append(filters, "rhp4_settings_max_contract_duration >= ?")
		} else {
			filters = append(filters, "settings_max_duration >= ?")
		}
		args = append(args, encode(params.MinDuration))
	}
	if !params.MaxStoragePrice.IsZero() {
		if params.V2 {
			filters = append(filters, "rhp4_prices_storage_price <= ?")
		} else {
			filters = append(filters, "settings_storage_price <= ?")
		}
		args = append(args, encode(params.MaxStoragePrice))
	}
	if !params.MaxContractPrice.IsZero() {
		if params.V2 {
			filters = append(filters, "rhp4_prices_contract_price <= ?")
		} else {
			filters = append(filters, "settings_contract_price <= ?")
		}
		args = append(args, encode(params.MaxContractPrice))
	}
	if !params.MaxUploadPrice.IsZero() {
		if params.V2 {
			filters = append(filters, "rhp4_prices_ingress_price <= ?")
		} else {
			filters = append(filters, "settings_upload_bandwidth_price <= ?")
		}
		args = append(args, encode(params.MaxUploadPrice))
	}
	if !params.MaxDownloadPrice.IsZero() {
		if params.V2 {
			filters = append(filters, "rhp4_prices_egress_price <= ?")
		} else {
			filters = append(filters, "settings_download_bandwidth_price <= ?")
		}
		args = append(args, encode(params.MaxDownloadPrice))
	}
	if !params.MaxBaseRPCPrice.IsZero() {
		filters = append(filters, "settings_base_rpc_price <= ?")
		args = append(args, encode(params.MaxBaseRPCPrice))
	}
	if !params.MaxSectorAccessPrice.IsZero() {
		filters = append(filters, "settings_sector_access_price <= ?")
		args = append(args, encode(params.MaxSectorAccessPrice))
	}
	if params.AcceptContracts {
		if params.V2 {
			filters = append(filters, "rhp4_settings_accepting_contracts = 1")
		} else {
			filters = append(filters, "settings_accepting_contracts = 1")
		}
	}
	if params.Online {
		filters = append(filters, "last_scan_successful = 1")
	}
	args = append(args, limit, offset)

	var sortColumn string
	switch sortBy {
	case explorer.HostSortDateCreated:
		sortColumn = "known_since"
	case explorer.HostSortNetAddress:
		sortColumn = "net_address"
	case explorer.HostSortPublicKey:
		sortColumn = "public_key"
	case explorer.HostSortUptime:
		sortColumn = uptimeValue
	case explorer.HostSortAcceptingContracts:
		if params.V2 {
			sortColumn = "rhp4_settings_accepting_contracts"
		} else {
			sortColumn = "settings_accepting_contracts"
		}
	case explorer.HostSortStoragePrice:
		if params.V2 {
			sortColumn = "rhp4_prices_storage_price"
		} else {
			sortColumn = "settings_storage_price"
		}
	case explorer.HostSortContractPrice:
		if params.V2 {
			sortColumn = "rhp4_prices_contract_price"
		} else {
			sortColumn = "settings_contract_price"
		}
	case explorer.HostSortDownloadPrice:
		if params.V2 {
			sortColumn = "rhp4_prices_egress_price"
		} else {
			sortColumn = "settings_download_bandwidth_price"
		}
	case explorer.HostSortUploadPrice:
		if params.V2 {
			sortColumn = "rhp4_prices_ingress_price"
		} else {
			sortColumn = "settings_upload_bandwidth_price"
		}
	case explorer.HostSortUsedStorage:
		if params.V2 {
			sortColumn = "rhp4_settings_total_storage - rhp4_settings_remaining_storage"
		} else {
			sortColumn = "settings_total_storage - settings_remaining_storage"
		}
	case explorer.HostSortTotalStorage:
		if params.V2 {
			sortColumn = "rhp4_settings_total_storage"
		} else {
			sortColumn = "settings_total_storage"
		}
	default:
		panic("invalid sort column")
	}

	whereClause := ""
	if len(filters) > 0 {
		whereClause = "WHERE " + strings.Join(filters, " AND ")
	}
	query := fmt.Sprintf(`
        SELECT public_key,v2,net_address,country_code,known_since,last_scan,last_scan_successful,last_announcement,total_scans,successful_interactions,failed_interactions,settings_accepting_contracts,settings_max_download_batch_size,settings_max_duration,settings_max_revise_batch_size,settings_net_address,settings_remaining_storage,settings_sector_size,settings_total_storage,settings_address,settings_window_size,settings_collateral,settings_max_collateral,settings_base_rpc_price,settings_contract_price,settings_download_bandwidth_price,settings_sector_access_price,settings_storage_price,settings_upload_bandwidth_price,settings_ephemeral_account_expiry,settings_max_ephemeral_account_balance,settings_revision_number,settings_version,settings_release,settings_sia_mux_port,price_table_uid,price_table_validity,price_table_host_block_height,price_table_update_price_table_cost,price_table_account_balance_cost,price_table_fund_account_cost,price_table_latest_revision_cost,price_table_subscription_memory_cost,price_table_subscription_notification_cost,price_table_init_base_cost,price_table_memory_time_cost,price_table_download_bandwidth_cost,price_table_upload_bandwidth_cost,price_table_drop_sectors_base_cost,price_table_drop_sectors_unit_cost,price_table_has_sector_base_cost,price_table_read_base_cost,price_table_read_length_cost,price_table_renew_contract_cost,price_table_revision_base_cost,price_table_swap_sector_base_cost,price_table_write_base_cost,price_table_write_length_cost,price_table_write_store_cost,price_table_txn_fee_min_recommended,price_table_txn_fee_max_recommended,price_table_contract_price,price_table_collateral_cost,price_table_max_collateral,price_table_max_duration,price_table_window_size,price_table_registry_entries_left,price_table_registry_entries_total,rhp4_settings_protocol_version,rhp4_settings_release,rhp4_settings_wallet_address,rhp4_settings_accepting_contracts,rhp4_settings_max_collateral,rhp4_settings_max_contract_duration,rhp4_settings_remaining_storage,rhp4_settings_total_storage,rhp4_prices_contract_price,rhp4_prices_collateral_price,rhp4_prices_storage_price,rhp4_prices_ingress_price,rhp4_prices_egress_price,rhp4_prices_free_sector_price,rhp4_prices_tip_height,rhp4_prices_valid_until,rhp4_prices_signature FROM host_info
        %s
        ORDER BY (%s) %s
        LIMIT ? OFFSET ?`,
		whereClause, sortColumn, dir,
	)

	err = st.transaction(func(tx *txn) error {
		v2AddrStmt, err := tx.Prepare(`SELECT protocol,address FROM host_info_v2_netaddresses WHERE public_key = ? ORDER BY netaddress_order`)
		if err != nil {
			return err
		}
		defer v2AddrStmt.Close()

		rows, err := tx.Query(query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			if err := func() error {
				var host explorer.Host
				var protocolVersion []uint8

				s, p := &host.Settings, &host.PriceTable
				sV4, pV4 := &host.RHPV4Settings, &host.RHPV4Settings.Prices
				if err := rows.Scan(decode(&host.PublicKey), &host.V2, &host.NetAddress, &host.CountryCode, decode(&host.KnownSince), decode(&host.LastScan), &host.LastScanSuccessful, decode(&host.LastAnnouncement), &host.TotalScans, &host.SuccessfulInteractions, &host.FailedInteractions, &s.AcceptingContracts, decode(&s.MaxDownloadBatchSize), decode(&s.MaxDuration), decode(&s.MaxReviseBatchSize), &s.NetAddress, decode(&s.RemainingStorage), decode(&s.SectorSize), decode(&s.TotalStorage), decode(&s.Address), decode(&s.WindowSize), decode(&s.Collateral), decode(&s.MaxCollateral), decode(&s.BaseRPCPrice), decode(&s.ContractPrice), decode(&s.DownloadBandwidthPrice), decode(&s.SectorAccessPrice), decode(&s.StoragePrice), decode(&s.UploadBandwidthPrice), &s.EphemeralAccountExpiry, decode(&s.MaxEphemeralAccountBalance), decode(&s.RevisionNumber), &s.Version, &s.Release, &s.SiaMuxPort, decode(&p.UID), &p.Validity, decode(&p.HostBlockHeight), decode(&p.UpdatePriceTableCost), decode(&p.AccountBalanceCost), decode(&p.FundAccountCost), decode(&p.LatestRevisionCost), decode(&p.SubscriptionMemoryCost), decode(&p.SubscriptionNotificationCost), decode(&p.InitBaseCost), decode(&p.MemoryTimeCost), decode(&p.DownloadBandwidthCost), decode(&p.UploadBandwidthCost), decode(&p.DropSectorsBaseCost), decode(&p.DropSectorsUnitCost), decode(&p.HasSectorBaseCost), decode(&p.ReadBaseCost), decode(&p.ReadLengthCost), decode(&p.RenewContractCost), decode(&p.RevisionBaseCost), decode(&p.SwapSectorBaseCost), decode(&p.WriteBaseCost), decode(&p.WriteLengthCost), decode(&p.WriteStoreCost), decode(&p.TxnFeeMinRecommended), decode(&p.TxnFeeMaxRecommended), decode(&p.ContractPrice), decode(&p.CollateralCost), decode(&p.MaxCollateral), decode(&p.MaxDuration), decode(&p.WindowSize), decode(&p.RegistryEntriesLeft), decode(&p.RegistryEntriesTotal), &protocolVersion, &sV4.Release, decode(&sV4.WalletAddress), &sV4.AcceptingContracts, decode(&sV4.MaxCollateral), decode(&sV4.MaxContractDuration), decode(&sV4.RemainingStorage), decode(&sV4.TotalStorage), decode(&pV4.ContractPrice), decode(&pV4.Collateral), decode(&pV4.StoragePrice), decode(&pV4.IngressPrice), decode(&pV4.EgressPrice), decode(&pV4.FreeSectorPrice), decode(&pV4.TipHeight), decode(&pV4.ValidUntil), decode(&pV4.Signature)); err != nil {
					return err
				}
				sV4.ProtocolVersion = [3]uint8(protocolVersion)

				if host.V2 {
					v2AddrRows, err := v2AddrStmt.Query(encode(host.PublicKey))
					if err != nil {
						return err
					}
					defer v2AddrRows.Close()
					for v2AddrRows.Next() {
						var netAddr chain.NetAddress
						if err := v2AddrRows.Scan(&netAddr.Protocol, &netAddr.Address); err != nil {
							return err
						}
						host.V2NetAddresses = append(host.V2NetAddresses, netAddr)
					}
				}

				result = append(result, host)
				return nil
			}(); err != nil {
				return err
			}
		}
		return nil
	})
	return
}
