package postgres

import (
	"fmt"
	"strings"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

// LastSuccessScan returns the last time a successful scan was performed.
// If no successful scan has been performed, it returns the zero time.
func (s *Store) LastSuccessScan() (lastScan time.Time, err error) {
	err = s.transaction(func(tx *txn) error {
		return tx.QueryRow(`SELECT MAX(last_scan) FROM host_info WHERE last_scan_successful = true`).Scan(decodeNull(&lastScan))
	})
	if err != nil {
		return time.Time{}, err
	}
	return
}

// HostsForScanning returns hosts ordered by their time to next scan.  Hosts
// which are repeatedly offline will face an exponentially growing next scan
// time to avoid wasting resources.
// Note that only the PublicKey, V2, NetAddress, V2NetAddresses,
// FailedInteractionsStreak fields are populated.
func (s *Store) HostsForScanning(minLastAnnouncement time.Time, limit uint64) (result []explorer.UnscannedHost, err error) {
	err = s.transaction(func(tx *txn) error {
		result = result[:0]

		rows, err := tx.Query(`SELECT public_key, v2, net_address, failed_interactions_streak FROM host_info WHERE next_scan <= $1 AND last_announcement >= $2 ORDER BY next_scan ASC LIMIT $3`, encode(types.CurrentTimestamp()), encode(minLastAnnouncement), limit)
		if err != nil {
			return fmt.Errorf("failed to query hosts: %w", err)
		}
		// pgx forbids concurrent operations on a connection, so drain the
		// outer rows before issuing per-host follow-up queries.
		var hosts []explorer.UnscannedHost
		for rows.Next() {
			var host explorer.UnscannedHost
			if err := rows.Scan(decode(&host.PublicKey), &host.V2, &host.NetAddress, &host.FailedInteractionsStreak); err != nil {
				rows.Close()
				return err
			}
			hosts = append(hosts, host)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to retrieve host rows: %w", err)
		}

		v2AddrStmt, err := tx.Prepare(`SELECT protocol,address FROM host_info_v2_netaddresses WHERE public_key = $1 ORDER BY netaddress_order`)
		if err != nil {
			return fmt.Errorf("failed to prepare v2 addrs statement: %w", err)
		}
		defer v2AddrStmt.Close()

		for _, host := range hosts {
			if host.V2 {
				err := func() error {
					v2AddrRows, err := v2AddrStmt.Query(encode(host.PublicKey))
					if err != nil {
						return fmt.Errorf("failed to query v2 addrs: %w", err)
					}
					defer v2AddrRows.Close()
					for v2AddrRows.Next() {
						var netAddr chain.NetAddress
						if err := v2AddrRows.Scan(&netAddr.Protocol, &netAddr.Address); err != nil {
							return fmt.Errorf("failed to scan v2 addrs: %w", err)
						}
						host.V2NetAddresses = append(host.V2NetAddresses, netAddr)
					}
					if err := v2AddrRows.Err(); err != nil {
						return fmt.Errorf("failed to retrieve v2 addr rows: %w", err)
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
	if dir != explorer.HostSortAsc && dir != explorer.HostSortDesc {
		return nil, fmt.Errorf("invalid HostSortDir: %s", dir)
	}
	err = st.transaction(func(tx *txn) error {
		result = result[:0]

		var args []any
		var filters []string

		if params.V2 != nil {
			if *params.V2 {
				filters = append(filters, `v2 = true`)
			} else {
				filters = append(filters, `v2 = false`)
			}
		}

		if len(params.PublicKeys) > 0 {
			filter := `public_key IN (` + queryPlaceHolders(len(args)+1, len(params.PublicKeys)) + `)`
			for _, pk := range params.PublicKeys {
				args = append(args, encode(pk))
			}
			filters = append(filters, filter)
		}

		if len(params.NetAddresses) > 0 {
			var addrFilters []string
			if params.V2 == nil || !*params.V2 {
				addrFilter := `net_address IN (` + queryPlaceHolders(len(args)+1, len(params.NetAddresses)) + `)`
				for _, netAddress := range params.NetAddresses {
					args = append(args, any(netAddress))
				}
				addrFilters = append(addrFilters, addrFilter)
			}
			if params.V2 == nil || *params.V2 {
				netAddresses := make([]any, 0, len(params.NetAddresses))
				for _, netAddress := range params.NetAddresses {
					netAddresses = append(netAddresses, any(netAddress))
				}
				rows, err := tx.Query(`SELECT public_key FROM host_info_v2_netaddresses WHERE address IN (`+queryPlaceHolders(1, len(params.NetAddresses))+`)`, netAddresses...)
				if err != nil {
					return fmt.Errorf("failed to get query public keys for given net addresses: %w", err)
				}
				defer rows.Close()

				var pks []any
				for rows.Next() {
					var pk types.PublicKey
					if err := rows.Scan(decode(&pk)); err != nil {
						return fmt.Errorf("failed to scan public key: %w", err)
					}
					pks = append(pks, encode(pk))
				}
				if err := rows.Err(); err != nil {
					return fmt.Errorf("error retrieving host public keys rows: %w", err)
				}

				// postgres rejects `IN ()`, so only contribute the v2 filter
				// when we actually have matching public keys.
				if len(pks) > 0 {
					addrFilter := `public_key IN (` + queryPlaceHolders(len(args)+1, len(pks)) + `)`
					args = append(args, pks...)
					addrFilters = append(addrFilters, addrFilter)
				}
			}
			if len(addrFilters) == 0 {
				// v2 only lookup with no v2 matches: no host can satisfy the
				// filter. Force the WHERE to evaluate to false rather than
				// emitting an empty `()`.
				filters = append(filters, `FALSE`)
			} else {
				filters = append(filters, `(`+strings.Join(addrFilters, ` OR `)+`)`)
			}
		}

		const uptimeValue = `(successful_interactions * 1.0 / GREATEST(1, total_scans))`
		if params.MinUptime != nil {
			filters = append(filters, fmt.Sprintf(`%s >= $%d`, uptimeValue, len(args)+1))
			args = append(args, *params.MinUptime/100.0)
		}
		if params.MinDuration != nil {
			n := len(args)
			filters = append(filters, fmt.Sprintf(`CASE WHEN v2=true THEN v2_settings_max_contract_duration >= $%d ELSE settings_max_duration >= $%d END`, n+1, n+2))
			args = append(args, encode(*params.MinDuration), encode(*params.MinDuration))
		}
		if params.MaxStoragePrice != nil {
			n := len(args)
			filters = append(filters, fmt.Sprintf(`CASE WHEN v2=true THEN v2_prices_storage_price <= $%d ELSE settings_storage_price <= $%d END`, n+1, n+2))
			args = append(args, encode(*params.MaxStoragePrice), encode(*params.MaxStoragePrice))
		}
		if params.MaxContractPrice != nil {
			n := len(args)
			filters = append(filters, fmt.Sprintf(`CASE WHEN v2=true THEN v2_prices_contract_price <= $%d ELSE settings_contract_price <= $%d END`, n+1, n+2))
			args = append(args, encode(*params.MaxContractPrice), encode(*params.MaxContractPrice))
		}
		if params.MaxUploadPrice != nil {
			n := len(args)
			filters = append(filters, fmt.Sprintf(`CASE WHEN v2=true THEN v2_prices_ingress_price <= $%d ELSE settings_upload_bandwidth_price <= $%d END`, n+1, n+2))
			args = append(args, encode(*params.MaxUploadPrice), encode(*params.MaxUploadPrice))
		}
		if params.MaxDownloadPrice != nil {
			n := len(args)
			filters = append(filters, fmt.Sprintf(`CASE WHEN v2=true THEN v2_prices_egress_price <= $%d ELSE settings_download_bandwidth_price <= $%d END`, n+1, n+2))
			args = append(args, encode(*params.MaxDownloadPrice), encode(*params.MaxDownloadPrice))
		}
		if params.MaxBaseRPCPrice != nil {
			filters = append(filters, fmt.Sprintf(`settings_base_rpc_price <= $%d`, len(args)+1))
			args = append(args, encode(*params.MaxBaseRPCPrice))
		}
		if params.MaxSectorAccessPrice != nil {
			filters = append(filters, fmt.Sprintf(`settings_sector_access_price <= $%d`, len(args)+1))
			args = append(args, encode(*params.MaxSectorAccessPrice))
		}
		if params.AcceptContracts != nil {
			v := "false"
			if *params.AcceptContracts {
				v = "true"
			}
			filters = append(filters, fmt.Sprintf(`CASE WHEN v2=true THEN v2_settings_accepting_contracts = %s ELSE settings_accepting_contracts = %s END`, v, v))
		}
		if params.Online != nil {
			v := "false"
			if *params.Online {
				v = "true"
			}
			filters = append(filters, fmt.Sprintf(`last_scan_successful = %s`, v))
		}
		limitPos := len(args) + 1
		offsetPos := len(args) + 2
		args = append(args, limit, offset)

		var sortColumn string
		switch sortBy {
		case explorer.HostSortDateCreated:
			sortColumn = `known_since`
		case explorer.HostSortNetAddress:
			sortColumn = `net_address`
		case explorer.HostSortPublicKey:
			sortColumn = `public_key`
		case explorer.HostSortUptime:
			sortColumn = uptimeValue
		case explorer.HostSortAcceptingContracts:
			sortColumn = `CASE WHEN v2=true THEN v2_settings_accepting_contracts ELSE settings_accepting_contracts END`
		case explorer.HostSortStoragePrice:
			sortColumn = `CASE WHEN v2=true THEN v2_prices_storage_price ELSE settings_storage_price END`
		case explorer.HostSortContractPrice:
			sortColumn = `CASE WHEN v2=true THEN v2_prices_contract_price ELSE settings_contract_price END`
		case explorer.HostSortDownloadPrice:
			sortColumn = `CASE WHEN v2=true THEN v2_prices_egress_price ELSE settings_download_bandwidth_price END`
		case explorer.HostSortUploadPrice:
			sortColumn = `CASE WHEN v2=true THEN v2_prices_ingress_price ELSE settings_upload_bandwidth_price END`
		case explorer.HostSortUsedStorage:
			sortColumn = `CASE WHEN v2=true THEN v2_settings_used_storage ELSE settings_used_storage END`
		case explorer.HostSortTotalStorage:
			sortColumn = `CASE WHEN v2=true THEN v2_settings_total_storage ELSE settings_total_storage END`
		default:
			return fmt.Errorf("%w: %s", explorer.ErrNoSortColumn, sortBy)
		}

		var whereClause string
		if len(filters) > 0 {
			whereClause = "WHERE " + strings.Join(filters, " AND ")
		}
		query := fmt.Sprintf(`
        SELECT public_key,v2,net_address,country_code,latitude,longitude,known_since,last_scan,last_scan_successful,last_scan_error,last_announcement,next_scan,total_scans,successful_interactions,failed_interactions_streak,settings_accepting_contracts,settings_max_download_batch_size,settings_max_duration,settings_max_revise_batch_size,settings_net_address,settings_remaining_storage,settings_sector_size,settings_total_storage,settings_address,settings_window_size,settings_collateral,settings_max_collateral,settings_base_rpc_price,settings_contract_price,settings_download_bandwidth_price,settings_sector_access_price,settings_storage_price,settings_upload_bandwidth_price,settings_ephemeral_account_expiry,settings_max_ephemeral_account_balance,settings_revision_number,settings_version,settings_release,settings_sia_mux_port,price_table_uid,price_table_validity,price_table_host_block_height,price_table_update_price_table_cost,price_table_account_balance_cost,price_table_fund_account_cost,price_table_latest_revision_cost,price_table_subscription_memory_cost,price_table_subscription_notification_cost,price_table_init_base_cost,price_table_memory_time_cost,price_table_download_bandwidth_cost,price_table_upload_bandwidth_cost,price_table_drop_sectors_base_cost,price_table_drop_sectors_unit_cost,price_table_has_sector_base_cost,price_table_read_base_cost,price_table_read_length_cost,price_table_renew_contract_cost,price_table_revision_base_cost,price_table_swap_sector_base_cost,price_table_write_base_cost,price_table_write_length_cost,price_table_write_store_cost,price_table_txn_fee_min_recommended,price_table_txn_fee_max_recommended,price_table_contract_price,price_table_collateral_cost,price_table_max_collateral,price_table_max_duration,price_table_window_size,price_table_registry_entries_left,price_table_registry_entries_total,v2_settings_protocol_version,v2_settings_release,v2_settings_wallet_address,v2_settings_accepting_contracts,v2_settings_max_collateral,v2_settings_max_contract_duration,v2_settings_remaining_storage,v2_settings_total_storage,v2_prices_contract_price,v2_prices_collateral_price,v2_prices_storage_price,v2_prices_ingress_price,v2_prices_egress_price,v2_prices_free_sector_price,v2_prices_tip_height,v2_prices_valid_until,v2_prices_signature FROM host_info
        %s
        ORDER BY (%s) %s
        LIMIT $%d OFFSET $%d`,
			whereClause, sortColumn, dir, limitPos, offsetPos,
		)

		rows, err := tx.Query(query, args...)
		if err != nil {
			return fmt.Errorf("failed to query hosts: %w", err)
		}
		// pgx forbids concurrent operations on a connection, so drain the
		// outer rows before issuing per-host follow-up queries.
		for rows.Next() {
			var host explorer.Host
			var protocolVersion []uint8
			var lastScanError string

			s, p := &host.Settings, &host.PriceTable
			sV2, pV2 := &host.V2Settings, &host.V2Settings.Prices
			if err := rows.Scan(decode(&host.PublicKey), &host.V2, &host.NetAddress, &host.Location.CountryCode, &host.Location.Latitude, &host.Location.Longitude, decode(&host.KnownSince), decode(&host.LastScan), &host.LastScanSuccessful, &lastScanError, decode(&host.LastAnnouncement), decode(&host.NextScan), &host.TotalScans, &host.SuccessfulInteractions, &host.FailedInteractions, &s.AcceptingContracts, decode(&s.MaxDownloadBatchSize), decode(&s.MaxDuration), decode(&s.MaxReviseBatchSize), &s.NetAddress, decode(&s.RemainingStorage), decode(&s.SectorSize), decode(&s.TotalStorage), decode(&s.Address), decode(&s.WindowSize), decode(&s.Collateral), decode(&s.MaxCollateral), decode(&s.BaseRPCPrice), decode(&s.ContractPrice), decode(&s.DownloadBandwidthPrice), decode(&s.SectorAccessPrice), decode(&s.StoragePrice), decode(&s.UploadBandwidthPrice), &s.EphemeralAccountExpiry, decode(&s.MaxEphemeralAccountBalance), decode(&s.RevisionNumber), &s.Version, &s.Release, &s.SiaMuxPort, decode(&p.UID), &p.Validity, decode(&p.HostBlockHeight), decode(&p.UpdatePriceTableCost), decode(&p.AccountBalanceCost), decode(&p.FundAccountCost), decode(&p.LatestRevisionCost), decode(&p.SubscriptionMemoryCost), decode(&p.SubscriptionNotificationCost), decode(&p.InitBaseCost), decode(&p.MemoryTimeCost), decode(&p.DownloadBandwidthCost), decode(&p.UploadBandwidthCost), decode(&p.DropSectorsBaseCost), decode(&p.DropSectorsUnitCost), decode(&p.HasSectorBaseCost), decode(&p.ReadBaseCost), decode(&p.ReadLengthCost), decode(&p.RenewContractCost), decode(&p.RevisionBaseCost), decode(&p.SwapSectorBaseCost), decode(&p.WriteBaseCost), decode(&p.WriteLengthCost), decode(&p.WriteStoreCost), decode(&p.TxnFeeMinRecommended), decode(&p.TxnFeeMaxRecommended), decode(&p.ContractPrice), decode(&p.CollateralCost), decode(&p.MaxCollateral), decode(&p.MaxDuration), decode(&p.WindowSize), decode(&p.RegistryEntriesLeft), decode(&p.RegistryEntriesTotal), &protocolVersion, &sV2.Release, decode(&sV2.WalletAddress), &sV2.AcceptingContracts, decode(&sV2.MaxCollateral), decode(&sV2.MaxContractDuration), decode(&sV2.RemainingStorage), decode(&sV2.TotalStorage), decode(&pV2.ContractPrice), decode(&pV2.Collateral), decode(&pV2.StoragePrice), decode(&pV2.IngressPrice), decode(&pV2.EgressPrice), decode(&pV2.FreeSectorPrice), decode(&pV2.TipHeight), decode(&pV2.ValidUntil), decode(&pV2.Signature)); err != nil {
				rows.Close()
				return err
			}
			sV2.ProtocolVersion = [3]uint8(protocolVersion)
			if lastScanError != "" {
				host.LastScanError = &lastScanError
			}

			result = append(result, host)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to retrieve host rows: %w", err)
		}

		v2AddrStmt, err := tx.Prepare(`SELECT protocol,address FROM host_info_v2_netaddresses WHERE public_key = $1 ORDER BY netaddress_order`)
		if err != nil {
			return fmt.Errorf("failed to prepare v2 addrs statement: %w", err)
		}
		defer v2AddrStmt.Close()

		for i := range result {
			host := &result[i]
			if !host.V2 {
				continue
			}
			err := func() error {
				v2AddrRows, err := v2AddrStmt.Query(encode(host.PublicKey))
				if err != nil {
					return fmt.Errorf("failed to query v2 addrs: %w", err)
				}
				defer v2AddrRows.Close()
				for v2AddrRows.Next() {
					var netAddr chain.NetAddress
					if err := v2AddrRows.Scan(&netAddr.Protocol, &netAddr.Address); err != nil {
						return fmt.Errorf("failed to scan v2 addr: %w", err)
					}
					host.V2NetAddresses = append(host.V2NetAddresses, netAddr)
				}
				if err := v2AddrRows.Err(); err != nil {
					return fmt.Errorf("failed to retrieve v2 addr rows: %w", err)
				}
				return nil
			}()
			if err != nil {
				return err
			}
		}
		return nil
	})
	return
}
