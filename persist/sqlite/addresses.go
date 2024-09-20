package sqlite

import (
	"database/sql"
	"fmt"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

func scanEvent(tx *txn, s scanner) (ev explorer.Event, eventID int64, err error) {
	var eventType string

	err = s.Scan(&eventID, decode(&ev.ID), &ev.MaturityHeight, decode(&ev.Timestamp), &ev.Index.Height, decode(&ev.Index.ID), &eventType)
	if err != nil {
		return
	}

	switch eventType {
	case explorer.EventTypeTransaction:
		var txnID int64
		var eventTx explorer.EventTransaction
		err = tx.QueryRow(`SELECT transaction_id, fee FROM transaction_events WHERE event_id = ?`, eventID).Scan(&txnID, decode(&eventTx.Fee))
		if err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to fetch transaction ID: %w", err)
		}
		txns, err := getTransactions(tx, map[int64]transactionID{txnID: {id: types.TransactionID(ev.ID)}})
		if err != nil || len(txns) == 0 {
			return explorer.Event{}, 0, fmt.Errorf("failed to fetch transaction: %w", err)
		}

		rows, err := tx.Query(`SELECT public_key, net_address FROM host_announcements WHERE transaction_id = ? ORDER BY transaction_order ASC`, txnID)
		if err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to get host announcements: %w", err)
		}
		defer rows.Close()

		eventTx.Transaction = txns[0]
		for rows.Next() {
			var announcement chain.HostAnnouncement
			if err := rows.Scan(decode(&announcement.PublicKey), &announcement.NetAddress); err != nil {
				return explorer.Event{}, 0, fmt.Errorf("failed to scan announcement: %w", err)
			}
			eventTx.HostAnnouncements = append(eventTx.HostAnnouncements, announcement)
		}
		ev.Data = &eventTx
	case explorer.EventTypeContractPayout:
		var m explorer.EventContractPayout
		err = tx.QueryRow(`SELECT sce.output_id, sce.leaf_index, sce.maturity_height, sce.address, sce.value, fce.contract_id, fce.leaf_index, fce.filesize, fce.file_merkle_root, fce.window_start, fce.window_end, fce.payout, fce.unlock_hash, fce.revision_number, ev.missed
FROM contract_payout_events ev
JOIN siacoin_elements sce ON ev.output_id = sce.id
JOIN file_contract_elements fce ON ev.contract_id = fce.id
WHERE ev.event_id = ?`, eventID).Scan(decode(&m.SiacoinOutput.StateElement.ID), decode(&m.SiacoinOutput.StateElement.LeafIndex), &m.SiacoinOutput.MaturityHeight, decode(&m.SiacoinOutput.SiacoinOutput.Address), decode(&m.SiacoinOutput.SiacoinOutput.Value), decode(&m.FileContract.StateElement.ID), decode(&m.FileContract.StateElement.LeafIndex), decode(&m.FileContract.FileContract.Filesize), decode(&m.FileContract.FileContract.FileMerkleRoot), decode(&m.FileContract.FileContract.WindowStart), decode(&m.FileContract.FileContract.WindowEnd), decode(&m.FileContract.FileContract.Payout), decode(&m.FileContract.FileContract.UnlockHash), decode(&m.FileContract.FileContract.RevisionNumber), &m.Missed)
		ev.Data = &m
	case explorer.EventTypeMinerPayout:
		var m explorer.EventMinerPayout
		err = tx.QueryRow(`SELECT sc.output_id, sc.leaf_index, sc.maturity_height, sc.address, sc.value
FROM siacoin_elements sc
INNER JOIN miner_payout_events ev ON (ev.output_id = sc.id)
WHERE ev.event_id = ?`, eventID).Scan(decode(&m.SiacoinOutput.StateElement.ID), decode(&m.SiacoinOutput.StateElement.LeafIndex), decode(&m.SiacoinOutput.MaturityHeight), decode(&m.SiacoinOutput.SiacoinOutput.Address), decode(&m.SiacoinOutput.SiacoinOutput.Value))
		if err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to fetch miner payout event data: %w", err)
		}
		ev.Data = &m
	case explorer.EventTypeFoundationSubsidy:
		var m explorer.EventFoundationSubsidy
		err = tx.QueryRow(`SELECT sc.output_id, sc.leaf_index, sc.maturity_height, sc.address, sc.value
FROM siacoin_elements sc
INNER JOIN foundation_subsidy_events ev ON (ev.output_id = sc.id)
WHERE ev.event_id = ?`, eventID).Scan(decode(&m.SiacoinOutput.StateElement.ID), decode(&m.SiacoinOutput.StateElement.LeafIndex), decode(&m.SiacoinOutput.MaturityHeight), decode(&m.SiacoinOutput.SiacoinOutput.Address), decode(&m.SiacoinOutput.SiacoinOutput.Value))
		ev.Data = &m
	default:
		return explorer.Event{}, 0, fmt.Errorf("unknown event type: %s", eventType)
	}

	if err != nil {
		return explorer.Event{}, 0, fmt.Errorf("failed to fetch transaction event data: %w", err)
	}

	return
}

// Hosts returns the hosts with the given public keys.
func (s *Store) Hosts(pks []types.PublicKey) (result []explorer.Host, err error) {
	err = s.transaction(func(tx *txn) error {
		var encoded []any
		for _, pk := range pks {
			encoded = append(encoded, encode(pk))
		}

		rows, err := tx.Query(`SELECT public_key,net_address,known_since,last_scan,last_scan_successful,last_announcement,total_scans,successful_interactions,failed_interactions,settings_accepting_contracts,settings_max_download_batch_size,settings_max_duration,settings_max_revise_batch_size,settings_net_address,settings_remaining_storage,settings_sector_size,settings_total_storage,settings_address,settings_window_size,settings_collateral,settings_max_collateral,settings_base_rpc_price,settings_contract_price,settings_download_bandwidth_price,settings_sector_access_price,settings_storage_price,settings_upload_bandwidth_price,settings_ephemeral_account_expiry,settings_max_ephemeral_account_balance,settings_revision_number,settings_version,settings_release,settings_sia_mux_port,price_table_uid,price_table_validity,price_table_host_block_height,price_table_update_price_table_cost,price_table_account_balance_cost,price_table_fund_account_cost,price_table_latest_revision_cost,price_table_subscription_memory_cost,price_table_subscription_notification_cost,price_table_init_base_cost,price_table_memory_time_cost,price_table_download_bandwidth_cost,price_table_upload_bandwidth_cost,price_table_drop_sectors_base_cost,price_table_drop_sectors_unit_cost,price_table_has_sector_base_cost,price_table_read_base_cost,price_table_read_length_cost,price_table_renew_contract_cost,price_table_revision_base_cost,price_table_swap_sector_base_cost,price_table_write_base_cost,price_table_write_length_cost,price_table_write_store_cost,price_table_txn_fee_min_recommended,price_table_txn_fee_max_recommended,price_table_contract_price,price_table_collateral_cost,price_table_max_collateral,price_table_max_duration,price_table_window_size,price_table_registry_entries_left,price_table_registry_entries_total FROM host_info WHERE public_key IN (`+queryPlaceHolders(len(pks))+`)`, encoded...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var host explorer.Host
			s, p := &host.Settings, &host.PriceTable
			if err := rows.Scan(decode(&host.PublicKey), &host.NetAddress, decode(&host.KnownSince), decode(&host.LastScan), &host.LastScanSuccessful, decode(&host.LastAnnouncement), &host.TotalScans, &host.SuccessfulInteractions, &host.FailedInteractions, &s.AcceptingContracts, decode(&s.MaxDownloadBatchSize), decode(&s.MaxDuration), decode(&s.MaxReviseBatchSize), &s.NetAddress, decode(&s.RemainingStorage), decode(&s.SectorSize), decode(&s.TotalStorage), decode(&s.Address), decode(&s.WindowSize), decode(&s.Collateral), decode(&s.MaxCollateral), decode(&s.BaseRPCPrice), decode(&s.ContractPrice), decode(&s.DownloadBandwidthPrice), decode(&s.SectorAccessPrice), decode(&s.StoragePrice), decode(&s.UploadBandwidthPrice), &s.EphemeralAccountExpiry, decode(&s.MaxEphemeralAccountBalance), decode(&s.RevisionNumber), &s.Version, &s.Release, &s.SiaMuxPort, decode(&p.UID), &p.Validity, decode(&p.HostBlockHeight), decode(&p.UpdatePriceTableCost), decode(&p.AccountBalanceCost), decode(&p.FundAccountCost), decode(&p.LatestRevisionCost), decode(&p.SubscriptionMemoryCost), decode(&p.SubscriptionNotificationCost), decode(&p.InitBaseCost), decode(&p.MemoryTimeCost), decode(&p.DownloadBandwidthCost), decode(&p.UploadBandwidthCost), decode(&p.DropSectorsBaseCost), decode(&p.DropSectorsUnitCost), decode(&p.HasSectorBaseCost), decode(&p.ReadBaseCost), decode(&p.ReadLengthCost), decode(&p.RenewContractCost), decode(&p.RevisionBaseCost), decode(&p.SwapSectorBaseCost), decode(&p.WriteBaseCost), decode(&p.WriteLengthCost), decode(&p.WriteStoreCost), decode(&p.TxnFeeMinRecommended), decode(&p.TxnFeeMaxRecommended), decode(&p.ContractPrice), decode(&p.CollateralCost), decode(&p.MaxCollateral), decode(&p.MaxDuration), decode(&p.WindowSize), decode(&p.RegistryEntriesLeft), decode(&p.RegistryEntriesTotal)); err != nil {
				return err
			}
			result = append(result, host)
		}
		return nil
	})
	return
}

// HostsForScanning returns hosts ordered by the transaction they were created in.
func (s *Store) HostsForScanning(maxLastScan, minLastAnnouncement time.Time, offset, limit uint64) (result []chain.HostAnnouncement, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT public_key, net_address FROM host_info WHERE last_scan <= ? AND last_announcement >= ? ORDER BY last_scan ASC LIMIT ? OFFSET ?`, encode(maxLastScan), encode(minLastAnnouncement), limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var host chain.HostAnnouncement
			if err := rows.Scan(decode(&host.PublicKey), &host.NetAddress); err != nil {
				return err
			}
			result = append(result, host)
		}
		return nil
	})
	return
}

// AddressEvents returns the events of a single address.
func (s *Store) AddressEvents(address types.Address, offset, limit uint64) (events []explorer.Event, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT ev.id, ev.event_id, ev.maturity_height, ev.date_created, ev.height, ev.block_id, ev.event_type
	FROM events ev
	INNER JOIN event_addresses ea ON (ev.id = ea.event_id)
	INNER JOIN address_balance sa ON (ea.address_id = sa.id)
	WHERE sa.address = $1
	ORDER BY ev.maturity_height DESC, ev.id DESC
	LIMIT $2 OFFSET $3`

		rows, err := tx.Query(query, encode(address), limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			event, _, err := scanEvent(tx, rows)
			if err != nil {
				return fmt.Errorf("failed to scan event: %w", err)
			}

			events = append(events, event)
		}
		return rows.Err()
	})
	return
}

func scanSiacoinOutput(s scanner) (sco explorer.SiacoinOutput, err error) {
	var spentIndex types.ChainIndex
	err = s.Scan(decode(&sco.StateElement.ID), decode(&sco.StateElement.LeafIndex), &sco.Source, decodeNull(&spentIndex), &sco.MaturityHeight, decode(&sco.SiacoinOutput.Address), decode(&sco.SiacoinOutput.Value))
	if spentIndex != (types.ChainIndex{}) {
		sco.SpentIndex = &spentIndex
	}
	return
}

func scanSiafundOutput(s scanner) (sfo explorer.SiafundOutput, err error) {
	var spentIndex types.ChainIndex
	err = s.Scan(decode(&sfo.StateElement.ID), decode(&sfo.StateElement.LeafIndex), decodeNull(&spentIndex), decode(&sfo.ClaimStart), decode(&sfo.SiafundOutput.Address), decode(&sfo.SiafundOutput.Value))
	if spentIndex != (types.ChainIndex{}) {
		sfo.SpentIndex = &spentIndex
	}
	return
}

// UnspentSiacoinOutputs implements explorer.Store.
func (s *Store) UnspentSiacoinOutputs(address types.Address, offset, limit uint64) (result []explorer.SiacoinOutput, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT output_id, leaf_index, source, spent_index, maturity_height, address, value FROM siacoin_elements WHERE address = ? AND spent_index IS NULL LIMIT ? OFFSET ?`, encode(address), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query siacoin outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			sco, err := scanSiacoinOutput(rows)
			if err != nil {
				return fmt.Errorf("failed to scan siacoin output: %w", err)
			}
			result = append(result, sco)
		}
		return nil
	})
	return
}

// UnspentSiafundOutputs implements explorer.Store.
func (s *Store) UnspentSiafundOutputs(address types.Address, offset, limit uint64) (result []explorer.SiafundOutput, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT output_id, leaf_index, spent_index, claim_start, address, value FROM siafund_elements WHERE address = ? AND spent_index IS NULL LIMIT ? OFFSET ?`, encode(address), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query siafund outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			sfo, err := scanSiafundOutput(rows)
			if err != nil {
				return fmt.Errorf("failed to scan siafund output: %w", err)
			}
			result = append(result, sfo)
		}
		return nil
	})
	return
}

// SiacoinElements implements explorer.Store.
func (s *Store) SiacoinElements(ids []types.SiacoinOutputID) (result []explorer.SiacoinOutput, err error) {
	err = s.transaction(func(tx *txn) error {
		var encoded []any
		for _, id := range ids {
			encoded = append(encoded, encode(id))
		}

		rows, err := tx.Query(`SELECT output_id, leaf_index, source, spent_index, maturity_height, address, value FROM siacoin_elements WHERE output_id IN (`+queryPlaceHolders(len(encoded))+`)`, encoded...)
		if err != nil {
			return fmt.Errorf("failed to query siacoin outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			sco, err := scanSiacoinOutput(rows)
			if err != nil {
				return fmt.Errorf("failed to scan siacoin output: %w", err)
			}
			result = append(result, sco)
		}
		return nil
	})
	return
}

// SiafundElements implements explorer.Store.
func (s *Store) SiafundElements(ids []types.SiafundOutputID) (result []explorer.SiafundOutput, err error) {
	err = s.transaction(func(tx *txn) error {
		var encoded []any
		for _, id := range ids {
			encoded = append(encoded, encode(id))
		}

		rows, err := tx.Query(`SELECT output_id, leaf_index, spent_index, claim_start, address, value FROM siafund_elements WHERE output_id IN (`+queryPlaceHolders(len(encoded))+`)`, encoded...)
		if err != nil {
			return fmt.Errorf("failed to query siafund outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			sfo, err := scanSiafundOutput(rows)
			if err != nil {
				return fmt.Errorf("failed to scan siafund output: %w", err)
			}
			result = append(result, sfo)
		}
		return nil
	})
	return
}

// Balance implements explorer.Store.
func (s *Store) Balance(address types.Address) (sc types.Currency, immatureSC types.Currency, sf uint64, err error) {
	err = s.transaction(func(tx *txn) error {
		err = tx.QueryRow(`SELECT siacoin_balance, immature_siacoin_balance, siafund_balance FROM address_balance WHERE address = ?`, encode(address)).Scan(decode(&sc), decode(&immatureSC), decode(&sf))
		if err == sql.ErrNoRows {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to query balances: %w", err)
		}
		return nil
	})
	return
}
