package sqlite

import (
	"database/sql"
	"fmt"

	"go.sia.tech/core/types"
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
		txns, err := getTransactions(tx, []int64{txnID})
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
			var announcement explorer.HostAnnouncement
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

// UnspentSiacoinOutputs implements explorer.Store.
func (s *Store) UnspentSiacoinOutputs(address types.Address, offset, limit uint64) (result []explorer.SiacoinOutput, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT output_id, leaf_index, source, maturity_height, address, value FROM siacoin_elements WHERE address = ? AND spent = 0 LIMIT ? OFFSET ?`, encode(address), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query siacoin outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sco explorer.SiacoinOutput
			if err := rows.Scan(decode(&sco.StateElement.ID), decode(&sco.StateElement.LeafIndex), &sco.Source, &sco.MaturityHeight, decode(&sco.SiacoinOutput.Address), decode(&sco.SiacoinOutput.Value)); err != nil {
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
		rows, err := tx.Query(`SELECT output_id, leaf_index, claim_start, address, value FROM siafund_elements WHERE address = ? AND spent = 0 LIMIT ? OFFSET ?`, encode(address), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query siafund outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sfo explorer.SiafundOutput
			if err := rows.Scan(decode(&sfo.StateElement.ID), decode(&sfo.StateElement.LeafIndex), decode(&sfo.ClaimStart), decode(&sfo.SiafundOutput.Address), decode(&sfo.SiafundOutput.Value)); err != nil {
				return fmt.Errorf("failed to scan siafund output: %w", err)
			}
			result = append(result, sfo)
		}
		return nil
	})
	return
}

// SiacoinElement implements explorer.Store.
func (s *Store) SiacoinElements(ids []types.SiacoinOutputID) (result []explorer.SiacoinOutput, err error) {
	err = s.transaction(func(tx *txn) error {
		var encoded []any
		for _, id := range ids {
			encoded = append(encoded, encode(id))
		}

		rows, err := tx.Query(`SELECT output_id, leaf_index, source, maturity_height, address, value FROM siacoin_elements WHERE output_id IN (`+queryPlaceHolders(len(encoded))+`)`, encoded...)
		if err != nil {
			return fmt.Errorf("failed to query siacoin outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sco explorer.SiacoinOutput
			if err := rows.Scan(decode(&sco.StateElement.ID), decode(&sco.StateElement.LeafIndex), &sco.Source, &sco.MaturityHeight, decode(&sco.SiacoinOutput.Address), decode(&sco.SiacoinOutput.Value)); err != nil {
				return fmt.Errorf("failed to scan siacoin output: %w", err)
			}
			result = append(result, sco)
		}
		return nil
	})
	return
}

// SiafundElement implements explorer.Store.
func (s *Store) SiafundElements(ids []types.SiafundOutputID) (result []types.SiafundElement, err error) {
	err = s.transaction(func(tx *txn) error {
		var encoded []any
		for _, id := range ids {
			encoded = append(encoded, encode(id))
		}

		rows, err := tx.Query(`SELECT output_id, leaf_index, claim_start, address, value FROM siafund_elements WHERE output_id IN (`+queryPlaceHolders(len(encoded))+`)`, encoded...)
		if err != nil {
			return fmt.Errorf("failed to query siafund outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sfo types.SiafundElement
			if err := rows.Scan(decode(&sfo.StateElement.ID), decode(&sfo.StateElement.LeafIndex), decode(&sfo.ClaimStart), decode(&sfo.SiafundOutput.Address), decode(&sfo.SiafundOutput.Value)); err != nil {
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
