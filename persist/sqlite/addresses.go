package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

func scanEvent(s scanner) (ev explorer.Event, eventID int64, err error) {
	var eventType string
	var eventBuf []byte

	err = s.Scan(&eventID, decode(&ev.ID), &ev.MaturityHeight, decode(&ev.Timestamp), &ev.Index.Height, decode(&ev.Index.ID), &eventType, &eventBuf)
	if err != nil {
		return
	}

	switch eventType {
	case explorer.EventTypeTransaction:
		var tx explorer.EventTransaction
		if err = json.Unmarshal(eventBuf, &tx); err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to unmarshal transaction event: %w", err)
		}
		ev.Data = &tx
	case explorer.EventTypeContractPayout:
		var m explorer.EventContractPayout
		if err = json.Unmarshal(eventBuf, &m); err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to unmarshal missed file contract event: %w", err)
		}
		ev.Data = &m
	case explorer.EventTypeMinerPayout:
		var m explorer.EventMinerPayout
		if err = json.Unmarshal(eventBuf, &m); err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to unmarshal payout event: %w", err)
		}
		ev.Data = &m
	case explorer.EventTypeFoundationSubsidy:
		var m explorer.EventFoundationSubsidy
		if err = json.Unmarshal(eventBuf, &m); err != nil {
			return explorer.Event{}, 0, fmt.Errorf("failed to unmarshal foundation subsidy event: %w", err)
		}
		ev.Data = &m
	default:
		return explorer.Event{}, 0, fmt.Errorf("unknown event type: %s", eventType)
	}
	return
}

// AddressEvents returns the events of a single address.
func (s *Store) AddressEvents(address types.Address, offset, limit uint64) (events []explorer.Event, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `SELECT ev.id, ev.event_id, ev.maturity_height, ev.date_created, ev.height, ev.block_id, ev.event_type, ev.event_data
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
			event, _, err := scanEvent(rows)
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