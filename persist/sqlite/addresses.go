package sqlite

import (
	"database/sql"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// AddressEvents returns the events of a single address.
func (s *Store) AddressEvents(address types.Address, offset, limit uint64) (events []explorer.Event, err error) {
	err = s.transaction(func(tx *txn) error {
		const query = `
WITH last_chain_index (height) AS (
    SELECT MAX(height) FROM blocks
)
SELECT
	ev.id,
	ev.event_id,
	ev.maturity_height,
	ev.date_created,
	b.height,
	b.id,
	CASE
		WHEN last_chain_index.height < b.height THEN 0
		ELSE last_chain_index.height - b.height
	END AS confirmations,
	ev.event_type
FROM events ev
INNER JOIN event_addresses ea ON (ev.id = ea.event_id)
INNER JOIN address_balance sa ON (ea.address_id = sa.id)
INNER JOIN blocks b ON (ev.block_id = b.id)
CROSS JOIN last_chain_index
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
			event.Relevant = []types.Address{address}
			events = append(events, event)
		}
		return rows.Err()
	})
	return
}

func scanSiacoinOutput(s scanner) (sco explorer.SiacoinOutput, err error) {
	var spentIndex types.ChainIndex
	err = s.Scan(decode(&sco.ID), decode(&sco.StateElement.LeafIndex), &sco.Source, decodeNull(&spentIndex), &sco.MaturityHeight, decode(&sco.SiacoinOutput.Address), decode(&sco.SiacoinOutput.Value))
	if spentIndex != (types.ChainIndex{}) {
		sco.SpentIndex = &spentIndex
	}
	return
}

func scanSiafundOutput(s scanner) (sfo explorer.SiafundOutput, err error) {
	var spentIndex types.ChainIndex
	err = s.Scan(decode(&sfo.ID), decode(&sfo.StateElement.LeafIndex), decodeNull(&spentIndex), decode(&sfo.ClaimStart), decode(&sfo.SiafundOutput.Address), decode(&sfo.SiafundOutput.Value))
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
