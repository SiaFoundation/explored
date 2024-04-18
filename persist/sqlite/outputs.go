package sqlite

import (
	"database/sql"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// UnspentSiacoinOutputs implements explorer.Store.
func (s *Store) UnspentSiacoinOutputs(address types.Address, limit, offset uint64) (result []explorer.SiacoinOutput, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT output_id, leaf_index, merkle_proof, source, maturity_height, address, value FROM siacoin_elements WHERE address = ? AND spent = 0 LIMIT ? OFFSET ?`, dbEncode(address), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query siacoin outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sco explorer.SiacoinOutput
			if err := rows.Scan(dbDecode(&sco.StateElement.ID), dbDecode(&sco.StateElement.LeafIndex), dbDecode(&sco.StateElement.MerkleProof), &sco.Source, &sco.MaturityHeight, dbDecode(&sco.SiacoinOutput.Address), dbDecode(&sco.SiacoinOutput.Value)); err != nil {
				return fmt.Errorf("failed to scan siacoin output: %w", err)
			}
			result = append(result, sco)
		}
		return nil
	})
	return
}

// UnspentSiafundOutputs implements explorer.Store.
func (s *Store) UnspentSiafundOutputs(address types.Address, limit, offset uint64) (result []explorer.SiafundOutput, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT output_id, leaf_index, merkle_proof, claim_start, address, value FROM siafund_elements WHERE address = ? AND spent = 0 LIMIT ? OFFSET ?`, dbEncode(address), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query siafund outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sfo explorer.SiafundOutput
			if err := rows.Scan(dbDecode(&sfo.StateElement.ID), dbDecode(&sfo.StateElement.LeafIndex), dbDecode(&sfo.StateElement.MerkleProof), dbDecode(&sfo.ClaimStart), dbDecode(&sfo.SiafundOutput.Address), dbDecode(&sfo.SiafundOutput.Value)); err != nil {
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
		err = tx.QueryRow(`SELECT siacoin_balance, immature_siacoin_balance, siafund_balance FROM address_balance WHERE address = ?`, dbEncode(address)).Scan(dbDecode(&sc), dbDecode(&immatureSC), dbDecode(&sf))
		if err == sql.ErrNoRows {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to query balances: %w", err)
		}
		return nil
	})
	return
}
