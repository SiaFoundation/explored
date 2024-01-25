package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// UnspentSiacoinOutputs implements explorer.Store.
func (s *Store) UnspentSiacoinOutputs(address types.Address, limit, offset uint64) (result []explorer.SiacoinOutput, err error) {
	err = s.transaction(func(tx txn) error {
		rows, err := tx.Query(`SELECT output_id, source, address, value FROM siacoin_outputs WHERE address = ? AND spent = 0 LIMIT ? OFFSET ?`, dbEncode(address), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query siacoin outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sco explorer.SiacoinOutput
			if err := rows.Scan(dbDecode(&sco.OutputID), &sco.Source, dbDecode(&sco.Address), dbDecode(&sco.Value)); err != nil {
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
	err = s.transaction(func(tx txn) error {
		rows, err := tx.Query(`SELECT output_id, claim_start, address, value FROM siafund_outputs WHERE address = ? AND spent = 0 LIMIT ? OFFSET ?`, dbEncode(address), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query siafund outputs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sco explorer.SiafundOutput
			if err := rows.Scan(dbDecode(&sco.OutputID), dbDecode(&sco.ClaimStart), dbDecode(&sco.Address), dbDecode(&sco.Value)); err != nil {
				return fmt.Errorf("failed to scan siafund output: %w", err)
			}
			result = append(result, sco)
		}
		return nil
	})
	return
}

// Balance implements explorer.Store.
func (s *Store) Balance(address types.Address) (sc types.Currency, sf uint64, err error) {
	err = s.transaction(func(tx txn) error {
		err = tx.QueryRow(`SELECT siacoin_balance, siafund_balance FROM address_balance WHERE address = ?`, dbEncode(address)).Scan(dbDecode(&sc), dbDecode(&sf))
		if err != nil {
			return fmt.Errorf("failed to query balances: %w", err)
		}
		return nil
	})
	return
}
