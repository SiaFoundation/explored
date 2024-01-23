package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
)

// UnspentSiacoinOutputs implements explorer.Store.
func (s *Store) UnspentSiacoinOutputs(address types.Address) (result []types.SiacoinOutput, err error) {
	err = s.transaction(func(tx txn) error {
		rows, err := tx.Query(`SELECT address, value FROM siacoin_outputs WHERE address = ? AND spent = 0`, dbEncode(address))
		if err != nil {
			return fmt.Errorf("failed to query siacoin outputs: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sco types.SiacoinOutput
			if err := rows.Scan(dbDecode(&sco.Address), dbDecode(&sco.Value)); err != nil {
				return fmt.Errorf("failed to scan siacoin output: %v", err)
			}
			result = append(result, sco)
		}
		return nil
	})
	return
}

// UnspentSiafundOutputs implements explorer.Store.
func (s *Store) UnspentSiafundOutputs(address types.Address) (result []types.SiafundOutput, err error) {
	err = s.transaction(func(tx txn) error {
		rows, err := tx.Query(`SELECT address, value FROM siafund_outputs WHERE address = ? AND spent = 0`, dbEncode(address))
		if err != nil {
			return fmt.Errorf("failed to query siafund outputs: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sco types.SiafundOutput
			if err := rows.Scan(dbDecode(&sco.Address), dbDecode(&sco.Value)); err != nil {
				return fmt.Errorf("failed to scan siafund output: %v", err)
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
		scRows, err := tx.Query(`SELECT value FROM siacoin_outputs WHERE address = ? AND spent = 0`, dbEncode(address))
		if err != nil {
			return fmt.Errorf("failed to query siacoin outputs: %v", err)
		}
		defer scRows.Close()

		for scRows.Next() {
			var value types.Currency
			if err := scRows.Scan(dbDecode(&value)); err != nil {
				return fmt.Errorf("failed to scan siacoin output: %v", err)
			}
			sc = sc.Add(value)
		}

		sfRows, err := tx.Query(`SELECT value FROM siafund_outputs WHERE address = ? AND spent = 0`, dbEncode(address))
		if err != nil {
			return fmt.Errorf("failed to query siafund outputs: %v", err)
		}
		defer sfRows.Close()

		for sfRows.Next() {
			var value uint64
			if err := sfRows.Scan(dbDecode(&value)); err != nil {
				return fmt.Errorf("failed to scan siafund output: %v", err)
			}
			sf += value
		}
		return nil
	})
	return
}
