package sqlite

import (
	"encoding/hex"
	"errors"
	"strings"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// Search implements explorer.Store.
func (s *Store) Search(input string) (explorer.SearchType, error) {
	decodeHex := func(input string) ([]byte, error) {
		// Strip prefix (i.e., "txid:") if present
		if idx := strings.Index(input, ":"); idx != -1 && len(input) >= idx {
			input = input[idx+1:]
		}
		decoded, err := hex.DecodeString(input)
		if err != nil {
			return nil, err
		}

		const idLen = len(types.Hash256{})
		if len(decoded) < len(types.Hash256{}) {
			return nil, errors.New("should have hex encoded 32 byte input")
		}
		return decoded[:idLen], nil
	}
	id, _ := decodeHex(input)

	var result explorer.SearchType
	err := s.transaction(func(tx *txn) error {
		var exists bool
		queries := []struct {
			str   bool
			query string
			typ   explorer.SearchType
		}{
			{false, `SELECT EXISTS(SELECT 1 FROM address_balance WHERE address=?)`, explorer.SearchTypeAddress},
			{false, `SELECT EXISTS(SELECT 1 FROM blocks WHERE id=?)`, explorer.SearchTypeBlock},
			{false, `SELECT EXISTS(SELECT 1 FROM transactions WHERE transaction_id=?)`, explorer.SearchTypeTransaction},
			{false, `SELECT EXISTS(SELECT 1 FROM v2_transactions WHERE transaction_id=?)`, explorer.SearchTypeV2Transaction},
			{false, `SELECT EXISTS(SELECT 1 FROM siacoin_elements WHERE output_id=?)`, explorer.SearchTypeSiacoinElement},
			{false, `SELECT EXISTS(SELECT 1 FROM siafund_elements WHERE output_id=?)`, explorer.SearchTypeSiafundElement},
			{false, `SELECT EXISTS(SELECT 1 FROM last_contract_revision WHERE contract_id=?)`, explorer.SearchTypeContract},
			{false, `SELECT EXISTS(SELECT 1 FROM v2_last_contract_revision WHERE contract_id=?)`, explorer.SearchTypeV2Contract},
			{false, `SELECT EXISTS(SELECT 1 FROM host_info WHERE public_key=?)`, explorer.SearchTypeHost},
			{true, `SELECT EXISTS(SELECT 1 FROM host_info WHERE net_address=?)`, explorer.SearchTypeHost},
			{true, `SELECT EXISTS(SELECT 1 FROM host_info_v2_netaddresses WHERE address=?)`, explorer.SearchTypeHost},
		}

		for _, q := range queries {
			if q.str {
				err := tx.QueryRow(q.query, input).Scan(&exists)
				if err != nil {
					return err
				}
			} else if !q.str && id != nil {
				err := tx.QueryRow(q.query, id).Scan(&exists)
				if err != nil {
					return err
				}
			}

			if exists {
				result = q.typ
				return nil
			}
		}
		return explorer.ErrNoSearchResults
	})
	if err != nil {
		return explorer.SearchTypeInvalid, err
	}
	return result, nil
}
