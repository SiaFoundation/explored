package sqlite

import (
	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// Search implements explorer.Store.
func (s *Store) Search(id types.Hash256) (explorer.SearchType, error) {
	var result explorer.SearchType
	err := s.transaction(func(tx *txn) error {
		var exists bool
		encoded := encode(id)

		// Address
		err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM address_balance WHERE address=?)`, encoded).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			result = explorer.SearchTypeAddress
			return nil
		}

		// Block
		err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM blocks WHERE id=?)`, encoded).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			result = explorer.SearchTypeBlock
			return nil
		}

		// Transaction
		err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM transactions WHERE transaction_id=?)`, encoded).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			result = explorer.SearchTypeTransaction
			return nil
		}

		// V2 transaction
		err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM v2_transactions WHERE transaction_id=?)`, encoded).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			result = explorer.SearchTypeV2Transaction
			return nil
		}

		// Siacoin element
		err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM siacoin_elements WHERE output_id=?)`, encoded).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			result = explorer.SearchTypeSiacoinElement
			return nil
		}

		// Siafund element
		err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM siafund_elements WHERE output_id=?)`, encoded).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			result = explorer.SearchTypeSiafundElement
			return nil
		}

		// File contract
		err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM last_contract_revision WHERE contract_id=?)`, encoded).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			result = explorer.SearchTypeContract
			return nil
		}

		// V2 file contract
		err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM v2_last_contract_revision WHERE contract_id=?)`, encoded).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			result = explorer.SearchTypeV2Contract
			return nil
		}

		// Host
		err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM host_info WHERE public_key=?)`, encoded).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			result = explorer.SearchTypeHost
			return nil
		}

		return nil
	})
	if err != nil {
		return explorer.SearchTypeInvalid, err
	}
	return result, nil
}
