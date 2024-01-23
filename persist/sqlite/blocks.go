package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
)

// BlockByID implements explorer.Store.
func (s *Store) BlockByID(id types.BlockID) (result types.Block, err error) {
	err = s.transaction(func(tx txn) error {
		err = tx.QueryRow(`SELECT parent_id, nonce, timestamp FROM blocks WHERE id=?`, dbEncode(id)).Scan(dbDecode(&result.ParentID), dbDecode(&result.Nonce), dbDecode(&result.Timestamp))
		if err != nil {
			return err
		}

		result.MinerPayouts, err = blockMinerPayouts(tx, id)
		if err != nil {
			return fmt.Errorf("failed to get miner payouts: %v", err)
		}

		// get block transaction IDs
		transactionIDs, err := blockTransactionIDs(tx, id)
		if err != nil {
			return fmt.Errorf("failed to get block transaction IDs: %v", err)
		}

		result.Transactions, err = s.getTransactions(tx, transactionIDs)
		if err != nil {
			return fmt.Errorf("failed to get transactions: %v", err)
		}

		return nil
	})
	return
}

// BlockByHeight implements explorer.Store.
func (s *Store) BlockByHeight(height uint64) (result types.Block, err error) {
	err = s.transaction(func(tx txn) error {
		var blockID types.BlockID
		err = tx.QueryRow(`SELECT id, parent_id, nonce, timestamp FROM blocks WHERE height=?`, height).Scan(dbDecode(&blockID), dbDecode(&result.ParentID), dbDecode(&result.Nonce), dbDecode(&result.Timestamp))
		if err != nil {
			return err
		}

		result.MinerPayouts, err = blockMinerPayouts(tx, blockID)
		if err != nil {
			return fmt.Errorf("failed to get miner payouts: %v", err)
		}

		// get block transaction IDs
		transactionIDs, err := blockTransactionIDs(tx, blockID)
		if err != nil {
			return fmt.Errorf("failed to get block transaction IDs: %v", err)
		}

		if result.Transactions, err = s.getTransactions(tx, transactionIDs); err != nil {
			return fmt.Errorf("failed to get transactions: %v", err)
		}

		return nil
	})
	return
}
