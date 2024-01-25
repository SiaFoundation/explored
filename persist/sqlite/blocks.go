package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
)

// Block implements explorer.Store.
func (s *Store) Block(id types.BlockID) (result types.Block, err error) {
	err = s.transaction(func(tx txn) error {
		err = tx.QueryRow(`SELECT parent_id, nonce, timestamp FROM blocks WHERE id=?`, dbEncode(id)).Scan(dbDecode(&result.ParentID), dbDecode(&result.Nonce), dbDecode(&result.Timestamp))
		if err != nil {
			return err
		}

		result.MinerPayouts, err = blockMinerPayouts(tx, id)
		if err != nil {
			return fmt.Errorf("failed to get miner payouts: %w", err)
		}

		// get block transaction IDs
		transactionIDs, err := blockTransactionIDs(tx, id)
		if err != nil {
			return fmt.Errorf("failed to get block transaction IDs: %w", err)
		}

		result.Transactions, err = s.getTransactions(tx, transactionIDs)
		if err != nil {
			return fmt.Errorf("failed to get transactions: %w", err)
		}

		return nil
	})
	return
}

// BestTip implements explorer.Store.
func (s *Store) BestTip(height uint64) (result types.ChainIndex, err error) {
	err = s.transaction(func(tx txn) error {
		err = tx.QueryRow(`SELECT id, height FROM blocks WHERE height=?`, height).Scan(dbDecode(&result.ID), dbDecode(&result.Height))
		if err != nil {
			return err
		}

		return nil
	})
	return
}
