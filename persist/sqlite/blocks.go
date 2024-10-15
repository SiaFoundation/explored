package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// Block implements explorer.Store.
func (s *Store) Block(id types.BlockID) (result explorer.Block, err error) {
	err = s.transaction(func(tx *txn) error {
		var v2Height uint64
		var v2Commitment types.Hash256
		err := tx.QueryRow(`SELECT parent_id, nonce, timestamp, height, v2_height, v2_commitment FROM blocks WHERE id = ?`, encode(id)).Scan(decode(&result.ParentID), decode(&result.Nonce), decode(&result.Timestamp), &result.Height, decodeNull(&v2Height), decodeNull(&v2Commitment))
		if err != nil {
			return fmt.Errorf("failed to get block: %w", err)
		}
		result.MinerPayouts, err = blockMinerPayouts(tx, id)
		if err != nil {
			return fmt.Errorf("failed to get miner payouts: %w", err)
		}

		if (v2Height != 0 && v2Commitment != types.Hash256{}) {
			result.V2 = new(explorer.V2BlockData)
			result.V2.Height = v2Height
			result.V2.Commitment = v2Commitment

			// get block transaction IDs
			transactionIDs, err := blockV2TransactionIDs(tx, id)
			if err != nil {
				return fmt.Errorf("failed to get block transaction IDs: %w", err)
			}

			result.V2.Transactions, err = getV2Transactions(tx, transactionIDs)
			if err != nil {
				return fmt.Errorf("failed to get transactions: %w", err)
			}
		}

		// get block transaction IDs
		transactionIDs, err := blockTransactionIDs(tx, id)
		if err != nil {
			return fmt.Errorf("failed to get block transaction IDs: %w", err)
		}

		result.Transactions, err = getTransactions(tx, transactionIDs)
		if err != nil {
			return fmt.Errorf("failed to get transactions: %w", err)
		}

		return nil
	})
	return
}

// BestTip implements explorer.Store.
func (s *Store) BestTip(height uint64) (result types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		err = tx.QueryRow(`SELECT id, height FROM blocks WHERE height=?`, height).Scan(decode(&result.ID), decode(&result.Height))
		if err != nil {
			return err
		}

		return nil
	})
	return
}
