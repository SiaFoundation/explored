package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// deleteV1Transactions deletes the transactions from the database if they are
// not referenced in any blocks.
func deleteV1Transactions(tx *txn, txns []types.Transaction) error {
	stmt, err := tx.Prepare(`DELETE FROM transactions AS t
WHERE t.transaction_id = ?
	AND NOT EXISTS (
		SELECT 1
		FROM block_transactions bt
		WHERE bt.transaction_id = t.id
);`)
	if err != nil {
		return fmt.Errorf("deleteV1Transactions: failed to prepare statement: %w", err)
	}

	for _, txn := range txns {
		if _, err := stmt.Exec(encode(txn.ID())); err != nil {
			return fmt.Errorf("deleteV1Transactions: failed to execute: %w", err)
		}
	}
	return nil
}

// deleteV2Transactions deletes the transactions from the database if they are
// not referenced in any blocks.
func deleteV2Transactions(tx *txn, txns []types.V2Transaction) error {
	stmt, err := tx.Prepare(`DELETE FROM v2_transactions AS t
WHERE t.transaction_id = ?
	AND NOT EXISTS (
		SELECT 1
		FROM v2_block_transactions bt
		WHERE bt.transaction_id = t.id
);`)
	if err != nil {
		return fmt.Errorf("deleteV2Transactions: failed to prepare statement: %w", err)
	}

	for _, txn := range txns {
		if _, err := stmt.Exec(encode(txn.ID())); err != nil {
			return fmt.Errorf("deleteV2Transactions: failed to execute: %w", err)
		}
	}
	return nil
}

func (ut *updateTx) RevertIndex(state explorer.UpdateState) error {
	if err := updateMaturedBalances(ut.tx, true, state.Metrics.Index.Height); err != nil {
		return fmt.Errorf("RevertIndex: failed to update matured balances: %w", err)
	} else if _, err := addSiacoinElements(
		ut.tx,
		state.Metrics.Index,
		state.SpentSiacoinElements,
		append(state.NewSiacoinElements, state.EphemeralSiacoinElements...),
	); err != nil {
		return fmt.Errorf("RevertIndex: failed to update siacoin output state: %w", err)
	} else if _, err := addSiafundElements(
		ut.tx,
		state.Metrics.Index,
		state.SpentSiafundElements,
		append(state.NewSiafundElements, state.EphemeralSiafundElements...),
	); err != nil {
		return fmt.Errorf("RevertIndex: failed to update siafund output state: %w", err)
	} else if err := updateBalances(ut.tx, state.Metrics.Index.Height, state.SpentSiacoinElements, state.NewSiacoinElements, state.SpentSiafundElements, state.NewSiafundElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update balances: %w", err)
	} else if _, err := updateFileContractElements(ut.tx, true, state.Metrics.Index, state.Block, state.FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update file contract state: %w", err)
	} else if _, err := updateV2FileContractElements(ut.tx, true, state.Metrics.Index, state.Block, state.V2FileContractElements); err != nil {
		return fmt.Errorf("ApplyIndex: failed to add v2 file contracts: %w", err)
	} else if err := deleteBlock(ut.tx, state.Block.ID()); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete block: %w", err)
	} else if err := deleteV1Transactions(ut.tx, state.Block.Transactions); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete v1 transactions: %w", err)
	} else if err := deleteV2Transactions(ut.tx, state.Block.V2Transactions()); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete v2 transactions: %w", err)
	} else if err := updateStateTree(ut.tx, state.TreeUpdates); err != nil {
		return fmt.Errorf("RevertIndex: failed to update state tree: %w", err)
	} else if err := updateFileContractIndices(ut.tx, true, state.Metrics.Index, state.FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update file contract element indices: %w", err)
	} else if err := updateV2FileContractIndices(ut.tx, true, state.Metrics.Index, state.V2FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update v2 file contract element indices: %w", err)
	}

	return nil
}
