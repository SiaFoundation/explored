package explorer

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
)

type (
	// FileContractUpdate represents a file contract from a consensus update.
	FileContractUpdate struct {
		FileContractElement types.FileContractElement
		Revision            *types.FileContractElement
		Resolved, Valid     bool
	}

	// A DBFileContract represents a file contract element in the DB.
	DBFileContract struct {
		ID             types.FileContractID
		RevisionNumber uint64
	}

	// A TreeNodeUpdate is a change to a merkle tree node.
	TreeNodeUpdate struct {
		Row    uint64
		Column uint64
		Hash   types.Hash256
	}

	// An UpdateTx atomically updates the state of a store.
	UpdateTx interface {
		UpdateStateTree(changes []TreeNodeUpdate) error
		AddSiacoinElements(bid types.BlockID, sources map[types.SiacoinOutputID]Source, spentElements, newElements []types.SiacoinElement) (map[types.SiacoinOutputID]int64, error)
		AddSiafundElements(bid types.BlockID, spentElements, newElements []types.SiafundElement) (map[types.SiafundOutputID]int64, error)
		AddFileContractElements(bid types.BlockID, fces []FileContractUpdate) (map[DBFileContract]int64, error)

		UpdateBalances(height uint64, spentSiacoinElements, newSiacoinElements []types.SiacoinElement, spentSiafundElements, newSiafundElements []types.SiafundElement) error
		UpdateMaturedBalances(revert bool, height uint64) error

		AddBlock(b types.Block, height uint64) error
		AddMinerPayouts(bid types.BlockID, height uint64, scos []types.SiacoinOutput, dbIDs map[types.SiacoinOutputID]int64) error
		AddTransactions(bid types.BlockID, txns []types.Transaction, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64, fcDBIds map[DBFileContract]int64) error

		DeleteBlock(bid types.BlockID) error
	}
)

// applyChainUpdate atomically applies a chain update to a store
func applyChainUpdate(tx UpdateTx, cau chain.ApplyUpdate) error {
	if err := tx.AddBlock(cau.Block, cau.State.Index.Height); err != nil {
		return fmt.Errorf("applyUpdates: failed to add block: %w", err)
	} else if err := tx.UpdateMaturedBalances(false, cau.State.Index.Height); err != nil {
		return fmt.Errorf("applyUpdates: failed to update matured balances: %w", err)
	}

	sources := make(map[types.SiacoinOutputID]Source)
	for i := range cau.Block.MinerPayouts {
		sources[cau.Block.ID().MinerOutputID(i)] = SourceMinerPayout
	}

	for _, txn := range cau.Block.Transactions {
		for i := range txn.SiacoinOutputs {
			sources[txn.SiacoinOutputID(i)] = SourceTransaction
		}

		for i := range txn.FileContracts {
			fcid := txn.FileContractID(i)
			for j := range txn.FileContracts[i].ValidProofOutputs {
				sources[fcid.ValidOutputID(j)] = SourceValidProofOutput
			}
			for j := range txn.FileContracts[i].MissedProofOutputs {
				sources[fcid.MissedOutputID(j)] = SourceMissedProofOutput
			}
		}
	}

	created := make(map[types.Hash256]bool)
	ephemeral := make(map[types.Hash256]bool)
	for _, txn := range cau.Block.Transactions {
		for i := range txn.SiacoinOutputs {
			created[types.Hash256(txn.SiacoinOutputID(i))] = true
		}
		for _, input := range txn.SiacoinInputs {
			ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
		}
		for i := range txn.SiafundOutputs {
			created[types.Hash256(txn.SiafundOutputID(i))] = true
		}
		for _, input := range txn.SiafundInputs {
			ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
		}
	}

	// add new siacoin elements to the store
	var newSiacoinElements, spentSiacoinElements []types.SiacoinElement
	var ephemeralSiacoinElements []types.SiacoinElement
	cau.ForEachSiacoinElement(func(se types.SiacoinElement, spent bool) {
		if ephemeral[se.ID] {
			ephemeralSiacoinElements = append(ephemeralSiacoinElements, se)
			return
		}

		if spent {
			spentSiacoinElements = append(spentSiacoinElements, se)
		} else {
			newSiacoinElements = append(newSiacoinElements, se)
		}
	})

	var newSiafundElements, spentSiafundElements []types.SiafundElement
	var ephemeralSiafundElements []types.SiafundElement
	cau.ForEachSiafundElement(func(se types.SiafundElement, spent bool) {
		if ephemeral[se.ID] {
			ephemeralSiafundElements = append(ephemeralSiafundElements, se)
			return
		}

		if spent {
			spentSiafundElements = append(spentSiafundElements, se)
		} else {
			newSiafundElements = append(newSiafundElements, se)
		}
	})

	var fces []FileContractUpdate
	cau.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		fces = append(fces, FileContractUpdate{
			FileContractElement: fce,
			Revision:            rev,
			Resolved:            resolved,
			Valid:               valid,
		})
	})

	var treeUpdates []TreeNodeUpdate
	cau.ForEachTreeNode(func(row, column uint64, hash types.Hash256) {
		treeUpdates = append(treeUpdates, TreeNodeUpdate{
			Row:    row,
			Column: column,
			Hash:   hash,
		})
	})

	scDBIds, err := tx.AddSiacoinElements(
		cau.Block.ID(),
		sources,
		append(spentSiacoinElements, ephemeralSiacoinElements...),
		newSiacoinElements,
	)
	if err != nil {
		return fmt.Errorf("applyUpdates: failed to add siacoin outputs: %w", err)
	}
	sfDBIds, err := tx.AddSiafundElements(
		cau.Block.ID(),
		append(spentSiafundElements, ephemeralSiafundElements...),
		newSiafundElements,
	)
	if err != nil {
		return fmt.Errorf("applyUpdates: failed to add siafund outputs: %w", err)
	}
	if err := tx.UpdateBalances(cau.State.Index.Height, spentSiacoinElements, newSiacoinElements, spentSiafundElements, newSiafundElements); err != nil {
		return fmt.Errorf("applyUpdates: failed to update balances: %w", err)
	}

	fcDBIds, err := tx.AddFileContractElements(cau.Block.ID(), fces)
	if err != nil {
		return fmt.Errorf("applyUpdates: failed to add file contracts: %w", err)
	}

	if err := tx.AddMinerPayouts(cau.Block.ID(), cau.State.Index.Height, cau.Block.MinerPayouts, scDBIds); err != nil {
		return fmt.Errorf("applyUpdates: failed to add miner payouts: %w", err)
	} else if err := tx.AddTransactions(cau.Block.ID(), cau.Block.Transactions, scDBIds, sfDBIds, fcDBIds); err != nil {
		return fmt.Errorf("applyUpdates: failed to add transactions: addTransactions: %w", err)
	} else if err := tx.UpdateStateTree(treeUpdates); err != nil {
		return fmt.Errorf("applyUpdates: failed to update state tree: %w", err)
	}

	return nil
}

// revertChainUpdate atomically reverts a chain update from a store
func revertChainUpdate(tx UpdateTx, cru chain.RevertUpdate, revertedIndex types.ChainIndex) error {
	if err := tx.UpdateMaturedBalances(true, revertedIndex.Height); err != nil {
		return fmt.Errorf("revertUpdate: failed to update matured balances: %w", err)
	}

	created := make(map[types.Hash256]bool)
	ephemeral := make(map[types.Hash256]bool)
	for _, txn := range cru.Block.Transactions {
		for i := range txn.SiacoinOutputs {
			created[types.Hash256(txn.SiacoinOutputID(i))] = true
		}
		for _, input := range txn.SiacoinInputs {
			ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
		}
		for i := range txn.SiafundOutputs {
			created[types.Hash256(txn.SiafundOutputID(i))] = true
		}
		for _, input := range txn.SiafundInputs {
			ephemeral[types.Hash256(input.ParentID)] = created[types.Hash256(input.ParentID)]
		}
	}

	// add new siacoin elements to the store
	var newSiacoinElements, spentSiacoinElements []types.SiacoinElement
	var ephemeralSiacoinElements []types.SiacoinElement
	cru.ForEachSiacoinElement(func(se types.SiacoinElement, spent bool) {
		if ephemeral[se.ID] {
			ephemeralSiacoinElements = append(ephemeralSiacoinElements, se)
			return
		}

		if spent {
			newSiacoinElements = append(newSiacoinElements, se)
		} else {
			spentSiacoinElements = append(spentSiacoinElements, se)
		}
	})

	var newSiafundElements, spentSiafundElements []types.SiafundElement
	var ephemeralSiafundElements []types.SiafundElement
	cru.ForEachSiafundElement(func(se types.SiafundElement, spent bool) {
		if ephemeral[se.ID] {
			ephemeralSiafundElements = append(ephemeralSiafundElements, se)
			return
		}

		if spent {
			newSiafundElements = append(newSiafundElements, se)
		} else {
			spentSiafundElements = append(spentSiafundElements, se)
		}
	})

	var fces []FileContractUpdate
	cru.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		fces = append(fces, FileContractUpdate{
			FileContractElement: fce,
			Revision:            rev,
			Resolved:            resolved,
			Valid:               valid,
		})
	})

	var treeUpdates []TreeNodeUpdate
	cru.ForEachTreeNode(func(row, column uint64, hash types.Hash256) {
		treeUpdates = append(treeUpdates, TreeNodeUpdate{
			Row:    row,
			Column: column,
			Hash:   hash,
		})
	})

	// log.Println("REVERT!")
	if _, err := tx.AddSiacoinElements(
		cru.Block.ID(),
		nil,
		spentSiacoinElements,
		append(newSiacoinElements, ephemeralSiacoinElements...),
	); err != nil {
		return fmt.Errorf("revertUpdate: failed to update siacoin output state: %w", err)
	} else if _, err := tx.AddSiafundElements(
		cru.Block.ID(),
		spentSiafundElements,
		append(newSiafundElements, ephemeralSiafundElements...),
	); err != nil {
		return fmt.Errorf("revertUpdate: failed to update siafund output state: %w", err)
	} else if err := tx.UpdateBalances(revertedIndex.Height, spentSiacoinElements, newSiacoinElements, spentSiafundElements, newSiafundElements); err != nil {
		return fmt.Errorf("revertUpdate: failed to update balances: %w", err)
	} else if _, err := tx.AddFileContractElements(cru.Block.ID(), fces); err != nil {
		return fmt.Errorf("revertUpdate: failed to update file contract state: %w", err)
	} else if err := tx.DeleteBlock(cru.Block.ID()); err != nil {
		return fmt.Errorf("revertUpdate: failed to delete block: %w", err)
	} else if err := tx.UpdateStateTree(treeUpdates); err != nil {
		return fmt.Errorf("revertUpdate: failed to update state tree: %w", err)
	}
	return nil
}

// UpdateChainState applies the reverts and updates.
func UpdateChainState(tx UpdateTx, crus []chain.RevertUpdate, caus []chain.ApplyUpdate) error {
	for _, cru := range crus {
		revertedIndex := types.ChainIndex{
			ID:     cru.Block.ID(),
			Height: cru.State.Index.Height + 1,
		}
		if err := revertChainUpdate(tx, cru, revertedIndex); err != nil {
			return fmt.Errorf("failed to revert chain update %q: %w", revertedIndex, err)
		}
	}

	for _, cau := range caus {
		if err := applyChainUpdate(tx, cau); err != nil {
			return fmt.Errorf("failed to apply chain update %q: %w", cau.State.Index, err)
		}
	}
	return nil
}
