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

	// An UpdateState contains information relevant to the block being applied
	// or reverted.
	UpdateState struct {
		Block types.Block
		Index types.ChainIndex

		Events      []Event
		TreeUpdates []TreeNodeUpdate

		Sources                  map[types.SiacoinOutputID]Source
		NewSiacoinElements       []types.SiacoinElement
		SpentSiacoinElements     []types.SiacoinElement
		EphemeralSiacoinElements []types.SiacoinElement

		NewSiafundElements       []types.SiafundElement
		SpentSiafundElements     []types.SiafundElement
		EphemeralSiafundElements []types.SiafundElement

		FileContractElements []FileContractUpdate
	}

	// An UpdateTx atomically updates the state of a store.
	UpdateTx interface {
		ApplyIndex(state UpdateState) error
		RevertIndex(state UpdateState) error
	}
)

// applyChainUpdate atomically applies a chain update to a store
func applyChainUpdate(tx UpdateTx, cau chain.ApplyUpdate) error {
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

	relevant := func(types.Address) bool { return true }
	events := AppliedEvents(cau.State, cau.Block, cau, relevant)

	state := UpdateState{
		Block: cau.Block,
		Index: cau.State.Index,

		Events:      events,
		TreeUpdates: treeUpdates,

		Sources:                  sources,
		NewSiacoinElements:       newSiacoinElements,
		SpentSiacoinElements:     spentSiacoinElements,
		EphemeralSiacoinElements: ephemeralSiacoinElements,

		NewSiafundElements:       newSiafundElements,
		SpentSiafundElements:     spentSiafundElements,
		EphemeralSiafundElements: ephemeralSiafundElements,

		FileContractElements: fces,
	}
	return tx.ApplyIndex(state)
}

// revertChainUpdate atomically reverts a chain update from a store
func revertChainUpdate(tx UpdateTx, cru chain.RevertUpdate, revertedIndex types.ChainIndex) error {
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

	state := UpdateState{
		Block:       cru.Block,
		Index:       revertedIndex,
		TreeUpdates: treeUpdates,

		NewSiacoinElements:       newSiacoinElements,
		SpentSiacoinElements:     spentSiacoinElements,
		EphemeralSiacoinElements: ephemeralSiacoinElements,

		NewSiafundElements:       newSiafundElements,
		SpentSiafundElements:     spentSiafundElements,
		EphemeralSiafundElements: ephemeralSiafundElements,

		FileContractElements: fces,
	}
	return tx.RevertIndex(state)
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
