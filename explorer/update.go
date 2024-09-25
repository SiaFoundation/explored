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

		ConfirmationTransactionID *types.TransactionID
		ProofTransactionID        *types.TransactionID
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

		Events      []Event
		Metrics     Metrics
		TreeUpdates []TreeNodeUpdate

		NewSiacoinElements       []SiacoinOutput
		SpentSiacoinElements     []SiacoinOutput
		EphemeralSiacoinElements []SiacoinOutput

		NewSiafundElements       []types.SiafundElement
		SpentSiafundElements     []types.SiafundElement
		EphemeralSiafundElements []types.SiafundElement

		FileContractElements []FileContractUpdate
	}

	// An UpdateTx atomically updates the state of a store.
	UpdateTx interface {
		Metrics(height uint64) (Metrics, error)
		HostExists(pubkey types.PublicKey) (bool, error)

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

	// add new siacoin elements to the store
	var newSiacoinElements, spentSiacoinElements []SiacoinOutput
	var ephemeralSiacoinElements []SiacoinOutput
	cau.ForEachSiacoinElement(func(se types.SiacoinElement, created, spent bool) {
		if created && spent {
			ephemeralSiacoinElements = append(ephemeralSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
				Source:         sources[types.SiacoinOutputID(se.StateElement.ID)],
			})
			return
		}

		if spent {
			spentSiacoinElements = append(spentSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
				Source:         sources[types.SiacoinOutputID(se.StateElement.ID)],
			})
		} else {
			newSiacoinElements = append(newSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
				Source:         sources[types.SiacoinOutputID(se.StateElement.ID)],
			})
		}
	})

	var newSiafundElements, spentSiafundElements []types.SiafundElement
	var ephemeralSiafundElements []types.SiafundElement
	cau.ForEachSiafundElement(func(se types.SiafundElement, created, spent bool) {
		if created && spent {
			ephemeralSiafundElements = append(ephemeralSiafundElements, se)
			return
		}

		if spent {
			spentSiafundElements = append(spentSiafundElements, se)
		} else {
			newSiafundElements = append(newSiafundElements, se)
		}
	})

	fceMap := make(map[types.FileContractID]FileContractUpdate)
	cau.ForEachFileContractElement(func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool) {
		fceMap[types.FileContractID(fce.ID)] = FileContractUpdate{
			FileContractElement: fce,
			Revision:            rev,
			Resolved:            resolved,
			Valid:               valid,
		}
	})
	for _, txn := range cau.Block.Transactions {
		txnID := txn.ID()
		for i := range txn.FileContracts {
			fcID := txn.FileContractID(i)

			v := fceMap[fcID]
			v.ConfirmationTransactionID = &txnID
			fceMap[fcID] = v
		}
		for _, sp := range txn.StorageProofs {
			fcID := sp.ParentID

			v := fceMap[fcID]
			v.ProofTransactionID = &txnID
			fceMap[fcID] = v
		}
	}

	var fces []FileContractUpdate
	for _, fce := range fceMap {
		fces = append(fces, fce)
	}

	var treeUpdates []TreeNodeUpdate
	cau.ForEachTreeNode(func(row, column uint64, hash types.Hash256) {
		treeUpdates = append(treeUpdates, TreeNodeUpdate{
			Row:    row,
			Column: column,
			Hash:   hash,
		})
	})

	events := AppliedEvents(cau.State, cau.Block, cau)

	state := UpdateState{
		Block: cau.Block,

		Events:      events,
		TreeUpdates: treeUpdates,

		NewSiacoinElements:       newSiacoinElements,
		SpentSiacoinElements:     spentSiacoinElements,
		EphemeralSiacoinElements: ephemeralSiacoinElements,

		NewSiafundElements:       newSiafundElements,
		SpentSiafundElements:     spentSiafundElements,
		EphemeralSiafundElements: ephemeralSiafundElements,

		FileContractElements: fces,
	}

	var err error
	var prevMetrics Metrics
	if cau.State.Index.Height > 0 {
		prevMetrics, err = tx.Metrics(cau.State.Index.Height - 1)
		if err != nil {
			return err
		}
	}
	state.Metrics, err = updateMetrics(tx, state, prevMetrics)
	if err != nil {
		return err
	}
	state.Metrics.Index = cau.State.Index
	state.Metrics.Difficulty = cau.State.Difficulty
	state.Metrics.SiafundPool = cau.State.SiafundPool

	return tx.ApplyIndex(state)
}

// revertChainUpdate atomically reverts a chain update from a store
func revertChainUpdate(tx UpdateTx, cru chain.RevertUpdate, revertedIndex types.ChainIndex) error {
	// add new siacoin elements to the store
	var newSiacoinElements, spentSiacoinElements []SiacoinOutput
	var ephemeralSiacoinElements []SiacoinOutput
	cru.ForEachSiacoinElement(func(se types.SiacoinElement, created, spent bool) {
		if created && spent {
			ephemeralSiacoinElements = append(ephemeralSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
			})
			return
		}

		if spent {
			newSiacoinElements = append(newSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
			})
		} else {
			spentSiacoinElements = append(spentSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
			})
		}
	})

	var newSiafundElements, spentSiafundElements []types.SiafundElement
	var ephemeralSiafundElements []types.SiafundElement
	cru.ForEachSiafundElement(func(se types.SiafundElement, created, spent bool) {
		if created && spent {
			ephemeralSiafundElements = append(ephemeralSiafundElements, se)
			return
		}

		if spent {
			newSiafundElements = append(newSiafundElements, se)
		} else {
			spentSiafundElements = append(spentSiafundElements, se)
		}
	})

	fceMap := make(map[types.FileContractID]FileContractUpdate)
	cru.ForEachFileContractElement(func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool) {
		fceMap[types.FileContractID(fce.ID)] = FileContractUpdate{
			FileContractElement: fce,
			Revision:            rev,
			Resolved:            resolved,
			Valid:               valid,
		}
	})
	for _, txn := range cru.Block.Transactions {
		txnID := txn.ID()
		for i := range txn.FileContracts {
			fcID := txn.FileContractID(i)

			v := fceMap[fcID]
			v.ConfirmationTransactionID = &txnID
			fceMap[fcID] = v
		}
		for _, sp := range txn.StorageProofs {
			fcID := sp.ParentID

			v := fceMap[fcID]
			v.ProofTransactionID = &txnID
			fceMap[fcID] = v
		}
	}

	var fces []FileContractUpdate
	for _, fce := range fceMap {
		fces = append(fces, fce)
	}

	var treeUpdates []TreeNodeUpdate
	cru.ForEachTreeNode(func(row, column uint64, hash types.Hash256) {
		treeUpdates = append(treeUpdates, TreeNodeUpdate{
			Row:    row,
			Column: column,
			Hash:   hash,
		})
	})

	state := UpdateState{
		Block: cru.Block,

		TreeUpdates: treeUpdates,

		NewSiacoinElements:       newSiacoinElements,
		SpentSiacoinElements:     spentSiacoinElements,
		EphemeralSiacoinElements: ephemeralSiacoinElements,

		NewSiafundElements:       newSiafundElements,
		SpentSiafundElements:     spentSiafundElements,
		EphemeralSiafundElements: ephemeralSiafundElements,

		FileContractElements: fces,
	}
	state.Metrics.Index = revertedIndex

	return tx.RevertIndex(state)
}

func updateMetrics(tx UpdateTx, s UpdateState, metrics Metrics) (Metrics, error) {
	seenHosts := make(map[types.PublicKey]struct{})
	for _, event := range s.Events {
		if event.Data.EventType() == EventTypeTransaction {
			txn := event.Data.(*EventTransaction)
			for _, host := range txn.HostAnnouncements {
				if _, ok := seenHosts[host.PublicKey]; ok {
					continue
				}

				exists, err := tx.HostExists(host.PublicKey)
				if err != nil {
					return Metrics{}, err
				}
				if !exists {
					// we haven't seen this host yet, increment count
					metrics.TotalHosts++
					seenHosts[host.PublicKey] = struct{}{}
				}
			}
		}
	}

	for _, fce := range s.FileContractElements {
		fc := fce.FileContractElement.FileContract
		if fce.Revision != nil {
			fc = fce.Revision.FileContract
		}

		if fce.Resolved {
			metrics.ActiveContracts--
			metrics.StorageUtilization -= fc.Filesize
		} else if fce.Revision == nil {
			// don't count revision as a new contract
			metrics.ActiveContracts++
			metrics.StorageUtilization += fc.Filesize
		} else {
			// filesize changed
			metrics.StorageUtilization += (fc.Filesize - fce.FileContractElement.FileContract.Filesize)
		}

		if fce.Resolved {
			if !fce.Valid {
				metrics.FailedContracts++
			} else {
				metrics.SuccessfulContracts++
				for _, vpo := range fc.ValidProofOutputs {
					metrics.ContractRevenue = metrics.ContractRevenue.Add(vpo.Value)
				}
			}
		}
	}

	for _, sce := range s.NewSiacoinElements {
		sco := sce.SiacoinOutput
		if sco.Address == types.VoidAddress {
			continue
		}
		metrics.CirculatingSupply = metrics.CirculatingSupply.Add(sco.Value)
	}
	for _, sce := range s.SpentSiacoinElements {
		sco := sce.SiacoinOutput
		if sco.Address == types.VoidAddress {
			continue
		}
		metrics.CirculatingSupply = metrics.CirculatingSupply.Sub(sco.Value)
	}

	return metrics, nil
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
