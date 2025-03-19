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

	// V2FileContractUpdate represents a v2 file contract from a consensus
	// update.
	V2FileContractUpdate struct {
		FileContractElement types.V2FileContractElement
		Revision            *types.V2FileContractElement
		Resolution          types.V2FileContractResolutionType

		ConfirmationTransactionID *types.TransactionID
		ResolutionTransactionID   *types.TransactionID
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
		Block             types.Block
		ChainIndexElement types.ChainIndexElement

		Events      []Event
		Metrics     Metrics
		TreeUpdates []TreeNodeUpdate

		HostAnnouncements   []chain.HostAnnouncement
		V2HostAnnouncements []V2HostAnnouncement

		NewSiacoinElements       []SiacoinOutput
		SpentSiacoinElements     []SiacoinOutput
		EphemeralSiacoinElements []SiacoinOutput

		NewSiafundElements       []types.SiafundElement
		SpentSiafundElements     []types.SiafundElement
		EphemeralSiafundElements []types.SiafundElement

		FileContractElements   []FileContractUpdate
		V2FileContractElements []V2FileContractUpdate
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
	}

	for _, txn := range cau.Block.V2Transactions() {
		txnID := txn.ID()
		for i := range txn.SiacoinOutputs {
			sources[txn.SiacoinOutputID(txnID, i)] = SourceTransaction
		}
	}

	for _, diff := range cau.FileContractElementDiffs() {
		if diff.Resolved {
			fcID := diff.FileContractElement.ID
			if diff.Valid {
				for i := range diff.FileContractElement.FileContract.ValidProofOutputs {
					sources[fcID.ValidOutputID(i)] = SourceValidProofOutput
				}
			} else {
				for i := range diff.FileContractElement.FileContract.MissedProofOutputs {
					sources[fcID.MissedOutputID(i)] = SourceMissedProofOutput
				}
			}
		}
	}

	for _, diff := range cau.V2FileContractElementDiffs() {
		if diff.Resolution != nil {
			fcID := diff.V2FileContractElement.ID
			switch r := diff.Resolution.(type) {
			case *types.V2FileContractRenewal:
				sources[fcID.V2RenterOutputID()] = SourceValidProofOutput
				sources[fcID.V2HostOutputID()] = SourceValidProofOutput
			case *types.V2StorageProof:
				sources[fcID.V2RenterOutputID()] = SourceValidProofOutput
				sources[fcID.V2HostOutputID()] = SourceValidProofOutput
			case *types.V2FileContractExpiration:
				sources[fcID.V2RenterOutputID()] = SourceMissedProofOutput
				sources[fcID.V2HostOutputID()] = SourceMissedProofOutput
			default:
				panic(fmt.Sprintf("unhandled resolution type %T", r))
			}
		}
	}

	// add new siacoin elements to the store
	var newSiacoinElements, spentSiacoinElements []SiacoinOutput
	var ephemeralSiacoinElements []SiacoinOutput
	for _, diff := range cau.SiacoinElementDiffs() {
		created, spent, se := diff.Created, diff.Spent, diff.SiacoinElement
		if created && spent {
			ephemeralSiacoinElements = append(ephemeralSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
				Source:         sources[se.ID],
			})
			continue
		}

		if spent {
			spentSiacoinElements = append(spentSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
				Source:         sources[se.ID],
			})
		} else {
			newSiacoinElements = append(newSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
				Source:         sources[se.ID],
			})
		}
	}

	var newSiafundElements, spentSiafundElements []types.SiafundElement
	var ephemeralSiafundElements []types.SiafundElement
	for _, diff := range cau.SiafundElementDiffs() {
		created, spent, se := diff.Created, diff.Spent, diff.SiafundElement
		if created && spent {
			ephemeralSiafundElements = append(ephemeralSiafundElements, se)
			continue
		}

		if spent {
			spentSiafundElements = append(spentSiafundElements, se)
		} else {
			newSiafundElements = append(newSiafundElements, se)
		}
	}

	fceMap := make(map[types.FileContractID]FileContractUpdate)
	for _, diff := range cau.FileContractElementDiffs() {
		var rev *types.FileContractElement
		if revision, ok := diff.RevisionElement(); ok {
			rev = &revision
		}
		fceMap[diff.FileContractElement.ID] = FileContractUpdate{
			FileContractElement: diff.FileContractElement,
			Revision:            rev,
			Resolved:            diff.Resolved,
			Valid:               diff.Valid,
		}
	}

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

	v2FceMap := make(map[types.FileContractID]V2FileContractUpdate)
	for _, diff := range cau.V2FileContractElementDiffs() {
		var rev *types.V2FileContractElement
		if revision, ok := diff.V2RevisionElement(); ok {
			rev = &revision
		}
		v2FceMap[types.FileContractID(diff.V2FileContractElement.ID)] = V2FileContractUpdate{
			FileContractElement: diff.V2FileContractElement,
			Revision:            rev,
			Resolution:          diff.Resolution,
		}
	}
	for _, txn := range cau.Block.V2Transactions() {
		txnID := txn.ID()
		for i := range txn.FileContracts {
			fcID := txn.V2FileContractID(txnID, i)

			v := v2FceMap[fcID]
			v.ConfirmationTransactionID = &txnID
			v2FceMap[fcID] = v
		}
		for _, fcr := range txn.FileContractResolutions {
			fcID := types.FileContractID(fcr.Parent.ID)

			v := v2FceMap[fcID]
			v.ResolutionTransactionID = &txnID
			v2FceMap[fcID] = v

			if _, ok := fcr.Resolution.(*types.V2FileContractRenewal); ok {
				renewalID := fcID.V2RenewalID()
				v := v2FceMap[renewalID]
				v.ConfirmationTransactionID = &txnID
				v2FceMap[renewalID] = v
			}
		}
	}

	var v2Fces []V2FileContractUpdate
	for _, fce := range v2FceMap {
		v2Fces = append(v2Fces, fce)
	}

	var treeUpdates []TreeNodeUpdate
	cau.ForEachTreeNode(func(row, column uint64, hash types.Hash256) {
		treeUpdates = append(treeUpdates, TreeNodeUpdate{
			Row:    row,
			Column: column,
			Hash:   hash,
		})
	})

	var hostAnnouncements []chain.HostAnnouncement
	for _, txn := range cau.Block.Transactions {
		for _, arb := range txn.ArbitraryData {
			var ha chain.HostAnnouncement
			if ha.FromArbitraryData(arb) {
				hostAnnouncements = append(hostAnnouncements, ha)
			}
		}
	}
	var v2HostAnnouncements []V2HostAnnouncement
	for _, txn := range cau.Block.V2Transactions() {
		for _, a := range txn.Attestations {
			var ha chain.V2HostAnnouncement
			if ha.FromAttestation(a) == nil {
				v2HostAnnouncements = append(v2HostAnnouncements, V2HostAnnouncement{
					PublicKey:          a.PublicKey,
					V2HostAnnouncement: ha,
				})
			}
		}
	}

	events := AppliedEvents(cau.State, cau.Block, cau)

	state := UpdateState{
		Block:             cau.Block,
		ChainIndexElement: cau.ChainIndexElement(),

		Events:      events,
		TreeUpdates: treeUpdates,

		HostAnnouncements:   hostAnnouncements,
		V2HostAnnouncements: v2HostAnnouncements,

		NewSiacoinElements:       newSiacoinElements,
		SpentSiacoinElements:     spentSiacoinElements,
		EphemeralSiacoinElements: ephemeralSiacoinElements,

		NewSiafundElements:       newSiafundElements,
		SpentSiafundElements:     spentSiafundElements,
		EphemeralSiafundElements: ephemeralSiafundElements,

		FileContractElements:   fces,
		V2FileContractElements: v2Fces,
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
	state.Metrics.SiafundTaxRevenue = cau.State.SiafundTaxRevenue
	state.Metrics.NumLeaves = cau.State.Elements.NumLeaves

	return tx.ApplyIndex(state)
}

// revertChainUpdate atomically reverts a chain update from a store
func revertChainUpdate(tx UpdateTx, cru chain.RevertUpdate, revertedIndex types.ChainIndex) error {
	// add new siacoin elements to the store
	var newSiacoinElements, spentSiacoinElements []SiacoinOutput
	var ephemeralSiacoinElements []SiacoinOutput
	for _, diff := range cru.SiacoinElementDiffs() {
		created, spent, se := diff.Created, diff.Spent, diff.SiacoinElement
		if created && spent {
			ephemeralSiacoinElements = append(ephemeralSiacoinElements, SiacoinOutput{
				SiacoinElement: se,
			})
			continue
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
	}

	var newSiafundElements, spentSiafundElements []types.SiafundElement
	var ephemeralSiafundElements []types.SiafundElement
	for _, diff := range cru.SiafundElementDiffs() {
		created, spent, se := diff.Created, diff.Spent, diff.SiafundElement
		if created && spent {
			ephemeralSiafundElements = append(ephemeralSiafundElements, se)
			continue
		}

		if spent {
			newSiafundElements = append(newSiafundElements, se)
		} else {
			spentSiafundElements = append(spentSiafundElements, se)
		}
	}

	fceMap := make(map[types.FileContractID]FileContractUpdate)
	for _, diff := range cru.FileContractElementDiffs() {
		var rev *types.FileContractElement
		if revision, ok := diff.RevisionElement(); ok {
			rev = &revision
		}
		fceMap[diff.FileContractElement.ID] = FileContractUpdate{
			FileContractElement: diff.FileContractElement,
			Revision:            rev,
			Resolved:            diff.Resolved,
			Valid:               diff.Valid,
		}
	}
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

	v2FceMap := make(map[types.FileContractID]V2FileContractUpdate)
	for _, diff := range cru.V2FileContractElementDiffs() {
		var rev *types.V2FileContractElement
		if revision, ok := diff.V2RevisionElement(); ok {
			rev = &revision
		}
		v2FceMap[types.FileContractID(diff.V2FileContractElement.ID)] = V2FileContractUpdate{
			FileContractElement: diff.V2FileContractElement,
			Revision:            rev,
			Resolution:          diff.Resolution,
		}
	}
	for _, txn := range cru.Block.V2Transactions() {
		txnID := txn.ID()
		for i := range txn.FileContracts {
			fcID := txn.V2FileContractID(txn.ID(), i)

			v := v2FceMap[fcID]
			v.ConfirmationTransactionID = &txnID
			v2FceMap[fcID] = v
		}
		for _, fcr := range txn.FileContractResolutions {
			fcID := types.FileContractID(fcr.Parent.ID)

			v := v2FceMap[fcID]
			v.ResolutionTransactionID = &txnID
			v2FceMap[fcID] = v
		}
	}

	var v2Fces []V2FileContractUpdate
	for _, fce := range v2FceMap {
		v2Fces = append(v2Fces, fce)
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

		FileContractElements:   fces,
		V2FileContractElements: v2Fces,
	}
	state.Metrics.Index = revertedIndex

	return tx.RevertIndex(state)
}

func updateMetrics(tx UpdateTx, s UpdateState, metrics Metrics) (Metrics, error) {
	seenHosts := make(map[types.PublicKey]struct{})
	for _, host := range s.HostAnnouncements {
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
	for _, host := range s.V2HostAnnouncements {
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
