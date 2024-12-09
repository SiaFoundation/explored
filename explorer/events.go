package explorer

import (
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
)

// event types indicate the source of an event. Events can
// either be created by sending Siacoins between addresses or they can be
// created by consensus (e.g. a miner payout, a siafund claim, or a contract).
const (
	EventTypeMinerPayout       = wallet.EventTypeMinerPayout
	EventTypeFoundationSubsidy = wallet.EventTypeFoundationSubsidy
	EventTypeSiafundClaim      = wallet.EventTypeSiafundClaim

	EventTypeV1Transaction        = wallet.EventTypeV1Transaction
	EventTypeV1ContractResolution = wallet.EventTypeV1ContractResolution

	EventTypeV2Transaction        = wallet.EventTypeV2Transaction
	EventTypeV2ContractResolution = wallet.EventTypeV2ContractResolution
)

type (
	// An EventPayout represents a miner payout, siafund claim, or foundation
	// subsidy.
	EventPayout = wallet.EventPayout
	// An EventV1Transaction pairs a v1 transaction with its spent siacoin and
	// siafund elements.
	EventV1Transaction = wallet.EventV1Transaction
	// An EventV1ContractResolution represents a file contract payout from a v1
	// contract.
	EventV1ContractResolution = wallet.EventV1ContractResolution
	// EventV2Transaction is a transaction event that includes the transaction
	EventV2Transaction = wallet.EventV2Transaction
	// An EventV2ContractResolution represents a file contract payout from a v2
	// contract.
	EventV2ContractResolution = wallet.EventV2ContractResolution

	// EventData is the data associated with an event.
	EventData = wallet.EventData
	// An Event is a record of a consensus event that affects the wallet.
	Event = wallet.Event
)

// A ChainUpdate is a set of changes to the consensus state.
type ChainUpdate interface {
	ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool))
	ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool))
	ForEachFileContractElement(func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool))
	ForEachV2FileContractElement(func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType))
}

// AppliedEvents extracts a list of relevant events from a chain update.
func AppliedEvents(cs consensus.State, b types.Block, cu ChainUpdate) (events []Event) {
	addEvent := func(id types.Hash256, maturityHeight uint64, eventType string, v EventData, relevant []types.Address) {
		// dedup relevant addresses
		seen := make(map[types.Address]bool)
		unique := relevant[:0]
		for _, addr := range relevant {
			if !seen[addr] {
				unique = append(unique, addr)
				seen[addr] = true
			}
		}

		events = append(events, Event{
			ID:             id,
			Timestamp:      b.Timestamp,
			Index:          cs.Index,
			MaturityHeight: maturityHeight,
			Relevant:       unique,
			Type:           eventType,
			Data:           v,
		})
	}

	// collect all elements
	sces := make(map[types.SiacoinOutputID]types.SiacoinElement)
	sfes := make(map[types.SiafundOutputID]types.SiafundElement)
	cu.ForEachSiacoinElement(func(sce types.SiacoinElement, _, _ bool) {
		sce.StateElement.MerkleProof = nil
		sces[types.SiacoinOutputID(sce.ID)] = sce
	})
	cu.ForEachSiafundElement(func(sfe types.SiafundElement, _, _ bool) {
		sfe.StateElement.MerkleProof = nil
		sfes[types.SiafundOutputID(sfe.ID)] = sfe
	})

	// handle v1 transactions
	for _, txn := range b.Transactions {
		addresses := make(map[types.Address]struct{})
		e := EventV1Transaction{
			Transaction:          txn,
			SpentSiacoinElements: make([]types.SiacoinElement, 0, len(txn.SiacoinInputs)),
			SpentSiafundElements: make([]types.SiafundElement, 0, len(txn.SiafundInputs)),
		}

		for _, sci := range txn.SiacoinInputs {
			sce, ok := sces[sci.ParentID]
			if !ok {
				continue
			}

			e.SpentSiacoinElements = append(e.SpentSiacoinElements, sce)
			addresses[sce.SiacoinOutput.Address] = struct{}{}
		}
		for _, sco := range txn.SiacoinOutputs {
			addresses[sco.Address] = struct{}{}
		}

		for _, sfi := range txn.SiafundInputs {
			sfe, ok := sfes[sfi.ParentID]
			if !ok {
				continue
			}

			e.SpentSiafundElements = append(e.SpentSiafundElements, sfe)
			addresses[sfe.SiafundOutput.Address] = struct{}{}

			sce, ok := sces[sfi.ParentID.ClaimOutputID()]
			if ok {
				addEvent(types.Hash256(sce.ID), sce.MaturityHeight, EventTypeSiafundClaim, EventPayout{
					SiacoinElement: sce,
				}, []types.Address{sfi.ClaimAddress})
			}
		}
		for _, sfo := range txn.SiafundOutputs {
			addresses[sfo.Address] = struct{}{}
		}

		for _, fc := range txn.FileContracts {
			addresses[fc.UnlockHash] = struct{}{}
			for _, vpo := range fc.ValidProofOutputs {
				addresses[vpo.Address] = struct{}{}
			}
			for _, mpo := range fc.MissedProofOutputs {
				addresses[mpo.Address] = struct{}{}
			}
		}
		// skip transactions with no relevant addresses
		if len(addresses) == 0 {
			continue
		}

		relevant := make([]types.Address, 0, len(addresses))
		for addr := range addresses {
			relevant = append(relevant, addr)
		}

		addEvent(types.Hash256(txn.ID()), cs.Index.Height, EventTypeV1Transaction, e, relevant) // transaction maturity height is the current block height
	}

	// handle v2 transactions
	for _, txn := range b.V2Transactions() {
		addresses := make(map[types.Address]struct{})
		for _, sci := range txn.SiacoinInputs {
			addresses[sci.Parent.SiacoinOutput.Address] = struct{}{}
		}
		for _, sco := range txn.SiacoinOutputs {
			addresses[sco.Address] = struct{}{}
		}
		for _, sfi := range txn.SiafundInputs {
			addresses[sfi.Parent.SiafundOutput.Address] = struct{}{}

			sce, ok := sces[types.SiafundOutputID(sfi.Parent.ID).V2ClaimOutputID()]
			if ok {
				addEvent(types.Hash256(sce.ID), sce.MaturityHeight, EventTypeSiafundClaim, EventPayout{
					SiacoinElement: sce,
				}, []types.Address{sfi.ClaimAddress})
			}
		}
		for _, sco := range txn.SiafundOutputs {
			addresses[sco.Address] = struct{}{}
		}

		ev := EventV2Transaction(txn)
		relevant := make([]types.Address, 0, len(addresses))
		for addr := range addresses {
			relevant = append(relevant, addr)
		}
		addEvent(types.Hash256(txn.ID()), cs.Index.Height, EventTypeV2Transaction, ev, relevant) // transaction maturity height is the current block height
	}

	// handle contracts
	cu.ForEachFileContractElement(func(fce types.FileContractElement, _ bool, rev *types.FileContractElement, resolved, valid bool) {
		if !resolved {
			return
		}

		fce.StateElement.MerkleProof = nil

		if valid {
			for i := range fce.FileContract.ValidProofOutputs {
				address := fce.FileContract.ValidProofOutputs[i].Address
				element := sces[types.FileContractID(fce.ID).ValidOutputID(i)]
				addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeV1ContractResolution, EventV1ContractResolution{
					Parent:         fce,
					SiacoinElement: element,
					Missed:         false,
				}, []types.Address{address})
			}
		} else {
			for i := range fce.FileContract.MissedProofOutputs {
				address := fce.FileContract.MissedProofOutputs[i].Address
				element := sces[types.FileContractID(fce.ID).MissedOutputID(i)]
				addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeV1ContractResolution, EventV1ContractResolution{
					Parent:         fce,
					SiacoinElement: element,
					Missed:         true,
				}, []types.Address{address})
			}
		}
	})

	cu.ForEachV2FileContractElement(func(fce types.V2FileContractElement, _ bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
		if res == nil {
			return
		}

		fce.StateElement.MerkleProof = nil

		var missed bool
		if _, ok := res.(*types.V2FileContractExpiration); ok {
			missed = true
		}

		{
			element := sces[types.FileContractID(fce.ID).V2HostOutputID()]
			addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeV2ContractResolution, EventV2ContractResolution{
				Resolution: types.V2FileContractResolution{
					Parent:     fce,
					Resolution: res,
				},
				SiacoinElement: element,
				Missed:         missed,
			}, []types.Address{fce.V2FileContract.HostOutput.Address})
		}

		{
			element := sces[types.FileContractID(fce.ID).V2RenterOutputID()]
			addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeV2ContractResolution, EventV2ContractResolution{
				Resolution: types.V2FileContractResolution{
					Parent:     fce,
					Resolution: res,
				},
				SiacoinElement: element,
				Missed:         missed,
			}, []types.Address{fce.V2FileContract.RenterOutput.Address})
		}
	})

	// handle block rewards
	for i := range b.MinerPayouts {
		element := sces[cs.Index.ID.MinerOutputID(i)]
		addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeMinerPayout, EventPayout{
			SiacoinElement: element,
		}, []types.Address{b.MinerPayouts[i].Address})
	}

	// handle foundation subsidy
	element, ok := sces[cs.Index.ID.FoundationOutputID()]
	if ok {
		addEvent(types.Hash256(element.ID), element.MaturityHeight, EventTypeFoundationSubsidy, EventPayout{
			SiacoinElement: element,
		}, []types.Address{element.SiacoinOutput.Address})
	}

	return events
}
