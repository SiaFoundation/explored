package explorer

import (
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
)

type (
	// An EventPayout represents a miner payout, siafund claim, or foundation
	// subsidy.
	EventPayout struct {
		SiacoinElement SiacoinOutput `json:"siacoinElement"`
	}

	// An EventV1Transaction pairs a v1 transaction with its spent siacoin and
	// siafund elements.
	EventV1Transaction struct {
		Transaction Transaction `json:"transaction"`
	}

	// An EventV1ContractResolution represents a file contract payout from a v1
	// contract.
	EventV1ContractResolution struct {
		Parent         ExtendedFileContract `json:"parent"`
		SiacoinElement SiacoinOutput        `json:"siacoinElement"`
		Missed         bool                 `json:"missed"`
	}

	// An EventV2ContractResolution represents a file contract payout from a v2
	// contract.
	EventV2ContractResolution struct {
		Resolution     V2FileContractResolution `json:"resolution"`
		SiacoinElement SiacoinOutput            `json:"siacoinElement"`
		Missed         bool                     `json:"missed"`
	}

	// EventV2Transaction is a transaction event that includes the transaction
	EventV2Transaction V2Transaction

	// EventData contains the data associated with an event.
	EventData interface {
		isEvent() bool
	}

	// An Event is a transaction or other event that affects the wallet including
	// miner payouts, siafund claims, and file contract payouts.
	Event struct {
		ID             types.Hash256    `json:"id"`
		Index          types.ChainIndex `json:"index"`
		Confirmations  uint64           `json:"confirmations"`
		Type           string           `json:"type"`
		Data           EventData        `json:"data"`
		MaturityHeight uint64           `json:"maturityHeight"`
		Timestamp      time.Time        `json:"timestamp"`
		Relevant       []types.Address  `json:"relevant,omitempty"`
	}
)

func (EventPayout) isEvent() bool               { return true }
func (EventV1Transaction) isEvent() bool        { return true }
func (EventV1ContractResolution) isEvent() bool { return true }
func (EventV2Transaction) isEvent() bool        { return true }
func (EventV2ContractResolution) isEvent() bool { return true }

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
		for _, sci := range txn.SiacoinInputs {
			sce, ok := sces[sci.ParentID]
			if !ok {
				continue
			}

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

			addresses[sfe.SiafundOutput.Address] = struct{}{}

			sce, ok := sces[sfi.ParentID.ClaimOutputID()]
			if ok {
				addEvent(types.Hash256(sce.ID), sce.MaturityHeight, wallet.EventTypeSiafundClaim, EventPayout{
					SiacoinElement: SiacoinOutput{SiacoinElement: sce},
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

		var ev EventV1Transaction
		relevant := make([]types.Address, 0, len(addresses))
		for addr := range addresses {
			relevant = append(relevant, addr)
		}

		addEvent(types.Hash256(txn.ID()), cs.Index.Height, wallet.EventTypeV1Transaction, ev, relevant) // transaction maturity height is the current block height
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
				addEvent(types.Hash256(sce.ID), sce.MaturityHeight, wallet.EventTypeSiafundClaim, EventPayout{
					SiacoinElement: SiacoinOutput{SiacoinElement: sce},
				}, []types.Address{sfi.ClaimAddress})
			}
		}
		for _, sco := range txn.SiafundOutputs {
			addresses[sco.Address] = struct{}{}
		}

		// ev := EventV2Transaction(txn)
		var ev EventV2Transaction
		relevant := make([]types.Address, 0, len(addresses))
		for addr := range addresses {
			relevant = append(relevant, addr)
		}
		addEvent(types.Hash256(txn.ID()), cs.Index.Height, wallet.EventTypeV2Transaction, ev, relevant) // transaction maturity height is the current block height
	}

	// handle contracts
	cu.ForEachFileContractElement(func(fce types.FileContractElement, _ bool, rev *types.FileContractElement, resolved, valid bool) {
		if !resolved {
			return
		}

		fce.StateElement.MerkleProof = nil

		var mpos, vpos []ContractSiacoinOutput
		for _, mpo := range fce.FileContract.MissedProofOutputs {
			mpos = append(mpos, ContractSiacoinOutput{SiacoinOutput: mpo})
		}
		for _, vpo := range fce.FileContract.ValidProofOutputs {
			vpos = append(vpos, ContractSiacoinOutput{SiacoinOutput: vpo})
		}
		efc := ExtendedFileContract{
			ID:                 fce.ID,
			Filesize:           fce.FileContract.Filesize,
			FileMerkleRoot:     fce.FileContract.FileMerkleRoot,
			WindowStart:        fce.FileContract.WindowStart,
			WindowEnd:          fce.FileContract.WindowEnd,
			Payout:             fce.FileContract.Payout,
			ValidProofOutputs:  vpos,
			MissedProofOutputs: mpos,
			UnlockHash:         fce.FileContract.UnlockHash,
			RevisionNumber:     fce.FileContract.RevisionNumber,
		}

		if valid {
			for i := range fce.FileContract.ValidProofOutputs {
				address := fce.FileContract.ValidProofOutputs[i].Address
				element := sces[types.FileContractID(fce.ID).ValidOutputID(i)]

				addEvent(types.Hash256(element.ID), element.MaturityHeight, wallet.EventTypeV1ContractResolution, EventV1ContractResolution{
					Parent:         efc,
					SiacoinElement: SiacoinOutput{SiacoinElement: element},
					Missed:         false,
				}, []types.Address{address})
			}
		} else {
			for i := range fce.FileContract.MissedProofOutputs {
				address := fce.FileContract.MissedProofOutputs[i].Address
				element := sces[types.FileContractID(fce.ID).MissedOutputID(i)]

				addEvent(types.Hash256(element.ID), element.MaturityHeight, wallet.EventTypeV1ContractResolution, EventV1ContractResolution{
					Parent:         efc,
					SiacoinElement: SiacoinOutput{SiacoinElement: element},
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

		var typ string
		switch res.(type) {
		case *types.V2FileContractRenewal:
			typ = "renewal"
		case *types.V2StorageProof:
			typ = "storageProof"
		case *types.V2FileContractExpiration:
			typ = "expiration"
		default:
			panic("unknown resolution type")
		}

		addV2Resolution := func(element types.SiacoinElement) {
			efc := V2FileContract{V2FileContractElement: fce}
			addEvent(types.Hash256(element.ID), element.MaturityHeight, wallet.EventTypeV2ContractResolution, EventV2ContractResolution{
				Resolution: V2FileContractResolution{
					Parent:     efc,
					Type:       typ,
					Resolution: res,
				},
				SiacoinElement: SiacoinOutput{SiacoinElement: element},
				Missed:         missed,
			}, []types.Address{element.SiacoinOutput.Address})
		}
		addV2Resolution(sces[types.FileContractID(fce.ID).V2RenterOutputID()])
		addV2Resolution(sces[types.FileContractID(fce.ID).V2HostOutputID()])
	})

	// handle block rewards
	for i := range b.MinerPayouts {
		element := sces[cs.Index.ID.MinerOutputID(i)]
		addEvent(types.Hash256(element.ID), element.MaturityHeight, wallet.EventTypeMinerPayout, EventPayout{
			SiacoinElement: SiacoinOutput{SiacoinElement: element},
		}, []types.Address{b.MinerPayouts[i].Address})
	}

	// handle foundation subsidy
	element, ok := sces[cs.Index.ID.FoundationOutputID()]
	if ok {
		addEvent(types.Hash256(element.ID), element.MaturityHeight, wallet.EventTypeFoundationSubsidy, EventPayout{
			SiacoinElement: SiacoinOutput{SiacoinElement: element},
		}, []types.Address{element.SiacoinOutput.Address})
	}

	return events
}
