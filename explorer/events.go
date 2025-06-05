package explorer

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
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

// UnmarshalJSON implements the json.Unmarshaler interface.
func (e *Event) UnmarshalJSON(b []byte) error {
	var je struct {
		ID             types.Hash256    `json:"id"`
		Index          types.ChainIndex `json:"index"`
		Confirmations  uint64           `json:"confirmations"`
		Timestamp      time.Time        `json:"timestamp"`
		MaturityHeight uint64           `json:"maturityHeight"`
		Type           string           `json:"type"`
		Data           json.RawMessage  `json:"data"`
		Relevant       []types.Address  `json:"relevant,omitempty"`
	}
	if err := json.Unmarshal(b, &je); err != nil {
		return err
	}

	e.ID = je.ID
	e.Index = je.Index
	e.Confirmations = je.Confirmations
	e.Timestamp = je.Timestamp
	e.MaturityHeight = je.MaturityHeight
	e.Type = je.Type
	e.Relevant = je.Relevant

	var err error
	switch je.Type {
	case wallet.EventTypeMinerPayout, wallet.EventTypeFoundationSubsidy, wallet.EventTypeSiafundClaim:
		var data EventPayout
		err = json.Unmarshal(je.Data, &data)
		e.Data = data
	case wallet.EventTypeV1ContractResolution:
		var data EventV1ContractResolution
		err = json.Unmarshal(je.Data, &data)
		e.Data = data
	case wallet.EventTypeV2ContractResolution:
		var data EventV2ContractResolution
		err = json.Unmarshal(je.Data, &data)
		e.Data = data
	case wallet.EventTypeV1Transaction:
		var data EventV1Transaction
		err = json.Unmarshal(je.Data, &data)
		e.Data = data
	case wallet.EventTypeV2Transaction:
		var data EventV2Transaction
		err = json.Unmarshal(je.Data, &data)
		e.Data = data
	default:
		return fmt.Errorf("unknown event type: %v", je.Type)
	}
	return err
}

// A ChainUpdate is a set of changes to the consensus state.
type ChainUpdate interface {
	SiacoinElementDiffs() []consensus.SiacoinElementDiff
	SiafundElementDiffs() []consensus.SiafundElementDiff
	FileContractElementDiffs() []consensus.FileContractElementDiff
	V2FileContractElementDiffs() []consensus.V2FileContractElementDiff
}

// RelevantAddressesV1 returns all the relevant addresses to a V1 transaction.
func RelevantAddressesV1(txn types.Transaction) []types.Address {
	addresses := make(map[types.Address]struct{})
	for _, sco := range txn.SiacoinOutputs {
		addresses[sco.Address] = struct{}{}
	}
	for _, sci := range txn.SiacoinInputs {
		addresses[sci.UnlockConditions.UnlockHash()] = struct{}{}
	}
	for _, sfo := range txn.SiafundOutputs {
		addresses[sfo.Address] = struct{}{}
	}
	for _, sfi := range txn.SiafundInputs {
		addresses[sfi.UnlockConditions.UnlockHash()] = struct{}{}
	}
	for _, fc := range txn.FileContracts {
		for _, vpo := range fc.ValidProofOutputs {
			addresses[vpo.Address] = struct{}{}
		}
		for _, mpo := range fc.MissedProofOutputs {
			addresses[mpo.Address] = struct{}{}
		}
	}
	for _, fcr := range txn.FileContractRevisions {
		for _, vpo := range fcr.FileContract.ValidProofOutputs {
			addresses[vpo.Address] = struct{}{}
		}
		for _, mpo := range fcr.FileContract.MissedProofOutputs {
			addresses[mpo.Address] = struct{}{}
		}
	}

	relevant := make([]types.Address, 0, len(addresses))
	for addr := range addresses {
		relevant = append(relevant, addr)
	}
	return relevant
}

// RelevantAddressesV2 returns all the relevant addresses to a V2 transaction.
func RelevantAddressesV2(txn types.V2Transaction) []types.Address {
	addresses := make(map[types.Address]struct{})
	for _, sco := range txn.SiacoinOutputs {
		addresses[sco.Address] = struct{}{}
	}
	for _, sci := range txn.SiacoinInputs {
		addresses[sci.Parent.SiacoinOutput.Address] = struct{}{}
	}
	for _, sfo := range txn.SiafundOutputs {
		addresses[sfo.Address] = struct{}{}
	}
	for _, sfi := range txn.SiafundInputs {
		addresses[sfi.Parent.SiafundOutput.Address] = struct{}{}
	}
	for _, fc := range txn.FileContracts {
		addresses[fc.HostOutput.Address] = struct{}{}
		addresses[fc.RenterOutput.Address] = struct{}{}
	}
	for _, fcr := range txn.FileContractRevisions {
		addresses[fcr.Parent.V2FileContract.HostOutput.Address] = struct{}{}
		addresses[fcr.Parent.V2FileContract.RenterOutput.Address] = struct{}{}
		addresses[fcr.Revision.HostOutput.Address] = struct{}{}
		addresses[fcr.Revision.RenterOutput.Address] = struct{}{}
	}
	for _, fcr := range txn.FileContractResolutions {
		addresses[fcr.Parent.V2FileContract.HostOutput.Address] = struct{}{}
		addresses[fcr.Parent.V2FileContract.RenterOutput.Address] = struct{}{}
		if v, ok := fcr.Resolution.(*types.V2FileContractRenewal); ok {
			addresses[v.NewContract.HostOutput.Address] = struct{}{}
			addresses[v.NewContract.RenterOutput.Address] = struct{}{}
		}
	}

	relevant := make([]types.Address, 0, len(addresses))
	for addr := range addresses {
		relevant = append(relevant, addr)
	}
	return relevant
}

// CoreToExplorerV1Transaction converts a core/types.Transaction to an
// event.Transaction. Fields we do not have information are unfilled in the
// return value.
func CoreToExplorerV1Transaction(txn types.Transaction) (result Transaction) {
	result.ID = txn.ID()

	coreToExplorerFC := func(fcID types.FileContractID, fc types.FileContract) ExtendedFileContract {
		efc := ExtendedFileContract{
			ConfirmationTransactionID: result.ID,
			ID:                        fcID,
			Filesize:                  fc.Filesize,
			FileMerkleRoot:            fc.FileMerkleRoot,
			WindowStart:               fc.WindowStart,
			WindowEnd:                 fc.WindowEnd,
			Payout:                    fc.Payout,
			UnlockHash:                fc.UnlockHash,
			RevisionNumber:            fc.RevisionNumber,
		}
		for j, vpo := range fc.ValidProofOutputs {
			efc.ValidProofOutputs = append(efc.ValidProofOutputs, ContractSiacoinOutput{
				ID:            fcID.ValidOutputID(j),
				SiacoinOutput: vpo,
			})
		}
		for j, mpo := range fc.MissedProofOutputs {
			efc.MissedProofOutputs = append(efc.MissedProofOutputs, ContractSiacoinOutput{
				ID:            fcID.MissedOutputID(j),
				SiacoinOutput: mpo,
			})
		}
		return efc
	}

	for _, sci := range txn.SiacoinInputs {
		result.SiacoinInputs = append(result.SiacoinInputs, SiacoinInput{
			Address: sci.UnlockConditions.UnlockHash(),

			ParentID:         sci.ParentID,
			UnlockConditions: sci.UnlockConditions,
		})
	}
	for i, sco := range txn.SiacoinOutputs {
		sce := types.SiacoinElement{
			ID:            txn.SiacoinOutputID(i),
			SiacoinOutput: sco,
		}
		result.SiacoinOutputs = append(result.SiacoinOutputs, SiacoinOutput{
			SiacoinElement: sce,
		})
	}
	for _, sfi := range txn.SiafundInputs {
		result.SiafundInputs = append(result.SiafundInputs, SiafundInput{
			Address: sfi.UnlockConditions.UnlockHash(),

			ParentID:         sfi.ParentID,
			UnlockConditions: sfi.UnlockConditions,
			ClaimAddress:     sfi.ClaimAddress,
		})
	}
	for i, sfo := range txn.SiafundOutputs {
		sfe := types.SiafundElement{
			ID:            txn.SiafundOutputID(i),
			SiafundOutput: sfo,
		}
		result.SiafundOutputs = append(result.SiafundOutputs, SiafundOutput{
			SiafundElement: sfe,
		})
	}
	for i, fc := range txn.FileContracts {
		result.FileContracts = append(result.FileContracts, coreToExplorerFC(txn.FileContractID(i), fc))
	}
	for _, fcr := range txn.FileContractRevisions {
		result.FileContractRevisions = append(result.FileContractRevisions, FileContractRevision{
			ParentID:             fcr.ParentID,
			UnlockConditions:     fcr.UnlockConditions,
			ExtendedFileContract: coreToExplorerFC(fcr.ParentID, fcr.FileContract),
		})
	}
	result.StorageProofs = append(result.StorageProofs, txn.StorageProofs...)
	result.MinerFees = append(result.MinerFees, txn.MinerFees...)
	result.ArbitraryData = append(result.ArbitraryData, txn.ArbitraryData...)
	result.Signatures = append(result.Signatures, txn.Signatures...)
	return
}

// CoreToExplorerV2Transaction converts a core/types.V2Transaction to an
// event.V2Transaction. Fields we do not have information are unfilled in the
// return value.
func CoreToExplorerV2Transaction(txn types.V2Transaction) (result V2Transaction) {
	result.ID = txn.ID()
	coreToExplorerFC := func(fcID types.FileContractID, fc types.V2FileContract) V2FileContract {
		fce := types.V2FileContractElement{
			ID:             fcID,
			V2FileContract: fc,
		}

		return V2FileContract{
			TransactionID:             result.ID,
			ConfirmationTransactionID: result.ID,
			V2FileContractElement:     fce,
		}
	}

	result.SiacoinInputs = append(result.SiacoinInputs, txn.SiacoinInputs...)
	for i, sco := range txn.SiacoinOutputs {
		sce := types.SiacoinElement{
			ID:            txn.SiacoinOutputID(result.ID, i),
			SiacoinOutput: sco,
		}
		result.SiacoinOutputs = append(result.SiacoinOutputs, SiacoinOutput{
			SiacoinElement: sce,
		})
	}

	result.SiafundInputs = append(result.SiafundInputs, txn.SiafundInputs...)
	for i, sfo := range txn.SiafundOutputs {
		sfe := types.SiafundElement{
			ID:            txn.SiafundOutputID(result.ID, i),
			SiafundOutput: sfo,
		}
		result.SiafundOutputs = append(result.SiafundOutputs, SiafundOutput{
			SiafundElement: sfe,
		})
	}
	for i, fc := range txn.FileContracts {
		result.FileContracts = append(result.FileContracts, coreToExplorerFC(txn.V2FileContractID(result.ID, i), fc))
	}
	for _, fcr := range txn.FileContractRevisions {
		parent := coreToExplorerFC(fcr.Parent.ID, fcr.Parent.V2FileContract)
		parent.V2FileContractElement.StateElement = fcr.Parent.StateElement
		result.FileContractRevisions = append(result.FileContractRevisions, V2FileContractRevision{
			Parent:   parent,
			Revision: coreToExplorerFC(fcr.Parent.ID, fcr.Revision),
		})
	}
	for _, fcr := range txn.FileContractResolutions {
		parent := coreToExplorerFC(fcr.Parent.ID, fcr.Parent.V2FileContract)
		parent.V2FileContractElement.StateElement = fcr.Parent.StateElement

		var res any
		switch v := fcr.Resolution.(type) {
		case *types.V2FileContractRenewal:
			res = V2FileContractRenewal{
				FinalRenterOutput: v.FinalRenterOutput,
				FinalHostOutput:   v.FinalHostOutput,
				RenterRollover:    v.RenterRollover,
				HostRollover:      v.HostRollover,
				NewContract:       coreToExplorerFC(fcr.Parent.ID.V2RenewalID(), v.NewContract),

				RenterSignature: v.RenterSignature,
				HostSignature:   v.HostSignature,
			}
		case *types.V2StorageProof:
			res = v
		case *types.V2FileContractExpiration:
			res = v
		}
		result.FileContractResolutions = append(result.FileContractResolutions, V2FileContractResolution{
			Parent:     parent,
			Type:       V2ResolutionType(fcr.Resolution),
			Resolution: res,
		})
	}

	for _, attestation := range txn.Attestations {
		result.Attestations = append(result.Attestations, attestation)

		var ha chain.V2HostAnnouncement
		if ha.FromAttestation(attestation) == nil {
			result.HostAnnouncements = append(result.HostAnnouncements, V2HostAnnouncement{
				V2HostAnnouncement: ha,
				PublicKey:          attestation.PublicKey,
			})
		}
	}
	result.ArbitraryData = append(result.ArbitraryData, txn.ArbitraryData...)
	result.NewFoundationAddress = txn.NewFoundationAddress
	result.MinerFee = txn.MinerFee

	return
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

		if eventType == wallet.EventTypeMinerPayout {
			log.Printf("%v: AppliedEvents: miner payout, id: %v, relevant: %v", b.ID(), id, relevant)
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
	for _, diff := range cu.SiacoinElementDiffs() {
		sce := diff.SiacoinElement
		sce.StateElement.MerkleProof = nil
		sces[types.SiacoinOutputID(sce.ID)] = sce
	}
	for _, diff := range cu.SiafundElementDiffs() {
		sfe := diff.SiafundElement
		sfe.StateElement.MerkleProof = nil
		sfes[types.SiafundOutputID(sfe.ID)] = sfe
	}

	// handle v1 transactions
	for _, txn := range b.Transactions {
		for _, sfi := range txn.SiafundInputs {
			sce, ok := sces[sfi.ParentID.ClaimOutputID()]
			if ok {
				addEvent(types.Hash256(sce.ID), sce.MaturityHeight, wallet.EventTypeSiafundClaim, EventPayout{
					SiacoinElement: SiacoinOutput{SiacoinElement: sce},
				}, []types.Address{sfi.ClaimAddress})
			}
		}

		relevant := RelevantAddressesV1(txn)
		ev := EventV1Transaction{CoreToExplorerV1Transaction(txn)}

		addEvent(types.Hash256(txn.ID()), cs.Index.Height, wallet.EventTypeV1Transaction, ev, relevant) // transaction maturity height is the current block height
	}

	// handle v2 transactions
	for _, txn := range b.V2Transactions() {
		for _, sfi := range txn.SiafundInputs {
			sfe, ok := sces[types.SiafundOutputID(sfi.Parent.ID).V2ClaimOutputID()]
			if ok {
				addEvent(types.Hash256(sfe.ID), sfe.MaturityHeight, wallet.EventTypeSiafundClaim, EventPayout{
					SiacoinElement: SiacoinOutput{SiacoinElement: sfe},
				}, []types.Address{sfi.ClaimAddress})
			}
		}

		relevant := RelevantAddressesV2(txn)
		ev := EventV2Transaction(CoreToExplorerV2Transaction(txn))
		addEvent(types.Hash256(txn.ID()), cs.Index.Height, wallet.EventTypeV2Transaction, ev, relevant) // transaction maturity height is the current block height
	}

	// handle contracts
	for _, diff := range cu.FileContractElementDiffs() {
		fce, resolved, valid := diff.FileContractElement, diff.Resolved, diff.Valid
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
	}

	for _, diff := range cu.V2FileContractElementDiffs() {
		fce, res := diff.V2FileContractElement, diff.Resolution
		if res == nil {
			return
		}

		fce.StateElement.MerkleProof = nil

		var missed bool
		if _, ok := res.(*types.V2FileContractExpiration); ok {
			missed = true
		}

		resolutionType := V2ResolutionType(res)
		addV2Resolution := func(element types.SiacoinElement) {
			efc := V2FileContract{V2FileContractElement: fce}
			addEvent(types.Hash256(element.ID), element.MaturityHeight, wallet.EventTypeV2ContractResolution, EventV2ContractResolution{
				Resolution: V2FileContractResolution{
					Parent:     efc,
					Type:       resolutionType,
					Resolution: res,
				},
				SiacoinElement: SiacoinOutput{SiacoinElement: element},
				Missed:         missed,
			}, []types.Address{element.SiacoinOutput.Address})
		}
		addV2Resolution(sces[types.FileContractID(fce.ID).V2RenterOutputID()])
		addV2Resolution(sces[types.FileContractID(fce.ID).V2HostOutputID()])
	}

	// handle block rewards
	log.Printf("%v: AppliedEvents: got %d miner payouts", b.ID(), len(b.MinerPayouts))
	for i := range b.MinerPayouts {
		element := sces[cs.Index.ID.MinerOutputID(i)]
		log.Printf("%v: AppliedEvents: calling addEvent, id: %v, element: %+v", b.ID(), cs.Index.ID.MinerOutputID(i), element)
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
