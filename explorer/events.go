package explorer

import (
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

// event type constants
const (
	EventTypeTransaction       = "transaction"
	EventTypeMinerPayout       = "miner payout"
	EventTypeContractPayout    = "contract payout"
	EventTypeSiafundClaim      = "siafund claim"
	EventTypeFoundationSubsidy = "foundation subsidy"
)

type eventData interface {
	EventType() string
}

// An Event is something interesting that happened on the Sia blockchain.
type Event struct {
	ID             types.Hash256    `json:"id"`
	Index          types.ChainIndex `json:"index"`
	Timestamp      time.Time        `json:"timestamp"`
	MaturityHeight uint64           `json:"maturityHeight"`
	Addresses      []types.Address  `json:"addresses"`
	Data           eventData        `json:"data"`
}

// EventType implements Event.
func (*EventTransaction) EventType() string { return EventTypeTransaction }

// EventType implements Event.
func (*EventMinerPayout) EventType() string { return EventTypeMinerPayout }

// EventType implements Event.
func (*EventFoundationSubsidy) EventType() string { return EventTypeFoundationSubsidy }

// EventType implements Event.
func (*EventContractPayout) EventType() string { return EventTypeContractPayout }

// A HostAnnouncement represents a host announcement within an EventTransaction.
type HostAnnouncement struct {
	PublicKey  types.PublicKey `json:"publicKey"`
	NetAddress string          `json:"netAddress"`
}

// An EventSiafundInput represents a siafund input within an EventTransaction.
type EventSiafundInput struct {
	SiafundElement types.SiafundElement `json:"siafundElement"`
	ClaimElement   types.SiacoinElement `json:"claimElement"`
}

// An EventFileContract represents a file contract within an EventTransaction.
type EventFileContract struct {
	FileContract types.FileContractElement `json:"fileContract"`
	// only non-nil if transaction revised contract
	Revision *types.FileContract `json:"revision,omitempty"`
	// only non-nil if transaction resolved contract
	ValidOutputs []types.SiacoinElement `json:"validOutputs,omitempty"`
}

// An EventV2FileContract represents a v2 file contract within an EventTransaction.
type EventV2FileContract struct {
	FileContract types.V2FileContractElement `json:"fileContract"`
	// only non-nil if transaction revised contract
	Revision *types.V2FileContract `json:"revision,omitempty"`
	// only non-nil if transaction resolved contract
	Resolution types.V2FileContractResolutionType `json:"resolution,omitempty"`
	Outputs    []types.SiacoinElement             `json:"outputs,omitempty"`
}

// An EventTransaction represents a transaction that affects the wallet.
type EventTransaction struct {
	Transaction       Transaction        `json:"transaction"`
	HostAnnouncements []HostAnnouncement `json:"hostAnnouncements"`
	Fee               types.Currency     `json:"fee"`
}

// An EventMinerPayout represents a miner payout from a block.
type EventMinerPayout struct {
	SiacoinOutput types.SiacoinElement `json:"siacoinOutput"`
}

// EventFoundationSubsidy represents a foundation subsidy from a block.
type EventFoundationSubsidy struct {
	SiacoinOutput types.SiacoinElement `json:"siacoinOutput"`
}

// An EventContractPayout represents a file contract payout
type EventContractPayout struct {
	FileContract  types.FileContractElement `json:"fileContract"`
	SiacoinOutput types.SiacoinElement      `json:"siacoinOutput"`
	Missed        bool                      `json:"missed"`
}

// A ChainUpdate is a set of changes to the consensus state.
type ChainUpdate interface {
	ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool))
	ForEachSiafundElement(func(sfe types.SiafundElement, spent bool))
	ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool))
	ForEachV2FileContractElement(func(fce types.V2FileContractElement, rev *types.V2FileContractElement, res types.V2FileContractResolutionType))
}

// AppliedEvents extracts a list of relevant events from a chain update.
func AppliedEvents(cs consensus.State, b types.Block, cu ChainUpdate) []Event {
	var events []Event
	addEvent := func(id types.Hash256, maturityHeight uint64, v eventData, addresses []types.Address) {
		// dedup relevant addresses
		seen := make(map[types.Address]bool)
		unique := addresses[:0]
		for _, addr := range addresses {
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
			Addresses:      unique,
			Data:           v,
		})
	}

	// collect all elements
	sces := make(map[types.SiacoinOutputID]types.SiacoinElement)
	sfes := make(map[types.SiafundOutputID]types.SiafundElement)
	fces := make(map[types.FileContractID]types.FileContractElement)
	v2fces := make(map[types.FileContractID]types.V2FileContractElement)
	cu.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		sce.MerkleProof = nil
		sces[types.SiacoinOutputID(sce.ID)] = sce
	})
	cu.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		sfe.MerkleProof = nil
		sfes[types.SiafundOutputID(sfe.ID)] = sfe
	})
	cu.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		fce.MerkleProof = nil
		fces[types.FileContractID(fce.ID)] = fce
	})
	cu.ForEachV2FileContractElement(func(fce types.V2FileContractElement, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
		fce.MerkleProof = nil
		v2fces[types.FileContractID(fce.ID)] = fce
	})

	relevantTxn := func(txn types.Transaction) (addrs []types.Address) {
		for _, sci := range txn.SiacoinInputs {
			addrs = append(addrs, sces[sci.ParentID].SiacoinOutput.Address)
		}
		for _, sco := range txn.SiacoinOutputs {
			addrs = append(addrs, sco.Address)
		}
		for _, sfi := range txn.SiafundInputs {
			addrs = append(addrs, sfes[sfi.ParentID].SiafundOutput.Address)
		}
		for _, sfo := range txn.SiafundOutputs {
			addrs = append(addrs, sfo.Address)
		}
		return
	}

	relevantV2Txn := func(txn types.V2Transaction) (addrs []types.Address) {
		for _, sci := range txn.SiacoinInputs {
			addrs = append(addrs, sci.Parent.SiacoinOutput.Address)
		}
		for _, sco := range txn.SiacoinOutputs {
			addrs = append(addrs, sco.Address)
		}
		for _, sfi := range txn.SiafundInputs {
			addrs = append(addrs, sfi.Parent.SiafundOutput.Address)
		}
		for _, sfo := range txn.SiafundOutputs {
			addrs = append(addrs, sfo.Address)
		}
		return
	}

	// handle v1 transactions
	for _, txn := range b.Transactions {
		relevant := relevantTxn(txn)
		if len(relevant) == 0 {
			continue
		}

		var e EventTransaction
		for _, arb := range txn.ArbitraryData {
			var prefix types.Specifier
			var uk types.UnlockKey
			d := types.NewBufDecoder(arb)
			prefix.DecodeFrom(d)
			netAddress := d.ReadString()
			uk.DecodeFrom(d)
			if d.Err() == nil && prefix == types.NewSpecifier("HostAnnouncement") &&
				uk.Algorithm == types.SpecifierEd25519 && len(uk.Key) == len(types.PublicKey{}) {
				e.HostAnnouncements = append(e.HostAnnouncements, HostAnnouncement{
					PublicKey:  *(*types.PublicKey)(uk.Key),
					NetAddress: netAddress,
				})
			}
		}
		for i := range txn.MinerFees {
			e.Fee = e.Fee.Add(txn.MinerFees[i])
		}

		addEvent(types.Hash256(txn.ID()), cs.Index.Height, &e, relevant) // transaction maturity height is the current block height
	}

	// handle v2 transactions
	for _, txn := range b.V2Transactions() {
		relevant := relevantV2Txn(txn)
		if len(relevant) == 0 {
			continue
		}

		var e EventTransaction
		for _, a := range txn.Attestations {
			if a.Key == "HostAnnouncement" {
				e.HostAnnouncements = append(e.HostAnnouncements, HostAnnouncement{
					PublicKey:  a.PublicKey,
					NetAddress: string(a.Value),
				})
			}
		}
		addEvent(types.Hash256(txn.ID()), cs.Index.Height, &e, relevant) // transaction maturity height is the current block height
	}

	// handle missed contracts
	cu.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		if !resolved {
			return
		}

		if valid {
			for i := range fce.FileContract.ValidProofOutputs {
				outputID := types.FileContractID(fce.ID).ValidOutputID(i)
				addEvent(types.Hash256(outputID), cs.MaturityHeight(), &EventContractPayout{
					FileContract:  fce,
					SiacoinOutput: sces[outputID],
					Missed:        false,
				}, []types.Address{fce.FileContract.ValidProofOutputs[i].Address})
			}
		} else {
			for i := range fce.FileContract.MissedProofOutputs {
				outputID := types.FileContractID(fce.ID).MissedOutputID(i)
				addEvent(types.Hash256(outputID), cs.MaturityHeight(), &EventContractPayout{
					FileContract:  fce,
					SiacoinOutput: sces[outputID],
					Missed:        true,
				}, []types.Address{fce.FileContract.MissedProofOutputs[i].Address})
			}
		}
	})

	// handle block rewards
	for i := range b.MinerPayouts {
		outputID := cs.Index.ID.MinerOutputID(i)
		addEvent(types.Hash256(outputID), cs.MaturityHeight(), &EventMinerPayout{
			SiacoinOutput: sces[outputID],
		}, []types.Address{b.MinerPayouts[i].Address})
	}

	// handle foundation subsidy
	outputID := cs.Index.ID.FoundationOutputID()
	sce, ok := sces[outputID]
	if ok {
		addEvent(types.Hash256(outputID), cs.MaturityHeight(), &EventFoundationSubsidy{
			SiacoinOutput: sce,
		}, []types.Address{cs.FoundationPrimaryAddress})
	}

	return events
}
