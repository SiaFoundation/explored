package explorer

import (
	"encoding/json"
	"time"

	"go.sia.tech/core/types"
)

// A Source represents where a siacoin output came from.
type Source int

const (
	// SourceInvalid represents a source we are not aware of.
	SourceInvalid Source = iota
	// SourceMinerPayout means the source of the output is a miner payout.
	SourceMinerPayout
	// SourceTransaction means the source of the output is a transaction.
	SourceTransaction
)

// MarshalJSON implements json.Marshaler.
func (d Source) MarshalJSON() ([]byte, error) {
	return json.Marshal([...]string{"invalid", "miner_payout", "transaction"}[d])
}

// A SiacoinOutput is a types.SiacoinOutput with added fields for output ID,
// source, and maturity height.
type SiacoinOutput struct {
	OutputID       types.SiacoinOutputID `json:"outputID"`
	Source         Source                `json:"source"`
	MaturityHeight int                   `json:"maturityHeight"`

	types.SiacoinOutput
}

// A SiafundOutput contains a types.SiafundOutput with added fields for output
// ID and claim start.
type SiafundOutput struct {
	OutputID   types.SiafundOutputID `json:"outputID"`
	ClaimStart types.Currency        `json:"claimStart"`

	types.SiafundOutput
}

// A Transaction is a transaction that uses the wrapped types above.
type Transaction struct {
	SiacoinInputs  []types.SiacoinInput `json:"siacoinInputs,omitempty"`
	SiacoinOutputs []SiacoinOutput      `json:"siacoinOutputs,omitempty"`
	SiafundInputs  []types.SiafundInput `json:"siafundInputs,omitempty"`
	SiafundOutputs []SiafundOutput      `json:"siafundOutputs,omitempty"`
	ArbitraryData  [][]byte             `json:"arbitraryData,omitempty"`
}

// A Block is a block containing wrapped transactions and siacoin
// outputs for the miner payouts.
type Block struct {
	Height uint64

	ParentID     types.BlockID   `json:"parentID"`
	Nonce        uint64          `json:"nonce"`
	Timestamp    time.Time       `json:"timestamp"`
	MinerPayouts []SiacoinOutput `json:"minerPayouts"`
	Transactions []Transaction   `json:"transactions"`
}
