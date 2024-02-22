package explorer

import (
	"encoding/json"
	"errors"
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
	switch d {
	case SourceInvalid:
		return json.Marshal("invalid")
	case SourceMinerPayout:
		return json.Marshal("miner_payout")
	case SourceTransaction:
		return json.Marshal("transaction")
	default:
		return nil, errors.New("invalid Source value")
	}
}

// A SiacoinOutput is a types.SiacoinElement with an added field for the
// source.
type SiacoinOutput struct {
	Source Source `json:"source"`
	types.SiacoinElement
}

// A SiafundOutput is a types.SiafundElement.
type SiafundOutput types.SiafundElement

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
