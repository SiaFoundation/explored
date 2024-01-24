package explorer

import (
	"go.sia.tech/core/chain"
	"go.sia.tech/core/types"
)

// A Store is a database that stores information about elements, contracts,
// and blocks.
type Store interface {
	chain.Subscriber

	Tip() (types.ChainIndex, error)
	Block(id types.BlockID) (types.Block, error)
	BestTip(height uint64) (types.ChainIndex, error)
	Transactions(ids []types.TransactionID) ([]types.Transaction, error)
	UnspentSiacoinOutputs(address types.Address, limit, offset uint64) ([]types.SiacoinOutput, error)
	UnspentSiafundOutputs(address types.Address, limit, offset uint64) ([]types.SiafundOutput, error)
	Balance(address types.Address) (sc types.Currency, sf uint64, err error)
}

// Explorer implements a Sia explorer.
type Explorer struct {
	s Store
}

// NewExplorer returns a Sia explorer.
func NewExplorer(s Store) *Explorer {
	return &Explorer{s: s}
}

// Tip returns the tip of the best known valid chain.
func (e *Explorer) Tip() (types.ChainIndex, error) {
	return e.s.Tip()
}

// Block returns the block with the specified ID.
func (e *Explorer) Block(id types.BlockID) (types.Block, error) {
	return e.s.Block(id)
}

// BestTip returns the chain index at the specified height.
func (e *Explorer) BestTip(height uint64) (types.ChainIndex, error) {
	return e.s.BestTip(height)
}

// Transactions returns the transactions with the specified IDs.
func (e *Explorer) Transactions(ids []types.TransactionID) ([]types.Transaction, error) {
	return e.s.Transactions(ids)
}

// UnspentSiacoinOutputs returns the unspent siacoin outputs owned by the
// specified address.
func (e *Explorer) UnspentSiacoinOutputs(address types.Address, limit, offset uint64) ([]types.SiacoinOutput, error) {
	return e.s.UnspentSiacoinOutputs(address, limit, offset)
}

// UnspentSiafundOutputs returns the unspent siafund outputs owned by the
// specified address.
func (e *Explorer) UnspentSiafundOutputs(address types.Address, limit, offset uint64) ([]types.SiafundOutput, error) {
	return e.s.UnspentSiafundOutputs(address, limit, offset)
}

// Balance returns the balance of an address.
func (e *Explorer) Balance(address types.Address) (sc types.Currency, sf uint64, err error) {
	return e.s.Balance(address)
}
