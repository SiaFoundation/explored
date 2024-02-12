package explorer

import (
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
)

// A HashStore is a database that stores the state element merkle tree.
type HashStore interface {
	chain.Subscriber

	Commit() error
	MerkleProof(leafIndex uint64) ([]types.Hash256, error)
	ModifyLeaf(elem types.StateElement) error
}

// A Store is a database that stores information about elements, contracts,
// and blocks.
type Store interface {
	chain.Subscriber

	Tip() (types.ChainIndex, error)
	Block(id types.BlockID) (Block, error)
	BestTip(height uint64) (types.ChainIndex, error)
	Transactions(ids []types.TransactionID) ([]Transaction, error)
	UnspentSiacoinOutputs(address types.Address, limit, offset uint64) ([]SiacoinOutput, error)
	UnspentSiafundOutputs(address types.Address, limit, offset uint64) ([]SiafundOutput, error)
	Balance(address types.Address) (sc types.Currency, sf uint64, err error)
}

// Explorer implements a Sia explorer.
type Explorer struct {
	s  Store
	hs HashStore
}

// NewExplorer returns a Sia explorer.
func NewExplorer(s Store, hs HashStore) *Explorer {
	return &Explorer{s: s, hs: hs}
}

// MerkleProof gets the merkle proof with the given leaf index.
func (e *Explorer) MerkleProof(leafIndex uint64) ([]types.Hash256, error) {
	return e.hs.MerkleProof(leafIndex)
}

// ModifyLeaf overwrites hashes in the tree with the proof hashes in the
// provided element.
func (e *Explorer) ModifyLeaf(elem types.StateElement) error {
	return e.hs.ModifyLeaf(elem)
}

// Tip returns the tip of the best known valid chain.
func (e *Explorer) Tip() (types.ChainIndex, error) {
	return e.s.Tip()
}

// Block returns the block with the specified ID.
func (e *Explorer) Block(id types.BlockID) (Block, error) {
	return e.s.Block(id)
}

// BestTip returns the chain index at the specified height.
func (e *Explorer) BestTip(height uint64) (types.ChainIndex, error) {
	return e.s.BestTip(height)
}

// Transactions returns the transactions with the specified IDs.
func (e *Explorer) Transactions(ids []types.TransactionID) ([]Transaction, error) {
	return e.s.Transactions(ids)
}

// UnspentSiacoinOutputs returns the unspent siacoin outputs owned by the
// specified address.
func (e *Explorer) UnspentSiacoinOutputs(address types.Address, limit, offset uint64) ([]SiacoinOutput, error) {
	return e.s.UnspentSiacoinOutputs(address, limit, offset)
}

// UnspentSiafundOutputs returns the unspent siafund outputs owned by the
// specified address.
func (e *Explorer) UnspentSiafundOutputs(address types.Address, limit, offset uint64) ([]SiafundOutput, error) {
	return e.s.UnspentSiafundOutputs(address, limit, offset)
}

// Balance returns the balance of an address.
func (e *Explorer) Balance(address types.Address) (sc types.Currency, sf uint64, err error) {
	return e.s.Balance(address)
}
