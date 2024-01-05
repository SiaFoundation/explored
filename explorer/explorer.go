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
	BlockByID(id types.BlockID) (types.Block, error)
	BlockByHeight(height uint64) (types.Block, error)
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

// BlockByID returns the block with the specified ID.
func (e *Explorer) BlockByID(id types.BlockID) (types.Block, error) {
	return e.s.BlockByID(id)
}

// BlockByHeight returns the block with the specified height.
func (e *Explorer) BlockByHeight(height uint64) (types.Block, error) {
	return e.s.BlockByHeight(height)
}
