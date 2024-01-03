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
}

// Explorer implements a Sia explorer.
type Explorer struct {
	s Store
}

// NewExplorer returns a Sia explorer.
func NewExplorer(s Store) *Explorer {
	return &Explorer{s: s}
}

func (e *Explorer) Tip() (types.ChainIndex, error) {
	return e.s.Tip()
}

func (e *Explorer) Block(id types.BlockID) (types.Block, error) {
	return e.s.Block(id)
}
