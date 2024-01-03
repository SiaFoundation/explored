package explorer

import (
	"go.sia.tech/core/chain"
)

// A Store is a database that stores information about elements, contracts,
// and blocks.
type Store interface {
	chain.Subscriber
}

// Explorer implements a Sia explorer.
type Explorer struct {
	s Store
}

// NewExplorer returns a Sia explorer.
func NewExplorer(s Store) *Explorer {
	return &Explorer{s: s}
}
