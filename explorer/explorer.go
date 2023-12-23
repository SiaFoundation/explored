package explorer

import (
	"go.sia.tech/core/chain"
	"go.sia.tech/core/types"
)

type Transaction interface {
	AddBlock(b types.Block, height uint64) error
	AddMinerPayouts(bid types.BlockID, scos []types.SiacoinOutput) error
}

// A Store is a database that stores information about elements, contracts,
// and blocks.
type Store interface {
	Transaction(fn func(tx Transaction) error) error
}

// Explorer implements a Sia explorer.
type Explorer struct {
	s Store
}

// NewExplorer returns a Sia explorer.
func NewExplorer(s Store) *Explorer {
	return &Explorer{s}
}

// ProcessChainApplyUpdate implements chain.Subscriber.
func (e *Explorer) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, mayCommit bool) error {
	return e.s.Transaction(func(tx Transaction) error {
		if err := tx.AddBlock(cau.Block, cau.State.Index.Height); err != nil {
			return err
		} else if err := tx.AddMinerPayouts(cau.Block.ID(), cau.Block.MinerPayouts); err != nil {
			return err
		}
		return nil
	})
}

// ProcessChainRevertUpdate implements chain.Subscriber.
func (e *Explorer) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	return nil
}
