package explorer

import (
	"sync"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/types"
)

type Transaction interface {
	// Create
	AddBlock(b types.Block, height uint64) error
	AddMinerPayouts(bid types.BlockID, scos []types.SiacoinOutput) error
	// Delete
	DeleteBlock(bid types.BlockID) error
}

// A Store is a database that stores information about elements, contracts,
// and blocks.
type Store interface {
	Transaction(fn func(tx Transaction) error) error
}

// Explorer implements a Sia explorer.
type Explorer struct {
	mu sync.Mutex

	s              Store
	pendingUpdates []*chain.ApplyUpdate
}

// NewExplorer returns a Sia explorer.
func NewExplorer(s Store) *Explorer {
	return &Explorer{s: s}
}

func (e *Explorer) applyUpdates(tx Transaction) error {
	for _, update := range e.pendingUpdates {
		if err := tx.AddBlock(update.Block, update.State.Index.Height); err != nil {
			return err
		} else if err := tx.AddMinerPayouts(update.Block.ID(), update.Block.MinerPayouts); err != nil {
			return err
		}
	}
	e.pendingUpdates = e.pendingUpdates[:0]
	return nil
}

// ProcessChainApplyUpdate implements chain.Subscriber.
func (e *Explorer) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, mayCommit bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.pendingUpdates = append(e.pendingUpdates, cau)
	if mayCommit {
		return e.s.Transaction(e.applyUpdates)
	}
	return nil
}

// ProcessChainRevertUpdate implements chain.Subscriber.
func (e *Explorer) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.s.Transaction(func(tx Transaction) error {
		if err := e.applyUpdates(tx); err != nil {
			panic(err)
			return err
		}
		if err := tx.DeleteBlock(cru.Block.ID()); err != nil {
			panic(err)
			return err
		}
		return nil
	})
}
