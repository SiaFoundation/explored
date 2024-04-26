package explorer

import (
	"errors"
	"fmt"
	"sync"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.uber.org/zap"
)

var (
	// ErrNoTip is returned when Tip() is unable to find any blocks in the
	// database and thus there is no tip. It does not mean there was an
	// error in the underlying database.
	ErrNoTip = errors.New("no tip found")
)

// A ChainManager manages the consensus state
type ChainManager interface {
	Tip() types.ChainIndex
	BestIndex(height uint64) (types.ChainIndex, bool)

	OnReorg(fn func(types.ChainIndex)) (cancel func())
	UpdatesSince(index types.ChainIndex, max int) (rus []chain.RevertUpdate, aus []chain.ApplyUpdate, err error)
}

// A Store is a database that stores information about elements, contracts,
// and blocks.
type Store interface {
	UpdateChainState(reverted []chain.RevertUpdate, applied []chain.ApplyUpdate) error

	Tip() (types.ChainIndex, error)
	Block(id types.BlockID) (Block, error)
	BestTip(height uint64) (types.ChainIndex, error)
	MerkleProof(leafIndex uint64) ([]types.Hash256, error)
	Transactions(ids []types.TransactionID) ([]Transaction, error)
	UnspentSiacoinOutputs(address types.Address, offset, limit uint64) ([]SiacoinOutput, error)
	UnspentSiafundOutputs(address types.Address, offset, limit uint64) ([]SiafundOutput, error)
	Balance(address types.Address) (sc types.Currency, immatureSC types.Currency, sf uint64, err error)
	Contracts(ids []types.FileContractID) (result []FileContract, err error)
	AddressEvents(address types.Address, offset, limit int) (events []Event, err error)
}

// Explorer implements a Sia explorer.
type Explorer struct {
	s  Store
	mu sync.Mutex

	unsubscribe func()
}

func syncStore(store Store, cm ChainManager, index types.ChainIndex) error {
	for index != cm.Tip() {
		crus, caus, err := cm.UpdatesSince(index, 1000)
		if err != nil {
			return fmt.Errorf("failed to subscribe to chain manager: %w", err)
		}

		if err := store.UpdateChainState(crus, caus); err != nil {
			return fmt.Errorf("failed to process updates: %w", err)
		}
		if len(crus) > 0 {
			index = crus[len(crus)-1].State.Index
		}
		if len(caus) > 0 {
			index = caus[len(caus)-1].State.Index
		}
	}
	return nil
}

// NewExplorer returns a Sia explorer.
func NewExplorer(cm ChainManager, store Store, log *zap.Logger) (*Explorer, error) {
	e := &Explorer{s: store}

	tip, err := store.Tip()
	if errors.Is(err, ErrNoTip) {
		tip = types.ChainIndex{}
	} else if err != nil {
		return nil, fmt.Errorf("failed to get tip: %w", err)
	}
	if err := syncStore(store, cm, tip); err != nil {
		return nil, fmt.Errorf("failed to subscribe to chain manager: %w", err)
	}

	reorgChan := make(chan types.ChainIndex, 1)
	go func() {
		for range reorgChan {
			e.mu.Lock()
			lastTip, err := store.Tip()
			if errors.Is(err, ErrNoTip) {
				lastTip = types.ChainIndex{}
			} else if err != nil {
				log.Error("failed to get tip", zap.Error(err))
			}
			if err := syncStore(store, cm, lastTip); err != nil {
				log.Error("failed to sync store", zap.Error(err))
			}
			e.mu.Unlock()
		}
	}()

	e.unsubscribe = cm.OnReorg(func(index types.ChainIndex) {
		select {
		case reorgChan <- index:
		default:
		}
	})
	return e, nil
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

// MerkleProof returns the proof of a given leaf.
func (e *Explorer) MerkleProof(leafIndex uint64) ([]types.Hash256, error) {
	return e.s.MerkleProof(leafIndex)
}

// Transactions returns the transactions with the specified IDs.
func (e *Explorer) Transactions(ids []types.TransactionID) ([]Transaction, error) {
	return e.s.Transactions(ids)
}

// UnspentSiacoinOutputs returns the unspent siacoin outputs owned by the
// specified address.
func (e *Explorer) UnspentSiacoinOutputs(address types.Address, offset, limit uint64) ([]SiacoinOutput, error) {
	return e.s.UnspentSiacoinOutputs(address, offset, limit)
}

// UnspentSiafundOutputs returns the unspent siafund outputs owned by the
// specified address.
func (e *Explorer) UnspentSiafundOutputs(address types.Address, offset, limit uint64) ([]SiafundOutput, error) {
	return e.s.UnspentSiafundOutputs(address, offset, limit)
}

// AddressEvents returns the events of a single address.
func (e *Explorer) AddressEvents(address types.Address, offset, limit int) (events []Event, err error) {
	return e.s.AddressEvents(address, offset, limit)
}

// Balance returns the balance of an address.
func (e *Explorer) Balance(address types.Address) (sc types.Currency, immatureSC types.Currency, sf uint64, err error) {
	return e.s.Balance(address)
}

// Contracts returns the contracts with the specified IDs.
func (e *Explorer) Contracts(ids []types.FileContractID) (result []FileContract, err error) {
	return e.s.Contracts(ids)
}
