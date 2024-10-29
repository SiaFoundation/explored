package explorer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/config"
	"go.uber.org/zap"
)

var (
	// ErrNoTip is returned when Tip() is unable to find any blocks in the
	// database and thus there is no tip. It does not mean there was an
	// error in the underlying database.
	ErrNoTip = errors.New("no tip found")

	// ErrContractNotFound is returned when ContractRevisions is unable to find
	// the specified contract ID.
	ErrContractNotFound = errors.New("contract not found")
)

// A ChainManager manages the consensus state
type ChainManager interface {
	Tip() types.ChainIndex
	TipState() consensus.State
	BestIndex(height uint64) (types.ChainIndex, bool)

	OnReorg(fn func(types.ChainIndex)) (cancel func())
	UpdatesSince(index types.ChainIndex, max int) (rus []chain.RevertUpdate, aus []chain.ApplyUpdate, err error)
}

// A Store is a database that stores information about elements, contracts,
// and blocks.
type Store interface {
	Close() error

	UpdateChainState(reverted []chain.RevertUpdate, applied []chain.ApplyUpdate) error
	AddHostScans(scans []HostScan) error

	Tip() (types.ChainIndex, error)
	Block(id types.BlockID) (Block, error)
	BestTip(height uint64) (types.ChainIndex, error)
	MerkleProof(leafIndex uint64) ([]types.Hash256, error)
	Metrics(id types.BlockID) (Metrics, error)
	HostMetrics() (HostMetrics, error)
	Transactions(ids []types.TransactionID) ([]Transaction, error)
	TransactionChainIndices(txid types.TransactionID, offset, limit uint64) ([]types.ChainIndex, error)
	V2Transactions(ids []types.TransactionID) ([]V2Transaction, error)
	V2TransactionChainIndices(txid types.TransactionID, offset, limit uint64) ([]types.ChainIndex, error)
	UnspentSiacoinOutputs(address types.Address, offset, limit uint64) ([]SiacoinOutput, error)
	UnspentSiafundOutputs(address types.Address, offset, limit uint64) ([]SiafundOutput, error)
	AddressEvents(address types.Address, offset, limit uint64) (events []Event, err error)
	Balance(address types.Address) (sc types.Currency, immatureSC types.Currency, sf uint64, err error)
	Contracts(ids []types.FileContractID) (result []FileContract, err error)
	ContractsKey(key types.PublicKey) (result []FileContract, err error)
	ContractRevisions(id types.FileContractID) (result []FileContract, err error)
	V2Contracts(ids []types.FileContractID) (result []V2FileContract, err error)
	V2ContractsKey(key types.PublicKey) (result []V2FileContract, err error)
	V2ContractRevisions(id types.FileContractID) (result []V2FileContract, err error)
	SiacoinElements(ids []types.SiacoinOutputID) (result []SiacoinOutput, err error)
	SiafundElements(ids []types.SiafundOutputID) (result []SiafundOutput, err error)

	Hosts(pks []types.PublicKey) ([]Host, error)
	HostsForScanning(maxLastScan, minLastAnnouncement time.Time, offset, limit uint64) ([]chain.HostAnnouncement, error)
}

// Explorer implements a Sia explorer.
type Explorer struct {
	s  Store
	cm ChainManager

	scanCfg config.Scanner

	log *zap.Logger

	wg        sync.WaitGroup
	ctx       context.Context
	ctxCancel context.CancelFunc

	unsubscribe func()
}

func (e *Explorer) syncStore(index types.ChainIndex, batchSize int) error {
	for index != e.cm.Tip() {
		crus, caus, err := e.cm.UpdatesSince(index, batchSize)
		if err != nil {
			return fmt.Errorf("failed to subscribe to chain manager: %w", err)
		}

		if err := e.s.UpdateChainState(crus, caus); err != nil {
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
func NewExplorer(cm ChainManager, store Store, batchSize int, scanCfg config.Scanner, log *zap.Logger) (*Explorer, error) {
	ctx, ctxCancel := context.WithCancel(context.Background())
	e := &Explorer{
		s:         store,
		cm:        cm,
		scanCfg:   scanCfg,
		ctx:       ctx,
		ctxCancel: ctxCancel,
		log:       log,
	}

	tip, err := e.s.Tip()
	if errors.Is(err, ErrNoTip) {
		tip = types.ChainIndex{}
	} else if err != nil {
		return nil, fmt.Errorf("failed to get tip: %w", err)
	}
	if err := e.syncStore(tip, batchSize); err != nil {
		return nil, fmt.Errorf("failed to subscribe to chain manager: %w", err)
	}

	reorgChan := make(chan types.ChainIndex, 1)
	go func() {
		for range reorgChan {
			lastTip, err := e.s.Tip()
			if errors.Is(err, ErrNoTip) {
				lastTip = types.ChainIndex{}
			} else if err != nil {
				e.log.Error("failed to get tip", zap.Error(err))
			}
			if err := e.syncStore(lastTip, batchSize); err != nil {
				e.log.Error("failed to sync store", zap.Error(err))
			}
		}
	}()

	go e.scanHosts()

	e.unsubscribe = e.cm.OnReorg(func(index types.ChainIndex) {
		select {
		case reorgChan <- index:
		default:
		}
	})
	return e, nil
}

// Shutdown tries to close the scanning goroutines in the explorer.
func (e *Explorer) Shutdown(ctx context.Context) error {
	e.ctxCancel()

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	// Wait for the WaitGroup to finish or the context to be cancelled
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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

// Metrics returns various metrics about Sia.
func (e *Explorer) Metrics(id types.BlockID) (Metrics, error) {
	return e.s.Metrics(id)
}

// HostMetrics returns various metrics about currently available hosts.
func (e *Explorer) HostMetrics() (HostMetrics, error) {
	return e.s.HostMetrics()
}

// Transactions returns the transactions with the specified IDs.
func (e *Explorer) Transactions(ids []types.TransactionID) ([]Transaction, error) {
	return e.s.Transactions(ids)
}

// TransactionChainIndices returns the chain indices of the blocks the transaction
// was included in. If the transaction has not been included in any blocks, the
// result will be nil,nil.
func (e *Explorer) TransactionChainIndices(id types.TransactionID, offset, limit uint64) ([]types.ChainIndex, error) {
	return e.s.TransactionChainIndices(id, offset, limit)
}

// V2Transactions returns the v2 transactions with the specified IDs.
func (e *Explorer) V2Transactions(ids []types.TransactionID) ([]V2Transaction, error) {
	return e.s.V2Transactions(ids)
}

// V2TransactionChainIndices returns the chain indices of the blocks the
// transaction was included in. If the transaction has not been included in
// any blocks, the result will be nil,nil.
func (e *Explorer) V2TransactionChainIndices(id types.TransactionID, offset, limit uint64) ([]types.ChainIndex, error) {
	return e.s.V2TransactionChainIndices(id, offset, limit)
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
func (e *Explorer) AddressEvents(address types.Address, offset, limit uint64) (events []Event, err error) {
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

// ContractsKey returns the contracts for a particular ed25519 key.
func (e *Explorer) ContractsKey(key types.PublicKey) (result []FileContract, err error) {
	return e.s.ContractsKey(key)
}

// ContractRevisions returns all the revisions of the contract with the
// specified ID.
func (e *Explorer) ContractRevisions(id types.FileContractID) (result []FileContract, err error) {
	return e.s.ContractRevisions(id)
}

// V2Contracts returns the v2 contracts with the specified IDs.
func (e *Explorer) V2Contracts(ids []types.FileContractID) (result []V2FileContract, err error) {
	return e.s.V2Contracts(ids)
}

// V2ContractsKey returns the v2 contracts for a particular ed25519 key.
func (e *Explorer) V2ContractsKey(key types.PublicKey) (result []V2FileContract, err error) {
	return e.s.V2ContractsKey(key)
}

// V2ContractRevisions returns all the revisions of the v2 contract with the
// specified ID.
func (e *Explorer) V2ContractRevisions(id types.FileContractID) (result []V2FileContract, err error) {
	return e.s.V2ContractRevisions(id)
}

// SiacoinElements returns the siacoin elements with the specified IDs.
func (e *Explorer) SiacoinElements(ids []types.SiacoinOutputID) (result []SiacoinOutput, err error) {
	return e.s.SiacoinElements(ids)
}

// SiafundElements returns the siafund elements with the specified IDs.
func (e *Explorer) SiafundElements(ids []types.SiafundOutputID) (result []SiafundOutput, err error) {
	return e.s.SiafundElements(ids)
}

// Hosts returns the hosts with the specified public keys.
func (e *Explorer) Hosts(pks []types.PublicKey) ([]Host, error) {
	return e.s.Hosts(pks)
}

// Search returns the element type (address, block, transaction, contract ID)
// for a given ID.
func (e *Explorer) Search(id types.Hash256) (SearchType, error) {
	events, err := e.AddressEvents(types.Address(id), 0, 1)
	if err != nil {
		return SearchTypeInvalid, err
	} else if len(events) > 0 {
		return SearchTypeAddress, nil
	}

	_, err = e.Block(types.BlockID(id))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return SearchTypeInvalid, err
	} else if err == nil {
		return SearchTypeBlock, nil
	}

	txns, err := e.Transactions([]types.TransactionID{types.TransactionID(id)})
	if err != nil {
		return SearchTypeInvalid, err
	} else if len(txns) > 0 {
		return SearchTypeTransaction, nil
	}

	scos, err := e.SiacoinElements([]types.SiacoinOutputID{types.SiacoinOutputID(id)})
	if err != nil {
		return SearchTypeInvalid, err
	} else if len(scos) > 0 {
		return SearchTypeSiacoinElement, nil
	}

	sfos, err := e.SiafundElements([]types.SiafundOutputID{types.SiafundOutputID(id)})
	if err != nil {
		return SearchTypeInvalid, err
	} else if len(sfos) > 0 {
		return SearchTypeSiafundElement, nil
	}

	contracts, err := e.Contracts([]types.FileContractID{types.FileContractID(id)})
	if err != nil {
		return SearchTypeInvalid, err
	} else if len(contracts) > 0 {
		return SearchTypeContract, nil
	}

	return SearchTypeInvalid, errors.New("no such element")
}
