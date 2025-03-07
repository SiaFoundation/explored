package explorer

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/config"
	"go.uber.org/zap"
)

var (
	// ErrNoTip is returned when we are unable to find the tip in the
	// database or there is no tips at all.
	ErrNoTip = errors.New("no tip found")

	// ErrContractNotFound is returned when ContractRevisions is unable to find
	// the specified contract ID.
	ErrContractNotFound = errors.New("contract not found")

	// ErrSearchParse is returned when Search is unable to parse the specified
	// ID.
	ErrSearchParse = errors.New("error parsing ID")

	// ErrNoSearchResults is returned when Search is unable to find anything
	// with the specified ID.
	ErrNoSearchResults = errors.New("no search results")

	// ErrNoSortColumn is returned when a host query requests that we sort by a
	// column that does not exist.
	ErrNoSortColumn = errors.New("no such sort column")
)

// A ChainManager manages the consensus state
type ChainManager interface {
	PoolTransactions() []types.Transaction
	V2PoolTransactions() []types.V2Transaction

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
	UnconfirmedEvents(index types.ChainIndex, timestamp time.Time, v1 []types.Transaction, v2 []types.V2Transaction) (annotated []Event, err error)
	AddressEvents(address types.Address, offset, limit uint64) (events []Event, err error)
	Events([]types.Hash256) ([]Event, error)
	Balance(address types.Address) (sc types.Currency, immatureSC types.Currency, sf uint64, err error)
	Contracts(ids []types.FileContractID) (result []ExtendedFileContract, err error)
	ContractsKey(key types.PublicKey) (result []ExtendedFileContract, err error)
	ContractRevisions(id types.FileContractID) (result []ExtendedFileContract, err error)
	V2Contracts(ids []types.FileContractID) (result []V2FileContract, err error)
	V2ContractsKey(key types.PublicKey) (result []V2FileContract, err error)
	V2ContractRevisions(id types.FileContractID) (result []V2FileContract, err error)
	SiacoinElements(ids []types.SiacoinOutputID) (result []SiacoinOutput, err error)
	SiafundElements(ids []types.SiafundOutputID) (result []SiafundOutput, err error)
	Search(id string) (SearchType, error)

	QueryHosts(params HostQuery, sortBy HostSortColumn, dir HostSortDir, offset, limit uint64) ([]Host, error)
	HostsForScanning(minLastAnnouncement time.Time, limit uint64) ([]UnscannedHost, error)
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
				e.log.Panic("failed to sync store", zap.Error(err))
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

// AddressUnconfirmedEvents returns the unconfirmed events for a single address.
func (e *Explorer) AddressUnconfirmedEvents(address types.Address) ([]Event, error) {
	relevantV1Txn := func(txn types.Transaction) bool {
		for _, output := range txn.SiacoinOutputs {
			if output.Address == address {
				return true
			}
		}
		for _, input := range txn.SiacoinInputs {
			if input.UnlockConditions.UnlockHash() == address {
				return true
			}
		}
		for _, output := range txn.SiafundOutputs {
			if output.Address == address {
				return true
			}
		}
		for _, input := range txn.SiafundInputs {
			if input.UnlockConditions.UnlockHash() == address {
				return true
			}
		}
		return false
	}
	relevantV2Txn := func(txn types.V2Transaction) bool {
		for _, output := range txn.SiacoinOutputs {
			if output.Address == address {
				return true
			}
		}
		for _, input := range txn.SiacoinInputs {
			if input.Parent.SiacoinOutput.Address == address {
				return true
			}
		}
		for _, output := range txn.SiafundOutputs {
			if output.Address == address {
				return true
			}
		}
		for _, input := range txn.SiafundInputs {
			if input.Parent.SiafundOutput.Address == address {
				return true
			}
		}
		return false
	}

	index := e.cm.Tip()
	index.Height++
	index.ID = types.BlockID{}
	timestamp := time.Now()

	v1, v2 := e.cm.PoolTransactions(), e.cm.V2PoolTransactions()

	relevantV1 := v1[:0]
	for _, txn := range v1 {
		if !relevantV1Txn(txn) {
			continue
		}
		relevantV1 = append(relevantV1, txn)
	}

	relevantV2 := v2[:0]
	for _, txn := range v2 {
		if !relevantV2Txn(txn) {
			continue
		}
		relevantV2 = append(relevantV2, txn)
	}

	events, err := e.s.UnconfirmedEvents(index, timestamp, relevantV1, relevantV2)
	if err != nil {
		return nil, err
	}
	for i := range events {
		events[i].Relevant = []types.Address{address}
	}
	return events, nil
}

// UnconfirmedEvents annotates a list of unconfirmed transactions.
func (e *Explorer) UnconfirmedEvents(index types.ChainIndex, timestamp time.Time, v1 []types.Transaction, v2 []types.V2Transaction) ([]Event, error) {
	return e.s.UnconfirmedEvents(index, timestamp, v1, v2)
}

// AddressEvents returns the events of a single address.
func (e *Explorer) AddressEvents(address types.Address, offset, limit uint64) (events []Event, err error) {
	return e.s.AddressEvents(address, offset, limit)
}

// Events returns the events with the specified IDs.
func (e *Explorer) Events(ids []types.Hash256) ([]Event, error) {
	return e.s.Events(ids)
}

// Balance returns the balance of an address.
func (e *Explorer) Balance(address types.Address) (sc types.Currency, immatureSC types.Currency, sf uint64, err error) {
	return e.s.Balance(address)
}

// Contracts returns the contracts with the specified IDs.
func (e *Explorer) Contracts(ids []types.FileContractID) (result []ExtendedFileContract, err error) {
	return e.s.Contracts(ids)
}

// ContractsKey returns the contracts for a particular ed25519 key.
func (e *Explorer) ContractsKey(key types.PublicKey) (result []ExtendedFileContract, err error) {
	return e.s.ContractsKey(key)
}

// ContractRevisions returns all the revisions of the contract with the
// specified ID.
func (e *Explorer) ContractRevisions(id types.FileContractID) (result []ExtendedFileContract, err error) {
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
	return e.s.QueryHosts(HostQuery{PublicKeys: pks}, HostSortPublicKey, HostSortAsc, 0, math.MaxInt64)
}

// QueryHosts returns the hosts matching the query parameters in the order
// specified by dir.
func (e *Explorer) QueryHosts(params HostQuery, sortBy HostSortColumn, dir HostSortDir, offset, limit uint64) ([]Host, error) {
	return e.s.QueryHosts(params, sortBy, dir, offset, limit)
}

// Search returns the type of an element (siacoin element, siafund element,
// contract, v2 contract, transaction, v2 transaction, block, or host).
func (e *Explorer) Search(id string) (SearchType, error) {
	return e.s.Search(id)
}
