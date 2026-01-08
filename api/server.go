package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"go.sia.tech/jape"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/gateway"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/syncer"
	"go.sia.tech/explored/build"
	"go.sia.tech/explored/exchangerates"
	"go.sia.tech/explored/explorer"
)

type (
	// A ChainManager manages blockchain and txpool state.
	ChainManager interface {
		Tip() types.ChainIndex
		TipState() consensus.State
		AddBlocks([]types.Block) error
		RecommendedFee() types.Currency
		PoolTransactions() []types.Transaction
		V2PoolTransactions() []types.V2Transaction
		AddPoolTransactions(txns []types.Transaction) (bool, error)
		AddV2PoolTransactions(index types.ChainIndex, txns []types.V2Transaction) (bool, error)
		UnconfirmedParents(txn types.Transaction) []types.Transaction
	}

	// A Syncer can connect to other peers and synchronize the blockchain.
	Syncer interface {
		Addr() string
		Peers() []*syncer.Peer
		Connect(ctx context.Context, addr string) (*syncer.Peer, error)
		BroadcastV2TransactionSet(index types.ChainIndex, txns []types.V2Transaction) error
		BroadcastV2BlockOutline(bo gateway.V2BlockOutline) error
	}

	// Explorer implements a Sia explorer.
	Explorer interface {
		Health() error

		Tip() (types.ChainIndex, error)
		Block(id types.BlockID) (explorer.Block, error)
		BestTip(height uint64) (types.ChainIndex, error)
		Metrics(id types.BlockID) (explorer.Metrics, error)
		HostMetrics() (explorer.HostMetrics, error)
		BlockTimeMetrics() (explorer.BlockTimeMetrics, error)
		DifficultyMetrics(start, end, step uint64) (explorer.DifficultyMetrics, error)
		Transactions(ids []types.TransactionID) ([]explorer.Transaction, error)
		TransactionChainIndices(id types.TransactionID, offset, limit uint64) ([]types.ChainIndex, error)
		UnconfirmedTransaction(id types.TransactionID) (explorer.Transaction, bool)
		V2Transactions(ids []types.TransactionID) ([]explorer.V2Transaction, error)
		V2TransactionChainIndices(id types.TransactionID, offset, limit uint64) ([]types.ChainIndex, error)
		UnconfirmedV2Transaction(id types.TransactionID) (explorer.V2Transaction, bool)
		Balance(address types.Address) (sc types.Currency, immatureSC types.Currency, sf uint64, err error)
		TopSiacoinAddresses(limit, offset int) (result []explorer.TopSiacoin, err error)
		TopSiafundAddresses(limit, offset int) (result []explorer.TopSiafund, err error)
		SiacoinElements(ids []types.SiacoinOutputID) (result []explorer.SiacoinOutput, err error)
		SiafundElements(ids []types.SiafundOutputID) (result []explorer.SiafundOutput, err error)
		UnspentSiacoinOutputs(address types.Address, offset, limit uint64) ([]explorer.SiacoinOutput, error)
		UnspentSiafundOutputs(address types.Address, offset, limit uint64) ([]explorer.SiafundOutput, error)
		AddressEvents(address types.Address, offset, limit uint64) (events []explorer.Event, err error)
		AddressCheckpoint(types.Address) (types.ChainIndex, error)
		AddressUnconfirmedEvents(address types.Address) ([]explorer.Event, error)
		Events(ids []types.Hash256) ([]explorer.Event, error)
		UnconfirmedEvents(index types.ChainIndex, timestamp time.Time, v1 []types.Transaction, v2 []types.V2Transaction) ([]explorer.Event, error)
		Contracts(ids []types.FileContractID) (result []explorer.ExtendedFileContract, err error)
		ContractsKey(key types.PublicKey) (result []explorer.ExtendedFileContract, err error)
		ContractRevisions(id types.FileContractID) (result []explorer.ExtendedFileContract, err error)
		V2Contracts(ids []types.FileContractID) (result []explorer.V2FileContract, err error)
		V2ContractsKey(key types.PublicKey) (result []explorer.V2FileContract, err error)
		V2ContractRevisions(id types.FileContractID) (result []explorer.V2FileContract, err error)
		Search(id string) (explorer.SearchType, error)

		ScanHosts(context.Context, ...types.PublicKey) ([]explorer.HostScan, error)
		Hosts(pks []types.PublicKey) ([]explorer.Host, error)
		QueryHosts(params explorer.HostQuery, sortBy explorer.HostSortColumn, dir explorer.HostSortDir, offset, limit uint64) ([]explorer.Host, error)
	}
)

const (
	maxIDs = 5000
)

const (
	defaultLimit uint64 = 100
	maxLimit     uint64 = 500
)

var (
	// ErrBadCredentials is returned when the supplied credentials for a protected
	// endpoint are invalid.
	ErrBadCredentials = errors.New("bad credentials")

	// ErrTransactionNotFound is returned by /transactions/:id when we are
	// unable to find the transaction with that `id`.
	ErrTransactionNotFound = errors.New("no transaction found")
	// ErrSiacoinOutputNotFound is returned by /outputs/siacoin/:id when we
	// are unable to find the siacoin output with that `id`.
	ErrSiacoinOutputNotFound = errors.New("no siacoin output found")
	// ErrSiafundOutputNotFound is returned by /outputs/siafund/:id when we
	// are unable to find the siafund output with that `id`.
	ErrSiafundOutputNotFound = errors.New("no siafund output found")
	// ErrHostNotFound is returned by /pubkey/:key/host when we are unable to
	// find the host with the pubkey `key`.
	ErrHostNotFound = errors.New("no host found")
	// ErrEventNotFound is returned by /events/:id when we can't find the event
	// with the id `id`.
	ErrEventNotFound = errors.New("no event found")

	// ErrTooManyIDs is returned by the batch transaction and contract
	// endpoints when more than maxIDs IDs are specified.
	ErrTooManyIDs = fmt.Errorf("too many IDs provided (provide less than %d)", maxIDs)
)

type server struct {
	cm          ChainManager
	e           Explorer
	s           Syncer
	ex          exchangerates.Source
	apiPassword string

	startTime time.Time
}

func (s *server) checkAuth(jc jape.Context) bool {
	// We could use jape.BasicAuth when defining the route in the map, but it
	// makes the jape linter think that the route is undefined, so we have some
	// auth code here.
	if _, p, ok := jc.Request.BasicAuth(); !ok || s.apiPassword == "" || p != s.apiPassword {
		jc.Error(ErrBadCredentials, http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *server) stateHandler(jc jape.Context) {
	jc.Encode(StateResponse{
		Version:   build.Version(),
		Commit:    build.Commit(),
		OS:        runtime.GOOS,
		BuildTime: build.Time(),
		StartTime: s.startTime,
	})
}

func (s *server) syncerConnectHandler(jc jape.Context) {
	if !s.checkAuth(jc) {
		return
	}

	var addr string
	if jc.Decode(&addr) != nil {
		return
	}
	_, err := s.s.Connect(context.Background(), addr)
	jc.Check("couldn't connect to peer", err)
}

func (s *server) syncerPeersHandler(jc jape.Context) {
	peers := s.s.Peers()

	var result []string
	for _, peer := range peers {
		result = append(result, peer.ConnAddr)
	}
	jc.Encode(result)
}

func (s *server) syncerBroadcastBlockHandler(jc jape.Context) {
	var b types.Block
	if jc.Decode(&b) != nil {
		return
	} else if jc.Check("block is invalid", s.cm.AddBlocks([]types.Block{b})) != nil {
		return
	} else if b.V2 == nil {
		jc.Error(errors.New("v1 blocks are not supported"), http.StatusBadRequest)
		return
	}

	if jc.Check("failed to broadcast block outline", s.s.BroadcastV2BlockOutline(gateway.OutlineBlock(b, s.cm.PoolTransactions(), s.cm.V2PoolTransactions()))) != nil {
		return
	}
}

func (s *server) txpoolTransactionsHandler(jc jape.Context) {
	jc.Encode(TxpoolTransactionsResponse{
		Transactions:   s.cm.PoolTransactions(),
		V2Transactions: s.cm.V2PoolTransactions(),
	})
}

func (s *server) txpoolFeeHandler(jc jape.Context) {
	jc.Encode(s.cm.RecommendedFee())
}

func (s *server) txpoolBroadcastHandler(jc jape.Context) {
	var tbr TxpoolBroadcastRequest
	if jc.Decode(&tbr) != nil {
		return
	}

	tip, err := s.e.Tip()
	if jc.Check("failed to get tip", err) != nil {
		return
	}
	if len(tbr.Transactions) != 0 {
		// TODO: remove support for v1 transactions
		_, err := s.cm.AddPoolTransactions(tbr.Transactions)
		if jc.Check("invalid transaction set", err) != nil {
			return
		}
	}
	if len(tbr.V2Transactions) != 0 {
		_, err := s.cm.AddV2PoolTransactions(tip, tbr.V2Transactions)
		if jc.Check("invalid v2 transaction set", err) != nil {
			return
		}
		if jc.Check("failed to broadcast v2 transaction set", s.s.BroadcastV2TransactionSet(tip, tbr.V2Transactions)) != nil {
			return
		}
	}
}

func (s *server) consensusTipHandler(jc jape.Context) {
	jc.Encode(s.cm.Tip())
}

func (s *server) consensusTipHeightHandler(jc jape.Context) {
	var height uint64
	if jc.DecodeParam("height", &height) != nil {
		return
	}

	tip, err := s.e.BestTip(height)
	if errors.Is(err, explorer.ErrNoTip) {
		jc.Error(explorer.ErrNoTip, http.StatusNotFound)
		return
	} else if jc.Check("failed to get tip", err) != nil {
		return
	}

	jc.Encode(tip)
}

func (s *server) consensusNetworkHandler(jc jape.Context) {
	jc.Encode(s.cm.TipState().Network)
}

func (s *server) consensusStateHandler(jc jape.Context) {
	jc.Encode(s.cm.TipState())
}

func (s *server) explorerTipHandler(jc jape.Context) {
	tip, err := s.e.Tip()
	if jc.Check("failed to get tip", err) != nil {
		return
	}
	jc.Encode(tip)
}

func (s *server) blocksMetricsHandler(jc jape.Context) {
	tip, err := s.e.Tip()
	if jc.Check("failed to get tip", err) != nil {
		return
	}

	metrics, err := s.e.Metrics(tip.ID)
	if jc.Check("failed to get metrics", err) != nil {
		return
	}
	jc.Encode(metrics)
}

func (s *server) blocksMetricsIDHandler(jc jape.Context) {
	var id types.BlockID
	if jc.DecodeParam("id", &id) != nil {
		return
	}
	metrics, err := s.e.Metrics(id)
	if jc.Check("failed to get metrics", err) != nil {
		return
	}
	jc.Encode(metrics)
}

func (s *server) hostMetricsHandler(jc jape.Context) {
	metrics, err := s.e.HostMetrics()
	if jc.Check("failed to get host metrics", err) != nil {
		return
	}
	jc.Encode(metrics)
}

func (s *server) blockTimeMetricsHandler(jc jape.Context) {
	metrics, err := s.e.BlockTimeMetrics()
	if jc.Check("failed to get block time metrics", err) != nil {
		return
	}
	jc.Encode(metrics)
}

func (s *server) difficultyMetricsHandler(jc jape.Context) {
	var start, end uint64
	if jc.DecodeForm("start", &start) != nil || jc.DecodeForm("end", &end) != nil {
		return
	}
	const targetPoints = 150
	step := uint64(1)
	if length := end - start + 1; length > targetPoints {
		step = length / targetPoints
	}
	metrics, err := s.e.DifficultyMetrics(start, end, step)
	if jc.Check("failed to get difficulty metrics", err) != nil {
		return
	}
	jc.Encode(metrics)
}

func (s *server) blocksIDHandler(jc jape.Context) {
	var id types.BlockID
	if jc.DecodeParam("id", &id) != nil {
		return
	}
	block, err := s.e.Block(id)
	if errors.Is(err, explorer.ErrNoBlock) {
		jc.Error(err, http.StatusNotFound)
		return
	} else if jc.Check("failed to get block", err) != nil {
		return
	}
	jc.Encode(block)
}

func (s *server) transactionsIDHandler(jc jape.Context) {
	var id types.TransactionID
	if jc.DecodeParam("id", &id) != nil {
		return
	}
	txns, err := s.e.Transactions([]types.TransactionID{id})
	if jc.Check("failed to get transaction", err) != nil {
		return
	} else if len(txns) > 0 {
		jc.Encode(txns[0])
		return
	}

	// check unconfirmed transaction pool
	if txn, ok := s.e.UnconfirmedTransaction(id); ok {
		jc.Encode(txn)
		return
	}

	jc.Error(ErrTransactionNotFound, http.StatusNotFound)
}

func (s *server) transactionsIDIndicesHandler(jc jape.Context) {
	var id types.TransactionID
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	limit := defaultLimit
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	indices, err := s.e.TransactionChainIndices(id, offset, limit)
	if jc.Check("failed to get transaction indices", err) != nil {
		return
	}
	jc.Encode(indices)
}

func (s *server) transactionsBatchHandler(jc jape.Context) {
	var ids []types.TransactionID
	if jc.Decode(&ids) != nil {
		return
	} else if len(ids) > maxIDs {
		jc.Error(ErrTooManyIDs, http.StatusBadRequest)
		return
	}

	txns, err := s.e.Transactions(ids)
	if jc.Check("failed to get transactions", err) != nil {
		return
	}
	jc.Encode(txns)
}

func (s *server) v2TransactionsIDHandler(jc jape.Context) {
	var id types.TransactionID
	if jc.DecodeParam("id", &id) != nil {
		return
	}
	txns, err := s.e.V2Transactions([]types.TransactionID{id})
	if jc.Check("failed to get transaction", err) != nil {
		return
	} else if len(txns) > 0 {
		jc.Encode(txns[0])
		return
	}

	// check unconfirmed transaction pool
	if txn, ok := s.e.UnconfirmedV2Transaction(id); ok {
		jc.Encode(txn)
		return
	}

	jc.Error(ErrTransactionNotFound, http.StatusNotFound)
}

func (s *server) v2TransactionsIDIndicesHandler(jc jape.Context) {
	var id types.TransactionID
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	limit := defaultLimit
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	indices, err := s.e.V2TransactionChainIndices(id, offset, limit)
	if jc.Check("failed to get transaction indices", err) != nil {
		return
	}
	jc.Encode(indices)
}

func (s *server) v2TransactionsBatchHandler(jc jape.Context) {
	var ids []types.TransactionID
	if jc.Decode(&ids) != nil {
		return
	} else if len(ids) > maxIDs {
		jc.Error(ErrTooManyIDs, http.StatusBadRequest)
		return
	}

	txns, err := s.e.V2Transactions(ids)
	if jc.Check("failed to get transactions", err) != nil {
		return
	}
	jc.Encode(txns)
}

func (s *server) addressessAddressUtxosSiacoinHandler(jc jape.Context) {
	var address types.Address
	if jc.DecodeParam("address", &address) != nil {
		return
	}

	limit := defaultLimit
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	outputs, err := s.e.UnspentSiacoinOutputs(address, offset, limit)
	if jc.Check("failed to get unspent siacoin outputs", err) != nil {
		return
	}
	jc.Encode(outputs)
}

func (s *server) addressessAddressUtxosSiafundHandler(jc jape.Context) {
	var address types.Address
	if jc.DecodeParam("address", &address) != nil {
		return
	}

	limit := defaultLimit
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	outputs, err := s.e.UnspentSiafundOutputs(address, offset, limit)
	if jc.Check("failed to get unspent siacoin outputs", err) != nil {
		return
	}
	jc.Encode(outputs)
}

func (s *server) addressessAddressBalanceHandler(jc jape.Context) {
	var address types.Address
	if jc.DecodeParam("address", &address) != nil {
		return
	}

	sc, immatureSC, sf, err := s.e.Balance(address)
	if jc.Check("failed to get balance", err) != nil {
		return
	}

	jc.Encode(AddressBalanceResponse{
		UnspentSiacoins:  sc,
		ImmatureSiacoins: immatureSC,
		UnspentSiafunds:  sf,
	})
}

func (s *server) addressessAddressEventsHandler(jc jape.Context) {
	var address types.Address
	if jc.DecodeParam("address", &address) != nil {
		return
	}

	limit := defaultLimit
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	events, err := s.e.AddressEvents(address, offset, limit)
	if jc.Check("failed to get address events", err) != nil {
		return
	}

	jc.Encode(events)
}

func (s *server) addressessAddressEventsUnconfirmedHandler(jc jape.Context) {
	var address types.Address
	if jc.DecodeParam("address", &address) != nil {
		return
	}

	events, err := s.e.AddressUnconfirmedEvents(address)
	if jc.Check("failed to get unconfirmed address events", err) != nil {
		return
	}

	jc.Encode(events)
}

func (s *server) addressessAddressCheckpointHandler(jc jape.Context) {
	var address types.Address
	if jc.DecodeParam("address", &address) != nil {
		return
	}

	checkpoint, err := s.e.AddressCheckpoint(address)
	if jc.Check("failed to get address checkpoint", err) != nil {
		return
	}
	jc.Encode(checkpoint)
}

func (s *server) eventsIDHandler(jc jape.Context) {
	var id types.Hash256
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	events, err := s.e.Events([]types.Hash256{id})
	if err != nil {
		return
	} else if len(events) > 0 {
		jc.Encode(events[0])
		return
	}

	v1, v2 := s.cm.PoolTransactions(), s.cm.V2PoolTransactions()
	events, err = s.e.UnconfirmedEvents(types.ChainIndex{}, types.CurrentTimestamp(), v1, v2)
	if jc.Check("failed to annotate events", err) != nil {
		return
	}
	for _, event := range events {
		if event.ID == id {
			jc.Encode(event)
			return
		}
	}

	jc.Error(ErrEventNotFound, http.StatusNotFound)
}

func (s *server) outputsSiacoinHandler(jc jape.Context) {
	var id types.SiacoinOutputID
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	outputs, err := s.e.SiacoinElements([]types.SiacoinOutputID{id})
	if jc.Check("failed to get siacoin elements", err) != nil {
		return
	} else if len(outputs) == 0 {
		jc.Error(ErrSiacoinOutputNotFound, http.StatusNotFound)
		return
	}

	jc.Encode(outputs[0])
}

func (s *server) outputsSiafundHandler(jc jape.Context) {
	var id types.SiafundOutputID
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	outputs, err := s.e.SiafundElements([]types.SiafundOutputID{id})
	if jc.Check("failed to get siafund elements", err) != nil {
		return
	} else if len(outputs) == 0 {
		jc.Error(ErrSiafundOutputNotFound, http.StatusNotFound)
		return
	}

	jc.Encode(outputs[0])
}

func (s *server) contractsIDHandler(jc jape.Context) {
	var id types.FileContractID
	if jc.DecodeParam("id", &id) != nil {
		return
	}
	fcs, err := s.e.Contracts([]types.FileContractID{id})
	if jc.Check("failed to get contract", err) != nil {
		return
	} else if len(fcs) == 0 {
		jc.Error(explorer.ErrContractNotFound, http.StatusNotFound)
		return
	}
	jc.Encode(fcs[0])
}

func (s *server) contractsIDRevisionsHandler(jc jape.Context) {
	var id types.FileContractID
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	fcs, err := s.e.ContractRevisions(id)
	if errors.Is(err, explorer.ErrContractNotFound) {
		jc.Error(fmt.Errorf("%w: %v", err, id), http.StatusNotFound)
		return
	} else if jc.Check("failed to fetch contract revisions", err) != nil {
		return
	}
	jc.Encode(fcs)
}

func (s *server) contractsBatchHandler(jc jape.Context) {
	var ids []types.FileContractID
	if jc.Decode(&ids) != nil {
		return
	} else if len(ids) > maxIDs {
		jc.Error(ErrTooManyIDs, http.StatusBadRequest)
		return
	}

	fcs, err := s.e.Contracts(ids)
	if jc.Check("failed to get contracts", err) != nil {
		return
	}
	jc.Encode(fcs)
}

func (s *server) v2ContractsIDHandler(jc jape.Context) {
	var id types.FileContractID
	if jc.DecodeParam("id", &id) != nil {
		return
	}
	fcs, err := s.e.V2Contracts([]types.FileContractID{id})
	if jc.Check("failed to get contract", err) != nil {
		return
	} else if len(fcs) == 0 {
		jc.Error(explorer.ErrContractNotFound, http.StatusNotFound)
		return
	}
	jc.Encode(fcs[0])
}

func (s *server) v2ContractsBatchHandler(jc jape.Context) {
	var ids []types.FileContractID
	if jc.Decode(&ids) != nil {
		return
	} else if len(ids) > maxIDs {
		jc.Error(ErrTooManyIDs, http.StatusBadRequest)
		return
	}

	fcs, err := s.e.V2Contracts(ids)
	if jc.Check("failed to get contracts", err) != nil {
		return
	}
	jc.Encode(fcs)
}

func (s *server) v2ContractsIDRevisionsHandler(jc jape.Context) {
	var id types.FileContractID
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	fcs, err := s.e.V2ContractRevisions(id)
	if errors.Is(err, explorer.ErrContractNotFound) {
		jc.Error(fmt.Errorf("%w: %v", err, id), http.StatusNotFound)
		return
	} else if jc.Check("failed to fetch contract revisions", err) != nil {
		return
	}
	jc.Encode(fcs)
}

func (s *server) v2PubkeyContractsHandler(jc jape.Context) {
	var key types.PublicKey
	if jc.DecodeParam("key", &key) != nil {
		return
	}
	fcs, err := s.e.V2ContractsKey(key)
	if jc.Check("failed to get contracts", err) != nil {
		return
	} else if len(fcs) == 0 {
		jc.Error(explorer.ErrContractNotFound, http.StatusNotFound)
		return
	}
	jc.Encode(fcs)
}

func (s *server) pubkeyContractsHandler(jc jape.Context) {
	var key types.PublicKey
	if jc.DecodeParam("key", &key) != nil {
		return
	}
	fcs, err := s.e.ContractsKey(key)
	if jc.Check("failed to get contracts", err) != nil {
		return
	} else if len(fcs) == 0 {
		jc.Error(explorer.ErrContractNotFound, http.StatusNotFound)
		return
	}
	jc.Encode(fcs)
}

func (s *server) pubkeyHostHandler(jc jape.Context) {
	var key types.PublicKey
	if jc.DecodeParam("key", &key) != nil {
		return
	}
	hosts, err := s.e.Hosts([]types.PublicKey{key})
	if jc.Check("failed to get host", err) != nil {
		return
	} else if len(hosts) == 0 {
		jc.Error(ErrHostNotFound, http.StatusNotFound)
		return
	}
	jc.Encode(hosts[0])
}

func (s *server) pubkeyHostScanHandler(jc jape.Context) {
	if !s.checkAuth(jc) {
		return
	}

	var key types.PublicKey
	if jc.DecodeParam("key", &key) != nil {
		return
	}

	scans, err := s.e.ScanHosts(jc.Request.Context(), key)
	if jc.Check("non host error when attempting to scan hosts", err) != nil {
		return
	} else if len(scans) == 0 {
		jc.Error(ErrHostNotFound, http.StatusNotFound)
		return
	}

	jc.Encode(scans[0])
}

func (s *server) hostsHandler(jc jape.Context) {
	var params explorer.HostQuery
	if jc.Decode(&params) != nil {
		return
	}

	limit := defaultLimit
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	dir := explorer.HostSortAsc
	sortBy := explorer.HostSortDateCreated
	if jc.DecodeForm("dir", &dir) != nil || jc.DecodeForm("sort", &sortBy) != nil {
		return
	}

	hosts, err := s.e.QueryHosts(params, sortBy, dir, offset, limit)
	if errors.Is(err, explorer.ErrNoSortColumn) {
		jc.Error(err, http.StatusBadRequest)
		return
	} else if jc.Check("failed to query hosts", err) != nil {
		return
	}
	jc.Encode(hosts)
}

func (s *server) searchIDHandler(jc jape.Context) {
	var id string
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	result, err := s.e.Search(id)
	if errors.Is(err, explorer.ErrNoSearchResults) {
		jc.Error(err, http.StatusNotFound)
		return
	} else if errors.Is(err, explorer.ErrSearchParse) {
		jc.Error(err, http.StatusBadRequest)
		return
	} else if jc.Check("failed to search ID", err) != nil {
		return
	}
	jc.Encode(result)
}

func (s *server) exchangeRateHandler(jc jape.Context) {
	var currency string
	if jc.DecodeParam("currency", &currency) != nil {
		return
	}
	if currency == "" {
		jc.Error(errors.New("provide a currency value such as USD or EUR"), http.StatusNotFound)
		return
	}

	currency = strings.ToUpper(currency)
	price, err := s.ex.Last(currency)
	if jc.Check("failed to get exchange rate", err) != nil {
		return
	}
	jc.Encode(price)
}

func (s *server) healthHandler(jc jape.Context) {
	if jc.Check("failed to check health", s.e.Health()) != nil {
		return
	}
	jc.Encode(nil)
}

func (s *server) topAddressesSiacoinsHandler(jc jape.Context) {
	limit := defaultLimit
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	topAddresses, err := s.e.TopSiacoinAddresses(int(limit), int(offset))
	if jc.Check("failed to get top siacoin addresses", err) != nil {
		return
	}
	jc.Encode(topAddresses)
}
func (s *server) topAddressesSiafundsHandler(jc jape.Context) {
	limit := defaultLimit
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	topAddresses, err := s.e.TopSiafundAddresses(int(limit), int(offset))
	if jc.Check("failed to get top siacoin addresses", err) != nil {
		return
	}
	jc.Encode(topAddresses)
}

// NewServer returns an HTTP handler that serves the explored API.
func NewServer(e Explorer, cm ChainManager, s Syncer, ex exchangerates.Source, apiPassword string) http.Handler {
	srv := server{
		cm:          cm,
		e:           e,
		s:           s,
		ex:          ex,
		apiPassword: apiPassword,
		startTime:   time.Now().UTC(),
	}

	return jape.Mux(map[string]jape.Handler{
		"GET 	/health":                   srv.healthHandler,
		"GET    /state":                  srv.stateHandler,
		"GET    /syncer/peers":           srv.syncerPeersHandler,
		"POST   /syncer/connect":         srv.syncerConnectHandler,
		"POST   /syncer/broadcast/block": srv.syncerBroadcastBlockHandler,

		"GET    /txpool/transactions": srv.txpoolTransactionsHandler,
		"GET    /txpool/fee":          srv.txpoolFeeHandler,
		"POST   /txpool/broadcast":    srv.txpoolBroadcastHandler,

		"GET	/consensus/network":        srv.consensusNetworkHandler,
		"GET 	/consensus/state":         srv.consensusStateHandler,
		"GET    /consensus/tip":         srv.consensusTipHandler,
		"GET    /consensus/tip/:height": srv.consensusTipHeightHandler,

		"GET    /explorer/tip": srv.explorerTipHandler,

		"GET    /blocks/:id": srv.blocksIDHandler,

		"GET    /transactions/:id":         srv.transactionsIDHandler,
		"POST   /transactions":             srv.transactionsBatchHandler,
		"GET    /transactions/:id/indices": srv.transactionsIDIndicesHandler,

		"GET    /v2/transactions/:id":         srv.v2TransactionsIDHandler,
		"POST   /v2/transactions":             srv.v2TransactionsBatchHandler,
		"GET    /v2/transactions/:id/indices": srv.v2TransactionsIDIndicesHandler,

		"GET    /addresses/:address/utxos/siacoin":      srv.addressessAddressUtxosSiacoinHandler,
		"GET    /addresses/:address/utxos/siafund":      srv.addressessAddressUtxosSiafundHandler,
		"GET    /addresses/:address/events":             srv.addressessAddressEventsHandler,
		"GET    /addresses/:address/events/unconfirmed": srv.addressessAddressEventsUnconfirmedHandler,
		"GET    /addresses/:address/balance":            srv.addressessAddressBalanceHandler,
		"GET /addresses/:address/checkpoint":            srv.addressessAddressCheckpointHandler,

		"GET /top/addresses/siacoins": srv.topAddressesSiacoinsHandler,
		"GET /top/addresses/siafunds": srv.topAddressesSiafundsHandler,

		"GET    /events/:id": srv.eventsIDHandler,

		"GET    /outputs/siacoin/:id": srv.outputsSiacoinHandler,
		"GET    /outputs/siafund/:id": srv.outputsSiafundHandler,

		"GET    /contracts/:id":           srv.contractsIDHandler,
		"GET    /contracts/:id/revisions": srv.contractsIDRevisionsHandler,
		"POST   /contracts":               srv.contractsBatchHandler,

		"GET    /v2/contracts/:id":           srv.v2ContractsIDHandler,
		"GET    /v2/contracts/:id/revisions": srv.v2ContractsIDRevisionsHandler,
		"POST   /v2/contracts":               srv.v2ContractsBatchHandler,

		"GET    /v2/pubkey/:key/contracts": srv.v2PubkeyContractsHandler,

		"GET    /pubkey/:key/contracts": srv.pubkeyContractsHandler,

		"GET    /hosts/:key":      srv.pubkeyHostHandler,
		"POST   /hosts/:key/scan": srv.pubkeyHostScanHandler,

		"GET    /metrics/block":      srv.blocksMetricsHandler,
		"GET    /metrics/block/:id":  srv.blocksMetricsIDHandler,
		"GET    /metrics/host":       srv.hostMetricsHandler,
		"GET    /metrics/blocktime":  srv.blockTimeMetricsHandler,
		"GET    /metrics/difficulty": srv.difficultyMetricsHandler,

		"POST   /hosts": srv.hostsHandler,

		"GET    /search/:id": srv.searchIDHandler,

		"GET    /exchange-rate/siacoin/:currency": srv.exchangeRateHandler,
	})
}
