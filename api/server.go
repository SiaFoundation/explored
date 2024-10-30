package api

import (
	"context"
	"encoding/hex"
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
		BroadcastHeader(bh gateway.BlockHeader)
		BroadcastTransactionSet(txns []types.Transaction)
		BroadcastV2TransactionSet(index types.ChainIndex, txns []types.V2Transaction)
		BroadcastV2BlockOutline(bo gateway.V2BlockOutline)
	}

	// Explorer implements a Sia explorer.
	Explorer interface {
		Tip() (types.ChainIndex, error)
		Block(id types.BlockID) (explorer.Block, error)
		BestTip(height uint64) (types.ChainIndex, error)
		Metrics(id types.BlockID) (explorer.Metrics, error)
		HostMetrics() (explorer.HostMetrics, error)
		Transactions(ids []types.TransactionID) ([]explorer.Transaction, error)
		TransactionChainIndices(id types.TransactionID, offset, limit uint64) ([]types.ChainIndex, error)
		V2Transactions(ids []types.TransactionID) ([]explorer.V2Transaction, error)
		V2TransactionChainIndices(id types.TransactionID, offset, limit uint64) ([]types.ChainIndex, error)
		Balance(address types.Address) (sc types.Currency, immatureSC types.Currency, sf uint64, err error)
		SiacoinElements(ids []types.SiacoinOutputID) (result []explorer.SiacoinOutput, err error)
		SiafundElements(ids []types.SiafundOutputID) (result []explorer.SiafundOutput, err error)
		UnspentSiacoinOutputs(address types.Address, offset, limit uint64) ([]explorer.SiacoinOutput, error)
		UnspentSiafundOutputs(address types.Address, offset, limit uint64) ([]explorer.SiafundOutput, error)
		AddressEvents(address types.Address, offset, limit uint64) (events []explorer.Event, err error)
		Contracts(ids []types.FileContractID) (result []explorer.FileContract, err error)
		ContractsKey(key types.PublicKey) (result []explorer.FileContract, err error)
		ContractRevisions(id types.FileContractID) (result []explorer.FileContract, err error)
		Search(id types.Hash256) (explorer.SearchType, error)

		Hosts(pks []types.PublicKey) ([]explorer.Host, error)
	}
)

const (
	maxIDs = 5000
)

var (
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

	// ErrNoSearchResults is returned by /search/:id when we do not find any
	// elements with that ID.
	ErrNoSearchResults = errors.New("no search results found")

	// ErrTooManyIDs is returned by the batch transaction and contract
	// endpoints when more than maxIDs IDs are specified.
	ErrTooManyIDs = fmt.Errorf("too many IDs provided (provide less than %d)", maxIDs)
)

type server struct {
	cm ChainManager
	e  Explorer
	s  Syncer

	startTime time.Time
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
	}
	if b.V2 == nil {
		s.s.BroadcastHeader(gateway.BlockHeader{
			ParentID:   b.ParentID,
			Nonce:      b.Nonce,
			Timestamp:  b.Timestamp,
			MerkleRoot: b.MerkleRoot(),
		})
	} else {
		s.s.BroadcastV2BlockOutline(gateway.OutlineBlock(b, s.cm.PoolTransactions(), s.cm.V2PoolTransactions()))
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
		_, err := s.cm.AddPoolTransactions(tbr.Transactions)
		if jc.Check("invalid transaction set", err) != nil {
			return
		}
		s.s.BroadcastTransactionSet(tbr.Transactions)
	}
	if len(tbr.V2Transactions) != 0 {
		_, err := s.cm.AddV2PoolTransactions(tip, tbr.V2Transactions)
		if jc.Check("invalid v2 transaction set", err) != nil {
			return
		}
		s.s.BroadcastV2TransactionSet(tip, tbr.V2Transactions)
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

func (s *server) blocksIDHandler(jc jape.Context) {
	var id types.BlockID
	if jc.DecodeParam("id", &id) != nil {
		return
	}
	block, err := s.e.Block(id)
	if jc.Check("failed to get block", err) != nil {
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
	} else if len(txns) == 0 {
		jc.Error(ErrTransactionNotFound, http.StatusNotFound)
		return
	}
	jc.Encode(txns[0])
}

func (s *server) transactionsIDIndicesHandler(jc jape.Context) {
	var id types.TransactionID
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	limit := uint64(100)
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}

	if limit > 500 {
		limit = 500
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
	} else if len(txns) == 0 {
		jc.Error(ErrTransactionNotFound, http.StatusNotFound)
		return
	}
	jc.Encode(txns[0])
}

func (s *server) v2TransactionsIDIndicesHandler(jc jape.Context) {
	var id types.TransactionID
	if jc.DecodeParam("id", &id) != nil {
		return
	}

	limit := uint64(100)
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}

	if limit > 500 {
		limit = 500
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

	limit := uint64(100)
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
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

	limit := uint64(100)
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
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

	limit := uint64(100)
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}

	events, err := s.e.AddressEvents(address, offset, limit)
	if jc.Check("failed to get address events", err) != nil {
		return
	}

	jc.Encode(events)
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

func (s *server) searchIDHandler(jc jape.Context) {
	const maxLen = len(types.Hash256{})

	// get everything after separator if there is one
	split := strings.Split(jc.PathParam("id"), ":")
	id, err := hex.DecodeString(split[len(split)-1])
	if jc.Check("failed to decode hex", err) != nil {
		return
	}

	trunc := id[:maxLen]
	result, err := s.e.Search(types.Hash256(trunc))
	if jc.Check("failed to search ID", err) != nil {
		return
	} else if result == explorer.SearchTypeInvalid {
		jc.Error(ErrNoSearchResults, http.StatusNotFound)
		return
	}
	jc.Encode(result)
}

// NewServer returns an HTTP handler that serves the explored API.
func NewServer(e Explorer, cm ChainManager, s Syncer) http.Handler {
	srv := server{
		cm:        cm,
		e:         e,
		s:         s,
		startTime: time.Now().UTC(),
	}
	return jape.Mux(map[string]jape.Handler{
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

		"GET    /addresses/:address/utxos/siacoin": srv.addressessAddressUtxosSiacoinHandler,
		"GET    /addresses/:address/utxos/siafund": srv.addressessAddressUtxosSiafundHandler,
		"GET    /addresses/:address/events":        srv.addressessAddressEventsHandler,
		"GET    /addresses/:address/balance":       srv.addressessAddressBalanceHandler,

		"GET    /outputs/siacoin/:id": srv.outputsSiacoinHandler,
		"GET    /outputs/siafund/:id": srv.outputsSiafundHandler,

		"GET    /contracts/:id":           srv.contractsIDHandler,
		"GET    /contracts/:id/revisions": srv.contractsIDRevisionsHandler,
		"POST   /contracts":               srv.contractsBatchHandler,

		"GET    /pubkey/:key/contracts": srv.pubkeyContractsHandler,
		"GET    /pubkey/:key/host":      srv.pubkeyHostHandler,

		"GET    /metrics/block":     srv.blocksMetricsHandler,
		"GET    /metrics/block/:id": srv.blocksMetricsIDHandler,
		"GET    /metrics/host":      srv.hostMetricsHandler,

		"GET    /search/:id": srv.searchIDHandler,
	})
}
