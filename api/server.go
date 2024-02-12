package api

import (
	"errors"
	"fmt"
	"net/http"

	"go.sia.tech/jape"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/gateway"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/syncer"
	"go.sia.tech/explored/explorer"
)

type (
	// A ChainManager manages blockchain and txpool state.
	ChainManager interface {
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
		Connect(addr string) (*syncer.Peer, error)
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
		Transactions(ids []types.TransactionID) ([]explorer.Transaction, error)
		Balance(address types.Address) (sc types.Currency, sf uint64, err error)
		UnspentSiacoinOutputs(address types.Address, limit, offset uint64) ([]explorer.SiacoinOutput, error)
		UnspentSiafundOutputs(address types.Address, limit, offset uint64) ([]explorer.SiafundOutput, error)
	}
)

type server struct {
	cm ChainManager
	e  Explorer
	s  Syncer
}

func (s *server) syncerConnectHandler(jc jape.Context) {
	var addr string
	if jc.Decode(&addr) != nil {
		return
	}
	_, err := s.s.Connect(addr)
	jc.Check("couldn't connect to peer", err)
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

func (s *server) explorerTipHandler(jc jape.Context) {
	tip, err := s.e.Tip()
	if jc.Check("failed to get tip", err) != nil {
		return
	}
	jc.Encode(tip)
}

func (s *server) explorerTipHeightHandler(jc jape.Context) {
	var height uint64
	if jc.DecodeParam("height", &height) != nil {
		return
	}
	tip, err := s.e.BestTip(height)
	if jc.Check("failed to get block", err) != nil {
		return
	}
	jc.Encode(tip)
}

func (s *server) explorerBlockHandler(jc jape.Context) {
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

func (s *server) explorerTransactionsIDHandler(jc jape.Context) {
	errNotFound := errors.New("no transaction found")

	var id types.TransactionID
	if jc.DecodeParam("id", &id) != nil {
		return
	}
	txns, err := s.e.Transactions([]types.TransactionID{id})
	if jc.Check("failed to get transaction", err) != nil {
		return
	} else if len(txns) == 0 {
		jc.Error(errNotFound, http.StatusNotFound)
		return
	}
	jc.Encode(txns[0])
}

func (s *server) explorerTransactionsHandler(jc jape.Context) {
	const (
		maxIDs = 5000
	)
	errTooManyIDs := fmt.Errorf("too many IDs provided (provide less than %d)", maxIDs)

	var ids []types.TransactionID
	if jc.Decode(&ids) != nil {
		return
	} else if len(ids) > maxIDs {
		jc.Error(errTooManyIDs, http.StatusBadRequest)
		return
	}

	txns, err := s.e.Transactions(ids)
	if jc.Check("failed to get transactions", err) != nil {
		return
	}
	jc.Encode(txns)
}

func (s *server) explorerAddressessAddressUtxosHandler(jc jape.Context) {
	var address types.Address
	if jc.DecodeParam("address", &address) != nil {
		return
	}

	limit := uint64(100)
	offset := uint64(0)
	if jc.DecodeForm("limit", &limit) != nil || jc.DecodeForm("offset", &offset) != nil {
		return
	}

	unspentSiacoinOutputs, err := s.e.UnspentSiacoinOutputs(address, limit, offset)
	if jc.Check("failed to get unspent siacoin outputs", err) != nil {
		return
	}
	unspentSiafundOutputs, err := s.e.UnspentSiafundOutputs(address, limit, offset)
	if jc.Check("failed to get unspent siafund outputs", err) != nil {
		return
	}

	jc.Encode(AddressUTXOsResponse{
		UnspentSiacoinOutputs: unspentSiacoinOutputs,
		UnspentSiafundOutputs: unspentSiafundOutputs,
	})
}

func (s *server) explorerAddressessAddressBalanceHandler(jc jape.Context) {
	var address types.Address
	if jc.DecodeParam("address", &address) != nil {
		return
	}

	sc, sf, err := s.e.Balance(address)
	if jc.Check("failed to get balance", err) != nil {
		return
	}

	jc.Encode(AddressBalanceResponse{
		UnspentSiacoins: sc,
		UnspentSiafunds: sf,
	})
}

// NewServer returns an HTTP handler that serves the explored API.
func NewServer(e Explorer, cm ChainManager, s Syncer) http.Handler {
	srv := server{
		cm: cm,
		e:  e,
		s:  s,
	}
	return jape.Mux(map[string]jape.Handler{
		"POST   /syncer/connect":         srv.syncerConnectHandler,
		"POST   /syncer/broadcast/block": srv.syncerBroadcastBlockHandler,

		"GET    /txpool/transactions": srv.txpoolTransactionsHandler,
		"GET    /txpool/fee":          srv.txpoolFeeHandler,
		"POST   /txpool/broadcast":    srv.txpoolBroadcastHandler,

		"GET    /explorer/tip":                        srv.explorerTipHandler,
		"GET    /explorer/tip/:height":                srv.explorerTipHeightHandler,
		"GET    /explorer/block/:id":                  srv.explorerBlockHandler,
		"GET    /explorer/transactions/:id":           srv.explorerTransactionsIDHandler,
		"POST   /explorer/transactions":               srv.explorerTransactionsHandler,
		"GET    /explorer/addresses/:address/utxos":   srv.explorerAddressessAddressUtxosHandler,
		"GET    /explorer/addresses/:address/balance": srv.explorerAddressessAddressBalanceHandler,
	})
}
