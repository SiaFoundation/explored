package api

import (
	"fmt"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/syncer"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/jape"
)

// A Client provides methods for interacting with a explored API server.
type Client struct {
	c jape.Client
	n *consensus.Network // for ConsensusTipState
}

// NewClient returns a client that communicates with a explored server listening
// on the specified address.
func NewClient(addr, password string) *Client {
	return &Client{c: jape.Client{
		BaseURL:  addr,
		Password: password,
	}}
}

// TxpoolBroadcast broadcasts a set of transaction to the network.
func (c *Client) TxpoolBroadcast(txns []types.Transaction, v2txns []types.V2Transaction) (err error) {
	err = c.c.POST("/txpool/broadcast", TxpoolBroadcastRequest{txns, v2txns}, nil)
	return
}

// TxpoolTransactions returns all transactions in the transaction pool.
func (c *Client) TxpoolTransactions() (txns []types.Transaction, v2txns []types.V2Transaction, err error) {
	var resp TxpoolTransactionsResponse
	err = c.c.GET("/txpool/transactions", &resp)
	return resp.Transactions, resp.V2Transactions, err
}

// TxpoolFee returns the recommended fee (per weight unit) to ensure a high
// probability of inclusion in the next block.
func (c *Client) TxpoolFee() (resp types.Currency, err error) {
	err = c.c.GET("/txpool/fee", &resp)
	return
}

// SyncerConnect adds the address as a peer of the syncer.
func (c *Client) SyncerConnect(addr string) (err error) {
	err = c.c.POST("/syncer/connect", addr, nil)
	return
}

// SyncerPeers returns the peers of the syncer.
func (c *Client) SyncerPeers() (resp []*syncer.Peer, err error) {
	err = c.c.GET("/syncer/peers", &resp)
	return
}

// SyncerBroadcastBlock broadcasts a block to all peers.
func (c *Client) SyncerBroadcastBlock(b types.Block) (err error) {
	err = c.c.POST("/syncer/broadcast/block", b, nil)
	return
}

// Tip returns the current tip of the explorer.
func (c *Client) Tip() (resp types.ChainIndex, err error) {
	err = c.c.GET("/consensus/tip", &resp)
	return
}

// BestIndex returns the chain index at the specified height.
func (c *Client) BestIndex(height uint64) (resp types.ChainIndex, err error) {
	err = c.c.GET(fmt.Sprintf("/consensus/tip/%d", height), &resp)
	return
}

// ConsensusNetwork returns the network parameters of the consensus set.
func (c *Client) ConsensusNetwork() (n *consensus.Network, err error) {
	err = c.c.GET("/consensus/network", &n)
	return
}

func (c *Client) ConsensusState() (state consensus.State, err error) {
	if c.n == nil {
		c.n, err = c.ConsensusNetwork()
		if err != nil {
			return
		}
	}
	err = c.c.GET("/consensus/state", &state)
	state.Network = c.n
	return
}

// Block returns the block with the specified ID.
func (c *Client) Block(id types.BlockID) (resp explorer.Block, err error) {
	err = c.c.GET(fmt.Sprintf("/blocks/%s", id), &resp)
	return
}

// Transaction returns the transaction with the specified ID.
func (c *Client) Transaction(id types.TransactionID) (resp explorer.Transaction, err error) {
	err = c.c.GET(fmt.Sprintf("/transactions/%s", id), &resp)
	return
}

// Transactions returns the transactions with the specified IDs.
func (c *Client) Transactions(ids []types.TransactionID) (resp []explorer.Transaction, err error) {
	err = c.c.POST("/explorer/transactions", ids, &resp)
	return
}

// AddressSiacoinUTXOs returns the specified address' unspent outputs.
func (c *Client) AddressSiacoinUTXOs(address types.Address, offset, limit uint64) (resp []explorer.SiacoinOutput, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/addresses/%s/utxos/siacoin?offset=%d&limit=%d", address, offset, limit), &resp)
	return
}

// AddressSiafundUTXOs returns the specified address' unspent outputs.
func (c *Client) AddressSiafundUTXOs(address types.Address, offset, limit uint64) (resp []explorer.SiafundOutput, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/addresses/%s/utxos/siafund?offset=%d&limit=%d", address, offset, limit), &resp)
	return
}

// AddressEvents returns the specified address' events.
func (c *Client) AddressEvents(address types.Address, offset, limit uint64) (resp []explorer.Event, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/addresses/%s/events?offset=%d&limit=%d", address, offset, limit), &resp)
	return
}

// AddressBalance returns the specified address' balance.
func (c *Client) AddressBalance(address types.Address) (resp AddressBalanceResponse, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/addresses/%s/balance", address), &resp)
	return
}

// Contract returns the file contract with the specified ID.
func (c *Client) Contract(id types.FileContractID) (resp explorer.FileContract, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/contracts/%s", id), &resp)
	return
}

// Contracts returns the transactions with the specified IDs.
func (c *Client) Contracts(ids []types.FileContractID) (resp []explorer.FileContract, err error) {
	err = c.c.POST("/explorer/contracts", ids, &resp)
	return
}

// ContractsKey returns the contracts for a particular ed25519 key.
func (c *Client) ContractsKey(key types.PublicKey) (resp []explorer.FileContract, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/pubkey/%s/contracts", key), &resp)
	return
}

// BlockMetrics returns the most recent metrics about the Sia blockchain.
func (c *Client) BlockMetrics() (resp explorer.Metrics, err error) {
	err = c.c.GET("/metrics/block", &resp)
	return
}

// BlockMetricsID returns various metrics about Sia at the given block ID.
func (c *Client) BlockMetricsID(id types.BlockID) (resp explorer.Metrics, err error) {
	err = c.c.GET(fmt.Sprintf("/metrics/block/%s", id), &resp)
	return
}

// Search returns what type of object an ID is.
func (c *Client) Search(id types.Hash256) (resp explorer.SearchType, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/search/%s", id), &resp)
	return
}
