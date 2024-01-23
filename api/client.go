package api

import (
	"fmt"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
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

// SyncerPeers returns the current peers of the syncer.
func (c *Client) SyncerPeers() (resp []GatewayPeer, err error) {
	err = c.c.GET("/syncer/peers", &resp)
	return
}

// SyncerConnect adds the address as a peer of the syncer.
func (c *Client) SyncerConnect(addr string) (err error) {
	err = c.c.POST("/syncer/connect", addr, nil)
	return
}

// SyncerBroadcastBlock broadcasts a block to all peers.
func (c *Client) SyncerBroadcastBlock(b types.Block) (err error) {
	err = c.c.POST("/syncer/broadcast/block", b, nil)
	return
}

// Tip returns the current tip of the explorer.
func (c *Client) Tip() (resp types.ChainIndex, err error) {
	err = c.c.GET("/explorer/tip", &resp)
	return
}

// BestTip returns the chain index at the specified height.
func (c *Client) BestTip(height uint64) (resp types.ChainIndex, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/tip/%d", height), &resp)
	return
}

// Block returns the block with the specified ID.
func (c *Client) Block(id types.BlockID) (resp types.Block, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/block/%s", id), &resp)
	return
}

// Transaction returns the transaction with the specified ID.
func (c *Client) Transaction(id types.TransactionID) (resp types.Transaction, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/transactions/%s", id), &resp)
	return
}

// Transactions returns the transactions with the specified IDs.
func (c *Client) Transactions(ids []types.TransactionID) (resp []types.Transaction, err error) {
	err = c.c.POST("/explorer/transactions", ids, &resp)
	return
}

// AddressUTXOs returns the specified address' unspent outputs.
func (c *Client) AddressUTXOs(address types.Address) (resp AddressUTXOsResponse, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/addresses/%s/utxos", address), &resp)
	return
}

// AddressBalance returns the specified address' balance.
func (c *Client) AddressBalance(address types.Address) (resp AddressBalanceResponse, err error) {
	err = c.c.GET(fmt.Sprintf("/explorer/addresses/%s/balance", address), &resp)
	return
}
