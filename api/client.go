package api

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
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

// State returns information about the current state of the explored daemon.
func (c *Client) State() (resp StateResponse, err error) {
	err = c.c.GET(context.Background(), "/state", &resp)
	return
}

// TxpoolBroadcast broadcasts a set of transaction to the network.
func (c *Client) TxpoolBroadcast(txns []types.Transaction, v2txns []types.V2Transaction) (err error) {
	err = c.c.POST(context.Background(), "/txpool/broadcast", TxpoolBroadcastRequest{txns, v2txns}, nil)
	return
}

// TxpoolTransactions returns all transactions in the transaction pool.
func (c *Client) TxpoolTransactions() (txns []types.Transaction, v2txns []types.V2Transaction, err error) {
	var resp TxpoolTransactionsResponse
	err = c.c.GET(context.Background(), "/txpool/transactions", &resp)
	return resp.Transactions, resp.V2Transactions, err
}

// TxpoolFee returns the recommended fee (per weight unit) to ensure a high
// probability of inclusion in the next block.
func (c *Client) TxpoolFee() (resp types.Currency, err error) {
	err = c.c.GET(context.Background(), "/txpool/fee", &resp)
	return
}

// SyncerConnect adds the address as a peer of the syncer.
func (c *Client) SyncerConnect(addr string) (err error) {
	err = c.c.POST(context.Background(), "/syncer/connect", addr, nil)
	return
}

// SyncerPeers returns the peers of the syncer.
func (c *Client) SyncerPeers() (resp []string, err error) {
	err = c.c.GET(context.Background(), "/syncer/peers", &resp)
	return
}

// SyncerBroadcastBlock broadcasts a block to all peers.
func (c *Client) SyncerBroadcastBlock(b types.Block) (err error) {
	err = c.c.POST(context.Background(), "/syncer/broadcast/block", b, nil)
	return
}

// ConsensusTip returns the current tip of the chain manager.
func (c *Client) ConsensusTip() (resp types.ChainIndex, err error) {
	err = c.c.GET(context.Background(), "/consensus/tip", &resp)
	return
}

// Tip returns the current tip of the explorer.
func (c *Client) Tip() (resp types.ChainIndex, err error) {
	err = c.c.GET(context.Background(), "/explorer/tip", &resp)
	return
}

// BestIndex returns the chain index at the specified height.
func (c *Client) BestIndex(height uint64) (resp types.ChainIndex, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/consensus/tip/%d", height), &resp)
	return
}

// ConsensusNetwork returns the network parameters of the consensus set.
func (c *Client) ConsensusNetwork() (n *consensus.Network, err error) {
	err = c.c.GET(context.Background(), "/consensus/network", &n)
	return
}

// ConsensusState returns the current state of the consensus set.
func (c *Client) ConsensusState() (state consensus.State, err error) {
	if c.n == nil {
		c.n, err = c.ConsensusNetwork()
		if err != nil {
			return
		}
	}
	err = c.c.GET(context.Background(), "/consensus/state", &state)
	state.Network = c.n
	return
}

// Block returns the block with the specified ID.
func (c *Client) Block(id types.BlockID) (resp explorer.Block, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/blocks/%s", id), &resp)
	return
}

// Transaction returns the transaction with the specified ID.
func (c *Client) Transaction(id types.TransactionID) (resp explorer.Transaction, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/transactions/%s", id), &resp)
	return
}

// Transactions returns the transactions with the specified IDs.
func (c *Client) Transactions(ids []types.TransactionID) (resp []explorer.Transaction, err error) {
	err = c.c.POST(context.Background(), "/transactions", ids, &resp)
	return
}

// TransactionChainIndices returns chain indices a transaction was
// included in.
func (c *Client) TransactionChainIndices(id types.TransactionID, offset, limit uint64) (resp []types.ChainIndex, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/transactions/%s/indices?offset=%d&limit=%d", id, offset, limit), &resp)
	return
}

// V2Transaction returns the v2 transaction with the specified ID.
func (c *Client) V2Transaction(id types.TransactionID) (resp explorer.V2Transaction, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/v2/transactions/%s", id), &resp)
	return
}

// V2Transactions returns the v2 transactions with the specified IDs.
func (c *Client) V2Transactions(ids []types.TransactionID) (resp []explorer.V2Transaction, err error) {
	err = c.c.POST(context.Background(), "/v2/transactions", ids, &resp)
	return
}

// V2TransactionChainIndices returns chain indices a v2 transaction was
// included in.
func (c *Client) V2TransactionChainIndices(id types.TransactionID, offset, limit uint64) (resp []types.ChainIndex, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/v2/transactions/%s/indices?offset=%d&limit=%d", id, offset, limit), &resp)
	return
}

// AddressSiacoinUTXOs returns the specified address' unspent outputs.
func (c *Client) AddressSiacoinUTXOs(address types.Address, offset, limit uint64) (resp []explorer.SiacoinOutput, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/addresses/%s/utxos/siacoin?offset=%d&limit=%d", address, offset, limit), &resp)
	return
}

// AddressSiafundUTXOs returns the specified address' unspent outputs.
func (c *Client) AddressSiafundUTXOs(address types.Address, offset, limit uint64) (resp []explorer.SiafundOutput, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/addresses/%s/utxos/siafund?offset=%d&limit=%d", address, offset, limit), &resp)
	return
}

// OutputSiacoin returns the specified siacoin output.
func (c *Client) OutputSiacoin(id types.SiacoinOutputID) (resp explorer.SiacoinOutput, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/outputs/siacoin/%s", id), &resp)
	return
}

// OutputSiafund returns the specified siafund output.
func (c *Client) OutputSiafund(id types.SiafundOutputID) (resp explorer.SiafundOutput, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/outputs/siafund/%s", id), &resp)
	return
}

// AddressEvents returns the specified address' events.
func (c *Client) AddressEvents(address types.Address, offset, limit uint64) (resp []explorer.Event, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/addresses/%s/events?offset=%d&limit=%d", address, offset, limit), &resp)
	return
}

// AddressUnconfirmedEvents returns the specified address' unconfirmed events.
func (c *Client) AddressUnconfirmedEvents(address types.Address) (resp []explorer.Event, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/addresses/%s/events/unconfirmed", address), &resp)
	return
}

// Event returns the specified event.
func (c *Client) Event(id types.Hash256) (resp explorer.Event, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/events/%s", id), &resp)
	return
}

// AddressBalance returns the specified address' balance.
func (c *Client) AddressBalance(address types.Address) (resp AddressBalanceResponse, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/addresses/%s/balance", address), &resp)
	return
}

// Contract returns the file contract with the specified ID.
func (c *Client) Contract(id types.FileContractID) (resp explorer.ExtendedFileContract, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/contracts/%s", id), &resp)
	return
}

// Contracts returns the contracts with the specified IDs.
func (c *Client) Contracts(ids []types.FileContractID) (resp []explorer.ExtendedFileContract, err error) {
	err = c.c.POST(context.Background(), "/contracts", ids, &resp)
	return
}

// ContractsKey returns the contracts for a particular ed25519 key.
func (c *Client) ContractsKey(key types.PublicKey) (resp []explorer.ExtendedFileContract, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/pubkey/%s/contracts", key), &resp)
	return
}

// ContractRevisions returns all the revisions of the contract with the
// specified ID.
func (c *Client) ContractRevisions(id types.FileContractID) (resp []explorer.ExtendedFileContract, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/contracts/%s/revisions", id), &resp)
	return
}

// V2Contract returns the v2 file contract with the specified ID.
func (c *Client) V2Contract(id types.FileContractID) (resp explorer.V2FileContract, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/v2/contracts/%s", id), &resp)
	return
}

// V2Contracts returns the v2 contracts with the specified IDs.
func (c *Client) V2Contracts(ids []types.FileContractID) (resp []explorer.V2FileContract, err error) {
	err = c.c.POST(context.Background(), "/v2/contracts", ids, &resp)
	return
}

// V2ContractRevisions returns all the revisions of the contract with the
// specified ID.
func (c *Client) V2ContractRevisions(id types.FileContractID) (resp []explorer.V2FileContract, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/v2/contracts/%s/revisions", id), &resp)
	return
}

// V2ContractsKey returns the v2 contracts for a particular ed25519 key.
func (c *Client) V2ContractsKey(key types.PublicKey) (resp []explorer.V2FileContract, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/v2/pubkey/%s/contracts", key), &resp)
	return
}

// Host returns information about the host with a given ed25519 key.
func (c *Client) Host(key types.PublicKey) (resp explorer.Host, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/hosts/%s", key), &resp)
	return
}

// ScanHost triggers a manual host scan.
func (c *Client) ScanHost(key types.PublicKey) (resp explorer.HostScan, err error) {
	err = c.c.POST(context.Background(), fmt.Sprintf("/hosts/%s/scan", key), nil, &resp)
	return
}

// BlockMetrics returns the most recent metrics about the Sia blockchain.
func (c *Client) BlockMetrics() (resp explorer.Metrics, err error) {
	err = c.c.GET(context.Background(), "/metrics/block", &resp)
	return
}

// BlockMetricsID returns various metrics about Sia at the given block ID.
func (c *Client) BlockMetricsID(id types.BlockID) (resp explorer.Metrics, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/metrics/block/%s", id), &resp)
	return
}

// HostMetrics returns various metrics about currently available hosts.
func (c *Client) HostMetrics() (resp explorer.HostMetrics, err error) {
	err = c.c.GET(context.Background(), "/metrics/host", &resp)
	return
}

// BlockTimeMetrics returns the average block time during various intervals.
func (c *Client) BlockTimeMetrics() (resp explorer.BlockTimeMetrics, err error) {
	err = c.c.GET(context.Background(), "/metrics/blocktime", &resp)
	return
}

// Search returns what type of object an ID is.
func (c *Client) Search(id string) (resp explorer.SearchType, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/search/%s", id), &resp)
	return
}

// HostsList searches the hosts by the given criteria.
func (c *Client) HostsList(params explorer.HostQuery, sortBy explorer.HostSortColumn, dir explorer.HostSortDir, offset, limit uint64) (resp []explorer.Host, err error) {
	v := url.Values{}
	v.Add("sort", string(sortBy))
	v.Add("dir", string(dir))
	v.Add("offset", strconv.FormatUint(offset, 10))
	v.Add("limit", strconv.FormatUint(limit, 10))
	err = c.c.POST(context.Background(), "/hosts?"+v.Encode(), params, &resp)
	return
}

// ExchangeRate returns the value of 1 SC in the specified currency.
func (c *Client) ExchangeRate(currency string) (resp float64, err error) {
	err = c.c.GET(context.Background(), fmt.Sprintf("/exchange-rate/siacoin/%s", currency), &resp)
	return
}

// Health checks the health of the explored daemon.
func (c *Client) Health() error {
	return c.c.GET(context.Background(), "/health", nil)
}
