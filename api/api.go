package api

import (
	"time"

	"go.sia.tech/core/types"
)

// A GatewayPeer is a currently-connected peer.
type GatewayPeer struct {
	Addr    string `json:"addr"`
	Inbound bool   `json:"inbound"`
	Version string `json:"version"`

	FirstSeen      time.Time     `json:"firstSeen"`
	ConnectedSince time.Time     `json:"connectedSince"`
	SyncedBlocks   uint64        `json:"syncedBlocks"`
	SyncDuration   time.Duration `json:"syncDuration"`
}

// TxpoolBroadcastRequest is the request type for /txpool/broadcast.
type TxpoolBroadcastRequest struct {
	Transactions   []types.Transaction   `json:"transactions"`
	V2Transactions []types.V2Transaction `json:"v2transactions"`
}

// TxpoolTransactionsResponse is the response type for /txpool/transactions.
type TxpoolTransactionsResponse struct {
	Transactions   []types.Transaction   `json:"transactions"`
	V2Transactions []types.V2Transaction `json:"v2transactions"`
}

// AddressUTXOsResponse is the response for /addresses/:address/utxos.
type AddressUTXOsResponse struct {
	UnspentSiacoinOutputs []types.SiacoinOutput `json:"unspentSiacoinOutputs"`
	UnspentSiafundOutputs []types.SiafundOutput `json:"unspentSiafundOutputs"`
}

// AddressBalanceResponse is the response for /addresses/:address/balance.
type AddressBalanceResponse struct {
	UnspentSiacoins types.Currency `json:"unspentSiacoins"`
	UnspentSiafunds uint64         `json:"unspentSiafunds"`
}
