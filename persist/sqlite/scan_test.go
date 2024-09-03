package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/config"
	"go.sia.tech/explored/explorer"
	"go.uber.org/zap/zaptest"
)

func testV1Network(giftAddr types.Address, sc types.Currency, sf uint64) (*consensus.Network, types.Block) {
	// use a modified version of Zen
	n, genesisBlock := chain.TestnetZen()
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkDevAddr.Height = 1
	n.HardforkTax.Height = 1
	n.HardforkStorageProof.Height = 1
	n.HardforkOak.Height = 1
	n.HardforkASIC.Height = 1
	n.HardforkFoundation.Height = 1
	n.HardforkV2.AllowHeight = 1000
	n.HardforkV2.RequireHeight = 1000
	genesisBlock.Transactions = []types.Transaction{{}}
	if sf > 0 {
		genesisBlock.Transactions[0].SiafundOutputs = []types.SiafundOutput{{
			Address: giftAddr,
			Value:   sf,
		}}
	}
	if sc.Cmp(types.ZeroCurrency) == 1 {
		genesisBlock.Transactions[0].SiacoinOutputs = []types.SiacoinOutput{{
			Address: giftAddr,
			Value:   sc,
		}}
	}
	return n, genesisBlock
}

func mineBlock(state consensus.State, txns []types.Transaction, minerAddr types.Address) types.Block {
	b := types.Block{
		ParentID:     state.Index.ID,
		Timestamp:    types.CurrentTimestamp(),
		Transactions: txns,
		MinerPayouts: []types.SiacoinOutput{{Address: minerAddr, Value: state.BlockReward()}},
	}
	for b.ID().CmpWork(state.ChildTarget) < 0 {
		b.Nonce += state.NonceFactor()
	}
	return b
}

func mineV2Block(state consensus.State, txns []types.V2Transaction, minerAddr types.Address) types.Block {
	b := types.Block{
		ParentID:     state.Index.ID,
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: minerAddr, Value: state.BlockReward()}},

		V2: &types.V2BlockData{
			Transactions: txns,
			Height:       state.Index.Height + 1,
		},
	}
	b.V2.Commitment = state.Commitment(state.TransactionsCommitment(b.Transactions, b.V2Transactions()), b.MinerPayouts[0].Address)
	for b.ID().CmpWork(state.ChildTarget) < 0 {
		b.Nonce += state.NonceFactor()
	}
	return b
}

func signTxn(cs consensus.State, pk types.PrivateKey, txn *types.Transaction) {
	appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
		sig := key.SignHash(cs.WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{
			ParentID:       parentID,
			CoveredFields:  types.CoveredFields{WholeTransaction: true},
			PublicKeyIndex: pubkeyIndex,
			Signature:      sig[:],
		})
	}
	for i := range txn.SiacoinInputs {
		appendSig(pk, 0, types.Hash256(txn.SiacoinInputs[i].ParentID))
	}
	for i := range txn.SiafundInputs {
		appendSig(pk, 0, types.Hash256(txn.SiafundInputs[i].ParentID))
	}
}

func syncDB(t *testing.T, db *Store, cm *chain.Manager) {
	index, err := db.Tip()
	if err != nil && !errors.Is(err, explorer.ErrNoTip) {
		t.Fatal(err)
	}

	for index != cm.Tip() {
		crus, caus, err := cm.UpdatesSince(index, 1000)
		if err != nil {
			t.Fatal(err)
		}

		if err := db.UpdateChainState(crus, caus); err != nil {
			t.Fatal("failed to process updates:", err)
		}
		if len(crus) > 0 {
			index = crus[len(crus)-1].State.Index
		}
		if len(caus) > 0 {
			index = caus[len(caus)-1].State.Index
		}
	}
}

func check[T any](t *testing.T, desc string, expect, got T) {
	if !reflect.DeepEqual(expect, got) {
		t.Fatalf("expected %v %s, got %v", expect, desc, got)
	}
}

func TestScan(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV1Network(types.VoidAddress, types.ZeroCurrency, 0)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	cfg := config.Scanner{
		Threads:     10,
		Timeout:     30 * time.Second,
		MaxLastScan: 3 * time.Hour,
	}

	e, err := explorer.NewExplorer(cm, db, 1000, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer timeoutCancel()
	defer e.Shutdown(timeoutCtx)

	var pubkey1 types.PublicKey
	if err := pubkey1.UnmarshalText([]byte(`ed25519:a90d3c26a22d66903c06a1bf869e14e829e95cfa25b6bf08189c98713fc92449`)); err != nil {
		t.Fatal(err)
	}
	pubkey2 := types.GeneratePrivateKey().PublicKey()
	hosts := []explorer.Host{
		{
			PublicKey:  pubkey1,
			NetAddress: "sia1.siahost.ca:9982",
		},
		{
			PublicKey:  pubkey2,
			NetAddress: "example.com:9982",
		},
	}

	if err := db.transaction(func(tx *txn) error {
		return addHosts(tx, hosts)
	}); err != nil {
		t.Fatal(err)
	}

	// explorer won't start scanning till a recent block is mined
	b := mineBlock(genesisState, nil, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(3 * cfg.Timeout)

	dbHosts, err := e.Hosts([]types.PublicKey{pubkey1, pubkey2})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "len(dbHosts)", 2, len(dbHosts))

	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].NetAddress < hosts[j].NetAddress
	})
	sort.Slice(dbHosts, func(i, j int) bool {
		return dbHosts[i].NetAddress < dbHosts[j].NetAddress
	})
	host1 := dbHosts[0]
	check(t, "host1.NetAddress", hosts[0].NetAddress, host1.NetAddress)
	check(t, "host1.PublicKey", hosts[0].PublicKey, host1.PublicKey)
	check(t, "host1.TotalScans", 1, host1.TotalScans)
	check(t, "host1.SuccessfulInteractions", 0, host1.SuccessfulInteractions)
	check(t, "host1.FailedInteractions", 1, host1.FailedInteractions)
	check(t, "host1.LastScanSuccessful", false, host1.LastScanSuccessful)

	host2 := dbHosts[1]
	check(t, "host2.NetAddress", hosts[1].NetAddress, host2.NetAddress)
	check(t, "host2.PublicKey", hosts[1].PublicKey, host2.PublicKey)
	check(t, "host2.TotalScans", 1, host2.TotalScans)
	check(t, "host2.SuccessfulInteractions", 1, host2.SuccessfulInteractions)
	check(t, "host2.FailedInteractions", 0, host2.FailedInteractions)
	check(t, "host2.LastScanSuccessful", true, host2.LastScanSuccessful)
}
