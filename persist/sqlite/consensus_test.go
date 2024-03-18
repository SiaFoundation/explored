package sqlite_test

import (
	"path/filepath"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap/zaptest"
)

func testV1Network() (*consensus.Network, types.Block) {
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
	return n, genesisBlock
}

func testV2Network() (*consensus.Network, types.Block) {
	// use a modified version of Zen
	n, genesisBlock := chain.TestnetZen()
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkDevAddr.Height = 1
	n.HardforkTax.Height = 1
	n.HardforkStorageProof.Height = 1
	n.HardforkOak.Height = 1
	n.HardforkASIC.Height = 1
	n.HardforkFoundation.Height = 1
	n.HardforkV2.AllowHeight = 100
	n.HardforkV2.RequireHeight = 110
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

func TestBalance(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := testV1Network()

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cm := chain.NewManager(store, genesisState)

	if err := cm.AddSubscriber(db, types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	checkBalance := func(addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
		sc, immatureSC, sf, err := db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		} else if sc != expectSC {
			t.Fatalf("expected %v siacoins, got %v", expectSC, sc)
		} else if immatureSC != expectImmatureSC {
			t.Fatalf("expected %v immature siacoins, got %v", expectImmatureSC, immatureSC)
		} else if sf != expectSF {
			t.Fatalf("expected %d siafunds, got %d", expectSF, sf)
		}
	}

	pk := types.GeneratePrivateKey()
	addr := types.StandardUnlockHash(pk.PublicKey())

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight() + 1

	// mine a block sending the payout to the wallet
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr)}); err != nil {
		t.Fatal(err)
	}

	utxos, err := db.UnspentSiacoinOutputs(addr, 100, 0)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 utxo, got %d", len(utxos))
	} else if utxos[0].SiacoinOutput.Value != expectedPayout {
		t.Fatalf("expected value %v, got %v", expectedPayout, utxos[0].SiacoinOutput.Value)
	}

	// mine until the payout matures
	for i := cm.TipState().Index.Height; i < maturityHeight; i++ {
		checkBalance(addr, types.ZeroCurrency, expectedPayout, 0)
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
	}

	checkBalance(addr, expectedPayout, types.ZeroCurrency, 0)
}
