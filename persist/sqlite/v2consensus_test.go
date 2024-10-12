package sqlite_test

import (
	"path/filepath"
	"testing"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/explored/internal/testutil"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap/zaptest"
)

func TestV2ArbitraryData(t *testing.T) {
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

	network, genesisBlock := ctestutil.V2Network()
	network.HardforkV2.AllowHeight = 1
	network.HardforkV2.RequireHeight = 2

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
	}

	txn2 := types.V2Transaction{
		ArbitraryData: []byte("world"),
	}

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1, txn2}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)
	prev := cm.Tip()

	{
		b, err := db.Block(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "v2 height", b.V2.Height, 1)
		testutil.CheckV2Transaction(t, txn1, b.V2.Transactions[0])
		testutil.CheckV2Transaction(t, txn2, b.V2.Transactions[1])
	}

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
		testutil.CheckV2Transaction(t, txn2, dbTxns[1])
	}

	txn3 := types.V2Transaction{
		ArbitraryData: []byte("12345"),
	}

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1, txn2, txn3}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		b, err := db.Block(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "v2 height", b.V2.Height, 2)
		testutil.CheckV2Transaction(t, txn1, b.V2.Transactions[0])
		testutil.CheckV2Transaction(t, txn2, b.V2.Transactions[1])
		testutil.CheckV2Transaction(t, txn3, b.V2.Transactions[2])
	}

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID(), txn3.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
		testutil.CheckV2Transaction(t, txn2, dbTxns[1])
		testutil.CheckV2Transaction(t, txn3, dbTxns[2])
	}

	testutil.CheckV2ChainIndices(t, db, txn1.ID(), []types.ChainIndex{cm.Tip(), prev})
	testutil.CheckV2ChainIndices(t, db, txn2.ID(), []types.ChainIndex{cm.Tip(), prev})
	testutil.CheckV2ChainIndices(t, db, txn3.ID(), []types.ChainIndex{cm.Tip()})
}
