package explorer_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/explored/config"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestChainMigration(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	n, genesis := ctestutil.Network()
	store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), n, genesis, chain.NewZapMigrationLogger(zap.NewNop()))
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)

	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	b := testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)
	cs, au := consensus.ApplyBlock(cm.TipState(), b, consensus.V1BlockSupplement{}, time.Time{})

	// add block to explorer store independent of chain manager
	err = db.UpdateChainState(nil, []chain.ApplyUpdate{{
		ApplyUpdate: au,
		State:       cs,
		Block:       b,
	}})
	if err != nil {
		t.Fatal(err)
	}

	explorerTip, err := db.Tip()
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "explorer tip", cs.Index, explorerTip)
	testutil.Equal(t, "cm tip", genesisState.Index, cm.Tip())

	e, err := explorer.NewExplorer(cm, db, config.Index{BatchSize: 1000}, config.Scanner{}, log)
	if err != nil {
		t.Fatal(err)
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer timeoutCancel()
	defer e.Shutdown(timeoutCtx)

	time.Sleep(1 * time.Second)

	// the fact that the explorer has a block not contained in the chain
	// manager's store should cause us to reset the state and reindex from
	// scratch

	explorerTip, err = db.Tip()
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "explorer tip", cm.Tip(), explorerTip)
	testutil.Equal(t, "cm tip", genesisState.Index, cm.Tip())

	// check that data is indexed in DB
	for _, expected := range genesis.Transactions {
		txns, err := db.Transactions([]types.TransactionID{expected.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 1, len(txns))
		testutil.CheckTransaction(t, expected, txns[0])
	}
}
