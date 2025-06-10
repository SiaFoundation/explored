package explorer_test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/gateway"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	rhp4 "go.sia.tech/coreutils/rhp/v4"
	"go.sia.tech/coreutils/rhp/v4/siamux"
	"go.sia.tech/coreutils/syncer"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/config"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func waitForSync(t testing.TB, cm *chain.Manager, e *explorer.Explorer) {
	t.Helper()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.Context().Done():
			return
		case <-ticker.C:
			syncedTip, err := e.Tip()
			if err != nil {
				t.Fatal(err)
			} else if syncedTip == cm.Tip() {
				return
			}
		}
	}
}

func testV2Host(tb testing.TB, cm *chain.Manager) rhp4.TransportClient {
	hostKey := types.GeneratePrivateKey()
	w, err := wallet.NewSingleAddressWallet(hostKey, cm, ctestutil.NewEphemeralWalletStore(), ctestutil.MockSyncer{})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { w.Close() })

	syncerListener, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { syncerListener.Close() })

	s := syncer.New(syncerListener, cm, ctestutil.NewEphemeralPeerStore(), gateway.Header{
		UniqueID: gateway.GenerateUniqueID(),
	})
	go s.Run()
	tb.Cleanup(func() { s.Close() })

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { l.Close() })

	rs := rhp4.NewServer(hostKey, cm, s, ctestutil.NewEphemeralContractor(cm), w, ctestutil.NewEphemeralSettingsReporter(), ctestutil.NewEphemeralSectorStore())
	go siamux.Serve(l, rs, zap.NewNop())

	// announce so the host is discoverable
	// by the explorer
	cs := cm.TipState()
	txn := types.V2Transaction{
		Attestations: []types.Attestation{
			chain.V2HostAnnouncement{
				{
					Protocol: siamux.Protocol,
					Address:  l.Addr().String(),
				},
			}.ToAttestation(cs, hostKey),
		},
	}
	if _, err := cm.AddV2PoolTransactions(cs.Index, []types.V2Transaction{txn}); err != nil {
		tb.Fatal(err)
	}
	ctestutil.MineBlocks(tb, cm, types.VoidAddress, 1)

	transport, err := siamux.Dial(context.Background(), l.Addr().String(), hostKey.PublicKey())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { transport.Close() })

	return transport
}

func TestHealth(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	n, genesis := ctestutil.V2Network()
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

	e, err := explorer.NewExplorer(cm, db, config.Index{BatchSize: 1000}, config.Scanner{NumThreads: 1, ScanTimeout: 10 * time.Second, ScanFrequency: 100 * time.Millisecond, ScanInterval: time.Second, MinLastAnnouncement: 24 * time.Hour}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown(context.Background())

	time.Sleep(time.Second)

	if err := e.Health(); !errors.Is(err, explorer.ErrNotSyncing) {
		t.Fatalf("expected error %q, got %q", explorer.ErrNotSyncing, err)
	}

	// mine a block to trigger a reorg
	ctestutil.MineBlocks(t, cm, types.VoidAddress, 1)
	waitForSync(t, cm, e)

	if err := e.Health(); !errors.Is(err, explorer.ErrNotScanning) {
		t.Fatalf("expected %q, got %v", explorer.ErrNotScanning, err)
	}

	// add a host so the explorer can scan it
	testV2Host(t, cm)
	waitForSync(t, cm, e)

	time.Sleep(time.Second)
	if err := e.Health(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

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
