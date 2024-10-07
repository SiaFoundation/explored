package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/explored/config"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"

	"go.uber.org/zap/zaptest"
)

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

	network, genesisBlock := ctestutil.Network()

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	cfg := config.Scanner{
		Threads:             10,
		Timeout:             30 * time.Second,
		MaxLastScan:         3 * time.Hour,
		MinLastAnnouncement: 90 * 24 * time.Hour,
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

	ts := types.CurrentTimestamp()
	hosts := []explorer.Host{
		{
			PublicKey:        pubkey1,
			NetAddress:       "sia1.siahost.ca:9982",
			LastAnnouncement: ts,
			KnownSince:       ts,
		},
		{
			PublicKey:        pubkey2,
			NetAddress:       "example.com:9982",
			LastAnnouncement: ts,
			KnownSince:       ts,
		},
	}

	if err := db.transaction(func(tx *txn) error {
		return addHosts(tx, hosts)
	}); err != nil {
		t.Fatal(err)
	}

	// explorer won't start scanning till a recent block is mined
	b := testutil.MineBlock(genesisState, nil, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(3 * cfg.Timeout)

	dbHosts, err := e.Hosts([]types.PublicKey{pubkey1, pubkey2})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(dbHosts)", 2, len(dbHosts))

	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].NetAddress < hosts[j].NetAddress
	})
	sort.Slice(dbHosts, func(i, j int) bool {
		return dbHosts[i].NetAddress < dbHosts[j].NetAddress
	})
	host1 := dbHosts[0]
	testutil.Equal(t, "host1.NetAddress", hosts[0].NetAddress, host1.NetAddress)
	testutil.Equal(t, "host1.PublicKey", hosts[0].PublicKey, host1.PublicKey)
	testutil.Equal(t, "host1.TotalScans", 1, host1.TotalScans)
	testutil.Equal(t, "host1.SuccessfulInteractions", 0, host1.SuccessfulInteractions)
	testutil.Equal(t, "host1.FailedInteractions", 1, host1.FailedInteractions)
	testutil.Equal(t, "host1.LastScanSuccessful", false, host1.LastScanSuccessful)

	host2 := dbHosts[1]
	testutil.Equal(t, "host2.NetAddress", hosts[1].NetAddress, host2.NetAddress)
	testutil.Equal(t, "host2.PublicKey", hosts[1].PublicKey, host2.PublicKey)
	testutil.Equal(t, "host2.TotalScans", 1, host2.TotalScans)
	testutil.Equal(t, "host2.SuccessfulInteractions", 1, host2.SuccessfulInteractions)
	testutil.Equal(t, "host2.FailedInteractions", 0, host2.FailedInteractions)
	testutil.Equal(t, "host2.LastScanSuccessful", true, host2.LastScanSuccessful)
}
