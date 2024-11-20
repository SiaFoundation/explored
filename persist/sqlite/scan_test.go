package sqlite

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/gateway"
	proto4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	crhpv4 "go.sia.tech/coreutils/rhp/v4"
	"go.sia.tech/coreutils/syncer"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/config"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"lukechampine.com/frand"

	"go.uber.org/zap"
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

func startTestNode(tb testing.TB, n *consensus.Network, genesis types.Block) (*chain.Manager, *syncer.Syncer, *wallet.SingleAddressWallet) {
	db, tipstate, err := chain.NewDBStore(chain.NewMemDB(), n, genesis)
	if err != nil {
		tb.Fatal(err)
	}
	cm := chain.NewManager(db, tipstate)

	syncerListener, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { syncerListener.Close() })

	s := syncer.New(syncerListener, cm, ctestutil.NewMemPeerStore(), gateway.Header{
		GenesisID:  genesis.ID(),
		UniqueID:   gateway.GenerateUniqueID(),
		NetAddress: "localhost:1234",
	})
	go s.Run(context.Background())
	tb.Cleanup(func() { s.Close() })

	ws := ctestutil.NewEphemeralWalletStore()
	w, err := wallet.NewSingleAddressWallet(types.GeneratePrivateKey(), cm, ws)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { w.Close() })

	reorgCh := make(chan struct{}, 1)
	tb.Cleanup(func() { close(reorgCh) })

	go func() {
		for range reorgCh {
			reverted, applied, err := cm.UpdatesSince(w.Tip(), 1000)
			if err != nil {
				tb.Error(err)
			}

			err = ws.UpdateChainState(func(tx wallet.UpdateTx) error {
				return w.UpdateChainState(tx, reverted, applied)
			})
			if err != nil {
				tb.Error(err)
			}
		}
	}()

	stop := cm.OnReorg(func(index types.ChainIndex) {
		select {
		case reorgCh <- struct{}{}:
		default:
		}
	})
	tb.Cleanup(stop)

	return cm, s, w
}

func testRenterHostPair(tb testing.TB, hostKey types.PrivateKey, cm crhpv4.ChainManager, s crhpv4.Syncer, w crhpv4.Wallet, c crhpv4.Contractor, sr crhpv4.Settings, ss crhpv4.Sectors, log *zap.Logger) string {
	rs := crhpv4.NewServer(hostKey, cm, s, c, w, sr, ss, crhpv4.WithContractProofWindowBuffer(10), crhpv4.WithPriceTableValidity(2*time.Minute))
	return ctestutil.ServeSiaMux(tb, rs, log.Named("siamux"))
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

	network, genesisBlock := ctestutil.Network()

	cm, s, w := startTestNode(t, network, genesisBlock)

	sr := ctestutil.NewEphemeralSettingsReporter()
	sr.Update(proto4.HostSettings{
		ProtocolVersion:     [3]uint8{1, 2, 3},
		Release:             "test",
		AcceptingContracts:  true,
		WalletAddress:       w.Address(),
		MaxCollateral:       types.Siacoins(10000),
		MaxContractDuration: 1000,
		MaxSectorDuration:   3 * 144,
		MaxSectorBatchSize:  100,
		RemainingStorage:    100 * proto4.SectorSize,
		TotalStorage:        100 * proto4.SectorSize,
		Prices: proto4.HostPrices{
			ContractPrice: types.Siacoins(uint32(frand.Uint64n(10000))),
			StoragePrice:  types.Siacoins(uint32(frand.Uint64n(10000))),
			IngressPrice:  types.Siacoins(uint32(frand.Uint64n(10000))),
			EgressPrice:   types.Siacoins(uint32(frand.Uint64n(10000))),
			Collateral:    types.Siacoins(uint32(frand.Uint64n(10000))),
		},
	})
	ss := ctestutil.NewEphemeralSectorStore()
	c := ctestutil.NewEphemeralContractor(cm)

	pk0 := types.GeneratePrivateKey()
	pubkey0 := pk0.PublicKey()

	v4Addr := testRenterHostPair(t, pk0, cm, s, w, c, sr, ss, zap.NewNop())

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
			PublicKey:        pubkey0,
			V2NetAddresses:   []chain.NetAddress{{Protocol: crhpv4.ProtocolTCPSiaMux, Address: v4Addr}},
			LastAnnouncement: ts,
			KnownSince:       ts,
		},
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
	b := testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(4 * cfg.Timeout)

	{
		dbHosts, err := e.Hosts([]types.PublicKey{pubkey0, pubkey1, pubkey2})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(dbHosts)", 3, len(dbHosts))

		sort.Slice(hosts, func(i, j int) bool {
			return hosts[i].NetAddress < hosts[j].NetAddress
		})
		sort.Slice(dbHosts, func(i, j int) bool {
			return dbHosts[i].NetAddress < dbHosts[j].NetAddress
		})

		host0 := dbHosts[0]
		testutil.Equal(t, "host0.NetAddress", hosts[0].NetAddress, host0.NetAddress)
		testutil.Equal(t, "host0.PublicKey", hosts[0].PublicKey, host0.PublicKey)
		testutil.Equal(t, "host0.TotalScans", 1, host0.TotalScans)
		testutil.Equal(t, "host0.SuccessfulInteractions", 1, host0.SuccessfulInteractions)
		testutil.Equal(t, "host0.FailedInteractions", 0, host0.FailedInteractions)
		testutil.Equal(t, "host0.LastScanSuccessful", true, host0.LastScanSuccessful)
		testutil.Equal(t, "host0.LastAnnouncement", ts, host0.LastAnnouncement)
		if !host0.RHPV4Settings.AcceptingContracts {
			log.Fatal("AcceptingContracts = false on host that's supposed to be active")
		}

		host1 := dbHosts[1]
		testutil.Equal(t, "host1.NetAddress", hosts[1].NetAddress, host1.NetAddress)
		testutil.Equal(t, "host1.PublicKey", hosts[1].PublicKey, host1.PublicKey)
		testutil.Equal(t, "host1.TotalScans", 1, host1.TotalScans)
		testutil.Equal(t, "host1.SuccessfulInteractions", 0, host1.SuccessfulInteractions)
		testutil.Equal(t, "host1.FailedInteractions", 1, host1.FailedInteractions)
		testutil.Equal(t, "host1.LastScanSuccessful", false, host1.LastScanSuccessful)
		testutil.Equal(t, "host1.LastAnnouncement", ts, host1.LastAnnouncement)

		host2 := dbHosts[2]
		testutil.Equal(t, "host2.NetAddress", hosts[2].NetAddress, host2.NetAddress)
		testutil.Equal(t, "host2.PublicKey", hosts[2].PublicKey, host2.PublicKey)
		testutil.Equal(t, "host2.CountryCode", "CA", host2.CountryCode)
		testutil.Equal(t, "host2.TotalScans", 1, host2.TotalScans)
		testutil.Equal(t, "host2.SuccessfulInteractions", 1, host2.SuccessfulInteractions)
		testutil.Equal(t, "host2.FailedInteractions", 0, host2.FailedInteractions)
		testutil.Equal(t, "host2.LastScanSuccessful", true, host2.LastScanSuccessful)
		testutil.Equal(t, "host2.LastAnnouncement", ts, host2.LastAnnouncement)
		if host2.Settings.SectorSize <= 0 {
			log.Fatal("SectorSize = 0 on host that's supposed to be active")
		}
	}

	ts = types.CurrentTimestamp()
	for i := range hosts {
		hosts[i].LastAnnouncement = ts
	}

	if err := db.transaction(func(tx *txn) error {
		return addHosts(tx, hosts)
	}); err != nil {
		t.Fatal(err)
	}

	{
		dbHosts, err := e.Hosts([]types.PublicKey{pubkey0, pubkey1, pubkey2})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(dbHosts)", 3, len(dbHosts))

		sort.Slice(hosts, func(i, j int) bool {
			return hosts[i].NetAddress < hosts[j].NetAddress
		})
		sort.Slice(dbHosts, func(i, j int) bool {
			return dbHosts[i].NetAddress < dbHosts[j].NetAddress
		})

		host0 := dbHosts[0]
		testutil.Equal(t, "host0.LastAnnouncement", ts, host0.LastAnnouncement)

		host1 := dbHosts[1]
		testutil.Equal(t, "host1.LastAnnouncement", ts, host1.LastAnnouncement)

		host2 := dbHosts[2]
		testutil.Equal(t, "host2.LastAnnouncement", ts, host2.LastAnnouncement)
	}

}
