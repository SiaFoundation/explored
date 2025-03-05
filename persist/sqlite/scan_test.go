package sqlite_test

import (
	"context"
	"encoding/base64"
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
	"go.sia.tech/coreutils/rhp/v4/siamux"
	"go.sia.tech/coreutils/syncer"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/config"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"go.sia.tech/explored/persist/sqlite"
	"lukechampine.com/frand"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

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

	s := syncer.New(syncerListener, cm, ctestutil.NewEphemeralPeerStore(), gateway.Header{
		GenesisID:  genesis.ID(),
		UniqueID:   gateway.GenerateUniqueID(),
		NetAddress: "localhost:1234",
	})
	go s.Run()
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

func testRenterHostPair(tb testing.TB, hostKey types.PrivateKey, cm crhpv4.ChainManager, s crhpv4.Syncer, w crhpv4.Wallet, c crhpv4.Contractor, sr crhpv4.Settings, ss crhpv4.Sectors, log *zap.Logger) (string, crhpv4.TransportClient) {
	rs := crhpv4.NewServer(hostKey, cm, s, c, w, sr, ss, crhpv4.WithPriceTableValidity(2*time.Minute))
	hostAddr := ctestutil.ServeSiaMux(tb, rs, log.Named("siamux"))

	transport, err := siamux.Dial(context.Background(), hostAddr, hostKey.PublicKey())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { transport.Close() })

	return hostAddr, transport
}

func TestScan(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	network, genesisBlock := ctestutil.V2Network()
	network.HardforkV2.AllowHeight = 1
	network.HardforkV2.RequireHeight = 5

	cm, s, w := startTestNode(t, network, genesisBlock)

	sr := ctestutil.NewEphemeralSettingsReporter()
	sr.Update(proto4.HostSettings{
		ProtocolVersion:     [3]uint8{1, 2, 3},
		Release:             "test",
		AcceptingContracts:  true,
		WalletAddress:       w.Address(),
		MaxCollateral:       types.Siacoins(10000),
		MaxContractDuration: 1000,
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

	// We do not have the private key to this host, so we copy their
	// announcement data because we cannot sign an announcement as
	// them.
	var pubkey1 types.PublicKey
	// pubkey of sia1.euregiohosting.nl:9982
	if err := pubkey1.UnmarshalText([]byte(`ed25519:e89e13affe9d2ab4dc6f1e157376c60cdcadddf061ea78a52db68b63e6070ee4`)); err != nil {
		t.Fatal(err)
	}
	// announcement copied from block 426479
	announcement, err := base64.StdEncoding.DecodeString("SG9zdEFubm91bmNlbWVudBsAAAAAAAAAc2lhMS5ldXJlZ2lvaG9zdGluZy5ubDo5OTgyZWQyNTUxOQAAAAAAAAAAACAAAAAAAAAA6J4Tr/6dKrTcbx4Vc3bGDNyt3fBh6nilLbaLY+YHDuRQ49Qr0uy4nZJq3XVW/8kCsqnJFyQT4Zj/CcvC5fG5orVLwnVp2xYdn0nNvBdPNV9LzHborsYz4pep1ywwn40C")
	if err != nil {
		t.Fatal(err)
	}

	pk2 := types.GeneratePrivateKey()
	pubkey2 := pk2.PublicKey()

	pk3 := types.GeneratePrivateKey()
	pubkey3 := pk3.PublicKey()

	v4Addr, _ := testRenterHostPair(t, pk3, cm, s, w, c, sr, ss, zap.NewNop())

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

	ha2 := chain.HostAnnouncement{
		PublicKey:  pubkey2,
		NetAddress: "example.com:9982",
	}
	txn1 := types.Transaction{
		ArbitraryData: [][]byte{
			announcement,
			ha2.ToArbitraryData(pk2),
		},
	}

	b1 := testutil.MineBlock(cm.TipState(), []types.Transaction{txn1}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b1}); err != nil {
		t.Fatal(err)
	}

	ha3 := chain.V2HostAnnouncement{{
		Protocol: siamux.Protocol,
		Address:  v4Addr,
	}}
	txn2 := types.V2Transaction{
		Attestations: []types.Attestation{ha3.ToAttestation(cm.TipState(), pk3)},
	}
	testutil.SignV2Transaction(cm.TipState(), pk3, &txn2)

	b2 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b2}); err != nil {
		t.Fatal(err)
	}

	for {
		tip, err := e.Tip()
		if err != nil {
			t.Fatal(err)
		}
		if tip != cm.Tip() {
			time.Sleep(time.Second)
		} else {
			break
		}
	}

	{
		now := types.CurrentTimestamp()
		lastAnnouncementCutoff := now.Add(-cfg.MinLastAnnouncement)

		dbHosts, err := db.HostsForScanning(lastAnnouncementCutoff, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(hostsForScanning)", 3, len(dbHosts))

		sort.Slice(dbHosts, func(i, j int) bool {
			return dbHosts[i].NetAddress < dbHosts[j].NetAddress
		})

		host1 := dbHosts[0]
		testutil.Equal(t, "host1.V2NetAddresses", ha3, host1.V2NetAddresses)
		testutil.Equal(t, "host1.PublicKey", pubkey3, host1.PublicKey)

		host2 := dbHosts[1]
		testutil.Equal(t, "host2.NetAddress", ha2.NetAddress, host2.NetAddress)
		testutil.Equal(t, "host2.PublicKey", ha2.PublicKey, host2.PublicKey)

		host3 := dbHosts[2]
		testutil.Equal(t, "host3.NetAddress", "sia1.euregiohosting.nl:9982", host3.NetAddress)
		testutil.Equal(t, "host3.PublicKey", pubkey1, host3.PublicKey)
	}

	time.Sleep(4 * cfg.Timeout)

	{
		dbHosts, err := e.Hosts([]types.PublicKey{pubkey3, pubkey2, pubkey1})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(dbHosts)", 3, len(dbHosts))

		sort.Slice(dbHosts, func(i, j int) bool {
			return dbHosts[i].NetAddress < dbHosts[j].NetAddress
		})

		host1 := dbHosts[0]
		testutil.Equal(t, "host1.V2NetAddresses", ha3, host1.V2NetAddresses)
		testutil.Equal(t, "host1.PublicKey", pubkey3, host1.PublicKey)
		testutil.Equal(t, "host1.TotalScans", 1, host1.TotalScans)
		testutil.Equal(t, "host1.SuccessfulInteractions", 1, host1.SuccessfulInteractions)
		testutil.Equal(t, "host1.FailedInteractions", 0, host1.FailedInteractions)
		testutil.Equal(t, "host1.LastScanSuccessful", true, host1.LastScanSuccessful)
		testutil.Equal(t, "host2.KnownSince", b2.Timestamp, host1.KnownSince)
		testutil.Equal(t, "host1.LastAnnouncement", b2.Timestamp, host1.LastAnnouncement)
		testutil.Equal(t, "host1.NextScan", host1.LastScan.Add(cfg.MaxLastScan), host1.NextScan)
		if !host1.RHPV4Settings.AcceptingContracts {
			t.Fatal("AcceptingContracts = false on host that's supposed to be active")
		}

		host2 := dbHosts[1]
		testutil.Equal(t, "host2.NetAddress", ha2.NetAddress, host2.NetAddress)
		testutil.Equal(t, "host2.PublicKey", ha2.PublicKey, host2.PublicKey)
		testutil.Equal(t, "host2.TotalScans", 1, host2.TotalScans)
		testutil.Equal(t, "host2.SuccessfulInteractions", 0, host2.SuccessfulInteractions)
		testutil.Equal(t, "host2.FailedInteractions", 1, host2.FailedInteractions)
		testutil.Equal(t, "host2.LastScanSuccessful", false, host2.LastScanSuccessful)
		testutil.Equal(t, "host2.KnownSince", b1.Timestamp, host2.KnownSince)
		testutil.Equal(t, "host2.LastAnnouncement", b1.Timestamp, host2.LastAnnouncement)
		testutil.Equal(t, "host2.NextScan", host2.LastScan.Add(2*cfg.MaxLastScan), host2.NextScan)

		host3 := dbHosts[2]
		testutil.Equal(t, "host3.NetAddress", "sia1.euregiohosting.nl:9982", host3.NetAddress)
		testutil.Equal(t, "host3.PublicKey", pubkey1, host3.PublicKey)
		testutil.Equal(t, "host3.Location.CountryCode", "NL", host3.Location.CountryCode)
		if host3.Location.Latitude == 0 || host3.Location.Longitude == 0 {
			t.Fatalf("Unset latitude/longitude: %v", host3.Location)
		}
		testutil.Equal(t, "host3.TotalScans", 1, host3.TotalScans)
		testutil.Equal(t, "host3.SuccessfulInteractions", 1, host3.SuccessfulInteractions)
		testutil.Equal(t, "host3.FailedInteractions", 0, host3.FailedInteractions)
		testutil.Equal(t, "host3.LastScanSuccessful", true, host3.LastScanSuccessful)
		testutil.Equal(t, "host3.KnownSince", b1.Timestamp, host2.KnownSince)
		testutil.Equal(t, "host3.LastAnnouncement", b1.Timestamp, host3.LastAnnouncement)
		testutil.Equal(t, "host3.NextScan", host3.LastScan.Add(cfg.MaxLastScan), host3.NextScan)
		if host3.Settings.SectorSize <= 0 {
			t.Fatal("SectorSize = 0 on host that's supposed to be active")
		}
	}

	// add v1 host announcements again
	b3 := testutil.MineBlock(cm.TipState(), []types.Transaction{txn1}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b3}); err != nil {
		t.Fatal(err)
	}
	// add v2 host announcements again
	b4 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b4}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * cfg.Timeout)

	{
		dbHosts, err := e.Hosts([]types.PublicKey{pubkey3, pubkey2, pubkey1})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(dbHosts)", 3, len(dbHosts))

		sort.Slice(dbHosts, func(i, j int) bool {
			return dbHosts[i].NetAddress < dbHosts[j].NetAddress
		})

		host1 := dbHosts[0]
		testutil.Equal(t, "host1.KnownSince", b2.Timestamp, host1.KnownSince)
		testutil.Equal(t, "host1.LastAnnouncement", b4.Timestamp, host1.LastAnnouncement)
		// settings should not be overwritten if there was not a successful scan
		if !host1.V2Settings.AcceptingContracts {
			t.Fatal("AcceptingContracts = false on host that's supposed to be active")
		}

		host2 := dbHosts[1]
		testutil.Equal(t, "host2.KnownSince", b1.Timestamp, host2.KnownSince)
		testutil.Equal(t, "host2.LastAnnouncement", b3.Timestamp, host2.LastAnnouncement)

		host3 := dbHosts[2]
		testutil.Equal(t, "host3.KnownSince", b1.Timestamp, host3.KnownSince)
		testutil.Equal(t, "host3.LastAnnouncement", b3.Timestamp, host3.LastAnnouncement)
		// settings should not be overwritten if there was not a successful scan
		if host3.Settings.SectorSize <= 0 {
			t.Fatal("SectorSize = 0 on host that's supposed to be active")
		}
	}

	{
		now := types.CurrentTimestamp()
		lastAnnouncementCutoff := now.Add(-cfg.MinLastAnnouncement)

		dbHosts, err := db.HostsForScanning(lastAnnouncementCutoff, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(hostsForScanning)", 0, len(dbHosts))
	}
}
