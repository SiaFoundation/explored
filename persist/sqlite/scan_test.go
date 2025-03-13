package sqlite_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/gateway"
	proto2 "go.sia.tech/core/rhp/v2"
	proto3 "go.sia.tech/core/rhp/v3"
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

func testV2Host(tb testing.TB, hostKey types.PrivateKey, cm crhpv4.ChainManager, s crhpv4.Syncer, w crhpv4.Wallet, c crhpv4.Contractor, sr crhpv4.Settings, ss crhpv4.Sectors, log *zap.Logger) (string, crhpv4.TransportClient) {
	rs := crhpv4.NewServer(hostKey, cm, s, c, w, sr, ss, crhpv4.WithPriceTableValidity(2*time.Minute))
	hostAddr := ctestutil.ServeSiaMux(tb, rs, log.Named("siamux"))

	transport, err := siamux.Dial(context.Background(), hostAddr, hostKey.PublicKey())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { transport.Close() })

	return hostAddr, transport
}

func testV1Host(tb testing.TB, hostKey types.PrivateKey, hostSettings *proto2.HostSettings, priceTable *proto3.HostPriceTable) (rhp2Addr string, rhp3Addr string) {
	rhp2Listener, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal(err)
	}
	rhp3Listener, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal(err)
	}
	rhp2Addr, rhp3Addr = rhp2Listener.Addr().String(), rhp3Listener.Addr().String()

	hostSettings.NetAddress = rhp2Listener.Addr().String()
	_, hostSettings.SiaMuxPort, err = net.SplitHostPort(rhp3Listener.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		rhp2Listener.Close()
		rhp3Listener.Close()
	})

	go func() {
		for {
			func() {
				conn, err := rhp2Listener.Accept()
				if errors.Is(err, net.ErrClosed) {
					return
				} else if err != nil {
					tb.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))

				transport, err := proto2.NewHostTransport(conn, hostKey)
				if err != nil {
					tb.Fatal(err)
				}
				defer transport.Close()

				id, err := transport.ReadID()
				if err != nil {
					tb.Fatal(err)
				} else if id != proto2.RPCSettingsID {
					tb.Fatal("received non settings RPC")
				}

				encoded, err := json.Marshal(hostSettings)
				if err != nil {
					tb.Fatal(err)
				}
				if err := transport.WriteResponse(&proto2.RPCSettingsResponse{
					Settings: encoded,
				}); err != nil {
					tb.Fatal(err)
				}
			}()
		}
	}()

	go func() {
		for {
			func() {
				conn, err := rhp3Listener.Accept()
				if errors.Is(err, net.ErrClosed) {
					return
				} else if err != nil {
					tb.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))

				transport, err := proto3.NewHostTransport(conn, hostKey)
				if err != nil {
					tb.Fatal(err)
				}
				defer transport.Close()

				stream, err := transport.AcceptStream()
				if err != nil {
					tb.Fatal(err)
				}
				defer stream.Close()

				id, err := stream.ReadID()
				if err != nil {
					tb.Fatal(err)
				} else if id != proto3.RPCUpdatePriceTableID {
					tb.Fatal("received non price table RPC")
				}

				encoded, err := json.Marshal(priceTable)
				if err != nil {
					tb.Fatal(err)
				}
				if err := stream.WriteResponse(&proto3.RPCUpdatePriceTableResponse{
					PriceTableJSON: encoded,
				}); err != nil {
					tb.Fatal(err)
				}
			}()
		}
	}()
}

func TestScan(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	randSC := func() types.Currency {
		return types.Siacoins(uint32(frand.Uint64n(10000)))
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

	settings := proto2.HostSettings{
		AcceptingContracts:   true,
		MaxDownloadBatchSize: 10,
		MaxDuration:          20,
		MaxReviseBatchSize:   30,
		RemainingStorage:     50,
		SectorSize:           60,
		TotalStorage:         70,

		Collateral:             randSC(),
		MaxCollateral:          randSC(),
		BaseRPCPrice:           randSC(),
		ContractPrice:          randSC(),
		DownloadBandwidthPrice: randSC(),
		SectorAccessPrice:      randSC(),
		StoragePrice:           randSC(),
		UploadBandwidthPrice:   randSC(),

		EphemeralAccountExpiry: time.Duration(80),
		RevisionNumber:         90,
		Version:                "version",
		Release:                "release",
	}
	table := proto3.HostPriceTable{
		Validity:        time.Duration(100),
		HostBlockHeight: cm.Tip().Height,

		UpdatePriceTableCost:         randSC(),
		AccountBalanceCost:           randSC(),
		FundAccountCost:              randSC(),
		LatestRevisionCost:           randSC(),
		SubscriptionMemoryCost:       randSC(),
		SubscriptionNotificationCost: randSC(),
		InitBaseCost:                 randSC(),
		MemoryTimeCost:               randSC(),
		DownloadBandwidthCost:        randSC(),
		UploadBandwidthCost:          randSC(),
		DropSectorsBaseCost:          randSC(),
		DropSectorsUnitCost:          randSC(),
		HasSectorBaseCost:            randSC(),
		ReadBaseCost:                 randSC(),
		ReadLengthCost:               randSC(),
		RenewContractCost:            randSC(),
		RevisionBaseCost:             randSC(),
		SwapSectorBaseCost:           randSC(),
		WriteBaseCost:                randSC(),
		WriteLengthCost:              randSC(),
		WriteStoreCost:               randSC(),
		TxnFeeMinRecommended:         randSC(),
		TxnFeeMaxRecommended:         randSC(),
		ContractPrice:                randSC(),
		CollateralCost:               randSC(),
		MaxCollateral:                randSC(),

		MaxDuration:          20,
		WindowSize:           30,
		RegistryEntriesLeft:  40,
		RegistryEntriesTotal: 50,
	}

	v2Settings := proto4.HostSettings{
		ProtocolVersion:     [3]uint8{4, 0, 0},
		Release:             "test",
		AcceptingContracts:  true,
		WalletAddress:       w.Address(),
		MaxCollateral:       randSC(),
		MaxContractDuration: 1000,
		RemainingStorage:    100,
		TotalStorage:        100,
		Prices: proto4.HostPrices{
			ContractPrice: randSC(),
			StoragePrice:  randSC(),
			IngressPrice:  randSC(),
			EgressPrice:   randSC(),
			Collateral:    randSC(),
		},
	}

	sr := ctestutil.NewEphemeralSettingsReporter()
	sr.Update(v2Settings)
	ss := ctestutil.NewEphemeralSectorStore()
	c := ctestutil.NewEphemeralContractor(cm)

	pk1 := types.GeneratePrivateKey()
	pubkey1 := pk1.PublicKey()

	pk2 := types.GeneratePrivateKey()
	pubkey2 := pk2.PublicKey()

	pk3 := types.GeneratePrivateKey()
	pubkey3 := pk3.PublicKey()

	rhp2Addr, _ := testV1Host(t, pk1, &settings, &table)
	v4Addr, _ := testV2Host(t, pk3, cm, s, w, c, sr, ss, zap.NewNop())

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

	ha1 := chain.HostAnnouncement{
		PublicKey:  pubkey1,
		NetAddress: rhp2Addr,
	}
	ha2 := chain.HostAnnouncement{
		PublicKey:  pubkey2,
		NetAddress: "127.0.0.1:9999",
	}
	txn1 := types.Transaction{
		ArbitraryData: [][]byte{
			ha1.ToArbitraryData(pk1),
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

	time.Sleep(1 * cfg.Timeout)

	{
		tests := []struct {
			name   string
			pubkey types.PublicKey
			checks func(explorer.Host)
		}{
			{
				name:   "online v2 host",
				pubkey: pubkey3,
				checks: func(host explorer.Host) {
					testutil.Equal(t, "host.V2NetAddresses", ha3, host.V2NetAddresses)
					testutil.Equal(t, "host.PublicKey", pubkey3, host.PublicKey)
					testutil.Equal(t, "host.TotalScans", 1, host.TotalScans)
					testutil.Equal(t, "host.SuccessfulInteractions", 1, host.SuccessfulInteractions)
					testutil.Equal(t, "host.FailedInteractions", 0, host.FailedInteractions)
					testutil.Equal(t, "host.LastScanSuccessful", true, host.LastScanSuccessful)
					testutil.Equal(t, "host2.KnownSince", b2.Timestamp, host.KnownSince)
					testutil.Equal(t, "host.LastAnnouncement", b2.Timestamp, host.LastAnnouncement)
					testutil.Equal(t, "host.NextScan", host.LastScan.Add(cfg.MaxLastScan), host.NextScan)

					host.V2Settings.Prices.ValidUntil, host.V2Settings.Prices.TipHeight, host.V2Settings.Prices.Signature = time.Time{}, 0, types.Signature{}
					testutil.Equal(t, "host.V2Settings", v2Settings, host.V2Settings)
				},
			},
			{
				name:   "offline v1 host",
				pubkey: pubkey2,
				checks: func(host explorer.Host) {
					testutil.Equal(t, "host.NetAddress", ha2.NetAddress, host.NetAddress)
					testutil.Equal(t, "host.PublicKey", ha2.PublicKey, host.PublicKey)
					testutil.Equal(t, "host.TotalScans", 1, host.TotalScans)
					testutil.Equal(t, "host.SuccessfulInteractions", 0, host.SuccessfulInteractions)
					testutil.Equal(t, "host.FailedInteractions", 1, host.FailedInteractions)
					testutil.Equal(t, "host.LastScanSuccessful", false, host.LastScanSuccessful)
					testutil.Equal(t, "host.KnownSince", b1.Timestamp, host.KnownSince)
					testutil.Equal(t, "host.LastAnnouncement", b1.Timestamp, host.LastAnnouncement)
					testutil.Equal(t, "host.NextScan", host.LastScan.Add(2*cfg.MaxLastScan), host.NextScan)
				},
			},
			{
				name:   "online v1 host",
				pubkey: pubkey1,
				checks: func(host explorer.Host) {
					testutil.Equal(t, "host.NetAddress", ha1.NetAddress, host.NetAddress)
					testutil.Equal(t, "host.PublicKey", pubkey1, host.PublicKey)
					testutil.Equal(t, "host.TotalScans", 1, host.TotalScans)
					testutil.Equal(t, "host.SuccessfulInteractions", 1, host.SuccessfulInteractions)
					testutil.Equal(t, "host.FailedInteractions", 0, host.FailedInteractions)
					testutil.Equal(t, "host.LastScanSuccessful", true, host.LastScanSuccessful)
					testutil.Equal(t, "host.KnownSince", b1.Timestamp, host.KnownSince)
					testutil.Equal(t, "host.LastAnnouncement", b1.Timestamp, host.LastAnnouncement)
					testutil.Equal(t, "host.NextScan", host.LastScan.Add(cfg.MaxLastScan), host.NextScan)

					testutil.Equal(t, "host.Settings", settings, host.Settings)
					testutil.Equal(t, "host.PriceTable", table, host.PriceTable)
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				hosts, err := e.Hosts([]types.PublicKey{tt.pubkey})
				if err != nil {
					t.Fatal(err)
				} else if len(hosts) != 1 {
					t.Fatalf("can't find host %s (%v) in DB", tt.name, tt.pubkey)
				}

				tt.checks(hosts[0])
			})
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

	time.Sleep(1 * cfg.Timeout)

	{
		tests := []struct {
			name   string
			pubkey types.PublicKey
			checks func(explorer.Host)
		}{
			{
				name:   "online v2 host",
				pubkey: pubkey3,
				checks: func(host explorer.Host) {
					testutil.Equal(t, "host.KnownSince", b2.Timestamp, host.KnownSince)
					testutil.Equal(t, "host.LastAnnouncement", b4.Timestamp, host.LastAnnouncement)

					// settings should not be overwritten if another successful scan has not occurred yet
					host.V2Settings.Prices.ValidUntil, host.V2Settings.Prices.TipHeight, host.V2Settings.Prices.Signature = time.Time{}, 0, types.Signature{}
					testutil.Equal(t, "host.V2Settings", v2Settings, host.V2Settings)
				},
			},
			{
				name:   "offline v1 host",
				pubkey: pubkey2,
				checks: func(host explorer.Host) {
					testutil.Equal(t, "host.KnownSince", b1.Timestamp, host.KnownSince)
					testutil.Equal(t, "host.LastAnnouncement", b3.Timestamp, host.LastAnnouncement)
				},
			},
			{
				name:   "online v1 host",
				pubkey: pubkey1,
				checks: func(host explorer.Host) {
					testutil.Equal(t, "host.KnownSince", b1.Timestamp, host.KnownSince)
					testutil.Equal(t, "host.LastAnnouncement", b3.Timestamp, host.LastAnnouncement)

					// settings should not be overwritten if another successful scan has not occurred yet
					testutil.Equal(t, "host.Settings", settings, host.Settings)
					testutil.Equal(t, "host.PriceTable", table, host.PriceTable)
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				hosts, err := e.Hosts([]types.PublicKey{tt.pubkey})
				if err != nil {
					t.Fatal(err)
				} else if len(hosts) != 1 {
					t.Fatalf("can't find host %s (%v) in DB", tt.name, tt.pubkey)
				}

				tt.checks(hosts[0])
			})
		}
	}

	{
		hosts, err := e.Hosts([]types.PublicKey{pubkey1, pubkey3})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(hosts)", 2, len(hosts))

		v1Host, v2Host := hosts[0], hosts[1]
		if v1Host.V2 {
			v1Host, v2Host = v2Host, v1Host
		}

		// we only have one v1 host and one v2 host, so the median will just be
		// whatever the values for that host are
		metrics, err := e.HostMetrics()
		if err != nil {
			t.Fatal(err)
		}

		// zero out fields we can't take median of
		v2Host.V2Settings.ProtocolVersion, v2Host.V2Settings.AcceptingContracts, v2Host.V2Settings.Release, v2Host.V2Settings.WalletAddress, v2Host.V2Settings.Prices.Signature = [3]uint8{}, false, "", types.VoidAddress, types.Signature{}
		v1Host.Settings.AcceptingContracts, v1Host.Settings.NetAddress, v1Host.Settings.Address, v1Host.Settings.Version, v1Host.Settings.Release, v1Host.Settings.SiaMuxPort, v1Host.PriceTable.UID = false, "", types.VoidAddress, "", "", "", proto3.SettingsID{}

		testutil.Equal(t, "metrics.TotalStorage", proto4.SectorSize*v2Host.V2Settings.TotalStorage+v1Host.Settings.TotalStorage, metrics.TotalStorage)
		testutil.Equal(t, "metrics.RemainingStorage", proto4.SectorSize*v2Host.V2Settings.RemainingStorage+v1Host.Settings.RemainingStorage, metrics.RemainingStorage)
		testutil.Equal(t, "metrics.V2Settings", v2Host.V2Settings, metrics.V2Settings)
		testutil.Equal(t, "metrics.Settings", v1Host.Settings, metrics.Settings)
		testutil.Equal(t, "metrics.PriceTable", v1Host.PriceTable, metrics.PriceTable)
	}
}
