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
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"lukechampine.com/frand"
)

func startTestNode(tb testing.TB, n *consensus.Network, genesis types.Block) (*chain.Manager, *syncer.Syncer, *wallet.SingleAddressWallet) {
	db, tipstate, err := chain.NewDBStore(chain.NewMemDB(), n, genesis, chain.NewZapMigrationLogger(zap.NewNop()))
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
	w, err := wallet.NewSingleAddressWallet(types.GeneratePrivateKey(), cm, ws, s)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { w.Close() })

	reorgCh := make(chan struct{}, 1)
	tb.Cleanup(func() { close(reorgCh) })

	go func() {
		for range reorgCh {
			tip, err := w.Tip()
			if err != nil {
				tb.Error(err)
				return
			}
			reverted, applied, err := cm.UpdatesSince(tip, 1000)
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

	return
}

func TestScan(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	randSC := func() types.Currency {
		return types.NewCurrency64(frand.Uint64n(10000))
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

	var pks [4]types.PrivateKey
	var pubkeys [4]types.PublicKey
	for i := range pks {
		pks[i] = types.GeneratePrivateKey()
		pubkeys[i] = pks[i].PublicKey()
	}

	rhp2Addr, _ := testV1Host(t, pks[0], &settings, &table)
	v4Addr, _ := testV2Host(t, pks[2], cm, s, w, c, sr, ss, zap.NewNop())

	cfg := config.Scanner{
		NumThreads:          100,
		ScanTimeout:         100 * time.Millisecond,
		ScanFrequency:       100 * time.Millisecond,
		ScanInterval:        3 * time.Hour,
		MinLastAnnouncement: 90 * 24 * time.Hour,
	}

	e, err := explorer.NewExplorer(cm, db, config.Index{BatchSize: 1000}, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer timeoutCancel()
	defer e.Shutdown(timeoutCtx)

	ha1 := chain.HostAnnouncement{PublicKey: pubkeys[0], NetAddress: rhp2Addr}
	ha2 := chain.HostAnnouncement{PublicKey: pubkeys[1], NetAddress: "127.0.0.1:9999"}
	txn1 := types.Transaction{
		ArbitraryData: [][]byte{
			ha1.ToArbitraryData(pks[0]),
			ha2.ToArbitraryData(pks[1]),
		},
	}

	b1 := testutil.MineBlock(cm.TipState(), []types.Transaction{txn1}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b1}); err != nil {
		t.Fatal(err)
	}

	ha3 := chain.V2HostAnnouncement{{Protocol: siamux.Protocol, Address: v4Addr}}
	txn2 := types.V2Transaction{
		Attestations: []types.Attestation{
			ha3.ToAttestation(cm.TipState(), pks[2]),
		},
	}
	testutil.SignV2Transaction(cm.TipState(), pks[2], &txn2)

	ha4 := chain.V2HostAnnouncement{{Protocol: siamux.Protocol, Address: "127.0.0.1:9999"}}
	txn3 := types.V2Transaction{
		Attestations: []types.Attestation{
			ha4.ToAttestation(cm.TipState(), pks[3]),
		},
	}
	testutil.SignV2Transaction(cm.TipState(), pks[3], &txn3)

	b2 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2, txn3}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b2}); err != nil {
		t.Fatal(err)
	}

	waitForTip := func() {
		t.Helper()

		for {
			if tip, err := e.Tip(); err != nil {
				t.Fatal(err)
			} else if tip == cm.Tip() {
				break
			}
			time.Sleep(time.Second)
		}
	}
	waitForTip()
	time.Sleep(2 * cfg.ScanTimeout)

	type hostTest struct {
		name               string
		pubkey             types.PublicKey
		totalScans         uint64
		lastScanSuccessful bool
		knownSince         time.Time
		lastAnnounce       time.Time
		nextScanFactor     int

		expectedV2NetAddresses []chain.NetAddress
		expectedNetAddress     *string
		expectedV2Settings     *proto4.HostSettings
		expectedSettings       *proto2.HostSettings
		expectedPriceTable     *proto3.HostPriceTable
	}

	runTests := func(tests []hostTest) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				hosts, err := e.Hosts([]types.PublicKey{tt.pubkey})
				if err != nil {
					t.Fatal(err)
				} else if len(hosts) != 1 {
					t.Fatalf("can't find host %s (%v) in DB", tt.name, tt.pubkey)
				}

				h := hosts[0]
				testutil.Equal(t, "PublicKey", tt.pubkey, h.PublicKey)
				testutil.Equal(t, "TotalScans", tt.totalScans, h.TotalScans)
				if tt.lastScanSuccessful {
					testutil.Equal(t, "SuccessfulInteractions", tt.totalScans, h.SuccessfulInteractions)
					testutil.Equal(t, "FailedInteractions", 0, h.FailedInteractions)
				} else {
					testutil.Equal(t, "FailedInteractions", tt.totalScans, h.FailedInteractions)
					testutil.Equal(t, "SuccessfulInteractions", 0, h.SuccessfulInteractions)
					if h.LastScanError == nil || *h.LastScanError == "" {
						t.Fatal("empty last scan error when last scan was unsuccessful")
					}
				}
				testutil.Equal(t, "LastScanSuccessful", tt.lastScanSuccessful, h.LastScanSuccessful)
				testutil.Equal(t, "KnownSince", tt.knownSince, h.KnownSince)
				testutil.Equal(t, "LastAnnouncement", tt.lastAnnounce, h.LastAnnouncement)
				testutil.Equal(t, "NextScan", h.LastScan.Add(time.Duration(tt.nextScanFactor)*cfg.ScanInterval), h.NextScan)

				if tt.expectedV2NetAddresses != nil {
					testutil.Equal(t, "V2NetAddresses", tt.expectedV2NetAddresses, h.V2NetAddresses)
				}
				if tt.expectedNetAddress != nil {
					testutil.Equal(t, "NetAddress", *tt.expectedNetAddress, h.NetAddress)
				}
				if tt.expectedV2Settings != nil {
					h.V2Settings.Prices.ValidUntil = time.Time{}
					h.V2Settings.Prices.TipHeight = 0
					h.V2Settings.Prices.Signature = types.Signature{}
					testutil.Equal(t, "V2Settings", *tt.expectedV2Settings, h.V2Settings)
				}
				if tt.expectedSettings != nil {
					testutil.Equal(t, "Settings", *tt.expectedSettings, h.Settings)
				}
				if tt.expectedPriceTable != nil {
					testutil.Equal(t, "PriceTable", *tt.expectedPriceTable, h.PriceTable)
				}
			})
		}
	}

	runTests([]hostTest{
		{
			name:                   "offline v2 host",
			pubkey:                 pubkeys[3],
			totalScans:             1,
			lastScanSuccessful:     false,
			knownSince:             b1.Timestamp,
			lastAnnounce:           b1.Timestamp,
			nextScanFactor:         2,
			expectedV2NetAddresses: ha4,
		},
		{
			name:                   "online v2 host",
			pubkey:                 pubkeys[2],
			totalScans:             1,
			lastScanSuccessful:     true,
			knownSince:             b2.Timestamp,
			lastAnnounce:           b2.Timestamp,
			nextScanFactor:         1,
			expectedV2NetAddresses: ha3,
			expectedV2Settings:     &v2Settings,
		},
		{
			name:               "offline v1 host",
			pubkey:             pubkeys[1],
			totalScans:         1,
			lastScanSuccessful: false,
			knownSince:         b1.Timestamp,
			lastAnnounce:       b1.Timestamp,
			nextScanFactor:     2,
			expectedNetAddress: &ha2.NetAddress,
		},
		{
			name:               "online v1 host",
			pubkey:             pubkeys[0],
			totalScans:         1,
			lastScanSuccessful: true,
			knownSince:         b1.Timestamp,
			lastAnnounce:       b1.Timestamp,
			nextScanFactor:     1,
			expectedNetAddress: &ha1.NetAddress,
			expectedSettings:   &settings,
			expectedPriceTable: &table,
		},
	})
	// Test host scanning after reannouncement
	b3 := testutil.MineBlock(cm.TipState(), []types.Transaction{txn1}, types.VoidAddress)
	cm.AddBlocks([]types.Block{b3})
	b4 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2, txn3}, types.VoidAddress)
	cm.AddBlocks([]types.Block{b4})

	waitForTip()
	time.Sleep(2 * cfg.ScanTimeout)

	runTests([]hostTest{
		{
			name:                   "offline v2 host",
			pubkey:                 pubkeys[3],
			totalScans:             2,
			lastScanSuccessful:     false,
			knownSince:             b1.Timestamp,
			lastAnnounce:           b4.Timestamp,
			nextScanFactor:         4,
			expectedV2NetAddresses: ha4,
		},
		{
			name:                   "online v2 host",
			pubkey:                 pubkeys[2],
			totalScans:             2,
			lastScanSuccessful:     true,
			knownSince:             b2.Timestamp,
			lastAnnounce:           b4.Timestamp,
			nextScanFactor:         1,
			expectedV2NetAddresses: ha3,
			expectedV2Settings:     &v2Settings,
		},
		{
			name:               "offline v1 host",
			pubkey:             pubkeys[1],
			totalScans:         2,
			lastScanSuccessful: false,
			knownSince:         b1.Timestamp,
			lastAnnounce:       b3.Timestamp,
			nextScanFactor:     4,
			expectedNetAddress: &ha2.NetAddress,
		},
		{
			name:               "online v1 host",
			pubkey:             pubkeys[0],
			totalScans:         2,
			lastScanSuccessful: true,
			knownSince:         b1.Timestamp,
			lastAnnounce:       b3.Timestamp,
			nextScanFactor:     1,
			expectedNetAddress: &ha1.NetAddress,
			expectedSettings:   &settings,
			expectedPriceTable: &table,
		},
	})

	// Check that we have no more hosts to scan
	now := types.CurrentTimestamp()
	dbHosts, err := db.HostsForScanning(now.Add(-cfg.MinLastAnnouncement), 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "hostsForScanning", 0, len(dbHosts))

	{
		hosts, err := e.Hosts([]types.PublicKey{pubkeys[0], pubkeys[2]})
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

	// Manually scan all the hosts
	if _, err := e.ScanHosts(context.Background(), pubkeys[:]...); err != nil {
		t.Fatal(err)
	}

	runTests([]hostTest{
		{
			name:                   "offline v2 host",
			pubkey:                 pubkeys[3],
			totalScans:             3,
			lastScanSuccessful:     false,
			knownSince:             b1.Timestamp,
			lastAnnounce:           b4.Timestamp,
			nextScanFactor:         1,
			expectedV2NetAddresses: ha4,
		},
		{
			name:                   "online v2 host",
			pubkey:                 pubkeys[2],
			totalScans:             3,
			lastScanSuccessful:     true,
			knownSince:             b2.Timestamp,
			lastAnnounce:           b4.Timestamp,
			nextScanFactor:         1,
			expectedV2NetAddresses: ha3,
			expectedV2Settings:     &v2Settings,
		},
		{
			name:               "offline v1 host",
			pubkey:             pubkeys[1],
			totalScans:         3,
			lastScanSuccessful: false,
			knownSince:         b1.Timestamp,
			lastAnnounce:       b3.Timestamp,
			nextScanFactor:     1,
			expectedNetAddress: &ha2.NetAddress,
		},
		{
			name:               "online v1 host",
			pubkey:             pubkeys[0],
			totalScans:         3,
			lastScanSuccessful: true,
			knownSince:         b1.Timestamp,
			lastAnnounce:       b3.Timestamp,
			nextScanFactor:     1,
			expectedNetAddress: &ha1.NetAddress,
			expectedSettings:   &settings,
			expectedPriceTable: &table,
		},
	})
}
