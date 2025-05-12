package sqlite

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/coreutils/rhp/v4/siamux"
	"lukechampine.com/frand"

	rhpv2 "go.sia.tech/core/rhp/v2"
	rhpv4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/geoip"
	"go.uber.org/zap/zaptest"
)

func TestLastSuccessScan(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "explored.sqlite3"), zaptest.NewLogger(t).Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ts, err := db.LastSuccessScan()
	if err != nil {
		t.Fatal(err)
	} else if !ts.IsZero() {
		t.Fatal("expected zero time")
	}

	// Add hosts to database
	hosts := []explorer.Host{
		{
			PublicKey:  frand.Entropy256(),
			V2:         false,
			NetAddress: "foo.bar:9982",
			Location: geoip.Location{
				CountryCode: "US",
				Latitude:    0.01,
				Longitude:   -0.02,
			},
			KnownSince:             time.Now().Add(-4 * time.Hour),
			LastScan:               time.Now(),
			LastScanSuccessful:     false,
			SuccessfulInteractions: 75,
			TotalScans:             100,
			Settings: rhpv2.HostSettings{
				AcceptingContracts:     true,
				MaxDuration:            1000,
				StoragePrice:           types.Siacoins(1),
				ContractPrice:          types.Siacoins(2),
				DownloadBandwidthPrice: types.Siacoins(3),
				UploadBandwidthPrice:   types.Siacoins(4),
				BaseRPCPrice:           types.Siacoins(5),
				SectorAccessPrice:      types.Siacoins(6),
				TotalStorage:           2000,
				RemainingStorage:       1000,
			},
		},
	}
	if err := db.transaction(func(tx *txn) error {
		return addHosts(tx, hosts)
	}); err != nil {
		t.Fatal(err)
	}

	if ts, err = db.LastSuccessScan(); err != nil {
		t.Fatal(err)
	} else if !ts.IsZero() {
		t.Fatal("expected zero time")
	}

	expectedTimestamp := time.Now().Add(-time.Minute).Round(time.Second)
	err = db.AddHostScans(explorer.HostScan{
		PublicKey: hosts[0].PublicKey,
		Success:   true,
		Timestamp: expectedTimestamp,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts, err = db.LastSuccessScan()
	if err != nil {
		t.Fatal(err)
	} else if !ts.Equal(expectedTimestamp) {
		t.Fatalf("expected %v, got %v", expectedTimestamp, ts)
	}
}

func TestQueryHosts(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	db, err := OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const (
		netAddr1 = "host1.com:9982"
		netAddr2 = "host2.com:9982"
		netAddr3 = "host3.com:9982"
		netAddr4 = "host4.com:9982"
	)

	pk1 := types.GeneratePrivateKey().PublicKey()
	pk2 := types.GeneratePrivateKey().PublicKey()
	pk3 := types.GeneratePrivateKey().PublicKey()
	pk4 := types.GeneratePrivateKey().PublicKey()

	tm := time.Now()
	hosts := []explorer.Host{
		{
			PublicKey:  pk1,
			V2:         false,
			NetAddress: netAddr1,
			Location: geoip.Location{
				CountryCode: "US",
				Latitude:    0.01,
				Longitude:   -0.02,
			},
			KnownSince:             tm.Add(-4 * time.Hour),
			LastScan:               tm,
			LastScanSuccessful:     true,
			SuccessfulInteractions: 75,
			TotalScans:             100,
			Settings: rhpv2.HostSettings{
				AcceptingContracts:     true,
				MaxDuration:            1000,
				StoragePrice:           types.Siacoins(1),
				ContractPrice:          types.Siacoins(2),
				DownloadBandwidthPrice: types.Siacoins(3),
				UploadBandwidthPrice:   types.Siacoins(4),
				BaseRPCPrice:           types.Siacoins(5),
				SectorAccessPrice:      types.Siacoins(6),
				TotalStorage:           2000,
				RemainingStorage:       1000,
			},
		},
		{
			PublicKey:  pk2,
			V2:         false,
			NetAddress: netAddr2,
			Location: geoip.Location{
				CountryCode: "US",
				Latitude:    0.01,
				Longitude:   -0.02,
			},
			KnownSince:             tm.Add(-3 * time.Hour),
			LastScan:               tm,
			LastScanSuccessful:     true,
			SuccessfulInteractions: 90,
			TotalScans:             100,
			Settings: rhpv2.HostSettings{
				AcceptingContracts:     false,
				MaxDuration:            10000,
				StoragePrice:           types.Siacoins(60),
				ContractPrice:          types.Siacoins(50),
				DownloadBandwidthPrice: types.Siacoins(40),
				UploadBandwidthPrice:   types.Siacoins(30),
				BaseRPCPrice:           types.Siacoins(20),
				SectorAccessPrice:      types.Siacoins(10),
				TotalStorage:           1000,
				RemainingStorage:       500,
			},
		},
		{
			PublicKey:      pk3,
			V2:             true,
			V2NetAddresses: []chain.NetAddress{{Protocol: siamux.Protocol, Address: netAddr3}},
			Location: geoip.Location{
				CountryCode: "DE",
				Latitude:    0.05,
				Longitude:   -0.10,
			},
			KnownSince:             tm.Add(-2 * time.Hour),
			LastScan:               tm,
			LastScanSuccessful:     false,
			SuccessfulInteractions: 95,
			TotalScans:             100,
			V2Settings: rhpv4.HostSettings{
				AcceptingContracts:  true,
				MaxContractDuration: 1000,
				TotalStorage:        2000,
				RemainingStorage:    1000,
				Prices: rhpv4.HostPrices{
					StoragePrice:  types.Siacoins(10),
					ContractPrice: types.Siacoins(20),
					EgressPrice:   types.Siacoins(30),
					IngressPrice:  types.Siacoins(40),
				},
			},
		},
		{
			PublicKey:      pk4,
			V2:             true,
			V2NetAddresses: []chain.NetAddress{{Protocol: siamux.Protocol, Address: netAddr4}},
			Location: geoip.Location{
				CountryCode: "DE",
				Latitude:    0.05,
				Longitude:   -0.10,
			},
			KnownSince:             tm.Add(-1 * time.Hour),
			LastScan:               tm,
			LastScanSuccessful:     false,
			SuccessfulInteractions: 75,
			TotalScans:             100,
			V2Settings: rhpv4.HostSettings{
				AcceptingContracts:  false,
				MaxContractDuration: 10000,
				TotalStorage:        1000,
				RemainingStorage:    500,
				Prices: rhpv4.HostPrices{
					StoragePrice:  types.Siacoins(1),
					ContractPrice: types.Siacoins(2),
					EgressPrice:   types.Siacoins(3),
					IngressPrice:  types.Siacoins(4),
				},
			},
		},
	}

	// Add hosts to database
	if err := db.transaction(func(tx *txn) error {
		return addHosts(tx, hosts)
	}); err != nil {
		t.Fatal(err)
	}

	uint64Ptr := func(x uint64) *uint64 {
		return &x
	}
	trueBool, falseBool := true, false
	tests := []struct {
		name   string
		query  explorer.HostQuery
		sortBy explorer.HostSortColumn
		dir    explorer.HostSortDir
		offset uint64
		want   []types.PublicKey // Expected host public keys in order
	}{
		{
			name:   "all hosts",
			query:  explorer.HostQuery{},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2, pk3, pk4},
		},
		{
			name:   "all hosts pubkey",
			query:  explorer.HostQuery{PublicKeys: []types.PublicKey{pk1, pk2, pk3, pk4}},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2, pk3, pk4},
		},
		{
			name:   "all hosts accepting contracts",
			query:  explorer.HostQuery{AcceptContracts: &trueBool},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk3},
		},
		{
			name:   "all hosts pubkey accepting contracts",
			query:  explorer.HostQuery{AcceptContracts: &trueBool, PublicKeys: []types.PublicKey{pk1, pk2, pk3, pk4}},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk3},
		},

		{
			name: "v1 asc AcceptingContracts",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk2, pk1},
		},
		{
			name: "v2 asc AcceptingContracts",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v1 desc AcceptingContracts",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v1 desc AcceptingContracts offset",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			offset: 1,
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk2},
		},
		{
			name: "v2 desc AcceptingContracts",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk3, pk4},
		},
		{
			name: "v2 desc AcceptingContracts offset",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			offset: 1,
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk4},
		},

		{
			name: "v1 asc DateCreated",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc DateCreated",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk3, pk4},
		},

		// host1.com:9982 < host2.com:9982
		{
			name: "v1 asc NetAddress",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortNetAddress,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},

		{
			name: "v1 asc Uptime",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortUptime,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc Uptime",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortUptime,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},

		{
			name: "v1 asc StoragePrice",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortStoragePrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc StoragePrice",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortStoragePrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v1 asc ContractPrice",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortContractPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc ContractPrice",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortContractPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v1 asc DownloadPrice",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortDownloadPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc DownloadPrice",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortDownloadPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v1 asc UploadPrice",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortUploadPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc UploadPrice",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortUploadPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},

		{
			name: "v1 asc TotalStorage",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortTotalStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk2, pk1},
		},
		{
			name: "v2 asc TotalStorage",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortTotalStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},

		{
			name: "v1 asc UsedStorage",
			query: explorer.HostQuery{
				V2: &falseBool,
			},
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk2, pk1},
		},
		{
			name: "v2 asc UsedStorage",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v2 asc UsedStorage offset 1",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			offset: 1,
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk3},
		},
		{
			name: "v2 desc UsedStorage offset 1",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			offset: 1,
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk4},
		},
		{
			name: "v2 desc UsedStorage offset 2",
			query: explorer.HostQuery{
				V2: &trueBool,
			},
			offset: 2,
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{},
		},

		{
			name: "v1 min duration 1000",
			query: explorer.HostQuery{
				V2:          &falseBool,
				MinDuration: uint64Ptr(1000),
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v1 min duration 5000",
			query: explorer.HostQuery{
				V2:          &falseBool,
				MinDuration: uint64Ptr(5000),
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk2},
		},
		{
			name: "v2 min duration 1000",
			query: explorer.HostQuery{
				V2:          &trueBool,
				MinDuration: uint64Ptr(1000),
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk3, pk4},
		},
		{
			name: "v2 min duration 5000",
			query: explorer.HostQuery{
				V2:          &trueBool,
				MinDuration: uint64Ptr(5000),
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk4},
		},

		{
			name: "net address 1 2 3 4",
			query: explorer.HostQuery{
				NetAddresses: []string{netAddr1, netAddr2, netAddr3, netAddr4},
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2, pk3, pk4},
		},
		{
			name: "net address 1 2 3",
			query: explorer.HostQuery{
				NetAddresses: []string{netAddr1, netAddr2, netAddr3},
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2, pk3},
		},
		{
			name: "net address pubkey 1 2 3",
			query: explorer.HostQuery{
				PublicKeys:   []types.PublicKey{pk1, pk2, pk3},
				NetAddresses: []string{netAddr1, netAddr3},
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk3},
		},
		{
			name: "net address v2 1 2 3 4",
			query: explorer.HostQuery{
				V2:           &trueBool,
				NetAddresses: []string{netAddr1, netAddr2, netAddr3, netAddr4},
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk3, pk4},
		},
		{
			name: "net address v2 3",
			query: explorer.HostQuery{
				V2:           &trueBool,
				NetAddresses: []string{netAddr3},
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk3},
		},
		{
			name: "net address v1 1",
			query: explorer.HostQuery{
				V2:           &falseBool,
				NetAddresses: []string{netAddr1},
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.QueryHosts(tt.query, tt.sortBy, tt.dir, tt.offset, math.MaxInt64)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Errorf("got %d results, want %d", len(got), len(tt.want))
				return
			}

			for i, want := range tt.want {
				if got[i].PublicKey != want {
					t.Errorf("%d got %v, want %v", i, got[i].PublicKey, want)
				}
			}

			if tt.sortBy == explorer.HostSortStoragePrice ||
				tt.sortBy == explorer.HostSortContractPrice ||
				tt.sortBy == explorer.HostSortDownloadPrice ||
				tt.sortBy == explorer.HostSortUploadPrice {
				verifyCurrencySort(t, got, tt.sortBy, tt.dir)
			}
		})
	}
}

// verifyCurrencySort ensures that currency values are properly sorted numerically
func verifyCurrencySort(t *testing.T, hosts []explorer.Host, sortBy explorer.HostSortColumn, dir explorer.HostSortDir) {
	if len(hosts) < 2 {
		return
	}

	for i := 1; i < len(hosts); i++ {
		var prev, curr types.Currency
		switch sortBy {
		case explorer.HostSortStoragePrice:
			if hosts[i].V2 {
				prev = hosts[i-1].V2Settings.Prices.StoragePrice
				curr = hosts[i].V2Settings.Prices.StoragePrice
			} else {
				prev = hosts[i-1].Settings.StoragePrice
				curr = hosts[i].Settings.StoragePrice
			}
		case explorer.HostSortContractPrice:
			if hosts[i].V2 {
				prev = hosts[i-1].V2Settings.Prices.ContractPrice
				curr = hosts[i].V2Settings.Prices.ContractPrice
			} else {
				prev = hosts[i-1].Settings.ContractPrice
				curr = hosts[i].Settings.ContractPrice
			}
		case explorer.HostSortDownloadPrice:
			if hosts[i].V2 {
				prev = hosts[i-1].V2Settings.Prices.EgressPrice
				curr = hosts[i].V2Settings.Prices.EgressPrice
			} else {
				prev = hosts[i-1].Settings.DownloadBandwidthPrice
				curr = hosts[i].Settings.DownloadBandwidthPrice
			}
		case explorer.HostSortUploadPrice:
			if hosts[i].V2 {
				prev = hosts[i-1].V2Settings.Prices.IngressPrice
				curr = hosts[i].V2Settings.Prices.IngressPrice
			} else {
				prev = hosts[i-1].Settings.UploadBandwidthPrice
				curr = hosts[i].Settings.UploadBandwidthPrice
			}
		}

		if dir == explorer.HostSortAsc {
			if prev.Cmp(curr) > 0 {
				t.Errorf("Ascending sort failed: %v > %v", prev, curr)
			}
		} else {
			if prev.Cmp(curr) < 0 {
				t.Errorf("Descending sort failed: %v < %v", prev, curr)
			}
		}
	}
}
