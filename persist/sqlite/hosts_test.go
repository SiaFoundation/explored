package sqlite

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	crhpv4 "go.sia.tech/coreutils/rhp/v4"

	rhpv2 "go.sia.tech/core/rhp/v2"
	rhpv4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
	"go.uber.org/zap/zaptest"
)

func TestQueryHosts(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	db, err := OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	pk1 := types.GeneratePrivateKey().PublicKey()
	pk2 := types.GeneratePrivateKey().PublicKey()
	pk3 := types.GeneratePrivateKey().PublicKey()
	pk4 := types.GeneratePrivateKey().PublicKey()

	tm := time.Now()
	hosts := []explorer.Host{
		{
			PublicKey:              pk1,
			V2:                     false,
			NetAddress:             "host1.com:9982",
			CountryCode:            "US",
			KnownSince:             tm.Add(-2 * time.Hour),
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
			PublicKey:              pk2,
			V2:                     false,
			NetAddress:             "host2.com:9982",
			CountryCode:            "US",
			KnownSince:             tm.Add(-time.Hour),
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
			PublicKey:              pk3,
			V2:                     true,
			V2NetAddresses:         []chain.NetAddress{{Protocol: crhpv4.ProtocolTCPSiaMux, Address: "host4.com:9982"}},
			CountryCode:            "DE",
			KnownSince:             tm.Add(-time.Hour),
			LastScan:               tm,
			LastScanSuccessful:     false,
			SuccessfulInteractions: 95,
			TotalScans:             100,
			RHPV4Settings: rhpv4.HostSettings{
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
			PublicKey:              pk4,
			V2:                     true,
			V2NetAddresses:         []chain.NetAddress{{Protocol: crhpv4.ProtocolTCPSiaMux, Address: "host4.com:9982"}},
			CountryCode:            "DE",
			KnownSince:             tm.Add(-2 * time.Hour),
			LastScan:               tm,
			LastScanSuccessful:     false,
			SuccessfulInteractions: 75,
			TotalScans:             100,
			RHPV4Settings: rhpv4.HostSettings{
				AcceptingContracts:  false,
				MaxContractDuration: 1000,
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

	tests := []struct {
		name   string
		query  explorer.HostQuery
		sortBy explorer.HostSortColumn
		dir    explorer.HostSortDir
		offset uint64
		want   []types.PublicKey // Expected host public keys in order
	}{
		{
			name: "v1 asc AcceptingContracts",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk2, pk1},
		},
		{
			name: "v2 asc AcceptingContracts",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v1 desc AcceptingContracts",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v1 desc AcceptingContracts offset",
			query: explorer.HostQuery{
				V2: false,
			},
			offset: 1,
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk2},
		},
		{
			name: "v2 desc AcceptingContracts",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk3, pk4},
		},
		{
			name: "v2 desc AcceptingContracts offset",
			query: explorer.HostQuery{
				V2: true,
			},
			offset: 1,
			sortBy: explorer.HostSortAcceptingContracts,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk4},
		},

		{
			name: "v1 asc DateCreated",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc DateCreated",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortDateCreated,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},

		// host1.com:9982 < host2.com:9982
		{
			name: "v1 asc NetAddress",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortNetAddress,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},

		{
			name: "v1 asc Uptime",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortUptime,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc Uptime",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortUptime,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},

		{
			name: "v1 asc StoragePrice",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortStoragePrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc StoragePrice",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortStoragePrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v1 asc ContractPrice",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortContractPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc ContractPrice",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortContractPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v1 asc DownloadPrice",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortDownloadPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc DownloadPrice",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortDownloadPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v1 asc UploadPrice",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortUploadPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk1, pk2},
		},
		{
			name: "v2 asc UploadPrice",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortUploadPrice,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},

		{
			name: "v1 asc TotalStorage",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortTotalStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk2, pk1},
		},
		{
			name: "v2 asc TotalStorage",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortTotalStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},

		{
			name: "v1 asc UsedStorage",
			query: explorer.HostQuery{
				V2: false,
			},
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk2, pk1},
		},
		{
			name: "v2 asc UsedStorage",
			query: explorer.HostQuery{
				V2: true,
			},
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk4, pk3},
		},
		{
			name: "v2 asc UsedStorage offset 1",
			query: explorer.HostQuery{
				V2: true,
			},
			offset: 1,
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortAsc,
			want:   []types.PublicKey{pk3},
		},
		{
			name: "v2 desc UsedStorage offset 1",
			query: explorer.HostQuery{
				V2: true,
			},
			offset: 1,
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{pk4},
		},
		{
			name: "v2 desc UsedStorage offset 2",
			query: explorer.HostQuery{
				V2: true,
			},
			offset: 2,
			sortBy: explorer.HostSortUsedStorage,
			dir:    explorer.HostSortDesc,
			want:   []types.PublicKey{},
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
				prev = hosts[i-1].RHPV4Settings.Prices.StoragePrice
				curr = hosts[i].RHPV4Settings.Prices.StoragePrice
			} else {
				prev = hosts[i-1].Settings.StoragePrice
				curr = hosts[i].Settings.StoragePrice
			}
		case explorer.HostSortContractPrice:
			if hosts[i].V2 {
				prev = hosts[i-1].RHPV4Settings.Prices.ContractPrice
				curr = hosts[i].RHPV4Settings.Prices.ContractPrice
			} else {
				prev = hosts[i-1].Settings.ContractPrice
				curr = hosts[i].Settings.ContractPrice
			}
		case explorer.HostSortDownloadPrice:
			if hosts[i].V2 {
				prev = hosts[i-1].RHPV4Settings.Prices.EgressPrice
				curr = hosts[i].RHPV4Settings.Prices.EgressPrice
			} else {
				prev = hosts[i-1].Settings.DownloadBandwidthPrice
				curr = hosts[i].Settings.DownloadBandwidthPrice
			}
		case explorer.HostSortUploadPrice:
			if hosts[i].V2 {
				prev = hosts[i-1].RHPV4Settings.Prices.IngressPrice
				curr = hosts[i].RHPV4Settings.Prices.IngressPrice
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
