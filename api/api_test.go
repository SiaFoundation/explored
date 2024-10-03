package api_test

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/syncer"
	"go.sia.tech/explored/api"
	"go.sia.tech/explored/build"
	"go.sia.tech/explored/config"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap/zaptest"
)

func newExplorer(t *testing.T, addr types.Address, giftSC types.Currency, giftSF uint64) (types.Block, *coreutils.BoltChainDB, *chain.Manager, explorer.Store, *explorer.Explorer, error) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}

	network, genesisBlock := testutil.TestV1Network(addr, giftSC, giftSF)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	e, err := explorer.NewExplorer(cm, db, 1000, config.Scanner{
		Threads:             10,
		Timeout:             30 * time.Second,
		MaxLastScan:         3 * time.Hour,
		MinLastAnnouncement: 90 * 24 * time.Hour,
	}, log)
	if err != nil {
		t.Fatal(err)
	}

	return genesisBlock, bdb, cm, db, e, err
}

func newServer(t *testing.T, cm *chain.Manager, e *explorer.Explorer, listenAddr string) (*http.Server, net.Listener, error) {
	api := api.NewServer(e, cm, &syncer.Syncer{})
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api") {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
				api.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		}),
		ReadTimeout: 15 * time.Second,
	}

	httpListener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		server.Serve(httpListener)
	}()

	return server, httpListener, nil
}

func TestAPI(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	giftSC := types.Siacoins(1000)
	giftSF := uint64(1000)
	contractFilesize := uint64(10)

	genesisBlock, bdb, cm, db, e, err := newExplorer(t, addr1, giftSC, giftSF)
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer e.Shutdown(ctx)

	listenAddr := "127.0.0.1:9999"
	server, listener, err := newServer(t, cm, e, listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer listener.Close()

	scOutputID := genesisBlock.Transactions[0].SiacoinOutputID(0)
	sfOutputID := genesisBlock.Transactions[0].SiafundOutputID(0)
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())

	windowStart := cm.Tip().Height + 10
	windowEnd := windowStart + 10
	fc := testutil.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), windowStart, windowEnd, types.VoidAddress)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         scOutputID,
			UnlockConditions: unlockConditions,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   giftSC.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn1)

	b1 := testutil.MineBlock(cm.TipState(), []types.Transaction{txn1}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b1}); err != nil {
		t.Fatal(err)
	}

	txn2 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         sfOutputID,
			UnlockConditions: unlockConditions,
		}},
		SiafundOutputs: []types.SiafundOutput{
			{
				Address: addr2,
				Value:   giftSF - 1,
			},
			{
				Address: addr1,
				Value:   1,
			},
		},
		ArbitraryData: [][]byte{
			testutil.CreateAnnouncement(pk1, "127.0.0.1:1234"),
		},
	}
	testutil.SignTransaction(cm.TipState(), pk1, &txn2)

	fcID := txn1.FileContractID(0)
	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			renterPublicKey.UnlockKey(),
			hostPublicKey.UnlockKey(),
		},
		SignaturesRequired: 2,
	}
	revFC := fc
	revFC.RevisionNumber++
	reviseTxn := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fcID,
			UnlockConditions: uc,
			FileContract:     revFC,
		}},
	}
	testutil.SignTransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &reviseTxn)

	b2 := testutil.MineBlock(cm.TipState(), []types.Transaction{txn2, reviseTxn}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b2}); err != nil {
		t.Fatal(err)
	}

	// Ensure explorer has time to add blocks
	time.Sleep(1 * time.Second)

	client := api.NewClient("http://"+listenAddr+"/api", "")

	subtests := []struct {
		name string
		test func(t *testing.T)
	}{
		{"State", func(t *testing.T) {
			resp, err := client.State()
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "Version", build.Version(), resp.Version)
			testutil.Check(t, "Commit", build.Commit(), resp.Commit)
			testutil.Check(t, "OS", runtime.GOOS, resp.OS)
			testutil.Check(t, "BuildTime", build.Time().UTC(), resp.BuildTime.UTC())
		}},
		{"ConsensusTip", func(t *testing.T) {
			resp, err := client.ConsensusTip()
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "tip", cm.Tip(), resp)
		}},
		{"BestIndex", func(t *testing.T) {
			for i := uint64(0); i < cm.Tip().Height; i++ {
				resp, err := client.BestIndex(i)
				if err != nil {
					t.Fatal(err)
				}
				tip, err := e.BestTip(i)
				if err != nil {
					t.Fatal(err)
				}
				testutil.Check(t, "tip", tip, resp)
			}
		}},

		{"ConsensusNetwork", func(t *testing.T) {
			resp, err := client.ConsensusNetwork()
			if err != nil {
				t.Fatal(err)
			}

			// fix because reflect.DeepEqual can't compare timestamps
			n := cm.TipState().Network
			n.HardforkOak.GenesisTimestamp = n.HardforkOak.GenesisTimestamp.UTC()
			resp.HardforkOak.GenesisTimestamp = resp.HardforkOak.GenesisTimestamp.UTC()

			testutil.Check(t, "network", n, resp)
		}},

		{"ConsensusState", func(t *testing.T) {
			resp, err := client.ConsensusState()
			if err != nil {
				t.Fatal(err)
			}
			cs := cm.TipState()
			testutil.Check(t, "index", cs.Index, resp.Index)

			// fix timestamps again
			for i := range cs.PrevTimestamps {
				cs.PrevTimestamps[i] = cs.PrevTimestamps[i].UTC()
			}
			for i := range resp.PrevTimestamps {
				resp.PrevTimestamps[i] = resp.PrevTimestamps[i].UTC()
			}

			testutil.Check(t, "previous timestamps", cs.PrevTimestamps, resp.PrevTimestamps)
			testutil.Check(t, "depth", cs.Depth, resp.Depth)
			testutil.Check(t, "child target", cs.ChildTarget, resp.ChildTarget)
			testutil.Check(t, "siafund pool", cs.SiafundPool, resp.SiafundPool)
		}},

		{"Tip", func(t *testing.T) {
			resp, err := client.Tip()
			if err != nil {
				t.Fatal(err)
			}
			tip, err := e.Tip()
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "tip", tip, resp)
		}},

		{"BlockMetrics", func(t *testing.T) {
			resp, err := client.BlockMetrics()
			if err != nil {
				t.Fatal(err)
			}
			cs := cm.TipState()
			testutil.Check(t, "index", cs.Index, resp.Index)
			testutil.Check(t, "difficulty", cs.Difficulty, resp.Difficulty)
			testutil.Check(t, "siafund pool", cs.SiafundPool, resp.SiafundPool)
			testutil.Check(t, "total hosts", 1, resp.TotalHosts)
			testutil.Check(t, "active contracts", 1, resp.ActiveContracts)
			testutil.Check(t, "failed contracts", 0, resp.FailedContracts)
			testutil.Check(t, "failed contracts", 0, resp.SuccessfulContracts)
			testutil.Check(t, "storage utilization", contractFilesize, resp.StorageUtilization)
			testutil.Check(t, "contract revenue", types.ZeroCurrency, resp.ContractRevenue)
		}},

		{"BlockMetricsID", func(t *testing.T) {
			// block before revision and host announcement
			tip, err := e.BestTip(1)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.BlockMetricsID(tip.ID)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "index", tip, resp.Index)
			// check(t, "difficulty", cs.Difficulty, resp.Difficulty)
			// check(t, "siafund pool", cs.SiafundPool, resp.SiafundPool)
			testutil.Check(t, "total hosts", 0, resp.TotalHosts)
			testutil.Check(t, "active contracts", 1, resp.ActiveContracts)
			testutil.Check(t, "failed contracts", 0, resp.FailedContracts)
			testutil.Check(t, "failed contracts", 0, resp.SuccessfulContracts)
			testutil.Check(t, "storage utilization", contractFilesize, resp.StorageUtilization)
			testutil.Check(t, "contract revenue", types.ZeroCurrency, resp.ContractRevenue)
		}},

		{"Block", func(t *testing.T) {
			tip := cm.Tip()
			parentIndex, err := e.BestTip(tip.Height - 1)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Block(tip.ID)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "height", tip.Height, resp.Height)
			testutil.Check(t, "parent ID", parentIndex.ID, resp.ParentID)
			testutil.Check(t, "nonce", b2.Nonce, resp.Nonce)
			testutil.Check(t, "timestamp", b2.Timestamp.UTC(), resp.Timestamp.UTC())
			testutil.Check(t, "miner payout address", b2.MinerPayouts[0].Address, resp.MinerPayouts[0].SiacoinOutput.Address)
			testutil.Check(t, "miner payout value", b2.MinerPayouts[0].Value, resp.MinerPayouts[0].SiacoinOutput.Value)
			testutil.Check(t, "miner payout source", explorer.SourceMinerPayout, resp.MinerPayouts[0].Source)
			testutil.Check(t, "miner payout spent index", nil, resp.MinerPayouts[0].SpentIndex)

			testutil.Check(t, "len(transactions)", len(b2.Transactions), len(resp.Transactions))
			for i := range b2.Transactions {
				testutil.CheckTransaction(t, b2.Transactions[i], resp.Transactions[i])
			}
		}},

		{"Transaction", func(t *testing.T) {
			resp, err := client.Transaction(txn1.ID())
			if err != nil {
				t.Fatal(err)
			}
			testutil.CheckTransaction(t, txn1, resp)
		}},

		{"Transactions", func(t *testing.T) {
			resp, err := client.Transactions([]types.TransactionID{txn2.ID()})
			if err != nil {
				t.Fatal(err)
			}
			testutil.CheckTransaction(t, txn2, resp[0])
		}},

		{"TransactionChainIndices", func(t *testing.T) {
			resp, err := client.TransactionChainIndices(txn2.ID(), 0, 500)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "len(chainIndices)", 1, len(resp))
			testutil.Check(t, "chain index", cm.Tip(), resp[0])
		}},

		{"AddressSiacoinUTXOs", func(t *testing.T) {
			resp, err := client.AddressSiacoinUTXOs(addr1, 0, 500)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "len(scos)", 1, len(resp))
			testutil.Check(t, "output source", explorer.SourceTransaction, resp[0].Source)
			testutil.Check(t, "output spent index", nil, resp[0].SpentIndex)
			testutil.Check(t, "output address", txn1.SiacoinOutputs[0].Address, resp[0].SiacoinOutput.Address)
			testutil.Check(t, "output value", txn1.SiacoinOutputs[0].Value, resp[0].SiacoinOutput.Value)
		}},

		{"AddressSiacoinUTXOs offset", func(t *testing.T) {
			resp, err := client.AddressSiacoinUTXOs(addr1, 1, 500)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "len(scos)", 0, len(resp))
		}},

		{"AddressSiacoinUTXOs limit", func(t *testing.T) {
			resp, err := client.AddressSiacoinUTXOs(addr1, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "len(scos)", 0, len(resp))
		}},

		{"AddressSiafundUTXOs", func(t *testing.T) {
			resp, err := client.AddressSiafundUTXOs(addr1, 0, 500)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "len(sfos)", 1, len(resp))
			testutil.Check(t, "output spent index", nil, resp[0].SpentIndex)
			testutil.Check(t, "output address", txn2.SiafundOutputs[1].Address, resp[0].SiafundOutput.Address)
			testutil.Check(t, "output value", txn2.SiafundOutputs[1].Value, resp[0].SiafundOutput.Value)
		}},

		{"AddressBalance", func(t *testing.T) {
			resp, err := client.AddressBalance(addr1)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "unspent siacoins", txn1.SiacoinOutputs[0].Value, resp.UnspentSiacoins)
			testutil.Check(t, "immature siacoins", types.ZeroCurrency, resp.ImmatureSiacoins)
			testutil.Check(t, "unspent siafunds", txn2.SiafundOutputs[1].Value, resp.UnspentSiafunds)
		}},

		// There is an issue with JSON unmarshaling of events.
		// TODO: fix when explorer.Events are replaced with wallet.Events
		// {
		// 	resp, err := client.AddressEvents(addr1, 0, 500)
		// 	if err != nil {
		// 		t.Fatal(err)
		// 	}
		// 	if len(resp) == 0 {
		// 		t.Fatal("no events for addr1")
		// 	}
		// }

		{"Contract", func(t *testing.T) {
			resp, err := client.Contract(txn1.FileContractID(0))
			if err != nil {
				t.Fatal(err)
			}
			testutil.CheckFC(t, true, false, false, revFC, resp)
		}},

		{"Contracts", func(t *testing.T) {
			resp, err := client.Contracts([]types.FileContractID{txn1.FileContractID(0)})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "len(contracts)", 1, len(resp))
			testutil.CheckFC(t, true, false, false, revFC, resp[0])
		}},

		{"ContractsKey", func(t *testing.T) {
			resp, err := client.ContractsKey(renterPublicKey)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "len(contracts)", 1, len(resp))
			testutil.CheckFC(t, true, false, false, revFC, resp[0])
		}},

		{"Search siacoin", func(t *testing.T) {
			resp, err := client.Search(types.Hash256(txn1.SiacoinOutputID(0)))
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "search type", explorer.SearchTypeSiacoinElement, resp)
		}},

		{"Search siafund", func(t *testing.T) {
			resp, err := client.Search(types.Hash256(txn2.SiafundOutputID(1)))
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "search type", explorer.SearchTypeSiafundElement, resp)
		}},

		{"Search contract", func(t *testing.T) {
			resp, err := client.Search(types.Hash256(txn1.FileContractID(0)))
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "search type", explorer.SearchTypeContract, resp)
		}},
	}

	for _, subtest := range subtests {
		t.Run(subtest.name, subtest.test)
	}
}
