package sqlite

import (
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	proto4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"lukechampine.com/frand"
)

func TestMetrics(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	assertMetrics := func(expected explorer.Metrics) {
		t.Helper()

		got, err := n.db.Metrics(n.tipState().Index.ID)
		if err != nil {
			t.Fatal(err)
		}

		cs := n.tipState()
		testutil.Equal(t, "Index", cs.Index, got.Index)
		testutil.Equal(t, "Difficulty", cs.Difficulty, got.Difficulty)
		testutil.Equal(t, "SiafundTaxRevenue", cs.SiafundTaxRevenue, got.SiafundTaxRevenue)
		testutil.Equal(t, "NumLeaves", cs.Elements.NumLeaves, got.NumLeaves)
		testutil.Equal(t, "ActiveContracts", expected.ActiveContracts, got.ActiveContracts)
		testutil.Equal(t, "FailedContracts", expected.FailedContracts, got.FailedContracts)
		testutil.Equal(t, "SuccessfulContracts", expected.SuccessfulContracts, got.SuccessfulContracts)
		testutil.Equal(t, "StorageUtilization", expected.StorageUtilization, got.StorageUtilization)
		testutil.Equal(t, "CirculatingSupply", expected.CirculatingSupply, got.CirculatingSupply)
		testutil.Equal(t, "ContractRevenue", expected.ContractRevenue, got.ContractRevenue)
		testutil.Equal(t, "TotalHosts", 0, got.TotalHosts)
	}

	var circulatingSupply types.Currency
	for _, txn := range n.genesis().Transactions {
		for _, sco := range txn.SiacoinOutputs {
			circulatingSupply = circulatingSupply.Add(sco.Value)
		}
	}
	metricsGenesis := explorer.Metrics{
		CirculatingSupply: circulatingSupply,
	}
	assertMetrics(metricsGenesis)

	if subsidy, ok := n.tipState().FoundationSubsidy(); ok {
		circulatingSupply = circulatingSupply.Add(subsidy.Value)
	}
	metrics1 := explorer.Metrics{
		CirculatingSupply: circulatingSupply,
	}

	n.mineTransactions(t)

	assertMetrics(metrics1)

	// form two contracts
	fc := prepareContract(addr1, n.tipState().Index.Height+3)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout.Mul64(2)),
		}},
		FileContracts: []types.FileContract{fc, fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	// funds now locked in contract so circulating supply goes down
	circulatingSupply = circulatingSupply.Sub(fc.Payout.Mul64(2))
	metrics2 := explorer.Metrics{
		ActiveContracts:   2,
		CirculatingSupply: circulatingSupply,
	}
	assertMetrics(metrics2)

	// revise first contract
	fcID := txn1.FileContractID(0)
	fcRevision1 := fc
	fcRevision1.Filesize = proto4.SectorSize
	fcRevision1.RevisionNumber++
	txn2 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fcID,
			UnlockConditions: uc1,
			FileContract:     fcRevision1,
		}},
	}
	signRevisions(n.tipState(), &txn2, pk1)

	n.mineTransactions(t, txn2)

	metrics3 := explorer.Metrics{
		ActiveContracts:    2,
		StorageUtilization: fcRevision1.Filesize,
		CirculatingSupply:  circulatingSupply,
	}
	assertMetrics(metrics3)

	// resolve second contract successfully
	txn3 := types.Transaction{
		StorageProofs: []types.StorageProof{{
			ParentID: txn1.FileContractID(1),
		}},
	}
	n.mineTransactions(t, txn3)

	// valid proof outputs created after proof successful
	var contractRevenue types.Currency
	for _, sco := range fc.ValidProofOutputs {
		circulatingSupply = circulatingSupply.Add(sco.Value)
		contractRevenue = contractRevenue.Add(sco.Value)
	}
	metrics4 := explorer.Metrics{
		ActiveContracts:     1,
		SuccessfulContracts: 1,
		StorageUtilization:  fcRevision1.Filesize,
		CirculatingSupply:   circulatingSupply,
		ContractRevenue:     contractRevenue,
	}
	assertMetrics(metrics4)

	// resolve first contract unsuccessfully
	for i := n.tipState().Index.Height; i < fc.WindowEnd; i++ {
		n.mineTransactions(t)
	}

	// missed proof outputs created after failed resolution
	for _, sco := range fc.MissedProofOutputs {
		circulatingSupply = circulatingSupply.Add(sco.Value)
	}
	metrics5 := explorer.Metrics{
		ActiveContracts:     0,
		SuccessfulContracts: 1,
		FailedContracts:     1,
		CirculatingSupply:   circulatingSupply,
		ContractRevenue:     contractRevenue,
	}
	assertMetrics(metrics5)

	// go back to before failed resolution
	for i := n.tipState().Index.Height; i >= fc.WindowEnd; i-- {
		assertMetrics(metrics5)
		n.revertBlock(t)
	}

	assertMetrics(metrics4)

	n.revertBlock(t)

	assertMetrics(metrics3)

	n.revertBlock(t)

	assertMetrics(metrics2)

	n.revertBlock(t)

	assertMetrics(metrics1)

	n.revertBlock(t)

	assertMetrics(metricsGenesis)
}

func TestMetricsTotalHosts(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	pk2 := types.GeneratePrivateKey()
	pk3 := types.GeneratePrivateKey()

	n := newTestChain(t, false, nil)

	assertMetrics := func(expectedHosts uint64) {
		t.Helper()

		got, err := n.db.Metrics(n.tipState().Index.ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "TotalHosts", expectedHosts, got.TotalHosts)
	}

	// no hosts announced yet
	assertMetrics(0)

	txn1 := types.Transaction{
		ArbitraryData: [][]byte{
			testutil.CreateAnnouncement(pk1, "127.0.0.1:1234"),
		},
	}

	n.mineTransactions(t, txn1)

	n.assertTransactions(t, txn1)
	// 1 host announced in txn1
	assertMetrics(1)

	txn2 := types.Transaction{
		ArbitraryData: [][]byte{
			testutil.CreateAnnouncement(pk1, "127.0.0.1:5678"),
		},
	}

	n.mineTransactions(t, txn2)

	n.assertTransactions(t, txn1, txn2)
	// host announced in txn2 has same pubkey as existing host so count
	// shouldn't go up
	assertMetrics(1)

	txn3 := types.Transaction{
		ArbitraryData: [][]byte{
			testutil.CreateAnnouncement(pk2, "127.0.0.1:8888"),
		},
	}
	txn4 := types.Transaction{
		ArbitraryData: [][]byte{
			testutil.CreateAnnouncement(pk3, "127.0.0.1:9999"),
		},
	}

	n.mineTransactions(t, txn3, txn4)

	n.assertTransactions(t, txn1, txn2, txn3, txn4)
	// 2 hosts with new publickeys announced; 1 + 2 = 3
	assertMetrics(3)

	n.revertBlock(t)

	n.assertTransactions(t, txn1, txn2)
	assertMetrics(1)

	n.revertBlock(t)

	n.assertTransactions(t, txn1)
	assertMetrics(1)

	n.revertBlock(t)

	assertMetrics(0)
}

func TestV2Metrics(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	renterPK := types.GeneratePrivateKey()
	hostPK := types.GeneratePrivateKey()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	assertMetrics := func(expected explorer.Metrics) {
		t.Helper()

		got, err := n.db.Metrics(n.tipState().Index.ID)
		if err != nil {
			t.Fatal(err)
		}

		cs := n.tipState()
		testutil.Equal(t, "Index", cs.Index, got.Index)
		testutil.Equal(t, "Difficulty", cs.Difficulty, got.Difficulty)
		testutil.Equal(t, "SiafundTaxRevenue", cs.SiafundTaxRevenue, got.SiafundTaxRevenue)
		testutil.Equal(t, "NumLeaves", cs.Elements.NumLeaves, got.NumLeaves)
		testutil.Equal(t, "ActiveContracts", expected.ActiveContracts, got.ActiveContracts)
		testutil.Equal(t, "FailedContracts", expected.FailedContracts, got.FailedContracts)
		testutil.Equal(t, "SuccessfulContracts", expected.SuccessfulContracts, got.SuccessfulContracts)
		testutil.Equal(t, "StorageUtilization", expected.StorageUtilization, got.StorageUtilization)
		testutil.Equal(t, "CirculatingSupply", expected.CirculatingSupply, got.CirculatingSupply)
		testutil.Equal(t, "ContractRevenue", expected.ContractRevenue, got.ContractRevenue)
		testutil.Equal(t, "TotalHosts", 0, got.TotalHosts)
	}

	var circulatingSupply types.Currency
	for _, txn := range n.genesis().Transactions {
		for _, sco := range txn.SiacoinOutputs {
			circulatingSupply = circulatingSupply.Add(sco.Value)
		}
	}
	metricsGenesis := explorer.Metrics{
		CirculatingSupply: circulatingSupply,
	}
	assertMetrics(metricsGenesis)

	if subsidy, ok := n.tipState().FoundationSubsidy(); ok {
		circulatingSupply = circulatingSupply.Add(subsidy.Value)
	}
	metrics1 := explorer.Metrics{
		CirculatingSupply: circulatingSupply,
	}

	n.mineTransactions(t)

	assertMetrics(metrics1)

	// form two contracts
	fc, payout := prepareV2Contract(renterPK, hostPK, n.tipState().Index.Height+2)
	fc.Capacity = proto4.SectorSize
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout.Mul64(2)),
		}},
		FileContracts: []types.V2FileContract{fc, fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn1)

	n.mineV2Transactions(t, txn1)

	// funds now locked in contract so circulating supply goes down
	circulatingSupply = circulatingSupply.Sub(payout.Mul64(2))
	metrics2 := explorer.Metrics{
		ActiveContracts:   2,
		CirculatingSupply: circulatingSupply,
	}
	assertMetrics(metrics2)

	// revise first contract
	fcID1 := txn1.V2FileContractID(txn1.ID(), 0)
	fcID2 := txn1.V2FileContractID(txn1.ID(), 1)
	fcRevision1 := fc
	fcRevision1.Filesize = proto4.SectorSize
	fcRevision1.RevisionNumber++
	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.db, fcID1),
			Revision: fcRevision1,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn2)

	n.mineV2Transactions(t, txn2)

	metrics3 := explorer.Metrics{
		ActiveContracts:    2,
		StorageUtilization: fcRevision1.Filesize,
		CirculatingSupply:  circulatingSupply,
	}
	assertMetrics(metrics3)

	// resolve second contract successfully
	sp := &types.V2StorageProof{
		ProofIndex: getCIE(t, n.db, n.tipState().Index.ID),
	}
	txn3 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fcID1),
			Resolution: sp,
		}},
	}
	n.mineV2Transactions(t, txn3)

	// valid proof outputs created after proof successful
	var contractRevenue types.Currency
	contractRevenue = contractRevenue.Add(fc.RenterOutput.Value)
	contractRevenue = contractRevenue.Add(fc.HostOutput.Value)
	circulatingSupply = circulatingSupply.Add(fc.RenterOutput.Value)
	circulatingSupply = circulatingSupply.Add(fc.HostOutput.Value)
	metrics4 := explorer.Metrics{
		ActiveContracts:     1,
		SuccessfulContracts: 1,
		StorageUtilization:  0,
		CirculatingSupply:   circulatingSupply,
		ContractRevenue:     contractRevenue,
	}
	assertMetrics(metrics4)

	// resolve first contract unsuccessfully
	for i := n.tipState().Index.Height; i < fc.ExpirationHeight; i++ {
		n.mineV2Transactions(t)
	}
	txn4 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fcID2),
			Resolution: &types.V2FileContractExpiration{},
		}},
	}
	n.mineV2Transactions(t, txn4)

	// missed proof outputs created after failed resolution
	circulatingSupply = circulatingSupply.Add(fc.RenterOutput.Value)
	circulatingSupply = circulatingSupply.Add(fc.MissedHostOutput().Value)
	metrics5 := explorer.Metrics{
		ActiveContracts:     0,
		SuccessfulContracts: 1,
		FailedContracts:     1,
		CirculatingSupply:   circulatingSupply,
		ContractRevenue:     contractRevenue,
	}
	assertMetrics(metrics5)

	// go back to before failed resolution
	for i := n.tipState().Index.Height; i > fc.ExpirationHeight; i-- {
		assertMetrics(metrics5)
		n.revertBlock(t)
	}
	assertMetrics(metrics4)

	n.revertBlock(t)

	assertMetrics(metrics3)

	n.revertBlock(t)

	assertMetrics(metrics2)

	n.revertBlock(t)

	assertMetrics(metrics1)

	n.revertBlock(t)

	assertMetrics(metricsGenesis)
}

func BenchmarkBlockTimeMetrics(b *testing.B) {
	n := newTestChain(b, false, nil)

	const month = 30 * 24 * time.Hour
	const blockTime = 10 * time.Minute

	now := time.Now().Add(-month)
	err := n.db.transaction(func(tx *txn) error {
		blockStmt, err := tx.Prepare(`INSERT INTO blocks(id, height, parent_id, nonce, timestamp, leaf_index) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer blockStmt.Close()

		var parentID types.BlockID
		nonce, leafIndex := encode(uint64(0)), encode(uint64(0))
		for i := range 500000 {
			if i%10000 == 0 {
				b.Log("Adding block:", i)
			}
			id := types.BlockID(frand.Entropy256())
			if _, err := blockStmt.Exec(encode(id), i, encode(parentID), nonce, encode(now), leafIndex); err != nil {
				b.Fatal(err)
			}

			parentID = id
			now = now.Add(blockTime)
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		blockTimes, err := n.db.BlockTimeMetrics()
		if err != nil {
			b.Fatal(err)
		}
		if blockTimes.Day != blockTime {
			b.Fatalf("expected %v average block time for past day, got %v", blockTime, blockTimes.Day)
		} else if blockTimes.Week != blockTime {
			b.Fatalf("expected %v average block time for past week, got %v", blockTime, blockTimes.Week)
		} else if blockTimes.Month != blockTime {
			b.Fatalf("expected %v average block time for past month, got %v", blockTime, blockTimes.Month)
		}
	}
}
