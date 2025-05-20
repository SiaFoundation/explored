package sqlite_test

import (
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap/zaptest"
)

func syncDB(t *testing.T, db explorer.Store, cm *chain.Manager) {
	t.Helper()

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

func newStore(t *testing.T, v2 bool, f func(*consensus.Network, types.Block)) (*consensus.Network, types.Block, *chain.Manager, explorer.Store) {
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

	var network *consensus.Network
	var genesisBlock types.Block
	if v2 {
		network, genesisBlock = ctestutil.V2Network()
	} else {
		network, genesisBlock = ctestutil.Network()
	}
	if f != nil {
		f(network, genesisBlock)
	}

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock, chain.NewZapMigrationLogger(log.Named("chaindb")))
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)
	syncDB(t, db, cm)

	t.Cleanup(func() {
		db.Close()
		bdb.Close()
	})
	return network, genesisBlock, cm, db
}

// CheckMetrics checks the that the metrics from the DB match what we expect.
func CheckMetrics(t *testing.T, db explorer.Store, cm *chain.Manager, expected explorer.Metrics) {
	t.Helper()

	tip, err := db.Tip()
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.Metrics(tip.ID)
	if err != nil {
		t.Fatal(err)
	}

	testutil.Equal(t, "index", cm.Tip(), got.Index)
	testutil.Equal(t, "difficulty", cm.TipState().Difficulty, got.Difficulty)
	testutil.Equal(t, "total hosts", expected.TotalHosts, got.TotalHosts)
	testutil.Equal(t, "active contracts", expected.ActiveContracts, got.ActiveContracts)
	testutil.Equal(t, "failed contracts", expected.FailedContracts, got.FailedContracts)
	testutil.Equal(t, "successful contracts", expected.SuccessfulContracts, got.SuccessfulContracts)
	testutil.Equal(t, "contract revenue", expected.ContractRevenue, got.ContractRevenue)
	testutil.Equal(t, "storage utilization", expected.StorageUtilization, got.StorageUtilization)
	// don't check circulating supply here because it requires a lot of accounting
}

// CheckChainIndices checks that the chain indices that a transaction was in
// from the explorer match the expected chain indices.
func CheckChainIndices(t *testing.T, db explorer.Store, txnID types.TransactionID, expected []types.ChainIndex) {
	t.Helper()

	indices, err := db.TransactionChainIndices(txnID, 0, 100)
	switch {
	case err != nil:
		t.Fatal(err)
	case len(indices) != len(expected):
		t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
	}
	for i := range indices {
		testutil.Equal(t, "index", expected[i], indices[i])
	}
}

// CheckFCRevisions checks that the revision numbers for the file contracts match.
func CheckFCRevisions(t *testing.T, confirmationIndex types.ChainIndex, confirmationTransactionID types.TransactionID, valid, missed []types.SiacoinOutput, revisionNumbers []uint64, fcs []explorer.ExtendedFileContract) {
	t.Helper()

	testutil.Equal(t, "number of revisions", len(revisionNumbers), len(fcs))
	for i := range revisionNumbers {
		testutil.Equal(t, "revision number", revisionNumbers[i], fcs[i].RevisionNumber)
		testutil.Equal(t, "confirmation index", confirmationIndex, fcs[i].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", confirmationTransactionID, fcs[i].ConfirmationTransactionID)

		testutil.Equal(t, "valid proof outputs", len(valid), len(fcs[i].ValidProofOutputs))
		for j := range valid {
			expected := valid[j]
			got := fcs[i].ValidProofOutputs[j]

			testutil.Equal(t, "id", fcs[i].ID.ValidOutputID(j), got.ID)
			testutil.Equal(t, "value", expected.Value, got.Value)
			testutil.Equal(t, "address", expected.Address, got.Address)
		}

		testutil.Equal(t, "missed proof outputs", len(missed), len(fcs[i].MissedProofOutputs))
		for j := range missed {
			expected := missed[j]
			got := fcs[i].MissedProofOutputs[j]

			testutil.Equal(t, "id", fcs[i].ID.MissedOutputID(j), got.ID)
			testutil.Equal(t, "value", expected.Value, got.Value)
			testutil.Equal(t, "address", expected.Address, got.Address)
		}
	}
}

func checkTransaction(t *testing.T, db explorer.Store, expected types.Transaction) {
	txns, err := db.Transactions([]types.TransactionID{expected.ID()})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(txns)", 1, len(txns))
	testutil.CheckTransaction(t, expected, txns[0])
}

func TestFileContract(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	_, genesisBlock, cm, db := newStore(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	scOutputID := genesisBlock.Transactions[0].SiacoinOutputID(0)
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())

	windowStart := cm.Tip().Height + 10
	windowEnd := windowStart + 10
	fc := testutil.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), windowStart, windowEnd, addr2)
	txn := types.Transaction{
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
	fcID := txn.FileContractID(0)
	testutil.SignTransaction(cm.TipState(), pk1, &txn)

	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	confirmationIndex := cm.Tip()
	confirmationTransactionID := txn.ID()

	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "fcs", 1, len(dbFCs))
		testutil.CheckFC(t, false, false, false, fc, dbFCs[0])
		testutil.Equal(t, "transaction ID", txn.ID(), dbFCs[0].TransactionID)
		testutil.Equal(t, "confirmation index", cm.Tip(), dbFCs[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), dbFCs[0].ConfirmationTransactionID)
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		CheckFCRevisions(t, confirmationIndex, confirmationTransactionID, fc.ValidProofOutputs, fc.MissedProofOutputs, []uint64{0}, dbFCs)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", 1, len(txns))
		testutil.Equal(t, "file contracts", 1, len(txns[0].FileContracts))
		testutil.CheckFC(t, false, false, false, fc, txns[0].FileContracts[0])

		testutil.Equal(t, "transaction ID", txn.ID(), txns[0].FileContracts[0].TransactionID)
		testutil.Equal(t, "confirmation index", cm.Tip(), txns[0].FileContracts[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), txns[0].FileContracts[0].ConfirmationTransactionID)
	}

	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			renterPublicKey.UnlockKey(),
			hostPublicKey.UnlockKey(),
		},
		SignaturesRequired: 2,
	}
	fc.RevisionNumber++
	reviseTxn := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fcID,
			UnlockConditions: uc,
			FileContract:     fc,
		}},
	}
	testutil.SignTransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &reviseTxn)

	prevTip := cm.Tip()
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{reviseTxn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		renterContracts, err := db.ContractsKey(renterPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		hostContracts, err := db.ContractsKey(hostPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
		testutil.Equal(t, "len(contracts)", 1, len(renterContracts))
		testutil.CheckFC(t, false, false, false, fc, renterContracts[0])
		testutil.CheckFC(t, false, false, false, fc, hostContracts[0])

		testutil.Equal(t, "transaction ID", reviseTxn.ID(), renterContracts[0].TransactionID)
		testutil.Equal(t, "transaction ID", reviseTxn.ID(), hostContracts[0].TransactionID)
		testutil.Equal(t, "confirmation index", prevTip, renterContracts[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), renterContracts[0].ConfirmationTransactionID)
		testutil.Equal(t, "confirmation index", prevTip, hostContracts[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), hostContracts[0].ConfirmationTransactionID)
	}

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    1,
		StorageUtilization: testutil.ContractFilesize,
	})

	// Explorer.Contracts should return latest revision
	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "fcs", 1, len(dbFCs))
		testutil.CheckFC(t, false, false, false, fc, dbFCs[0])
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		CheckFCRevisions(t, confirmationIndex, confirmationTransactionID, fc.ValidProofOutputs, fc.MissedProofOutputs, []uint64{0, 1}, dbFCs)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", 1, len(txns))
		testutil.Equal(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Equal(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Equal(t, "unlock conditions", uc, fcr.UnlockConditions)

		testutil.Equal(t, "confirmation index", prevTip, fcr.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), fcr.ConfirmationTransactionID)

		testutil.CheckFC(t, false, false, false, fc, fcr.ExtendedFileContract)
	}

	for i := cm.Tip().Height; i < windowEnd; i++ {
		CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    1,
			StorageUtilization: 1 * testutil.ContractFilesize,
		})

		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:          0,
		ActiveContracts:     0,
		FailedContracts:     1,
		SuccessfulContracts: 0,
		StorageUtilization:  0,
	})

	{
		events, err := db.AddressEvents(addr2, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 3, len(events))

		ev0 := events[0].Data.(explorer.EventV1ContractResolution)
		testutil.Equal(t, "event 0 parent ID", fcID, ev0.Parent.ID)
		testutil.Equal(t, "event 0 output ID", fcID.MissedOutputID(0), ev0.SiacoinElement.ID)
		testutil.Equal(t, "event 0 output source", explorer.SourceMissedProofOutput, ev0.SiacoinElement.Source)
		testutil.Equal(t, "event 0 missed", true, ev0.Missed)

		ev1 := events[1].Data.(explorer.EventV1Transaction)
		testutil.CheckTransaction(t, reviseTxn, ev1.Transaction)

		ev2 := events[2].Data.(explorer.EventV1Transaction)
		testutil.CheckTransaction(t, txn, ev2.Transaction)
	}

	{
		events, err := db.Events([]types.Hash256{types.Hash256(reviseTxn.ID()), types.Hash256(txn.ID())})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 2, len(events))

		ev0 := events[0].Data.(explorer.EventV1Transaction)
		testutil.CheckTransaction(t, reviseTxn, ev0.Transaction)

		ev1 := events[1].Data.(explorer.EventV1Transaction)
		testutil.CheckTransaction(t, txn, ev1.Transaction)
	}

	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "fcs", 1, len(dbFCs))
		testutil.CheckFC(t, false, true, false, fc, dbFCs[0])

		testutil.Equal(t, "confirmation index", prevTip, dbFCs[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), dbFCs[0].ConfirmationTransactionID)
	}

	for i := 0; i < 100; i++ {
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	{
		renterContracts, err := db.ContractsKey(renterPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		hostContracts, err := db.ContractsKey(hostPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
		testutil.Equal(t, "len(contracts)", 1, len(renterContracts))
		testutil.CheckFC(t, false, true, false, fc, renterContracts[0])
		testutil.CheckFC(t, false, true, false, fc, hostContracts[0])

		testutil.Equal(t, "transaction ID", reviseTxn.ID(), renterContracts[0].TransactionID)
		testutil.Equal(t, "transaction ID", reviseTxn.ID(), hostContracts[0].TransactionID)
		testutil.Equal(t, "confirmation index", prevTip, renterContracts[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), renterContracts[0].ConfirmationTransactionID)
		testutil.Equal(t, "confirmation index", prevTip, hostContracts[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), hostContracts[0].ConfirmationTransactionID)
	}

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:          0,
		ActiveContracts:     0,
		FailedContracts:     1,
		SuccessfulContracts: 0,
		StorageUtilization:  0,
	})
}

func TestHostAnnouncement(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	pk3 := types.GeneratePrivateKey()

	_, genesisBlock, cm, db := newStore(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})

	hostPubkeys := func(pks []types.PublicKey) ([]explorer.Host, error) {
		return db.QueryHosts(explorer.HostQuery{PublicKeys: pks}, explorer.HostSortPublicKey, explorer.HostSortAsc, 0, math.MaxInt64)
	}

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         genesisBlock.Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   genesisBlock.Transactions[0].SiacoinOutputs[0].Value,
		}},
		ArbitraryData: [][]byte{
			testutil.CreateAnnouncement(pk1, "127.0.0.1:1234"),
		},
	}
	testutil.SignTransaction(cm.TipState(), pk1, &txn1)

	// Mine a block containing host announcement
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         1,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	txn2 := types.Transaction{
		ArbitraryData: [][]byte{
			testutil.CreateAnnouncement(pk1, "127.0.0.1:5678"),
		},
	}
	txn3 := types.Transaction{
		ArbitraryData: [][]byte{
			testutil.CreateAnnouncement(pk2, "127.0.0.1:9999"),
		},
	}
	txn4 := types.Transaction{
		ArbitraryData: [][]byte{
			testutil.CreateAnnouncement(pk3, "127.0.0.1:9999"),
		},
	}

	// Mine a block containing host announcement
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{txn2, txn3, txn4}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         3,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	{
		b, err := db.Block(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 3, len(b.Transactions))
		testutil.Equal(t, "txns[0].ID", txn2.ID(), b.Transactions[0].ID)
		testutil.Equal(t, "txns[1].ID", txn3.ID(), b.Transactions[1].ID)
		testutil.Equal(t, "txns[2].ID", txn4.ID(), b.Transactions[2].ID)
	}

	checkTransaction(t, db, txn1)
	checkTransaction(t, db, txn2)
	checkTransaction(t, db, txn3)
	checkTransaction(t, db, txn4)

	{
		events, err := db.AddressEvents(addr1, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 2, len(events))
		testutil.CheckTransaction(t, txn1, events[0].Data.(explorer.EventV1Transaction).Transaction)
		testutil.CheckTransaction(t, genesisBlock.Transactions[0], events[1].Data.(explorer.EventV1Transaction).Transaction)
	}

	checkTransaction(t, db, txn1)
	checkTransaction(t, db, txn2)
	checkTransaction(t, db, txn3)

	hosts, err := db.HostsForScanning(time.Unix(0, 0), 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(hosts)", 3, len(hosts))

	{
		scans, err := hostPubkeys([]types.PublicKey{hosts[0].PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(scans)", 1, len(scans))
	}

	scan1 := explorer.HostScan{
		PublicKey: hosts[0].PublicKey,
		Success:   true,
		Timestamp: time.Now(),
	}
	scan2 := explorer.HostScan{
		PublicKey: hosts[0].PublicKey,
		Success:   false,
		Timestamp: time.Now(),
		Error: func() *string {
			x := "error"
			return &x
		}(),
	}

	{
		if err := db.AddHostScans([]explorer.HostScan{scan1}...); err != nil {
			t.Fatal(err)
		}

		scans, err := hostPubkeys([]types.PublicKey{hosts[0].PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(scans)", 1, len(scans))

		scan := scans[0]
		testutil.Equal(t, "last scan", scan1.Timestamp.Unix(), scan.LastScan.Unix())
		testutil.Equal(t, "last scan successful", scan1.Success, scan.LastScanSuccessful)
		testutil.Equal(t, "total scans", 1, scan.TotalScans)
		testutil.Equal(t, "successful interactions", 1, scan.SuccessfulInteractions)
		testutil.Equal(t, "failed interactions", 0, scan.FailedInteractions)
	}

	{
		if err := db.AddHostScans([]explorer.HostScan{scan2}...); err != nil {
			t.Fatal(err)
		}

		scans, err := hostPubkeys([]types.PublicKey{hosts[0].PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(scans)", 1, len(scans))

		scan := scans[0]
		testutil.Equal(t, "last scan", scan2.Timestamp.Unix(), scan.LastScan.Unix())
		testutil.Equal(t, "last scan successful", scan2.Success, scan.LastScanSuccessful)
		testutil.Equal(t, "total scans", 2, scan.TotalScans)
		testutil.Equal(t, "successful interactions", 1, scan.SuccessfulInteractions)
		testutil.Equal(t, "failed interactions", 1, scan.FailedInteractions)
	}
}

func TestMultipleReorgFileContract(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	_, genesisBlock, cm, db := newStore(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisState := cm.TipState()
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	scOutputID := genesisBlock.Transactions[0].SiacoinOutputID(0)
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())

	windowStart := cm.Tip().Height + 10
	windowEnd := windowStart + 10
	fc := testutil.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), windowStart, windowEnd, types.VoidAddress)
	txn := types.Transaction{
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
	fcID := txn.FileContractID(0)
	testutil.SignTransaction(cm.TipState(), pk1, &txn)

	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	confirmationIndex := cm.Tip()
	confirmationTransactionID := txn.ID()

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    1,
		StorageUtilization: testutil.ContractFilesize,
	})

	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "fcs", 1, len(dbFCs))
		testutil.CheckFC(t, false, false, false, fc, dbFCs[0])

		testutil.Equal(t, "confirmation index", cm.Tip(), dbFCs[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), dbFCs[0].ConfirmationTransactionID)
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		CheckFCRevisions(t, confirmationIndex, confirmationTransactionID, fc.ValidProofOutputs, fc.MissedProofOutputs, []uint64{0}, dbFCs)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", 1, len(txns))
		testutil.Equal(t, "file contracts", 1, len(txns[0].FileContracts))
		testutil.CheckFC(t, false, false, false, fc, txns[0].FileContracts[0])
	}

	{
		events, err := db.AddressEvents(addr1, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 2, len(events))
		testutil.CheckTransaction(t, txn, events[0].Data.(explorer.EventV1Transaction).Transaction)
		testutil.CheckTransaction(t, genesisBlock.Transactions[0], events[1].Data.(explorer.EventV1Transaction).Transaction)
	}

	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			renterPublicKey.UnlockKey(),
			hostPublicKey.UnlockKey(),
		},
		SignaturesRequired: 2,
	}
	revFC := fc
	// add 10 bytes to filesize and increment revision number
	revFC.Filesize += 10
	revFC.RevisionNumber++
	reviseTxn := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fcID,
			UnlockConditions: uc,
			FileContract:     revFC,
		}},
	}
	testutil.SignTransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &reviseTxn)

	// state before revision
	prevState1 := cm.TipState()
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{reviseTxn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)
	prevState2 := cm.TipState()

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    1,
		StorageUtilization: testutil.ContractFilesize + 10,
	})

	// Explorer.Contracts should return latest revision
	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "fcs", 1, len(dbFCs))
		testutil.CheckFC(t, false, false, false, revFC, dbFCs[0])

		testutil.Equal(t, "transaction ID", reviseTxn.ID(), dbFCs[0].TransactionID)
		testutil.Equal(t, "confirmation index", prevState1.Index, dbFCs[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), dbFCs[0].ConfirmationTransactionID)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", 1, len(txns))
		testutil.Equal(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Equal(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Equal(t, "unlock conditions", uc, fcr.UnlockConditions)

		testutil.CheckFC(t, false, false, false, revFC, fcr.ExtendedFileContract)
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		CheckFCRevisions(t, confirmationIndex, confirmationTransactionID, fc.ValidProofOutputs, fc.MissedProofOutputs, []uint64{0, 1}, dbFCs)
	}

	{
		renterContracts, err := db.ContractsKey(renterPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		hostContracts, err := db.ContractsKey(hostPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
		testutil.Equal(t, "len(contracts)", 1, len(renterContracts))
		testutil.Equal(t, "transaction ID", reviseTxn.ID(), renterContracts[0].TransactionID)
		testutil.Equal(t, "transaction ID", reviseTxn.ID(), hostContracts[0].TransactionID)
		testutil.CheckFC(t, false, false, false, revFC, renterContracts[0])
		testutil.CheckFC(t, false, false, false, revFC, hostContracts[0])
	}

	extra := cm.Tip().Height - prevState1.Index.Height + 1
	for reorg := uint64(0); reorg < 2; reorg++ {
		// revert the revision
		{
			var blocks []types.Block
			state := prevState1
			for i := uint64(0); i < reorg+extra; i++ {
				pk := types.GeneratePrivateKey()
				addr := types.StandardUnlockHash(pk.PublicKey())

				blocks = append(blocks, testutil.MineBlock(state, nil, addr))
				state.Index.ID = blocks[len(blocks)-1].ID()
				state.Index.Height++
			}
			if err := cm.AddBlocks(blocks); err != nil {
				t.Fatal(err)
			}
			syncDB(t, db, cm)
		}

		// we should be back in state before the revision
		{
			dbFCs, err := db.Contracts([]types.FileContractID{fcID})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "fcs", 1, len(dbFCs))
			testutil.CheckFC(t, false, false, false, fc, dbFCs[0])

			testutil.Equal(t, "transaction ID", txn.ID(), dbFCs[0].TransactionID)
			testutil.Equal(t, "confirmation index", prevState1.Index, dbFCs[0].ConfirmationIndex)
			testutil.Equal(t, "confirmation transaction ID", txn.ID(), dbFCs[0].ConfirmationTransactionID)
		}

		{
			dbFCs, err := db.ContractRevisions(fcID)
			if err != nil {
				t.Fatal(err)
			}
			CheckFCRevisions(t, confirmationIndex, confirmationTransactionID, fc.ValidProofOutputs, fc.MissedProofOutputs, []uint64{0}, dbFCs)
		}

		// storage utilization should be back to testutil.ContractFilesize instead of
		// testutil.ContractFilesize + 10
		CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    1,
			StorageUtilization: testutil.ContractFilesize,
		})
	}

	extra = cm.Tip().Height - prevState2.Index.Height + 1
	for reorg := uint64(0); reorg < 2; reorg++ {
		// bring the revision back
		{
			var blocks []types.Block
			state := prevState2
			for i := uint64(0); i < reorg+extra; i++ {
				pk := types.GeneratePrivateKey()
				addr := types.StandardUnlockHash(pk.PublicKey())

				blocks = append(blocks, testutil.MineBlock(state, nil, addr))
				state.Index.ID = blocks[len(blocks)-1].ID()
				state.Index.Height++
			}
			if err := cm.AddBlocks(blocks); err != nil {
				t.Fatal(err)
			}
			syncDB(t, db, cm)
		}

		// revision should be applied
		{
			dbFCs, err := db.Contracts([]types.FileContractID{fcID})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "fcs", 1, len(dbFCs))
			testutil.CheckFC(t, false, false, false, revFC, dbFCs[0])

			testutil.Equal(t, "transaction ID", reviseTxn.ID(), dbFCs[0].TransactionID)
			testutil.Equal(t, "confirmation index", prevState1.Index, dbFCs[0].ConfirmationIndex)
			testutil.Equal(t, "confirmation transaction ID", txn.ID(), dbFCs[0].ConfirmationTransactionID)
		}

		// should have revision filesize
		CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    1,
			StorageUtilization: testutil.ContractFilesize + 10,
		})
	}

	extra = cm.Tip().Height - genesisState.Index.Height + 1
	for reorg := uint64(0); reorg < 2; reorg++ {
		{
			var blocks []types.Block
			state := genesisState
			for i := uint64(0); i < reorg+extra; i++ {
				pk := types.GeneratePrivateKey()
				addr := types.StandardUnlockHash(pk.PublicKey())

				blocks = append(blocks, testutil.MineBlock(state, nil, addr))
				state.Index.ID = blocks[len(blocks)-1].ID()
				state.Index.Height++
			}
			if err := cm.AddBlocks(blocks); err != nil {
				t.Fatal(err)
			}
			syncDB(t, db, cm)
		}

		// contract should no longer exist
		{
			dbFCs, err := db.Contracts([]types.FileContractID{fcID})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "fcs", 0, len(dbFCs))
		}

		{
			renterContracts, err := db.ContractsKey(renterPublicKey)
			if err != nil {
				t.Fatal(err)
			}
			hostContracts, err := db.ContractsKey(hostPublicKey)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
			testutil.Equal(t, "len(contracts)", 0, len(renterContracts))
		}

		{
			_, err := db.ContractRevisions(fcID)
			if err != explorer.ErrContractNotFound {
				t.Fatal(err)
			}
		}

		// no more contracts or storage utilization
		CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts: 0,
		})
	}

	{
		events, err := db.AddressEvents(addr1, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 1, len(events))
		testutil.CheckTransaction(t, genesisBlock.Transactions[0], events[0].Data.(explorer.EventV1Transaction).Transaction)
	}
}
