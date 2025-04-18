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

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
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

func TestBalance(t *testing.T) {
	_, _, cm, db := newStore(t, false, nil)

	// Generate three addresses: addr1, addr2, addr3
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	pk3 := types.GeneratePrivateKey()
	addr3 := types.StandardUnlockHash(pk3.PublicKey())

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()

	// Mine a block sending the payout to addr1
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, addr1)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "utxos", 1, len(utxos))
	testutil.Equal(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	testutil.Equal(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

	{
		events, err := db.AddressEvents(addr1, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 1, len(events))

		ev0 := events[0].Data.(explorer.EventPayout)
		testutil.Equal(t, "event 0 output ID", cm.Tip().ID.MinerOutputID(0), ev0.SiacoinElement.ID)
		testutil.Equal(t, "event 0 output source", explorer.SourceMinerPayout, ev0.SiacoinElement.Source)
	}

	// Mine until the payout matures
	for i := cm.Tip().Height; i < maturityHeight; i++ {
		testutil.CheckBalance(t, db, addr1, types.ZeroCurrency, expectedPayout, 0)
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	testutil.CheckBalance(t, db, addr1, expectedPayout, types.ZeroCurrency, 0)

	// Send all of the payout except 100 SC to addr2
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())
	parentTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         utxos[0].ID,
				UnlockConditions: unlockConditions,
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr1, Value: types.Siacoins(100)},
			{Address: addr2, Value: utxos[0].SiacoinOutput.Value.Sub(types.Siacoins(100))},
		},
	}
	testutil.SignTransaction(cm.TipState(), pk1, &parentTxn)

	// In the same block, have addr1 send the 100 SC it still has left to
	// addr3
	outputID := parentTxn.SiacoinOutputID(0)
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         outputID,
				UnlockConditions: unlockConditions,
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr3, Value: types.Siacoins(100)},
		},
	}
	testutil.SignTransaction(cm.TipState(), pk1, &txn)

	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{parentTxn, txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	testutil.CheckBalance(t, db, addr2, utxos[0].SiacoinOutput.Value.Sub(types.Siacoins(100)), types.ZeroCurrency, 0)
	testutil.CheckBalance(t, db, addr3, types.Siacoins(100), types.ZeroCurrency, 0)
}

func TestSiafundBalance(t *testing.T) {
	// Generate three addresses: addr1, addr2, addr3
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	pk3 := types.GeneratePrivateKey()
	addr3 := types.StandardUnlockHash(pk3.PublicKey())

	_, genesisBlock, cm, db := newStore(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	giftSF := genesisBlock.Transactions[0].SiafundOutputs[0].Value

	// Send all of the payout except 100 SF to addr2
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())
	parentTxn := types.Transaction{
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         genesisBlock.Transactions[0].SiafundOutputID(0),
				UnlockConditions: unlockConditions,
			},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: addr1, Value: 100},
			{Address: addr2, Value: genesisBlock.Transactions[0].SiafundOutputs[0].Value - 100},
		},
	}
	testutil.SignTransaction(cm.TipState(), pk1, &parentTxn)

	// In the same block, have addr1 send the 100 SF it still has left to
	// addr3
	outputID := parentTxn.SiafundOutputID(0)
	txn := types.Transaction{
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         outputID,
				UnlockConditions: unlockConditions,
			},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: addr3, Value: 100},
		},
	}
	testutil.SignTransaction(cm.TipState(), pk1, &txn)

	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{parentTxn, txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	testutil.CheckBalance(t, db, addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
	testutil.CheckBalance(t, db, addr2, types.ZeroCurrency, types.ZeroCurrency, giftSF-100)
	testutil.CheckBalance(t, db, addr3, types.ZeroCurrency, types.ZeroCurrency, 100)
}

func TestSendTransactions(t *testing.T) {
	// Generate three addresses: addr1, addr2, addr3
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	pk3 := types.GeneratePrivateKey()
	addr3 := types.StandardUnlockHash(pk3.PublicKey())

	_, genesisBlock, cm, db := newStore(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	giftSF := genesisBlock.Transactions[0].SiafundOutputs[0].Value

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()

	// Mine a block sending the payout to the addr1
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, addr1)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	// Mine until the payout matures
	for i := cm.Tip().Height; i < maturityHeight; i++ {
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	testutil.CheckBalance(t, db, addr1, expectedPayout, types.ZeroCurrency, giftSF)
	testutil.CheckBalance(t, db, addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
	testutil.CheckBalance(t, db, addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

	const n = 100

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, 0, n)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "utxos", 1, len(utxos))
	testutil.Equal(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	testutil.Equal(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

	sfOutputID := genesisBlock.Transactions[0].SiafundOutputID(0)
	scOutputID := utxos[0].ID
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())
	// Send 1 SC to addr2 and 2 SC to addr3 100 times in consecutive blocks
	for i := 0; i < n; i++ {
		addr1SCs := expectedPayout.Sub(types.Siacoins(1 + 2).Mul64(uint64(i + 1)))
		addr1SFs := giftSF - (1+2)*uint64(i+1)

		parentTxn := types.Transaction{
			SiacoinInputs: []types.SiacoinInput{
				{
					ParentID:         scOutputID,
					UnlockConditions: unlockConditions,
				},
			},
			SiafundInputs: []types.SiafundInput{
				{
					ParentID:         sfOutputID,
					UnlockConditions: unlockConditions,
				},
			},
			SiacoinOutputs: []types.SiacoinOutput{
				{Address: addr2, Value: types.Siacoins(1)},
				{Address: addr3, Value: types.Siacoins(2)},
				{Address: addr1, Value: addr1SCs},
			},
			SiafundOutputs: []types.SiafundOutput{
				{Address: addr2, Value: 1},
				{Address: addr3, Value: 2},
				{Address: addr1, Value: addr1SFs},
			},
		}

		testutil.SignTransaction(cm.TipState(), pk1, &parentTxn)
		scOutputID = parentTxn.SiacoinOutputID(2)
		sfOutputID = parentTxn.SiafundOutputID(2)

		// Mine a block with the above transaction
		b := testutil.MineBlock(cm.TipState(), []types.Transaction{parentTxn}, types.VoidAddress)
		if err := cm.AddBlocks([]types.Block{b}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		CheckMetrics(t, db, cm, explorer.Metrics{})

		testutil.CheckBalance(t, db, addr1, addr1SCs, types.ZeroCurrency, addr1SFs)
		testutil.CheckBalance(t, db, addr2, types.Siacoins(1).Mul64(uint64(i+1)), types.ZeroCurrency, 1*uint64(i+1))
		testutil.CheckBalance(t, db, addr3, types.Siacoins(2).Mul64(uint64(i+1)), types.ZeroCurrency, 2*uint64(i+1))

		// Ensure the block we retrieved from the database is the same as the
		// actual block
		block, err := db.Block(b.ID())
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", len(b.Transactions), len(block.Transactions))
		testutil.Equal(t, "miner payouts", len(b.MinerPayouts), len(block.MinerPayouts))
		testutil.Equal(t, "nonce", b.Nonce, block.Nonce)
		testutil.Equal(t, "timestamp", b.Timestamp, block.Timestamp)

		// Ensure the miner payouts in the block match
		for i := range b.MinerPayouts {
			testutil.Equal(t, "address", b.MinerPayouts[i].Address, b.MinerPayouts[i].Address)
			testutil.Equal(t, "value", b.MinerPayouts[i].Value, b.MinerPayouts[i].Value)
		}

		// Ensure the transactions in the block and retrieved separately match
		// with the actual transactions
		for i := range b.Transactions {
			testutil.CheckTransaction(t, b.Transactions[i], block.Transactions[i])
			CheckChainIndices(t, db, b.Transactions[i].ID(), []types.ChainIndex{cm.Tip()})

			txns, err := db.Transactions([]types.TransactionID{b.Transactions[i].ID()})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "transactions", 1, len(txns))
			testutil.CheckTransaction(t, b.Transactions[i], txns[0])
		}

		type expectedUTXOs struct {
			addr types.Address

			sc      int
			scValue types.Currency

			sf      int
			sfValue uint64
		}
		expected := []expectedUTXOs{
			{addr1, 1, addr1SCs, 1, addr1SFs},
			{addr2, i + 1, types.Siacoins(1), i + 1, 1},
			{addr3, i + 1, types.Siacoins(2), i + 1, 2},
		}
		for _, e := range expected {
			sc, err := db.UnspentSiacoinOutputs(e.addr, 0, n)
			if err != nil {
				t.Fatal(err)
			}
			sf, err := db.UnspentSiafundOutputs(e.addr, 0, n)
			if err != nil {
				t.Fatal(err)
			}

			testutil.Equal(t, "sc utxos", e.sc, len(sc))
			testutil.Equal(t, "sf utxos", e.sf, len(sf))

			for _, sco := range sc {
				testutil.Equal(t, "address", e.addr, sco.SiacoinOutput.Address)
				testutil.Equal(t, "value", e.scValue, sco.SiacoinOutput.Value)
				testutil.Equal(t, "source", explorer.SourceTransaction, sco.Source)
			}
			for _, sfo := range sf {
				testutil.Equal(t, "address", e.addr, sfo.SiafundOutput.Address)
				testutil.Equal(t, "value", e.sfValue, sfo.SiafundOutput.Value)
			}
		}
	}
}

func TestTip(t *testing.T) {
	_, _, cm, db := newStore(t, false, nil)

	const n = 100
	for i := cm.Tip().Height; i < n; i++ {
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		tip, err := db.Tip()
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "tip", cm.Tip(), tip)
	}

	for i := 0; i < n; i++ {
		best, err := db.BestTip(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if cmBest, ok := cm.BestIndex(uint64(i)); !ok || cmBest != best {
			t.Fatal("best tip mismatch")
		}
	}
}

func TestMissingBlock(t *testing.T) {
	_, _, cm, db := newStore(t, false, nil)

	id := cm.Tip().ID
	_, err := db.Block(id)
	if err != nil {
		t.Fatalf("error retrieving genesis block: %v", err)
	}

	id[0] ^= 255
	_, err = db.Block(id)
	if !errors.Is(err, explorer.ErrNoBlock) {
		t.Fatalf("did not get ErrNoBlock retrieving missing block: %v", err)
	}
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

func TestEphemeralFileContract(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

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

	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			renterPublicKey.UnlockKey(),
			hostPublicKey.UnlockKey(),
		},
		SignaturesRequired: 2,
	}
	revisedFC1 := fc
	revisedFC1.RevisionNumber++
	reviseTxn1 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fcID,
			UnlockConditions: uc,
			FileContract:     revisedFC1,
		}},
	}
	testutil.SignTransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &reviseTxn1)

	// Create a contract and revise it in the same block
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{txn, reviseTxn1}, types.VoidAddress)}); err != nil {
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
		testutil.CheckFC(t, true, false, false, revisedFC1, renterContracts[0])
		testutil.CheckFC(t, true, false, false, revisedFC1, hostContracts[0])
	}

	// Explorer.Contracts should return latest revision
	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "fcs", 1, len(dbFCs))
		testutil.CheckFC(t, true, false, false, revisedFC1, dbFCs[0])
		testutil.Equal(t, "transaction ID", reviseTxn1.ID(), dbFCs[0].TransactionID)
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		CheckFCRevisions(t, confirmationIndex, confirmationTransactionID, fc.ValidProofOutputs, fc.MissedProofOutputs, []uint64{0, 1}, dbFCs)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", 1, len(txns))
		testutil.Equal(t, "file contracts", 1, len(txns[0].FileContracts))
		testutil.CheckFC(t, true, false, false, fc, txns[0].FileContracts[0])

		testutil.Equal(t, "transaction ID", txn.ID(), txns[0].FileContracts[0].TransactionID)
		testutil.Equal(t, "confirmation index", cm.Tip(), txns[0].FileContracts[0].ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn.ID(), txns[0].FileContracts[0].ConfirmationTransactionID)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", 1, len(txns))
		testutil.Equal(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Equal(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Equal(t, "unlock conditions", uc, fcr.UnlockConditions)

		testutil.CheckFC(t, true, false, false, revisedFC1, fcr.ExtendedFileContract)
	}

	revisedFC2 := revisedFC1
	revisedFC2.RevisionNumber++
	reviseTxn2 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fcID,
			UnlockConditions: uc,
			FileContract:     revisedFC2,
		}},
	}
	testutil.SignTransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &reviseTxn2)

	revisedFC3 := revisedFC2
	revisedFC3.RevisionNumber++
	reviseTxn3 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fcID,
			UnlockConditions: uc,
			FileContract:     revisedFC3,
		}},
	}
	testutil.SignTransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &reviseTxn3)

	// Two more revisions of the same contract in the next block
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{reviseTxn2, reviseTxn3}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

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
		testutil.CheckFC(t, true, false, false, revisedFC3, dbFCs[0])
		testutil.Equal(t, "transaction ID", reviseTxn3.ID(), dbFCs[0].TransactionID)
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		CheckFCRevisions(t, confirmationIndex, confirmationTransactionID, fc.ValidProofOutputs, fc.MissedProofOutputs, []uint64{0, 1, 2, 3}, dbFCs)
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
		testutil.CheckFC(t, true, false, false, revisedFC3, renterContracts[0])
		testutil.CheckFC(t, true, false, false, revisedFC3, hostContracts[0])
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", 1, len(txns))
		testutil.Equal(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Equal(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Equal(t, "unlock conditions", uc, fcr.UnlockConditions)
		testutil.CheckFC(t, true, false, false, revisedFC2, fcr.ExtendedFileContract)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn3.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", 1, len(txns))
		testutil.Equal(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Equal(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Equal(t, "unlock conditions", uc, fcr.UnlockConditions)
		testutil.CheckFC(t, true, false, false, revisedFC3, fcr.ExtendedFileContract)
	}
}

func TestRevertTip(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	_, _, cm, db := newStore(t, false, nil)
	genesisState := cm.TipState()

	const n = 100
	for i := cm.Tip().Height; i < n; i++ {
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, addr1)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		tip, err := db.Tip()
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "tip", cm.Tip(), tip)
	}

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	{
		// mine to trigger a reorg
		var blocks []types.Block
		state := genesisState
		for i := uint64(0); i < n+5; i++ {
			blocks = append(blocks, testutil.MineBlock(state, nil, addr2))
			state.Index.ID = blocks[len(blocks)-1].ID()
			state.Index.Height++
		}
		if err := cm.AddBlocks(blocks); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		tip, err := db.Tip()
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "tip", cm.Tip(), tip)
	}

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	for i := 0; i < n; i++ {
		best, err := db.BestTip(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if cmBest, ok := cm.BestIndex(uint64(i)); !ok || cmBest != best {
			t.Fatal("best tip mismatch")
		}
	}
}

func TestRevertBalance(t *testing.T) {
	// Generate three addresses: addr1, addr2, addr3
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	pk3 := types.GeneratePrivateKey()
	addr3 := types.StandardUnlockHash(pk3.PublicKey())

	_, _, cm, db := newStore(t, false, nil)
	genesisState := cm.TipState()

	// t.Log("addr1:", addr1)
	// t.Log("addr2:", addr2)
	// t.Log("addr3:", addr3)

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()

	// Mine a block sending the payout to addr1
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, addr1)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "utxos", 1, len(utxos))
	testutil.Equal(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	testutil.Equal(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

	{
		// Mine to trigger a reorg
		// Send payout to addr2 instead of addr1 for these blocks
		var blocks []types.Block
		state := genesisState
		for i := uint64(0); i < 2; i++ {
			blocks = append(blocks, testutil.MineBlock(state, nil, addr2))
			state.Index.ID = blocks[len(blocks)-1].ID()
			state.Index.Height++
		}
		if err := cm.AddBlocks(blocks); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	// Mine until the payout matures
	for i := cm.Tip().Height; i < maturityHeight; i++ {
		testutil.CheckBalance(t, db, addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
		testutil.CheckBalance(t, db, addr2, types.ZeroCurrency, expectedPayout.Mul64(2), 0)
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    0,
			StorageUtilization: 0,
		})
	}
	testutil.CheckBalance(t, db, addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
	testutil.CheckBalance(t, db, addr2, expectedPayout.Mul64(1), expectedPayout.Mul64(1), 0)

	utxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "addr1 utxos", 0, len(utxos1))

	utxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "addr2 utxos", 2, len(utxos2))
	for _, utxo := range utxos2 {
		testutil.Equal(t, "value", expectedPayout, utxo.SiacoinOutput.Value)
		testutil.Equal(t, "source", explorer.SourceMinerPayout, utxo.Source)
	}

	// Send all of the payout except 100 SC to addr3
	hundredSC := types.Siacoins(100)
	unlockConditions := types.StandardUnlockConditions(pk2.PublicKey())
	parentTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         utxos2[0].ID,
				UnlockConditions: unlockConditions,
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr2, Value: hundredSC},
			{Address: addr3, Value: utxos2[0].SiacoinOutput.Value.Sub(hundredSC)},
		},
	}
	testutil.SignTransaction(cm.TipState(), pk2, &parentTxn)

	// In the same block, have addr2 send the 100 SC it still has left to
	// addr1
	outputID := parentTxn.SiacoinOutputID(0)
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         outputID,
				UnlockConditions: unlockConditions,
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr1, Value: hundredSC},
		},
	}
	testutil.SignTransaction(cm.TipState(), pk2, &txn)

	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{parentTxn, txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		b, err := db.Block(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "spent_index", *b.Transactions[0].SiacoinOutputs[0].SpentIndex, cm.Tip())
		testutil.Equal(t, "spent_index", b.Transactions[1].SiacoinOutputs[0].SpentIndex, (*types.ChainIndex)(nil))
	}

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	testutil.CheckBalance(t, db, addr1, hundredSC, types.ZeroCurrency, 0)
	// second block added in reorg has now matured
	testutil.CheckBalance(t, db, addr2, utxos2[1].SiacoinOutput.Value, types.ZeroCurrency, 0)
	testutil.CheckBalance(t, db, addr3, utxos2[0].SiacoinOutput.Value.Sub(hundredSC), types.ZeroCurrency, 0)

	{
		// Reorg everything from before
		// Send payout to void instead of addr2 for these blocks except for
		// the first block where the payout goes to addr1, and the second block
		// where the payout goes to addr2.
		var blocks []types.Block
		state := genesisState
		for i := uint64(0); i < maturityHeight+10; i++ {
			addr := types.VoidAddress
			if i == 0 {
				addr = addr1
			} else if i == 1 {
				addr = addr2
			}
			blocks = append(blocks, testutil.MineBlock(state, nil, addr))
			state.Index.ID = blocks[len(blocks)-1].ID()
			state.Index.Height++
		}
		if err := cm.AddBlocks(blocks); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	testutil.CheckBalance(t, db, addr1, expectedPayout, types.ZeroCurrency, 0)
	testutil.CheckBalance(t, db, addr2, expectedPayout, types.ZeroCurrency, 0)
	testutil.CheckBalance(t, db, addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

	utxos1, err = db.UnspentSiacoinOutputs(addr1, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "addr1 utxos", 1, len(utxos1))
	for _, utxo := range utxos1 {
		testutil.Equal(t, "value", expectedPayout, utxo.SiacoinOutput.Value)
		testutil.Equal(t, "source", explorer.SourceMinerPayout, utxo.Source)
	}

	utxos2, err = db.UnspentSiacoinOutputs(addr2, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "addr2 utxos", 1, len(utxos2))
	for _, utxo := range utxos2 {
		testutil.Equal(t, "value", expectedPayout, utxo.SiacoinOutput.Value)
		testutil.Equal(t, "source", explorer.SourceMinerPayout, utxo.Source)
	}

	utxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "addr3 utxos", 0, len(utxos3))
}

func TestRevertSendTransactions(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	// Generate three addresses: addr1, addr2, addr3
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	pk3 := types.GeneratePrivateKey()
	addr3 := types.StandardUnlockHash(pk3.PublicKey())

	// t.Log("addr1:", addr1)
	// t.Log("addr2:", addr2)
	// t.Log("addr3:", addr3)

	network, genesisBlock := ctestutil.Network()
	genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	giftSF := genesisBlock.Transactions[0].SiafundOutputs[0].Value

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()

	var blocks []types.Block
	b1 := testutil.MineBlock(cm.TipState(), nil, addr1)
	// Mine a block sending the payout to the addr1
	if err := cm.AddBlocks([]types.Block{b1}); err != nil {
		t.Fatal(err)
	}
	blocks = append(blocks, b1)
	syncDB(t, db, cm)

	// Mine until the payout matures
	for i := cm.Tip().Height; i < maturityHeight; i++ {
		b := testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)
		if err := cm.AddBlocks([]types.Block{b}); err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, b)
		syncDB(t, db, cm)
	}

	testutil.CheckBalance(t, db, addr1, expectedPayout, types.ZeroCurrency, giftSF)
	testutil.CheckBalance(t, db, addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
	testutil.CheckBalance(t, db, addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

	const n = 26

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, 0, n)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "utxos", 1, len(utxos))
	testutil.Equal(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	testutil.Equal(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

	sfOutputID := genesisBlock.Transactions[0].SiafundOutputID(0)
	scOutputID := utxos[0].ID
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())
	// Send 1 SC to addr2 and 2 SC to addr3 100 times in consecutive blocks
	for i := 0; i < n; i++ {
		addr1SCs := expectedPayout.Sub(types.Siacoins(1 + 2).Mul64(uint64(i + 1)))
		addr1SFs := giftSF - (1+2)*uint64(i+1)

		parentTxn := types.Transaction{
			SiacoinInputs: []types.SiacoinInput{
				{
					ParentID:         scOutputID,
					UnlockConditions: unlockConditions,
				},
			},
			SiafundInputs: []types.SiafundInput{
				{
					ParentID:         sfOutputID,
					UnlockConditions: unlockConditions,
				},
			},
			SiacoinOutputs: []types.SiacoinOutput{
				{Address: addr2, Value: types.Siacoins(1)},
				{Address: addr3, Value: types.Siacoins(2)},
				{Address: addr1, Value: addr1SCs},
			},
			SiafundOutputs: []types.SiafundOutput{
				{Address: addr2, Value: 1},
				{Address: addr3, Value: 2},
				{Address: addr1, Value: addr1SFs},
			},
		}

		testutil.SignTransaction(cm.TipState(), pk1, &parentTxn)
		scOutputID = parentTxn.SiacoinOutputID(2)
		sfOutputID = parentTxn.SiafundOutputID(2)

		// Mine a block with the above transaction
		b := testutil.MineBlock(cm.TipState(), []types.Transaction{parentTxn}, types.VoidAddress)
		if err := cm.AddBlocks([]types.Block{b}); err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, b)
		syncDB(t, db, cm)

		CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    0,
			StorageUtilization: 0,
		})

		testutil.CheckBalance(t, db, addr1, addr1SCs, types.ZeroCurrency, addr1SFs)
		testutil.CheckBalance(t, db, addr2, types.Siacoins(1).Mul64(uint64(i+1)), types.ZeroCurrency, 1*uint64(i+1))
		testutil.CheckBalance(t, db, addr3, types.Siacoins(2).Mul64(uint64(i+1)), types.ZeroCurrency, 2*uint64(i+1))

		// Ensure the block we retrieved from the database is the same as the
		// actual block
		block, err := db.Block(b.ID())
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "transactions", len(b.Transactions), len(block.Transactions))
		testutil.Equal(t, "miner payouts", len(b.MinerPayouts), len(block.MinerPayouts))
		testutil.Equal(t, "nonce", b.Nonce, block.Nonce)
		testutil.Equal(t, "timestamp", b.Timestamp, block.Timestamp)

		// Ensure the miner payouts in the block match
		for i := range b.MinerPayouts {
			testutil.Equal(t, "address", b.MinerPayouts[i].Address, b.MinerPayouts[i].Address)
			testutil.Equal(t, "value", b.MinerPayouts[i].Value, b.MinerPayouts[i].Value)
		}

		// Ensure the transactions in the block and retrieved separately match
		// with the actual transactions
		for i := range b.Transactions {
			testutil.CheckTransaction(t, b.Transactions[i], block.Transactions[i])
			CheckChainIndices(t, db, b.Transactions[i].ID(), []types.ChainIndex{cm.Tip()})

			txns, err := db.Transactions([]types.TransactionID{b.Transactions[i].ID()})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "transactions", 1, len(txns))
			testutil.CheckTransaction(t, b.Transactions[i], txns[0])
		}

		type expectedUTXOs struct {
			addr types.Address

			sc      int
			scValue types.Currency

			sf      int
			sfValue uint64
		}
		expected := []expectedUTXOs{
			{addr1, 1, addr1SCs, 1, addr1SFs},
			{addr2, i + 1, types.Siacoins(1), i + 1, 1},
			{addr3, i + 1, types.Siacoins(2), i + 1, 2},
		}
		for _, e := range expected {
			sc, err := db.UnspentSiacoinOutputs(e.addr, 0, n)
			if err != nil {
				t.Fatal(err)
			}
			sf, err := db.UnspentSiafundOutputs(e.addr, 0, n)
			if err != nil {
				t.Fatal(err)
			}

			testutil.Equal(t, "sc utxos", e.sc, len(sc))
			testutil.Equal(t, "sf utxos", e.sf, len(sf))

			for _, sco := range sc {
				testutil.Equal(t, "address", e.addr, sco.SiacoinOutput.Address)
				testutil.Equal(t, "value", e.scValue, sco.SiacoinOutput.Value)
				testutil.Equal(t, "source", explorer.SourceTransaction, sco.Source)
			}
			for _, sfo := range sf {
				testutil.Equal(t, "address", e.addr, sfo.SiafundOutput.Address)
				testutil.Equal(t, "value", e.sfValue, sfo.SiafundOutput.Value)
			}
		}
	}

	{
		// take 3 blocks off the top
		// revertBlocks := blocks[len(blocks)-3:]
		newBlocks := blocks[:len(blocks)-3]

		state, ok := store.State(newBlocks[len(newBlocks)-1].ID())
		if !ok {
			t.Fatal("no such block")
		}
		for i := 0; i < 3+1; i++ {
			newBlocks = append(newBlocks, testutil.MineBlock(state, nil, types.VoidAddress))
			state.Index.ID = newBlocks[len(newBlocks)-1].ID()
			state.Index.Height++
		}

		if err := cm.AddBlocks(newBlocks); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		addr1SCs := expectedPayout.Sub(types.Siacoins(1 + 2).Mul64(uint64(n - 3)))
		addr1SFs := giftSF - (1+2)*uint64(n-3)

		testutil.CheckBalance(t, db, addr1, addr1SCs, types.ZeroCurrency, addr1SFs)
		testutil.CheckBalance(t, db, addr2, types.Siacoins(1).Mul64(uint64(n-3)), types.ZeroCurrency, 1*uint64(n-3))
		testutil.CheckBalance(t, db, addr3, types.Siacoins(2).Mul64(uint64(n-3)), types.ZeroCurrency, 2*uint64(n-3))

		scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr1 sc utxos", 1, len(scUtxos1))
		for _, sce := range scUtxos1 {
			testutil.Equal(t, "address", addr1, sce.SiacoinOutput.Address)
			testutil.Equal(t, "value", addr1SCs, sce.SiacoinOutput.Value)
			testutil.Equal(t, "source", explorer.SourceTransaction, sce.Source)
		}

		scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr2 sc utxos", n-3, len(scUtxos2))
		for _, sce := range scUtxos2 {
			testutil.Equal(t, "address", addr2, sce.SiacoinOutput.Address)
			testutil.Equal(t, "value", types.Siacoins(1), sce.SiacoinOutput.Value)
			testutil.Equal(t, "source", explorer.SourceTransaction, sce.Source)
		}

		scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr3 sc utxos", n-3, len(scUtxos3))
		for _, sce := range scUtxos3 {
			testutil.Equal(t, "address", addr3, sce.SiacoinOutput.Address)
			testutil.Equal(t, "value", types.Siacoins(2), sce.SiacoinOutput.Value)
			testutil.Equal(t, "source", explorer.SourceTransaction, sce.Source)
		}

		sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr1 sf utxos", 1, len(sfUtxos1))
		for _, sfe := range sfUtxos1 {
			testutil.Equal(t, "address", addr1, sfe.SiafundOutput.Address)
			testutil.Equal(t, "value", addr1SFs, sfe.SiafundOutput.Value)
		}

		sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr2 sf utxos", n-3, len(sfUtxos2))
		for _, sfe := range sfUtxos2 {
			testutil.Equal(t, "address", addr2, sfe.SiafundOutput.Address)
			testutil.Equal(t, "value", uint64(1), sfe.SiafundOutput.Value)
		}

		sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr3 sf utxos", n-3, len(sfUtxos3))
		for _, sfe := range sfUtxos3 {
			testutil.Equal(t, "address", addr3, sfe.SiafundOutput.Address)
			testutil.Equal(t, "value", uint64(2), sfe.SiafundOutput.Value)
		}
	}

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    0,
		StorageUtilization: 0,
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

	{
		dbTxns, err := db.Transactions([]types.TransactionID{txn1.ID(), txn2.ID(), txn3.ID(), txn4.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 4, len(dbTxns))
		testutil.Equal(t, "txns[0].ID", txn1.ID(), dbTxns[0].ID)
		testutil.Equal(t, "txns[1].ID", txn2.ID(), dbTxns[1].ID)
		testutil.Equal(t, "txns[2].ID", txn3.ID(), dbTxns[2].ID)
		testutil.Equal(t, "txns[3].ID", txn4.ID(), dbTxns[3].ID)
	}

	{
		events, err := db.AddressEvents(addr1, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 2, len(events))
		testutil.CheckTransaction(t, txn1, events[0].Data.(explorer.EventV1Transaction).Transaction)
		testutil.CheckTransaction(t, genesisBlock.Transactions[0], events[1].Data.(explorer.EventV1Transaction).Transaction)
	}

	{
		dbTxns, err := db.Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckTransaction(t, txn1, dbTxns[0])
	}

	{
		dbTxns, err := db.Transactions([]types.TransactionID{txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckTransaction(t, txn2, dbTxns[0])
	}

	{
		dbTxns, err := db.Transactions([]types.TransactionID{txn3.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckTransaction(t, txn3, dbTxns[0])
	}

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

func TestMultipleReorg(t *testing.T) {
	// Generate three addresses: addr1, addr2, addr3
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	pk3 := types.GeneratePrivateKey()
	addr3 := types.StandardUnlockHash(pk3.PublicKey())

	_, genesisBlock, cm, db := newStore(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value
	giftSF := genesisBlock.Transactions[0].SiafundOutputs[0].Value

	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	// transfer gift from addr1 to addr2
	// element gets added at height 1
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         genesisBlock.Transactions[0].SiacoinOutputID(0),
				UnlockConditions: uc1,
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr2, Value: giftSC},
		},
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         genesisBlock.Transactions[0].SiafundOutputID(0),
				UnlockConditions: uc1,
			},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: addr2, Value: giftSF},
		},
	}
	testutil.SignTransaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	{
		// addr2 should have all the SC
		testutil.CheckBalance(t, db, addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
		testutil.CheckBalance(t, db, addr2, giftSC, types.ZeroCurrency, giftSF)
		testutil.CheckBalance(t, db, addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

		scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr1 sc utxos", 0, len(scUtxos1))

		scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr2 sc utxos", 1, len(scUtxos2))

		scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr3 sc utxos", 0, len(scUtxos3))

		sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr1 sf utxos", 0, len(sfUtxos1))

		sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr2 sf utxos", 1, len(sfUtxos2))

		sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr3 sf utxos", 0, len(sfUtxos3))
	}

	for i := 0; i < 10; i++ {
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	// element gets spent at height 12
	// transfer gift from addr2 to addr3
	txn2 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         txn1.SiacoinOutputID(0),
				UnlockConditions: uc2,
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr3, Value: giftSC},
		},
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         txn1.SiafundOutputID(0),
				UnlockConditions: uc2,
			},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: addr3, Value: giftSF},
		},
	}
	testutil.SignTransaction(cm.TipState(), pk2, &txn2)

	prevState1 := cm.TipState()
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{txn2}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)
	prevState2 := cm.TipState()

	{
		// addr3 should have all the SC
		testutil.CheckBalance(t, db, addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
		testutil.CheckBalance(t, db, addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
		testutil.CheckBalance(t, db, addr3, giftSC, types.ZeroCurrency, giftSF)

		scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr1 sc utxos", 0, len(scUtxos1))

		scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr2 sc utxos", 0, len(scUtxos2))

		scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr3 sc utxos", 1, len(scUtxos3))

		sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr1 sf utxos", 0, len(sfUtxos1))

		sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr2 sf utxos", 0, len(sfUtxos2))

		sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "addr3 sf utxos", 1, len(sfUtxos3))
	}

	// revert block 12 with increasingly large reorgs and sanity check results
	for reorg := 0; reorg < 2; reorg++ {
		// revert block 12 (the addr2 -> addr3 transfer), unspending the
		// element
		{
			var blocks []types.Block
			state := prevState1
			for i := 0; i < reorg+2; i++ {
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

		// we should be back in state before block 12 (addr2 has all the SC
		// instead of addr3)
		{
			testutil.CheckBalance(t, db, addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
			testutil.CheckBalance(t, db, addr2, giftSC, types.ZeroCurrency, giftSF)
			testutil.CheckBalance(t, db, addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

			scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr1 sc utxos", 0, len(scUtxos1))

			scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr2 sc utxos", 1, len(scUtxos2))

			scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr3 sc utxos", 0, len(scUtxos3))

			sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr1 sf utxos", 0, len(sfUtxos1))

			sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr2 sf utxos", 1, len(sfUtxos2))

			sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr3 sf utxos", 0, len(sfUtxos3))
		}
	}

	// now make the original chain where addr3 got the coins the longest
	// and make sure addr3 ends up with the coins
	extra := cm.Tip().Height - prevState2.Index.Height + 1
	for reorg := uint64(0); reorg < 2; reorg++ {
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

		// we should be back in state before the reverts (addr3 has all the SC
		// instead of addr2)
		{
			testutil.CheckBalance(t, db, addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
			testutil.CheckBalance(t, db, addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
			testutil.CheckBalance(t, db, addr3, giftSC, types.ZeroCurrency, giftSF)

			scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr1 sc utxos", 0, len(scUtxos1))

			scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr2 sc utxos", 0, len(scUtxos2))

			scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr3 sc utxos", 1, len(scUtxos3))

			sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr1 sf utxos", 0, len(sfUtxos1))

			sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr2 sf utxos", 0, len(sfUtxos2))

			sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "addr3 sf utxos", 1, len(sfUtxos3))
		}
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

func TestMetricCirculatingSupply(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	_, genesisBlock, cm, db := newStore(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisState := cm.TipState()

	var circulatingSupply types.Currency
	if foundationSubsidy, ok := genesisState.FoundationSubsidy(); ok {
		circulatingSupply = circulatingSupply.Add(foundationSubsidy.Value)
	}
	for _, txn := range genesisBlock.Transactions {
		for _, sco := range txn.SiacoinOutputs {
			circulatingSupply = circulatingSupply.Add(sco.Value)
		}
	}

	var rewards []types.Currency
	prev := cm.TipState()
	for i := 0; i < 10; i++ {
		state := cm.TipState()
		rewards = append(rewards, state.BlockReward())
		circulatingSupply = circulatingSupply.Add(state.BlockReward())
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(state, nil, addr1)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		{
			metrics, err := db.Metrics(cm.Tip().ID)
			if err != nil {
				t.Fatal(err)
			}

			testutil.Equal(t, "circulating supply", circulatingSupply, metrics.CirculatingSupply)
		}
	}

	{
		var blocks []types.Block
		state := prev

		// remove reverted rewards
		for _, reward := range rewards {
			circulatingSupply = circulatingSupply.Sub(reward)
		}
		rewards = rewards[:0]

		for i := uint64(0); i < 15; i++ {
			pk := types.GeneratePrivateKey()
			addr := types.StandardUnlockHash(pk.PublicKey())

			blocks = append(blocks, testutil.MineBlock(state, nil, addr))
			state.Index.ID = blocks[len(blocks)-1].ID()
			state.Index.Height++

			rewards = append(rewards, state.BlockReward())
			circulatingSupply = circulatingSupply.Add(state.BlockReward())
		}

		if err := cm.AddBlocks(blocks); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	{
		metrics, err := db.Metrics(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}

		testutil.Equal(t, "circulating supply", circulatingSupply, metrics.CirculatingSupply)
	}
}
