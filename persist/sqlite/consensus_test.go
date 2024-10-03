package sqlite_test

import (
	"bytes"
	"errors"
	"math/bits"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap/zaptest"
)

const contractFilesize = 10

func syncDB(t *testing.T, db *sqlite.Store, cm *chain.Manager) {
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

func TestBalance(t *testing.T) {
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

	network, genesisBlock := testutil.TestV1Network(types.VoidAddress, types.ZeroCurrency, 0)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	// checkBalance checks that an address has the balances we expect
	checkBalance := func(addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
		sc, immatureSC, sf, err := db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "siacoins", expectSC, sc)
		testutil.Check(t, "immature siacoins", expectImmatureSC, immatureSC)
		testutil.Check(t, "siafunds", expectSF, sf)
	}

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
	testutil.Check(t, "utxos", 1, len(utxos))
	testutil.Check(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	testutil.Check(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

	// Mine until the payout matures
	for i := cm.Tip().Height; i < maturityHeight; i++ {
		checkBalance(addr1, types.ZeroCurrency, expectedPayout, 0)
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	checkBalance(addr1, expectedPayout, types.ZeroCurrency, 0)

	// Send all of the payout except 100 SC to addr2
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())
	parentTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         types.SiacoinOutputID(utxos[0].ID),
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

	checkBalance(addr2, utxos[0].SiacoinOutput.Value.Sub(types.Siacoins(100)), types.ZeroCurrency, 0)
	checkBalance(addr3, types.Siacoins(100), types.ZeroCurrency, 0)
}

func TestSiafundBalance(t *testing.T) {
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

	const giftSF = 10000
	network, genesisBlock := testutil.TestV1Network(addr1, types.ZeroCurrency, giftSF)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	// checkBalance checks that an address has the balances we expect
	checkBalance := func(addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
		sc, immatureSC, sf, err := db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "siacoins", expectSC, sc)
		testutil.Check(t, "immature siacoins", expectImmatureSC, immatureSC)
		testutil.Check(t, "siafunds", expectSF, sf)
	}

	// Send all of the payout except 100 SF to addr2
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())
	parentTxn := types.Transaction{
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         types.SiafundOutputID(genesisBlock.Transactions[0].SiafundOutputID(0)),
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

	checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
	checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency, giftSF-100)
	checkBalance(addr3, types.ZeroCurrency, types.ZeroCurrency, 100)
}

func TestSendTransactions(t *testing.T) {
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

	const giftSF = 10000
	network, genesisBlock := testutil.TestV1Network(addr1, types.ZeroCurrency, giftSF)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	// checkBalance checks that an address has the balances we expect
	checkBalance := func(addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
		sc, immatureSC, sf, err := db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "siacoins", expectSC, sc)
		testutil.Check(t, "immature siacoins", expectImmatureSC, immatureSC)
		testutil.Check(t, "siafunds", expectSF, sf)
	}

	checkChainIndices := func(t *testing.T, txnID types.TransactionID, expected []types.ChainIndex) {
		indices, err := db.TransactionChainIndices(txnID, 0, 100)
		switch {
		case err != nil:
			t.Fatal(err)
		case len(indices) != len(expected):
			t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
		}
		for i := range indices {
			testutil.Check(t, "index", expected[i], indices[i])
		}
	}

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

	checkBalance(addr1, expectedPayout, types.ZeroCurrency, giftSF)
	checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
	checkBalance(addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

	const n = 100

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, 0, n)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Check(t, "utxos", 1, len(utxos))
	testutil.Check(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	testutil.Check(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

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
					ParentID:         types.SiacoinOutputID(scOutputID),
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
		scOutputID = types.Hash256(parentTxn.SiacoinOutputID(2))
		sfOutputID = parentTxn.SiafundOutputID(2)

		// Mine a block with the above transaction
		b := testutil.MineBlock(cm.TipState(), []types.Transaction{parentTxn}, types.VoidAddress)
		if err := cm.AddBlocks([]types.Block{b}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		testutil.CheckMetrics(t, db, cm, explorer.Metrics{})

		checkBalance(addr1, addr1SCs, types.ZeroCurrency, addr1SFs)
		checkBalance(addr2, types.Siacoins(1).Mul64(uint64(i+1)), types.ZeroCurrency, 1*uint64(i+1))
		checkBalance(addr3, types.Siacoins(2).Mul64(uint64(i+1)), types.ZeroCurrency, 2*uint64(i+1))

		// Ensure the block we retrieved from the database is the same as the
		// actual block
		block, err := db.Block(b.ID())
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", len(b.Transactions), len(block.Transactions))
		testutil.Check(t, "miner payouts", len(b.MinerPayouts), len(block.MinerPayouts))
		testutil.Check(t, "nonce", b.Nonce, block.Nonce)
		testutil.Check(t, "timestamp", b.Timestamp, block.Timestamp)

		// Ensure the miner payouts in the block match
		for i := range b.MinerPayouts {
			testutil.Check(t, "address", b.MinerPayouts[i].Address, b.MinerPayouts[i].Address)
			testutil.Check(t, "value", b.MinerPayouts[i].Value, b.MinerPayouts[i].Value)
		}

		// Ensure the transactions in the block and retrieved separately match
		// with the actual transactions
		for i := range b.Transactions {
			testutil.CheckTransaction(t, b.Transactions[i], block.Transactions[i])
			checkChainIndices(t, b.Transactions[i].ID(), []types.ChainIndex{cm.Tip()})

			txns, err := db.Transactions([]types.TransactionID{b.Transactions[i].ID()})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "transactions", 1, len(txns))
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

			testutil.Check(t, "sc utxos", e.sc, len(sc))
			testutil.Check(t, "sf utxos", e.sf, len(sf))

			for _, sco := range sc {
				testutil.Check(t, "address", e.addr, sco.SiacoinOutput.Address)
				testutil.Check(t, "value", e.scValue, sco.SiacoinOutput.Value)
				testutil.Check(t, "source", explorer.SourceTransaction, sco.Source)
			}
			for _, sfo := range sf {
				testutil.Check(t, "address", e.addr, sfo.SiafundOutput.Address)
				testutil.Check(t, "value", e.sfValue, sfo.SiafundOutput.Value)
			}
		}
	}
}

func TestTip(t *testing.T) {
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

	network, genesisBlock := testutil.TestV1Network(types.VoidAddress, types.ZeroCurrency, 0)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

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
		testutil.Check(t, "tip", cm.Tip(), tip)
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

// copied from rhp/v2 to avoid import cycle
func prepareContractFormation(renterPubKey types.PublicKey, hostKey types.PublicKey, renterPayout, hostCollateral types.Currency, startHeight uint64, endHeight uint64, refundAddr types.Address) types.FileContract {
	taxAdjustedPayout := func(target types.Currency) types.Currency {
		guess := target.Mul64(1000).Div64(961)
		mod64 := func(c types.Currency, v uint64) types.Currency {
			var r uint64
			if c.Hi < v {
				_, r = bits.Div64(c.Hi, c.Lo, v)
			} else {
				_, r = bits.Div64(0, c.Hi, v)
				_, r = bits.Div64(r, c.Lo, v)
			}
			return types.NewCurrency64(r)
		}
		sfc := (consensus.State{}).SiafundCount()
		tm := mod64(target, sfc)
		gm := mod64(guess, sfc)
		if gm.Cmp(tm) < 0 {
			guess = guess.Sub(types.NewCurrency64(sfc))
		}
		return guess.Add(tm).Sub(gm)
	}
	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			renterPubKey.UnlockKey(),
			hostKey.UnlockKey(),
		},
		SignaturesRequired: 2,
	}
	hostPayout := hostCollateral
	payout := taxAdjustedPayout(renterPayout.Add(hostPayout))
	return types.FileContract{
		Filesize:       contractFilesize,
		FileMerkleRoot: types.Hash256{},
		WindowStart:    startHeight,
		WindowEnd:      endHeight,
		Payout:         payout,
		UnlockHash:     types.Hash256(uc.UnlockHash()),
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: refundAddr},
			{Value: hostPayout, Address: types.VoidAddress},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: refundAddr},
			{Value: hostPayout, Address: types.VoidAddress},
			{Value: types.ZeroCurrency, Address: types.VoidAddress},
		},
	}
}

func TestFileContract(t *testing.T) {
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

	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	giftSC := types.Siacoins(1000)
	network, genesisBlock := testutil.TestV1Network(addr1, giftSC, 0)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	scOutputID := genesisBlock.Transactions[0].SiacoinOutputID(0)
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())

	checkFC := func(resolved, valid bool, expected types.FileContract, got explorer.FileContract) {
		testutil.Check(t, "resolved state", resolved, got.Resolved)
		testutil.Check(t, "valid state", valid, got.Valid)

		gotFC := got.FileContract
		testutil.Check(t, "filesize", expected.Filesize, gotFC.Filesize)
		testutil.Check(t, "file merkle root", expected.FileMerkleRoot, gotFC.FileMerkleRoot)
		testutil.Check(t, "window start", expected.WindowStart, gotFC.WindowStart)
		testutil.Check(t, "window end", expected.WindowEnd, gotFC.WindowEnd)
		testutil.Check(t, "payout", expected.Payout, gotFC.Payout)
		testutil.Check(t, "unlock hash", expected.UnlockHash, gotFC.UnlockHash)
		testutil.Check(t, "revision number", expected.RevisionNumber, gotFC.RevisionNumber)
		testutil.Check(t, "valid proof outputs", len(expected.ValidProofOutputs), len(gotFC.ValidProofOutputs))
		for i := range expected.ValidProofOutputs {
			testutil.Check(t, "valid proof output address", expected.ValidProofOutputs[i].Address, gotFC.ValidProofOutputs[i].Address)
			testutil.Check(t, "valid proof output value", expected.ValidProofOutputs[i].Value, gotFC.ValidProofOutputs[i].Value)
		}
		testutil.Check(t, "missed proof outputs", len(expected.MissedProofOutputs), len(gotFC.MissedProofOutputs))
		for i := range expected.MissedProofOutputs {
			testutil.Check(t, "missed proof output address", expected.MissedProofOutputs[i].Address, gotFC.MissedProofOutputs[i].Address)
			testutil.Check(t, "missed proof output value", expected.MissedProofOutputs[i].Value, gotFC.MissedProofOutputs[i].Value)
		}
	}

	windowStart := cm.Tip().Height + 10
	windowEnd := windowStart + 10
	fc := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), windowStart, windowEnd, types.VoidAddress)
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

	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "fcs", 1, len(dbFCs))
		checkFC(false, false, fc, dbFCs[0])
		testutil.Check(t, "confirmation index", cm.Tip(), *dbFCs[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *dbFCs[0].ConfirmationTransactionID)
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckFCRevisions(t, []uint64{0}, dbFCs)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", 1, len(txns))
		testutil.Check(t, "file contracts", 1, len(txns[0].FileContracts))
		checkFC(false, false, fc, txns[0].FileContracts[0])

		testutil.Check(t, "confirmation index", cm.Tip(), *txns[0].FileContracts[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *txns[0].FileContracts[0].ConfirmationTransactionID)
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
		testutil.Check(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
		testutil.Check(t, "len(contracts)", 1, len(renterContracts))
		checkFC(false, false, fc, renterContracts[0])
		checkFC(false, false, fc, hostContracts[0])

		testutil.Check(t, "confirmation index", prevTip, *renterContracts[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *renterContracts[0].ConfirmationTransactionID)
		testutil.Check(t, "confirmation index", prevTip, *hostContracts[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *hostContracts[0].ConfirmationTransactionID)
	}

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    1,
		StorageUtilization: contractFilesize,
	})

	// Explorer.Contracts should return latest revision
	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "fcs", 1, len(dbFCs))
		checkFC(false, false, fc, dbFCs[0])
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckFCRevisions(t, []uint64{0, 1}, dbFCs)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", 1, len(txns))
		testutil.Check(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Check(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Check(t, "unlock conditions", uc, fcr.UnlockConditions)

		testutil.Check(t, "confirmation index", prevTip, *fcr.ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *fcr.ConfirmationTransactionID)

		checkFC(false, false, fc, fcr.FileContract)
	}

	for i := cm.Tip().Height; i < windowEnd; i++ {
		testutil.CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    1,
			StorageUtilization: 1 * contractFilesize,
		})

		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:          0,
		ActiveContracts:     0,
		FailedContracts:     1,
		SuccessfulContracts: 0,
		StorageUtilization:  0,
	})

	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "fcs", 1, len(dbFCs))
		checkFC(true, false, fc, dbFCs[0])

		testutil.Check(t, "confirmation index", prevTip, *dbFCs[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *dbFCs[0].ConfirmationTransactionID)
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
		testutil.Check(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
		testutil.Check(t, "len(contracts)", 1, len(renterContracts))
		checkFC(true, false, fc, renterContracts[0])
		checkFC(true, false, fc, hostContracts[0])

		testutil.Check(t, "confirmation index", prevTip, *renterContracts[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *renterContracts[0].ConfirmationTransactionID)
		testutil.Check(t, "confirmation index", prevTip, *hostContracts[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *hostContracts[0].ConfirmationTransactionID)
	}

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:          0,
		ActiveContracts:     0,
		FailedContracts:     1,
		SuccessfulContracts: 0,
		StorageUtilization:  0,
	})
}

func TestEphemeralFileContract(t *testing.T) {
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

	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	giftSC := types.Siacoins(1000)
	network, genesisBlock := testutil.TestV1Network(addr1, giftSC, 0)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	scOutputID := genesisBlock.Transactions[0].SiacoinOutputID(0)
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())

	checkFC := func(revision, resolved, valid bool, expected types.FileContract, got explorer.FileContract) {
		testutil.Check(t, "resolved state", resolved, got.Resolved)
		testutil.Check(t, "valid state", valid, got.Valid)

		gotFC := got.FileContract
		testutil.Check(t, "filesize", expected.Filesize, gotFC.Filesize)
		testutil.Check(t, "file merkle root", expected.FileMerkleRoot, gotFC.FileMerkleRoot)
		testutil.Check(t, "window start", expected.WindowStart, gotFC.WindowStart)
		testutil.Check(t, "window end", expected.WindowEnd, gotFC.WindowEnd)

		// See core/types.FileContractRevision
		// Essentially, a revision cannot change the total payout, so this value
		// is replaced with a sentinel value of types.MaxCurrency in revisions
		// if it is decoded.
		if !revision {
			testutil.Check(t, "payout", expected.Payout, gotFC.Payout)
		}

		testutil.Check(t, "unlock hash", expected.UnlockHash, gotFC.UnlockHash)
		testutil.Check(t, "revision number", expected.RevisionNumber, gotFC.RevisionNumber)
		testutil.Check(t, "valid proof outputs", len(expected.ValidProofOutputs), len(gotFC.ValidProofOutputs))
		for i := range expected.ValidProofOutputs {
			testutil.Check(t, "valid proof output address", expected.ValidProofOutputs[i].Address, gotFC.ValidProofOutputs[i].Address)
			testutil.Check(t, "valid proof output value", expected.ValidProofOutputs[i].Value, gotFC.ValidProofOutputs[i].Value)
		}
		testutil.Check(t, "missed proof outputs", len(expected.MissedProofOutputs), len(gotFC.MissedProofOutputs))
		for i := range expected.MissedProofOutputs {
			testutil.Check(t, "missed proof output address", expected.MissedProofOutputs[i].Address, gotFC.MissedProofOutputs[i].Address)
			testutil.Check(t, "missed proof output value", expected.MissedProofOutputs[i].Value, gotFC.MissedProofOutputs[i].Value)
		}
	}

	windowStart := cm.Tip().Height + 10
	windowEnd := windowStart + 10
	fc := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), windowStart, windowEnd, types.VoidAddress)
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

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    1,
		StorageUtilization: contractFilesize,
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
		testutil.Check(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
		testutil.Check(t, "len(contracts)", 1, len(renterContracts))
		checkFC(true, false, false, revisedFC1, renterContracts[0])
		checkFC(true, false, false, revisedFC1, hostContracts[0])
	}

	// Explorer.Contracts should return latest revision
	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "fcs", 1, len(dbFCs))
		checkFC(true, false, false, revisedFC1, dbFCs[0])
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckFCRevisions(t, []uint64{0, 1}, dbFCs)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", 1, len(txns))
		testutil.Check(t, "file contracts", 1, len(txns[0].FileContracts))
		checkFC(true, false, false, fc, txns[0].FileContracts[0])

		testutil.Check(t, "confirmation index", cm.Tip(), *txns[0].FileContracts[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *txns[0].FileContracts[0].ConfirmationTransactionID)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", 1, len(txns))
		testutil.Check(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Check(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Check(t, "unlock conditions", uc, fcr.UnlockConditions)

		checkFC(true, false, false, revisedFC1, fcr.FileContract)
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

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    1,
		StorageUtilization: contractFilesize,
	})

	// Explorer.Contracts should return latest revision
	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "fcs", 1, len(dbFCs))
		checkFC(true, false, false, revisedFC3, dbFCs[0])
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckFCRevisions(t, []uint64{0, 1, 2, 3}, dbFCs)
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
		testutil.Check(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
		testutil.Check(t, "len(contracts)", 1, len(renterContracts))
		checkFC(true, false, false, revisedFC3, renterContracts[0])
		checkFC(true, false, false, revisedFC3, hostContracts[0])
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", 1, len(txns))
		testutil.Check(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Check(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Check(t, "unlock conditions", uc, fcr.UnlockConditions)
		checkFC(true, false, false, revisedFC2, fcr.FileContract)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn3.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", 1, len(txns))
		testutil.Check(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Check(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Check(t, "unlock conditions", uc, fcr.UnlockConditions)
		checkFC(true, false, false, revisedFC3, fcr.FileContract)
	}
}

func TestRevertTip(t *testing.T) {
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

	network, genesisBlock := testutil.TestV1Network(types.VoidAddress, types.ZeroCurrency, 0)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

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
		testutil.Check(t, "tip", cm.Tip(), tip)
	}

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
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
		testutil.Check(t, "tip", cm.Tip(), tip)
	}

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
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

	network, genesisBlock := testutil.TestV1Network(types.VoidAddress, types.ZeroCurrency, 0)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	// checkBalance checks that an address has the balances we expect
	checkBalance := func(addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
		sc, immatureSC, sf, err := db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "siacoins", expectSC, sc)
		testutil.Check(t, "immature siacoins", expectImmatureSC, immatureSC)
		testutil.Check(t, "siafunds", expectSF, sf)
	}

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
	testutil.Check(t, "utxos", 1, len(utxos))
	testutil.Check(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	testutil.Check(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

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
		checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
		checkBalance(addr2, types.ZeroCurrency, expectedPayout.Mul64(2), 0)
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		testutil.CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    0,
			StorageUtilization: 0,
		})
	}
	checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
	checkBalance(addr2, expectedPayout.Mul64(1), expectedPayout.Mul64(1), 0)

	utxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Check(t, "addr1 utxos", 0, len(utxos1))

	utxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Check(t, "addr2 utxos", 2, len(utxos2))
	for _, utxo := range utxos2 {
		testutil.Check(t, "value", expectedPayout, utxo.SiacoinOutput.Value)
		testutil.Check(t, "source", explorer.SourceMinerPayout, utxo.Source)
	}

	// Send all of the payout except 100 SC to addr3
	hundredSC := types.Siacoins(100)
	unlockConditions := types.StandardUnlockConditions(pk2.PublicKey())
	parentTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         types.SiacoinOutputID(utxos2[0].ID),
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
		testutil.Check(t, "spent_index", *b.Transactions[0].SiacoinOutputs[0].SpentIndex, cm.Tip())
		testutil.Check(t, "spent_index", b.Transactions[1].SiacoinOutputs[0].SpentIndex, (*types.ChainIndex)(nil))
	}

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	checkBalance(addr1, hundredSC, types.ZeroCurrency, 0)
	// second block added in reorg has now matured
	checkBalance(addr2, utxos2[1].SiacoinOutput.Value, types.ZeroCurrency, 0)
	checkBalance(addr3, utxos2[0].SiacoinOutput.Value.Sub(hundredSC), types.ZeroCurrency, 0)

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

	checkBalance(addr1, expectedPayout, types.ZeroCurrency, 0)
	checkBalance(addr2, expectedPayout, types.ZeroCurrency, 0)
	checkBalance(addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

	utxos1, err = db.UnspentSiacoinOutputs(addr1, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Check(t, "addr1 utxos", 1, len(utxos1))
	for _, utxo := range utxos1 {
		testutil.Check(t, "value", expectedPayout, utxo.SiacoinOutput.Value)
		testutil.Check(t, "source", explorer.SourceMinerPayout, utxo.Source)
	}

	utxos2, err = db.UnspentSiacoinOutputs(addr2, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Check(t, "addr2 utxos", 1, len(utxos2))
	for _, utxo := range utxos2 {
		testutil.Check(t, "value", expectedPayout, utxo.SiacoinOutput.Value)
		testutil.Check(t, "source", explorer.SourceMinerPayout, utxo.Source)
	}

	utxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Check(t, "addr3 utxos", 0, len(utxos3))
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

	const giftSF = 10000
	network, genesisBlock := testutil.TestV1Network(addr1, types.ZeroCurrency, giftSF)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	// checkBalance checks that an address has the balances we expect
	checkBalance := func(addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
		sc, immatureSC, sf, err := db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "siacoins", expectSC, sc)
		testutil.Check(t, "immature siacoins", expectImmatureSC, immatureSC)
		testutil.Check(t, "siafunds", expectSF, sf)
	}

	checkChainIndices := func(t *testing.T, txnID types.TransactionID, expected []types.ChainIndex) {
		indices, err := db.TransactionChainIndices(txnID, 0, 100)
		switch {
		case err != nil:
			t.Fatal(err)
		case len(indices) != len(expected):
			t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
		}
		for i := range indices {
			testutil.Check(t, "index", expected[i], indices[i])
		}
	}

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

	checkBalance(addr1, expectedPayout, types.ZeroCurrency, giftSF)
	checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
	checkBalance(addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

	const n = 26

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, 0, n)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Check(t, "utxos", 1, len(utxos))
	testutil.Check(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	testutil.Check(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

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
					ParentID:         types.SiacoinOutputID(scOutputID),
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
		scOutputID = types.Hash256(parentTxn.SiacoinOutputID(2))
		sfOutputID = parentTxn.SiafundOutputID(2)

		// Mine a block with the above transaction
		b := testutil.MineBlock(cm.TipState(), []types.Transaction{parentTxn}, types.VoidAddress)
		if err := cm.AddBlocks([]types.Block{b}); err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, b)
		syncDB(t, db, cm)

		testutil.CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    0,
			StorageUtilization: 0,
		})

		checkBalance(addr1, addr1SCs, types.ZeroCurrency, addr1SFs)
		checkBalance(addr2, types.Siacoins(1).Mul64(uint64(i+1)), types.ZeroCurrency, 1*uint64(i+1))
		checkBalance(addr3, types.Siacoins(2).Mul64(uint64(i+1)), types.ZeroCurrency, 2*uint64(i+1))

		// Ensure the block we retrieved from the database is the same as the
		// actual block
		block, err := db.Block(b.ID())
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", len(b.Transactions), len(block.Transactions))
		testutil.Check(t, "miner payouts", len(b.MinerPayouts), len(block.MinerPayouts))
		testutil.Check(t, "nonce", b.Nonce, block.Nonce)
		testutil.Check(t, "timestamp", b.Timestamp, block.Timestamp)

		// Ensure the miner payouts in the block match
		for i := range b.MinerPayouts {
			testutil.Check(t, "address", b.MinerPayouts[i].Address, b.MinerPayouts[i].Address)
			testutil.Check(t, "value", b.MinerPayouts[i].Value, b.MinerPayouts[i].Value)
		}

		// Ensure the transactions in the block and retrieved separately match
		// with the actual transactions
		for i := range b.Transactions {
			testutil.CheckTransaction(t, b.Transactions[i], block.Transactions[i])
			checkChainIndices(t, b.Transactions[i].ID(), []types.ChainIndex{cm.Tip()})

			txns, err := db.Transactions([]types.TransactionID{b.Transactions[i].ID()})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "transactions", 1, len(txns))
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

			testutil.Check(t, "sc utxos", e.sc, len(sc))
			testutil.Check(t, "sf utxos", e.sf, len(sf))

			for _, sco := range sc {
				testutil.Check(t, "address", e.addr, sco.SiacoinOutput.Address)
				testutil.Check(t, "value", e.scValue, sco.SiacoinOutput.Value)
				testutil.Check(t, "source", explorer.SourceTransaction, sco.Source)
			}
			for _, sfo := range sf {
				testutil.Check(t, "address", e.addr, sfo.SiafundOutput.Address)
				testutil.Check(t, "value", e.sfValue, sfo.SiafundOutput.Value)
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

		checkBalance(addr1, addr1SCs, types.ZeroCurrency, addr1SFs)
		checkBalance(addr2, types.Siacoins(1).Mul64(uint64(n-3)), types.ZeroCurrency, 1*uint64(n-3))
		checkBalance(addr3, types.Siacoins(2).Mul64(uint64(n-3)), types.ZeroCurrency, 2*uint64(n-3))

		scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr1 sc utxos", 1, len(scUtxos1))
		for _, sce := range scUtxos1 {
			testutil.Check(t, "address", addr1, sce.SiacoinOutput.Address)
			testutil.Check(t, "value", addr1SCs, sce.SiacoinOutput.Value)
			testutil.Check(t, "source", explorer.SourceTransaction, sce.Source)
		}

		scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr2 sc utxos", n-3, len(scUtxos2))
		for _, sce := range scUtxos2 {
			testutil.Check(t, "address", addr2, sce.SiacoinOutput.Address)
			testutil.Check(t, "value", types.Siacoins(1), sce.SiacoinOutput.Value)
			testutil.Check(t, "source", explorer.SourceTransaction, sce.Source)
		}

		scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr3 sc utxos", n-3, len(scUtxos3))
		for _, sce := range scUtxos3 {
			testutil.Check(t, "address", addr3, sce.SiacoinOutput.Address)
			testutil.Check(t, "value", types.Siacoins(2), sce.SiacoinOutput.Value)
			testutil.Check(t, "source", explorer.SourceTransaction, sce.Source)
		}

		sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr1 sf utxos", 1, len(sfUtxos1))
		for _, sfe := range sfUtxos1 {
			testutil.Check(t, "address", addr1, sfe.SiafundOutput.Address)
			testutil.Check(t, "value", addr1SFs, sfe.SiafundOutput.Value)
		}

		sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr2 sf utxos", n-3, len(sfUtxos2))
		for _, sfe := range sfUtxos2 {
			testutil.Check(t, "address", addr2, sfe.SiafundOutput.Address)
			testutil.Check(t, "value", uint64(1), sfe.SiafundOutput.Value)
		}

		sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr3 sf utxos", n-3, len(sfUtxos3))
		for _, sfe := range sfUtxos3 {
			testutil.Check(t, "address", addr3, sfe.SiafundOutput.Address)
			testutil.Check(t, "value", uint64(2), sfe.SiafundOutput.Value)
		}
	}

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})
}

// from hostd
func createAnnouncement(priv types.PrivateKey, netaddress string) []byte {
	// encode the announcement
	var buf bytes.Buffer
	pub := priv.PublicKey()
	enc := types.NewEncoder(&buf)
	explorer.SpecifierAnnouncement.EncodeTo(enc)
	enc.WriteString(netaddress)
	pub.UnlockKey().EncodeTo(enc)
	if err := enc.Flush(); err != nil {
		panic(err)
	}
	// hash without the signature
	sigHash := types.HashBytes(buf.Bytes())
	// sign
	sig := priv.SignHash(sigHash)
	sig.EncodeTo(enc)
	if err := enc.Flush(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func TestHostAnnouncement(t *testing.T) {
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

	network, genesisBlock := testutil.TestV1Network(types.VoidAddress, types.ZeroCurrency, 0)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	pk1 := types.GeneratePrivateKey()
	pk2 := types.GeneratePrivateKey()
	pk3 := types.GeneratePrivateKey()

	checkHostAnnouncements := func(expectedArbitraryData [][]byte, got []chain.HostAnnouncement) {
		t.Helper()

		var expected []chain.HostAnnouncement
		for _, arb := range expectedArbitraryData {
			var ha chain.HostAnnouncement
			if ha.FromArbitraryData(arb) {
				expected = append(expected, ha)
			}
		}
		testutil.Check(t, "len(hostAnnouncements)", len(expected), len(got))
		for i := range expected {
			testutil.Check(t, "host public key", expected[i].PublicKey, got[i].PublicKey)
			testutil.Check(t, "host net address", expected[i].NetAddress, got[i].NetAddress)
		}
	}

	txn1 := types.Transaction{
		ArbitraryData: [][]byte{
			createAnnouncement(pk1, "127.0.0.1:1234"),
		},
	}
	testutil.SignTransaction(cm.TipState(), pk1, &txn1)

	// Mine a block containing host announcement
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         1,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	txn2 := types.Transaction{
		ArbitraryData: [][]byte{
			createAnnouncement(pk1, "127.0.0.1:5678"),
		},
	}
	txn3 := types.Transaction{
		ArbitraryData: [][]byte{
			createAnnouncement(pk2, "127.0.0.1:9999"),
		},
	}
	txn4 := types.Transaction{
		ArbitraryData: [][]byte{
			createAnnouncement(pk3, "127.0.0.1:9999"),
		},
	}

	// Mine a block containing host announcement
	if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), []types.Transaction{txn2, txn3, txn4}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         3,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	{
		b, err := db.Block(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "len(txns)", 3, len(b.Transactions))
		testutil.Check(t, "txns[0].ID", txn2.ID(), b.Transactions[0].ID)
		testutil.Check(t, "txns[1].ID", txn3.ID(), b.Transactions[1].ID)
		testutil.Check(t, "txns[2].ID", txn4.ID(), b.Transactions[2].ID)
	}

	{
		dbTxns, err := db.Transactions([]types.TransactionID{txn1.ID(), txn2.ID(), txn3.ID(), txn4.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "len(txns)", 4, len(dbTxns))
		testutil.Check(t, "txns[0].ID", txn1.ID(), dbTxns[0].ID)
		testutil.Check(t, "txns[1].ID", txn2.ID(), dbTxns[1].ID)
		testutil.Check(t, "txns[2].ID", txn3.ID(), dbTxns[2].ID)
		testutil.Check(t, "txns[3].ID", txn4.ID(), dbTxns[3].ID)
	}

	{
		dbTxns, err := db.Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "len(txns)", 1, len(dbTxns))
		checkHostAnnouncements(txn1.ArbitraryData, dbTxns[0].HostAnnouncements)
	}

	{
		dbTxns, err := db.Transactions([]types.TransactionID{txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "len(txns)", 1, len(dbTxns))
		checkHostAnnouncements(txn2.ArbitraryData, dbTxns[0].HostAnnouncements)
	}

	{
		dbTxns, err := db.Transactions([]types.TransactionID{txn3.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "len(txns)", 1, len(dbTxns))
		checkHostAnnouncements(txn3.ArbitraryData, dbTxns[0].HostAnnouncements)
	}

	ts := time.Unix(0, 0)
	hosts, err := db.HostsForScanning(ts, ts, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Check(t, "len(hosts)", 3, len(hosts))

	{
		scans, err := db.Hosts([]types.PublicKey{hosts[0].PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "len(scans)", 1, len(scans))
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
	}

	{
		if err := db.AddHostScans([]explorer.HostScan{scan1}); err != nil {
			t.Fatal(err)
		}

		scans, err := db.Hosts([]types.PublicKey{hosts[0].PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "len(scans)", 1, len(scans))

		scan := scans[0]
		testutil.Check(t, "last scan", scan1.Timestamp.Unix(), scan.LastScan.Unix())
		testutil.Check(t, "last scan successful", scan1.Success, scan.LastScanSuccessful)
		testutil.Check(t, "total scans", 1, scan.TotalScans)
		testutil.Check(t, "successful interactions", 1, scan.SuccessfulInteractions)
		testutil.Check(t, "failed interactions", 0, scan.FailedInteractions)
	}

	{
		if err := db.AddHostScans([]explorer.HostScan{scan2}); err != nil {
			t.Fatal(err)
		}

		scans, err := db.Hosts([]types.PublicKey{hosts[0].PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "len(scans)", 1, len(scans))

		scan := scans[0]
		testutil.Check(t, "last scan", scan2.Timestamp.Unix(), scan.LastScan.Unix())
		testutil.Check(t, "last scan successful", scan2.Success, scan.LastScanSuccessful)
		testutil.Check(t, "total scans", 2, scan.TotalScans)
		testutil.Check(t, "successful interactions", 1, scan.SuccessfulInteractions)
		testutil.Check(t, "failed interactions", 1, scan.FailedInteractions)
	}
}

func TestMultipleReorg(t *testing.T) {
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

	const giftSF = 500
	giftSC := types.Siacoins(500)
	network, genesisBlock := testutil.TestV1Network(addr1, giftSC, giftSF)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	// checkBalance checks that an address has the balances we expect
	checkBalance := func(addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
		sc, immatureSC, sf, err := db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "siacoins", expectSC, sc)
		testutil.Check(t, "immature siacoins", expectImmatureSC, immatureSC)
		testutil.Check(t, "siafunds", expectSF, sf)
	}

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

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    0,
		StorageUtilization: 0,
	})

	{
		// addr2 should have all the SC
		checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
		checkBalance(addr2, giftSC, types.ZeroCurrency, giftSF)
		checkBalance(addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

		scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr1 sc utxos", 0, len(scUtxos1))

		scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr2 sc utxos", 1, len(scUtxos2))

		scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr3 sc utxos", 0, len(scUtxos3))

		sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr1 sf utxos", 0, len(sfUtxos1))

		sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr2 sf utxos", 1, len(sfUtxos2))

		sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr3 sf utxos", 0, len(sfUtxos3))
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
		checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
		checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
		checkBalance(addr3, giftSC, types.ZeroCurrency, giftSF)

		scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr1 sc utxos", 0, len(scUtxos1))

		scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr2 sc utxos", 0, len(scUtxos2))

		scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr3 sc utxos", 1, len(scUtxos3))

		sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr1 sf utxos", 0, len(sfUtxos1))

		sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr2 sf utxos", 0, len(sfUtxos2))

		sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "addr3 sf utxos", 1, len(sfUtxos3))
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
			checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
			checkBalance(addr2, giftSC, types.ZeroCurrency, giftSF)
			checkBalance(addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

			scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr1 sc utxos", 0, len(scUtxos1))

			scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr2 sc utxos", 1, len(scUtxos2))

			scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr3 sc utxos", 0, len(scUtxos3))

			sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr1 sf utxos", 0, len(sfUtxos1))

			sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr2 sf utxos", 1, len(sfUtxos2))

			sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr3 sf utxos", 0, len(sfUtxos3))
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
			checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency, 0)
			checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
			checkBalance(addr3, giftSC, types.ZeroCurrency, giftSF)

			scUtxos1, err := db.UnspentSiacoinOutputs(addr1, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr1 sc utxos", 0, len(scUtxos1))

			scUtxos2, err := db.UnspentSiacoinOutputs(addr2, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr2 sc utxos", 0, len(scUtxos2))

			scUtxos3, err := db.UnspentSiacoinOutputs(addr3, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr3 sc utxos", 1, len(scUtxos3))

			sfUtxos1, err := db.UnspentSiafundOutputs(addr1, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr1 sf utxos", 0, len(sfUtxos1))

			sfUtxos2, err := db.UnspentSiafundOutputs(addr2, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr2 sf utxos", 0, len(sfUtxos2))

			sfUtxos3, err := db.UnspentSiafundOutputs(addr3, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Check(t, "addr3 sf utxos", 1, len(sfUtxos3))
		}
	}
}

func TestMultipleReorgFileContract(t *testing.T) {
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

	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	giftSC := types.Siacoins(1000)
	network, genesisBlock := testutil.TestV1Network(addr1, giftSC, 0)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	scOutputID := genesisBlock.Transactions[0].SiacoinOutputID(0)
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())

	checkFC := func(resolved, valid bool, expected types.FileContract, got explorer.FileContract) {
		testutil.Check(t, "resolved state", resolved, got.Resolved)
		testutil.Check(t, "valid state", valid, got.Valid)

		gotFC := got.FileContract
		testutil.Check(t, "filesize", expected.Filesize, gotFC.Filesize)
		testutil.Check(t, "file merkle root", expected.FileMerkleRoot, gotFC.FileMerkleRoot)
		testutil.Check(t, "window start", expected.WindowStart, gotFC.WindowStart)
		testutil.Check(t, "window end", expected.WindowEnd, gotFC.WindowEnd)
		testutil.Check(t, "payout", expected.Payout, gotFC.Payout)
		testutil.Check(t, "unlock hash", expected.UnlockHash, gotFC.UnlockHash)
		testutil.Check(t, "revision number", expected.RevisionNumber, gotFC.RevisionNumber)
		testutil.Check(t, "valid proof outputs", len(expected.ValidProofOutputs), len(gotFC.ValidProofOutputs))
		for i := range expected.ValidProofOutputs {
			testutil.Check(t, "valid proof output address", expected.ValidProofOutputs[i].Address, gotFC.ValidProofOutputs[i].Address)
			testutil.Check(t, "valid proof output value", expected.ValidProofOutputs[i].Value, gotFC.ValidProofOutputs[i].Value)
		}
		testutil.Check(t, "missed proof outputs", len(expected.MissedProofOutputs), len(gotFC.MissedProofOutputs))
		for i := range expected.MissedProofOutputs {
			testutil.Check(t, "missed proof output address", expected.MissedProofOutputs[i].Address, gotFC.MissedProofOutputs[i].Address)
			testutil.Check(t, "missed proof output value", expected.MissedProofOutputs[i].Value, gotFC.MissedProofOutputs[i].Value)
		}
	}

	windowStart := cm.Tip().Height + 10
	windowEnd := windowStart + 10
	fc := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), windowStart, windowEnd, types.VoidAddress)
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

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    1,
		StorageUtilization: contractFilesize,
	})

	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "fcs", 1, len(dbFCs))
		checkFC(false, false, fc, dbFCs[0])

		testutil.Check(t, "confirmation index", cm.Tip(), *dbFCs[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *dbFCs[0].ConfirmationTransactionID)
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckFCRevisions(t, []uint64{0}, dbFCs)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", 1, len(txns))
		testutil.Check(t, "file contracts", 1, len(txns[0].FileContracts))
		checkFC(false, false, fc, txns[0].FileContracts[0])
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

	testutil.CheckMetrics(t, db, cm, explorer.Metrics{
		TotalHosts:         0,
		ActiveContracts:    1,
		StorageUtilization: contractFilesize + 10,
	})

	// Explorer.Contracts should return latest revision
	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "fcs", 1, len(dbFCs))
		checkFC(false, false, revFC, dbFCs[0])

		testutil.Check(t, "confirmation index", prevState1.Index, *dbFCs[0].ConfirmationIndex)
		testutil.Check(t, "confirmation transaction ID", txn.ID(), *dbFCs[0].ConfirmationTransactionID)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Check(t, "transactions", 1, len(txns))
		testutil.Check(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		testutil.Check(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		testutil.Check(t, "unlock conditions", uc, fcr.UnlockConditions)

		checkFC(false, false, revFC, fcr.FileContract)
	}

	{
		dbFCs, err := db.ContractRevisions(fcID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckFCRevisions(t, []uint64{0, 1}, dbFCs)
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
		testutil.Check(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
		testutil.Check(t, "len(contracts)", 1, len(renterContracts))
		checkFC(false, false, revFC, renterContracts[0])
		checkFC(false, false, revFC, hostContracts[0])
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
			testutil.Check(t, "fcs", 1, len(dbFCs))
			checkFC(false, false, fc, dbFCs[0])

			testutil.Check(t, "confirmation index", prevState1.Index, *dbFCs[0].ConfirmationIndex)
			testutil.Check(t, "confirmation transaction ID", txn.ID(), *dbFCs[0].ConfirmationTransactionID)
		}

		{
			dbFCs, err := db.ContractRevisions(fcID)
			if err != nil {
				t.Fatal(err)
			}
			testutil.CheckFCRevisions(t, []uint64{0}, dbFCs)
		}

		// storage utilization should be back to contractFilesize instead of
		// contractFilesize + 10
		testutil.CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    1,
			StorageUtilization: contractFilesize,
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
			testutil.Check(t, "fcs", 1, len(dbFCs))
			checkFC(false, false, revFC, dbFCs[0])

			testutil.Check(t, "confirmation index", prevState1.Index, *dbFCs[0].ConfirmationIndex)
			testutil.Check(t, "confirmation transaction ID", txn.ID(), *dbFCs[0].ConfirmationTransactionID)
		}

		// should have revision filesize
		testutil.CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts:         0,
			ActiveContracts:    1,
			StorageUtilization: contractFilesize + 10,
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
			testutil.Check(t, "fcs", 0, len(dbFCs))
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
			testutil.Check(t, "renter contracts and host contracts", len(renterContracts), len(hostContracts))
			testutil.Check(t, "len(contracts)", 0, len(renterContracts))
		}

		{
			_, err := db.ContractRevisions(fcID)
			if err != explorer.ErrContractNotFound {
				t.Fatal(err)
			}
		}

		// no more contracts or storage utilization
		testutil.CheckMetrics(t, db, cm, explorer.Metrics{
			TotalHosts: 0,
		})
	}
}

func TestMetricCirculatingSupply(t *testing.T) {
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

	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	giftSC := types.Siacoins(1000)
	network, genesisBlock := testutil.TestV1Network(addr1, giftSC, 0)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	circulatingSupply := genesisState.FoundationSubsidy().Value
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

			testutil.Check(t, "circulating supply", circulatingSupply, metrics.CirculatingSupply)
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

		testutil.Check(t, "circulating supply", circulatingSupply, metrics.CirculatingSupply)
	}
}
