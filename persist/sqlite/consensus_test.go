package sqlite_test

import (
	"errors"
	"math/bits"
	"path/filepath"
	"reflect"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap/zaptest"
)

func testV1Network(giftAddr types.Address, sc types.Currency, sf uint64) (*consensus.Network, types.Block) {
	// use a modified version of Zen
	n, genesisBlock := chain.TestnetZen()
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkDevAddr.Height = 1
	n.HardforkTax.Height = 1
	n.HardforkStorageProof.Height = 1
	n.HardforkOak.Height = 1
	n.HardforkASIC.Height = 1
	n.HardforkFoundation.Height = 1
	n.HardforkV2.AllowHeight = 1000
	n.HardforkV2.RequireHeight = 1000
	genesisBlock.Transactions = []types.Transaction{{}}
	if sf > 0 {
		genesisBlock.Transactions[0].SiafundOutputs = []types.SiafundOutput{{
			Address: giftAddr,
			Value:   sf,
		}}
	}
	if sc.Cmp(types.ZeroCurrency) == 1 {
		genesisBlock.Transactions[0].SiacoinOutputs = []types.SiacoinOutput{{
			Address: giftAddr,
			Value:   sc,
		}}
	}
	return n, genesisBlock
}

func testV2Network() (*consensus.Network, types.Block) {
	// use a modified version of Zen
	n, genesisBlock := chain.TestnetZen()
	n.InitialTarget = types.BlockID{0xFF}
	n.HardforkDevAddr.Height = 1
	n.HardforkTax.Height = 1
	n.HardforkStorageProof.Height = 1
	n.HardforkOak.Height = 1
	n.HardforkASIC.Height = 1
	n.HardforkFoundation.Height = 1
	n.HardforkV2.AllowHeight = 100
	n.HardforkV2.RequireHeight = 110
	return n, genesisBlock
}

func mineBlock(state consensus.State, txns []types.Transaction, minerAddr types.Address) types.Block {
	b := types.Block{
		ParentID:     state.Index.ID,
		Timestamp:    types.CurrentTimestamp(),
		Transactions: txns,
		MinerPayouts: []types.SiacoinOutput{{Address: minerAddr, Value: state.BlockReward()}},
	}
	for b.ID().CmpWork(state.ChildTarget) < 0 {
		b.Nonce += state.NonceFactor()
	}
	return b
}

func mineV2Block(state consensus.State, txns []types.V2Transaction, minerAddr types.Address) types.Block {
	b := types.Block{
		ParentID:     state.Index.ID,
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: minerAddr, Value: state.BlockReward()}},

		V2: &types.V2BlockData{
			Transactions: txns,
			Height:       state.Index.Height + 1,
		},
	}
	b.V2.Commitment = state.Commitment(state.TransactionsCommitment(b.Transactions, b.V2Transactions()), b.MinerPayouts[0].Address)
	for b.ID().CmpWork(state.ChildTarget) < 0 {
		b.Nonce += state.NonceFactor()
	}
	return b
}

func signTxn(cs consensus.State, pk types.PrivateKey, txn *types.Transaction) {
	appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
		sig := key.SignHash(cs.WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{
			ParentID:       parentID,
			CoveredFields:  types.CoveredFields{WholeTransaction: true},
			PublicKeyIndex: pubkeyIndex,
			Signature:      sig[:],
		})
	}
	for i := range txn.SiacoinInputs {
		appendSig(pk, 0, types.Hash256(txn.SiacoinInputs[i].ParentID))
	}
	for i := range txn.SiafundInputs {
		appendSig(pk, 0, types.Hash256(txn.SiafundInputs[i].ParentID))
	}
}

func check(t *testing.T, desc string, expect, got any) {
	if !reflect.DeepEqual(expect, got) {
		t.Fatalf("expected %v %s, got %v", expect, desc, got)
	}
}

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

		if err := db.ProcessChainUpdates(crus, caus); err != nil {
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

	network, genesisBlock := testV1Network(types.VoidAddress, types.ZeroCurrency, 0)

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
		check(t, "siacoins", expectSC, sc)
		check(t, "immature siacoins", expectImmatureSC, immatureSC)
		check(t, "siafunds", expectSF, sf)
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
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr1)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	check(t, "utxos", 1, len(utxos))
	check(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	check(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

	// Mine until the payout matures
	for i := cm.Tip().Height; i < maturityHeight; i++ {
		checkBalance(addr1, types.ZeroCurrency, expectedPayout, 0)
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
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
	signTxn(cm.TipState(), pk1, &parentTxn)

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
	signTxn(cm.TipState(), pk1, &txn)

	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), []types.Transaction{parentTxn, txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	checkBalance(addr2, utxos[0].SiacoinOutput.Value.Sub(types.Siacoins(100)), types.ZeroCurrency, 0)
	checkBalance(addr3, types.Siacoins(100), types.ZeroCurrency, 0)
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
	network, genesisBlock := testV1Network(addr1, types.ZeroCurrency, giftSF)

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
		check(t, "siacoins", expectSC, sc)
		check(t, "immature siacoins", expectImmatureSC, immatureSC)
		check(t, "siafunds", expectSF, sf)
	}

	checkTransaction := func(expectTxn types.Transaction, gotTxn explorer.Transaction) {
		check(t, "siacoin inputs", len(expectTxn.SiacoinInputs), len(gotTxn.SiacoinInputs))
		check(t, "siacoin outputs", len(expectTxn.SiacoinOutputs), len(gotTxn.SiacoinOutputs))
		check(t, "siafund inputs", len(expectTxn.SiafundInputs), len(gotTxn.SiafundInputs))
		check(t, "siafund outputs", len(expectTxn.SiafundOutputs), len(gotTxn.SiafundOutputs))

		for i := range expectTxn.SiacoinInputs {
			expectSci := expectTxn.SiacoinInputs[i]
			gotSci := gotTxn.SiacoinInputs[i]

			check(t, "parent ID", expectSci.ParentID, gotSci.ParentID)
			check(t, "unlock conditions", expectSci.UnlockConditions, gotSci.UnlockConditions)
		}
		for i := range expectTxn.SiacoinOutputs {
			expectSco := expectTxn.SiacoinOutputs[i]
			gotSco := gotTxn.SiacoinOutputs[i].SiacoinOutput

			check(t, "address", expectSco.Address, gotSco.Address)
			check(t, "value", expectSco.Value, gotSco.Value)
			check(t, "source", explorer.SourceTransaction, gotTxn.SiacoinOutputs[i].Source)
		}
		for i := range expectTxn.SiafundInputs {
			expectSfi := expectTxn.SiafundInputs[i]
			gotSfi := gotTxn.SiafundInputs[i]

			check(t, "parent ID", expectSfi.ParentID, gotSfi.ParentID)
			check(t, "claim address", expectSfi.ClaimAddress, gotSfi.ClaimAddress)
			check(t, "unlock conditions", expectSfi.UnlockConditions, gotSfi.UnlockConditions)
		}
		for i := range expectTxn.SiafundOutputs {
			expectSfo := expectTxn.SiafundOutputs[i]
			gotSfo := gotTxn.SiafundOutputs[i].SiafundOutput

			check(t, "address", expectSfo.Address, gotSfo.Address)
			check(t, "value", expectSfo.Value, gotSfo.Value)
		}
	}

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight()

	// Mine a block sending the payout to the addr1
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr1)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	// Mine until the payout matures
	for i := cm.Tip().Height; i < maturityHeight; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	checkBalance(addr1, expectedPayout, types.ZeroCurrency, giftSF)
	checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
	checkBalance(addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

	const n = 100

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, n, 0)
	if err != nil {
		t.Fatal(err)
	}
	check(t, "utxos", 1, len(utxos))
	check(t, "value", expectedPayout, utxos[0].SiacoinOutput.Value)
	check(t, "source", explorer.SourceMinerPayout, utxos[0].Source)

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

		signTxn(cm.TipState(), pk1, &parentTxn)
		scOutputID = types.Hash256(parentTxn.SiacoinOutputID(2))
		sfOutputID = parentTxn.SiafundOutputID(2)

		// Mine a block with the above transaction
		b := mineBlock(cm.TipState(), []types.Transaction{parentTxn}, types.VoidAddress)
		if err := cm.AddBlocks([]types.Block{b}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		checkBalance(addr1, addr1SCs, types.ZeroCurrency, addr1SFs)
		checkBalance(addr2, types.Siacoins(1).Mul64(uint64(i+1)), types.ZeroCurrency, 1*uint64(i+1))
		checkBalance(addr3, types.Siacoins(2).Mul64(uint64(i+1)), types.ZeroCurrency, 2*uint64(i+1))

		// Ensure the block we retrieved from the database is the same as the
		// actual block
		block, err := db.Block(b.ID())
		if err != nil {
			t.Fatal(err)
		}
		check(t, "transactions", len(b.Transactions), len(block.Transactions))
		check(t, "miner payouts", len(b.MinerPayouts), len(block.MinerPayouts))
		check(t, "nonce", b.Nonce, block.Nonce)
		check(t, "timestamp", b.Timestamp, block.Timestamp)

		// Ensure the miner payouts in the block match
		for i := range b.MinerPayouts {
			check(t, "address", b.MinerPayouts[i].Address, b.MinerPayouts[i].Address)
			check(t, "value", b.MinerPayouts[i].Value, b.MinerPayouts[i].Value)
		}

		// Ensure the transactions in the block and retrieved separately match
		// with the actual transactions
		for i := range b.Transactions {
			checkTransaction(b.Transactions[i], block.Transactions[i])

			txns, err := db.Transactions([]types.TransactionID{b.Transactions[i].ID()})
			if err != nil {
				t.Fatal(err)
			}
			check(t, "transactions", 1, len(txns))
			checkTransaction(b.Transactions[i], txns[0])
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
			sc, err := db.UnspentSiacoinOutputs(e.addr, n, 0)
			if err != nil {
				t.Fatal(err)
			}
			sf, err := db.UnspentSiafundOutputs(e.addr, n, 0)
			if err != nil {
				t.Fatal(err)
			}

			check(t, "sc utxos", e.sc, len(sc))
			check(t, "sf utxos", e.sf, len(sf))

			for _, sco := range sc {
				check(t, "address", e.addr, sco.SiacoinOutput.Address)
				check(t, "value", e.scValue, sco.SiacoinOutput.Value)
				check(t, "source", explorer.SourceTransaction, sco.Source)
			}
			for _, sfo := range sf {
				check(t, "address", e.addr, sfo.SiafundOutput.Address)
				check(t, "value", e.sfValue, sfo.SiafundOutput.Value)
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

	network, genesisBlock := testV1Network(types.VoidAddress, types.ZeroCurrency, 0)

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	const n = 100
	for i := cm.Tip().Height; i < n; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)

		tip, err := db.Tip()
		if err != nil {
			t.Fatal(err)
		}
		check(t, "tip", cm.Tip(), tip)
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
func prepareContractFormation(renterPubKey types.PublicKey, hostKey types.PublicKey, renterPayout, hostCollateral types.Currency, endHeight uint64, windowSize uint64, refundAddr types.Address) types.FileContract {
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
		Filesize:       0,
		FileMerkleRoot: types.Hash256{},
		WindowStart:    endHeight,
		WindowEnd:      endHeight + windowSize,
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
	network, genesisBlock := testV1Network(addr1, giftSC, 0)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	scOutputID := genesisBlock.Transactions[0].SiacoinOutputID(0)
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())

	signTxn := func(txn *types.Transaction) {
		appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
			sig := key.SignHash(cm.TipState().WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
			txn.Signatures = append(txn.Signatures, types.TransactionSignature{
				ParentID:       parentID,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
				PublicKeyIndex: pubkeyIndex,
				Signature:      sig[:],
			})
		}
		for i := range txn.SiacoinInputs {
			appendSig(pk1, 0, types.Hash256(txn.SiacoinInputs[i].ParentID))
		}
		for i := range txn.SiafundInputs {
			appendSig(pk1, 0, types.Hash256(txn.SiafundInputs[i].ParentID))
		}
		for i := range txn.FileContractRevisions {
			appendSig(renterPrivateKey, 0, types.Hash256(txn.FileContractRevisions[i].ParentID))
			appendSig(hostPrivateKey, 1, types.Hash256(txn.FileContractRevisions[i].ParentID))
		}
	}

	checkFC := func(resolved, valid bool, expected types.FileContract, got explorer.FileContract) {
		check(t, "resolved state", resolved, got.Resolved)
		check(t, "valid state", valid, got.Valid)
		check(t, "filesize", expected.Filesize, got.Filesize)
		check(t, "file merkle root", expected.FileMerkleRoot, got.FileMerkleRoot)
		check(t, "window start", expected.WindowStart, got.WindowStart)
		check(t, "window end", expected.WindowEnd, got.WindowEnd)
		check(t, "payout", expected.Payout, got.Payout)
		check(t, "unlock hash", expected.UnlockHash, got.UnlockHash)
		check(t, "revision number", expected.RevisionNumber, got.RevisionNumber)
		check(t, "valid proof outputs", len(expected.ValidProofOutputs), len(got.ValidProofOutputs))
		for i := range expected.ValidProofOutputs {
			check(t, "valid proof output address", expected.ValidProofOutputs[i].Address, got.ValidProofOutputs[i].Address)
			check(t, "valid proof output value", expected.ValidProofOutputs[i].Value, got.ValidProofOutputs[i].Value)
		}
		check(t, "missed proof outputs", len(expected.MissedProofOutputs), len(got.MissedProofOutputs))
		for i := range expected.MissedProofOutputs {
			check(t, "missed proof output address", expected.MissedProofOutputs[i].Address, got.MissedProofOutputs[i].Address)
			check(t, "missed proof output value", expected.MissedProofOutputs[i].Value, got.MissedProofOutputs[i].Value)
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
	signTxn(&txn)

	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), []types.Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		check(t, "fcs", 1, len(dbFCs))
		checkFC(false, true, fc, dbFCs[0])
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		check(t, "transactions", 1, len(txns))
		check(t, "file contracts", 1, len(txns[0].FileContracts))
		checkFC(false, true, fc, txns[0].FileContracts[0])
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
	signTxn(&reviseTxn)

	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), []types.Transaction{reviseTxn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	// Explorer.Contracts should return latest revision
	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		check(t, "fcs", 1, len(dbFCs))
		checkFC(false, true, fc, dbFCs[0])
	}

	{
		txns, err := db.Transactions([]types.TransactionID{reviseTxn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		check(t, "transactions", 1, len(txns))
		check(t, "file contracts", 1, len(txns[0].FileContractRevisions))

		fcr := txns[0].FileContractRevisions[0]
		check(t, "parent id", txn.FileContractID(0), fcr.ParentID)
		check(t, "unlock conditions", uc, fcr.UnlockConditions)

		checkFC(false, true, fc, fcr.FileContract)
	}

	for i := cm.Tip().Height; i < windowEnd+10; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	{
		dbFCs, err := db.Contracts([]types.FileContractID{fcID})
		if err != nil {
			t.Fatal(err)
		}
		check(t, "fcs", 1, len(dbFCs))
		checkFC(true, false, fc, dbFCs[0])
	}
}
