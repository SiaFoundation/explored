package sqlite_test

import (
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
	defer store.Close()

	cm := chain.NewManager(store, genesisState)

	if err := cm.AddSubscriber(db, types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	// checkBalance checks that an address has the balances we expect
	checkBalance := func(addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
		sc, immatureSC, sf, err := db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		} else if sc != expectSC {
			t.Fatalf("expected %v siacoins, got %v", expectSC, sc)
		} else if immatureSC != expectImmatureSC {
			t.Fatalf("expected %v immature siacoins, got %v", expectImmatureSC, immatureSC)
		} else if sf != expectSF {
			t.Fatalf("expected %d siafunds, got %d", expectSF, sf)
		}
	}

	// Generate three addresses: addr1, addr2, addr3
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	pk3 := types.GeneratePrivateKey()
	addr3 := types.StandardUnlockHash(pk3.PublicKey())

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight() + 1

	// Mine a block sending the payout to addr1
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr1)}); err != nil {
		t.Fatal(err)
	}

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, 100, 0)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 utxo, got %d", len(utxos))
	} else if utxos[0].SiacoinOutput.Value != expectedPayout {
		t.Fatalf("expected value %v, got %v", expectedPayout, utxos[0].SiacoinOutput.Value)
	}

	// Mine until the payout matures
	for i := cm.TipState().Index.Height; i < maturityHeight; i++ {
		checkBalance(addr1, types.ZeroCurrency, expectedPayout, 0)
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
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
	defer store.Close()

	cm := chain.NewManager(store, genesisState)

	if err := cm.AddSubscriber(db, types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	// checkBalance checks that an address has the balances we expect
	checkBalance := func(addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
		sc, immatureSC, sf, err := db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		} else if sc != expectSC {
			t.Fatalf("expected %v siacoins, got %v", expectSC, sc)
		} else if immatureSC != expectImmatureSC {
			t.Fatalf("expected %v immature siacoins, got %v", expectImmatureSC, immatureSC)
		} else if sf != expectSF {
			t.Fatalf("expected %d siafunds, got %d", expectSF, sf)
		}
	}

	checkTransaction := func(expectTxn types.Transaction, gotTxn explorer.Transaction) {
		if len(expectTxn.SiacoinInputs) != len(gotTxn.SiacoinInputs) {
			t.Fatalf("expected %d siacoin inputs, got %d", len(expectTxn.SiacoinInputs), len(gotTxn.SiacoinInputs))
		} else if len(expectTxn.SiacoinOutputs) != len(gotTxn.SiacoinOutputs) {
			t.Fatalf("expected %d siacoin outputs, got %d", len(expectTxn.SiacoinOutputs), len(gotTxn.SiacoinOutputs))
		} else if len(expectTxn.SiafundInputs) != len(gotTxn.SiafundInputs) {
			t.Fatalf("expected %d siafund inputs, got %d", len(expectTxn.SiafundInputs), len(gotTxn.SiafundInputs))
		} else if len(expectTxn.SiafundOutputs) != len(gotTxn.SiafundOutputs) {
			t.Fatalf("expected %d siafund outputs, got %d", len(expectTxn.SiafundOutputs), len(gotTxn.SiafundOutputs))
		}

		for i := range expectTxn.SiacoinInputs {
			expectSci := expectTxn.SiacoinInputs[i]
			gotSci := gotTxn.SiacoinInputs[i]
			if expectSci.ParentID != gotSci.ParentID {
				t.Fatalf("expected parent ID %v, got %v", expectSci.ParentID, gotSci.ParentID)
			} else if !reflect.DeepEqual(expectSci.UnlockConditions, gotSci.UnlockConditions) {
				t.Fatalf("expected unlock conditions %v, got %v", expectSci.UnlockConditions, gotSci.UnlockConditions)
			}
		}
		for i := range expectTxn.SiacoinOutputs {
			expectSco := expectTxn.SiacoinOutputs[i]
			gotSco := gotTxn.SiacoinOutputs[i].SiacoinOutput
			if expectSco.Address != gotSco.Address {
				t.Fatalf("expected address %v, got %v", expectSco.Address, gotSco.Address)
			} else if expectSco.Value != gotSco.Value {
				t.Fatalf("expected value %v, got %v", expectSco.Value, gotSco.Value)
			} else if gotTxn.SiacoinOutputs[i].Source != explorer.SourceTransaction {
				t.Fatalf("expected source %v, got %v", explorer.SourceTransaction, gotTxn.SiacoinOutputs[i].Source)
			}
		}
		for i := range expectTxn.SiafundInputs {
			expectSfi := expectTxn.SiafundInputs[i]
			gotSfi := gotTxn.SiafundInputs[i]
			if expectSfi.ParentID != gotSfi.ParentID {
				t.Fatalf("expected parent ID %v, got %v", expectSfi.ParentID, gotSfi.ParentID)
			} else if expectSfi.ClaimAddress != gotSfi.ClaimAddress {
				t.Fatalf("expected claim address %v, got %v", expectSfi.ClaimAddress, gotSfi.ClaimAddress)
			} else if !reflect.DeepEqual(expectSfi.UnlockConditions, gotSfi.UnlockConditions) {
				t.Fatalf("expected unlock conditions %v, got %v", expectSfi.UnlockConditions, gotSfi.UnlockConditions)
			}
		}
		for i := range expectTxn.SiafundOutputs {
			expectSfo := expectTxn.SiafundOutputs[i]
			gotSfo := gotTxn.SiafundOutputs[i].SiafundOutput
			if expectSfo.Address != gotSfo.Address {
				t.Fatalf("expected address %v, got %v", expectSfo.Address, gotSfo.Address)
			} else if expectSfo.Value != gotSfo.Value {
				t.Fatalf("expected value %v, got %v", expectSfo.Value, gotSfo.Value)
			}
		}
	}

	expectedPayout := cm.TipState().BlockReward()
	maturityHeight := cm.TipState().MaturityHeight() + 1

	// Mine a block sending the payout to the addr1
	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, addr1)}); err != nil {
		t.Fatal(err)
	}

	// Mine until the payout matures
	for i := cm.TipState().Index.Height; i < maturityHeight; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
	}

	checkBalance(addr1, expectedPayout, types.ZeroCurrency, giftSF)
	checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency, 0)
	checkBalance(addr3, types.ZeroCurrency, types.ZeroCurrency, 0)

	const n = 100

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, n, 0)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 utxo, got %d", len(utxos))
	} else if utxos[0].SiacoinOutput.Value != expectedPayout {
		t.Fatalf("expected value %v, got %v", expectedPayout, utxos[0].SiacoinOutput.Value)
	} else if utxos[0].Source != explorer.SourceMinerPayout {
		t.Fatalf("expected source %v, got %v", explorer.SourceMinerPayout, utxos[0].Source)
	}

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

		checkBalance(addr1, addr1SCs, types.ZeroCurrency, addr1SFs)
		checkBalance(addr2, types.Siacoins(1).Mul64(uint64(i+1)), types.ZeroCurrency, 1*uint64(i+1))
		checkBalance(addr3, types.Siacoins(2).Mul64(uint64(i+1)), types.ZeroCurrency, 2*uint64(i+1))

		// Ensure the block we retrieved from the database is the same as the
		// actual block
		block, err := db.Block(b.ID())
		if err != nil {
			t.Fatal(err)
		} else if len(b.Transactions) != len(block.Transactions) {
			t.Fatalf("expected %d transactions, got %d", len(b.Transactions), len(block.Transactions))
		} else if b.Nonce != block.Nonce {
			t.Fatalf("expected nonce %d, got %d", b.Nonce, block.Nonce)
		} else if b.Timestamp != block.Timestamp {
			t.Fatalf("expected timestamp %d, got %d", b.Timestamp.Unix(), block.Timestamp.Unix())
		} else if len(b.MinerPayouts) != len(block.MinerPayouts) {
			t.Fatalf("expected %d miner payouts, got %d", len(b.MinerPayouts), len(block.MinerPayouts))
		} else if len(b.Transactions) != len(block.Transactions) {
			t.Fatalf("expected %d transactions, got %d", len(b.Transactions), len(block.Transactions))
		}

		// Ensure the miner payouts in the block match
		for i := range b.MinerPayouts {
			if b.MinerPayouts[i].Address != block.MinerPayouts[i].SiacoinOutput.Address {
				t.Fatalf("expected address %v, got %v", b.MinerPayouts[i].Address, block.MinerPayouts[i].SiacoinOutput.Address)
			} else if b.MinerPayouts[i].Value != block.MinerPayouts[i].SiacoinOutput.Value {
				t.Fatalf("expected value %v, got %v", b.MinerPayouts[i].Value, block.MinerPayouts[i].SiacoinOutput.Value)
			}
		}

		// Ensure the transactions in the block and retrieved separately match
		// with the actual transactions
		for i := range b.Transactions {
			checkTransaction(b.Transactions[i], block.Transactions[i])

			txns, err := db.Transactions([]types.TransactionID{b.Transactions[i].ID()})
			if err != nil {
				t.Fatal(err)
			} else if len(txns) != 1 {
				t.Fatal("failed to get transaction")
			}
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

			if e.sc != len(sc) {
				t.Fatalf("expected %d siacoin utxos, got %d", e.sc, len(sc))
			} else if e.sf != len(sf) {
				t.Fatalf("expected %d siafund utxos, got %d", e.sf, len(sf))
			}

			for _, sco := range sc {
				if e.addr != sco.SiacoinOutput.Address {
					t.Fatalf("expected address %v, got %v", e.addr, sco.SiacoinOutput.Address)
				} else if e.scValue != sco.SiacoinOutput.Value {
					t.Fatalf("expected value %v, got %v", e.scValue, sco.SiacoinOutput.Value)
				} else if explorer.SourceTransaction != sco.Source {
					t.Fatalf("expected source %v, got %v", explorer.SourceTransaction, sco.Source)
				}
			}
			for _, sfo := range sf {
				if e.addr != sfo.SiafundOutput.Address {
					t.Fatalf("expected address %v, got %v", e.addr, sfo.SiafundOutput.Address)
				} else if e.sfValue != sfo.SiafundOutput.Value {
					t.Fatalf("expected value %v, got %v", e.sfValue, sfo.SiafundOutput.Value)
				}
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
	defer store.Close()

	cm := chain.NewManager(store, genesisState)

	if err := cm.AddSubscriber(db, types.ChainIndex{}); err != nil {
		t.Fatal(err)
	}

	const n = 100
	for i := cm.TipState().Index.Height; i < n; i++ {
		if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}

		tip, err := db.Tip()
		if err != nil {
			t.Fatal(err)
		}
		if cm.Tip() != tip {
			t.Fatal("tip mismatch")
		}
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
			{Algorithm: types.SpecifierEd25519, Key: renterPubKey[:]},
			{Algorithm: types.SpecifierEd25519, Key: hostKey[:]},
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
	defer store.Close()

	cm := chain.NewManager(store, genesisState)
	// if err := cm.AddSubscriber(db, types.ChainIndex{}); err != nil {
	// 	t.Fatal(err)
	// }

	scOutputID := genesisBlock.Transactions[0].SiacoinOutputID(0)
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())

	signTxn := func(cs consensus.State, txn *types.Transaction) {
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

	fc := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), cm.Tip().Height+1, 100, types.VoidAddress)
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
	signTxn(cm.TipState(), &txn)

	if err := cm.AddBlocks([]types.Block{mineBlock(cm.TipState(), []types.Transaction{txn}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
}
