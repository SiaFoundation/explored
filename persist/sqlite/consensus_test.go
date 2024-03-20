package sqlite_test

import (
	"path/filepath"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap/zaptest"
)

func testV1Network() (*consensus.Network, types.Block) {
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

	network, genesisBlock := testV1Network()

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
		Signatures: []types.TransactionSignature{
			{
				ParentID:       utxos[0].ID,
				PublicKeyIndex: 0,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
			},
		},
	}
	parentSigHash := cm.TipState().WholeSigHash(parentTxn, utxos[0].ID, 0, 0, nil)
	parentSig := pk1.SignHash(parentSigHash)
	parentTxn.Signatures[0].Signature = parentSig[:]

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
		Signatures: []types.TransactionSignature{
			{
				ParentID:       types.Hash256(outputID),
				PublicKeyIndex: 0,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
			},
		},
	}
	sigHash := cm.TipState().WholeSigHash(txn, types.Hash256(outputID), 0, 0, nil)
	sig := pk1.SignHash(sigHash)
	txn.Signatures[0].Signature = sig[:]

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

	network, genesisBlock := testV1Network()

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cm := chain.NewManager(store, genesisState)

	if err := cm.AddSubscriber(db, types.ChainIndex{}); err != nil {
		t.Fatal(err)
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

	// Check that addr1 has the miner payout output
	utxos, err := db.UnspentSiacoinOutputs(addr1, 100, 0)
	if err != nil {
		t.Fatal(err)
	} else if len(utxos) != 1 {
		t.Fatalf("expected 1 utxo, got %d", len(utxos))
	} else if utxos[0].SiacoinOutput.Value != expectedPayout {
		t.Fatalf("expected value %v, got %v", expectedPayout, utxos[0].SiacoinOutput.Value)
	}

	checkTransaction := func(expectTxn types.Transaction, gotTxn explorer.Transaction) {
		if len(expectTxn.SiacoinOutputs) != len(expectTxn.SiacoinOutputs) {
			t.Fatalf("expected %d siacoin outputs, got %d", len(expectTxn.SiacoinOutputs), len(expectTxn.SiacoinOutputs))
		}

		for j := range expectTxn.SiacoinOutputs {
			expectSco := expectTxn.SiacoinOutputs[j]
			gotSco := gotTxn.SiacoinOutputs[j].SiacoinOutput
			if expectSco.Address != gotSco.Address {
				t.Fatalf("expected address %v, got %v", expectSco.Address, gotSco.Address)
			} else if expectSco.Value != gotSco.Value {
				t.Fatalf("expected value %v, got %v", expectSco.Value, gotSco.Value)
			}
		}
	}

	outputID := utxos[0].ID
	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())
	// Send 1 SC to addr2 and 2 SC to addr3 100 times in consecutive blocks
	for i := 0; i < 100; i++ {
		parentTxn := types.Transaction{
			SiacoinInputs: []types.SiacoinInput{
				{
					ParentID:         types.SiacoinOutputID(outputID),
					UnlockConditions: unlockConditions,
				},
			},
			SiacoinOutputs: []types.SiacoinOutput{
				{Address: addr2, Value: types.Siacoins(1)},
				{Address: addr3, Value: types.Siacoins(2)},
				{Address: addr1, Value: expectedPayout.Sub(types.Siacoins(1 + 2).Mul64(uint64(i + 1)))},
			},
			Signatures: []types.TransactionSignature{
				{
					ParentID:       outputID,
					PublicKeyIndex: 0,
					CoveredFields:  types.CoveredFields{WholeTransaction: true},
				},
			},
		}

		parentSigHash := cm.TipState().WholeSigHash(parentTxn, outputID, 0, 0, nil)
		parentSig := pk1.SignHash(parentSigHash)
		parentTxn.Signatures[0].Signature = parentSig[:]
		outputID = types.Hash256(parentTxn.SiacoinOutputID(2))

		// Mine a block with the above transaction
		b := mineBlock(cm.TipState(), []types.Transaction{parentTxn}, addr1)
		if err := cm.AddBlocks([]types.Block{b}); err != nil {
			t.Fatal(err)
		}

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
	}
}
