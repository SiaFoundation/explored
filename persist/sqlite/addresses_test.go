package sqlite

import (
	"math"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
)

// assertSCE asserts the Siacoin element in the db has the right source, index and output
func (n *testChain) assertSCE(t testing.TB, scID types.SiacoinOutputID, index *types.ChainIndex, sco types.SiacoinOutput) {
	t.Helper()

	sces, err := n.db.SiacoinElements([]types.SiacoinOutputID{scID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(sces)", 1, len(sces))

	sce := sces[0]
	testutil.Equal(t, "sce.Source", explorer.SourceTransaction, sce.Source)
	testutil.Equal(t, "sce.SpentIndex", index, sce.SpentIndex)
	testutil.Equal(t, "sce.SiacoinElement.SiacoinOutput", sco, sce.SiacoinOutput)
}

// assertSFE asserts the Siafund element in the db has the right source, index and output
func (n *testChain) assertSFE(t testing.TB, sfID types.SiafundOutputID, index *types.ChainIndex, sfo types.SiafundOutput) {
	t.Helper()

	sfes, err := n.db.SiafundElements([]types.SiafundOutputID{sfID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(sfes)", 1, len(sfes))

	sfe := sfes[0]
	testutil.Equal(t, "sfe.SpentIndex", index, sfe.SpentIndex)
	testutil.Equal(t, "sfe.SiafundElement.SiafundOutput", sfo, sfe.SiafundOutput)
}

func TestSiacoinOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	scID := n.genesis().Transactions[0].SiacoinOutputID(0)
	genesisOutput := n.genesis().Transactions[0].SiacoinOutputs[0]

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSCE(t, scID, nil, genesisOutput)

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         scID,
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	n.assertTransactions(t, txn1)

	// genesis output should be spent
	tip := n.tipState().Index
	n.assertSCE(t, scID, &tip, genesisOutput)

	// the output from txn1 should exist now that the block with txn1 was
	// mined
	n.assertSCE(t, txn1.SiacoinOutputID(0), nil, txn1.SiacoinOutputs[0])

	n.revertBlock(t)

	// the genesis output should be unspent now because we reverted the block
	// containing txn1 which spent it
	n.assertSCE(t, scID, nil, genesisOutput)

	// the output from txn1 should not exist after txn1 reverted
	{
		sces, err := n.db.SiacoinElements([]types.SiacoinOutputID{txn1.SiacoinOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 0, len(sces))
	}
}

func TestEphemeralSiacoinOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	scID := n.genesis().Transactions[0].SiacoinOutputID(0)
	genesisOutput := n.genesis().Transactions[0].SiacoinOutputs[0]

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSCE(t, scID, nil, genesisOutput)

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         scID,
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	txn2 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         txn1.SiacoinOutputID(0),
			UnlockConditions: uc2,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   txn1.SiacoinOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk2, &txn2)

	n.mineTransactions(t, txn1, txn2)

	n.assertTransactions(t, txn1, txn2)

	tip := n.tipState().Index
	// genesis output should be spent
	n.assertSCE(t, scID, &tip, genesisOutput)

	// now that txn1 and txn2 are mined the outputs from them should exist
	n.assertSCE(t, txn1.SiacoinOutputID(0), &tip, txn1.SiacoinOutputs[0])
	n.assertSCE(t, txn2.SiacoinOutputID(0), nil, txn2.SiacoinOutputs[0])

	n.revertBlock(t)

	// genesis output should be unspent now that we reverted
	n.assertSCE(t, scID, nil, genesisOutput)

	// outputs from txn1 and txn2 should not exist because those transactions
	// were reverted
	{
		sces, err := n.db.SiacoinElements([]types.SiacoinOutputID{txn1.SiacoinOutputID(0), txn2.SiacoinOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 0, len(sces))
	}
}

func TestSiafundOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	sfID := n.genesis().Transactions[0].SiafundOutputID(0)

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSFE(t, sfID, nil, n.genesis().Transactions[0].SiafundOutputs[0])

	txn1 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         sfID,
			UnlockConditions: uc1,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   n.genesis().Transactions[0].SiafundOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	n.assertTransactions(t, txn1)

	// genesis output should be spent
	tip := n.tipState().Index
	n.assertSFE(t, sfID, &tip, n.genesis().Transactions[0].SiafundOutputs[0])

	// the output from txn1 should exist now that the block with txn1 was
	// mined
	n.assertSFE(t, txn1.SiafundOutputID(0), nil, txn1.SiafundOutputs[0])

	n.revertBlock(t)

	// the genesis output should be unspent now because we reverted the block
	// containing txn1 which spent it
	n.assertSFE(t, sfID, nil, n.genesis().Transactions[0].SiafundOutputs[0])

	// the output from txn1 should not exist after txn1 reverted
	{
		sfes, err := n.db.SiafundElements([]types.SiafundOutputID{txn1.SiafundOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 0, len(sfes))
	}
}

func TestEphemeralSiafundOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	sfID := n.genesis().Transactions[0].SiafundOutputID(0)

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSFE(t, sfID, nil, n.genesis().Transactions[0].SiafundOutputs[0])

	txn1 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         sfID,
			UnlockConditions: uc1,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   n.genesis().Transactions[0].SiafundOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	txn2 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         txn1.SiafundOutputID(0),
			UnlockConditions: uc2,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: types.VoidAddress,
			Value:   txn1.SiafundOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk2, &txn2)

	n.mineTransactions(t, txn1, txn2)

	n.assertTransactions(t, txn1, txn2)

	tip := n.tipState().Index
	// genesis output should be spent
	n.assertSFE(t, sfID, &tip, n.genesis().Transactions[0].SiafundOutputs[0])

	// now that txn1 and txn2 are mined the outputs from them should exist
	n.assertSFE(t, txn1.SiafundOutputID(0), &tip, txn1.SiafundOutputs[0])
	n.assertSFE(t, txn2.SiafundOutputID(0), nil, txn2.SiafundOutputs[0])

	n.revertBlock(t)

	// genesis output should be unspent now that we reverted
	n.assertSFE(t, sfID, nil, n.genesis().Transactions[0].SiafundOutputs[0])

	// outputs from txn1 and txn2 should not exist because those transactions
	// were reverted
	{
		sfes, err := n.db.SiafundElements([]types.SiafundOutputID{txn1.SiafundOutputID(0), txn2.SiafundOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 0, len(sfes))
	}
}

func TestSiacoinBalance(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	checkBalance := func(addr types.Address, expectedSC, expectedImmatureSC types.Currency) {
		t.Helper()

		sc, immatureSC, sf, err := n.db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "siacoins", expectedSC, sc)
		testutil.Equal(t, "immature siacoins", expectedImmatureSC, immatureSC)
		testutil.Equal(t, "siafunds", 0, sf)
	}

	// only addr1 should have SC from genesis block
	checkBalance(types.VoidAddress, types.ZeroCurrency, types.ZeroCurrency)
	checkBalance(addr1, val, types.ZeroCurrency)
	checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency)

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   val,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	// send addr1 output to addr2
	b := testutil.MineBlock(n.tipState(), []types.Transaction{txn1}, types.VoidAddress)
	n.applyBlock(t, b)

	// addr2 should have SC and the void address should have immature SC from
	// block
	checkBalance(types.VoidAddress, types.ZeroCurrency, b.MinerPayouts[0].Value)
	checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency)
	checkBalance(addr2, val, types.ZeroCurrency)

	n.revertBlock(t)

	// after revert, addr1 should have funds again and the void address should
	// have nothing
	checkBalance(types.VoidAddress, types.ZeroCurrency, types.ZeroCurrency)
	checkBalance(addr1, val, types.ZeroCurrency)
	checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency)
}

func TestSiafundBalance(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiafundOutputs[0].Value

	checkBalance := func(addr types.Address, expectedSF uint64) {
		t.Helper()

		sc, immatureSC, sf, err := n.db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "siacoins", types.ZeroCurrency, sc)
		if addr != types.VoidAddress {
			testutil.Equal(t, "immature siacoins", types.ZeroCurrency, immatureSC)
		}
		testutil.Equal(t, "siafunds", expectedSF, sf)
	}

	// addr1 should have SF from genesis block
	checkBalance(types.VoidAddress, 0)
	checkBalance(addr1, val)
	checkBalance(addr2, 0)

	txn1 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         n.genesis().Transactions[0].SiafundOutputID(0),
			UnlockConditions: uc1,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   val,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	// send addr1 SF to addr2
	n.mineTransactions(t, txn1)

	// addr2 should have SF now
	checkBalance(types.VoidAddress, 0)
	checkBalance(addr1, 0)
	checkBalance(addr2, val)

	n.revertBlock(t)

	// after revert, addr1 should have SF again
	checkBalance(types.VoidAddress, 0)
	checkBalance(addr1, val)
	checkBalance(addr2, 0)
}

func TestEphemeralSiacoinBalance(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	checkBalance := func(addr types.Address, expectedSC types.Currency) {
		t.Helper()

		sc, immatureSC, sf, err := n.db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "siacoins", expectedSC, sc)
		testutil.Equal(t, "immature siacoins", types.ZeroCurrency, immatureSC)
		testutil.Equal(t, "siafunds", 0, sf)
	}

	// only addr1 should have SC from genesis block
	checkBalance(addr1, val)
	checkBalance(addr2, types.ZeroCurrency)
	checkBalance(addr3, types.ZeroCurrency)

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   val,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	txn2 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         txn1.SiacoinOutputID(0),
			UnlockConditions: uc2,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr3,
			Value:   val,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk2, &txn2)

	// net effect of txn1 and txn2 is to send addr1 output to addr3
	n.mineTransactions(t, txn1, txn2)

	// addr3 should have all the value now
	checkBalance(addr1, types.ZeroCurrency)
	checkBalance(addr2, types.ZeroCurrency)
	checkBalance(addr3, val)

	n.revertBlock(t)

	// after revert, addr1 should have funds again and the others should
	// have nothing
	checkBalance(addr1, val)
	checkBalance(addr2, types.ZeroCurrency)
	checkBalance(addr3, types.ZeroCurrency)
}

func TestEphemeralSiafundBalance(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiafundOutputs[0].Value

	checkBalance := func(addr types.Address, expectedSF uint64) {
		t.Helper()

		sc, immatureSC, sf, err := n.db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "siacoins", types.ZeroCurrency, sc)
		testutil.Equal(t, "immature siacoins", types.ZeroCurrency, immatureSC)
		testutil.Equal(t, "siafunds", expectedSF, sf)
	}

	// only addr1 should have SF from genesis block
	checkBalance(addr1, val)
	checkBalance(addr2, 0)
	checkBalance(addr3, 0)

	txn1 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         n.genesis().Transactions[0].SiafundOutputID(0),
			UnlockConditions: uc1,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   val,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	txn2 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         txn1.SiafundOutputID(0),
			UnlockConditions: uc2,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr3,
			Value:   val,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk2, &txn2)

	// net effect of txn1 and txn2 is to send addr1 output to addr3
	n.mineTransactions(t, txn1, txn2)

	// addr3 should have all the value now
	checkBalance(addr1, 0)
	checkBalance(addr2, 0)
	checkBalance(addr3, val)

	n.revertBlock(t)

	// after revert, addr1 should have funds again and the others should
	// have nothing
	checkBalance(addr1, val)
	checkBalance(addr2, 0)
	checkBalance(addr3, 0)
}

func TestMaturedSiacoinBalance(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, nil)

	checkBalance := func(addr types.Address, expectedSC, expectedImmatureSC types.Currency) {
		t.Helper()

		sc, immatureSC, sf, err := n.db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "siacoins", expectedSC, sc)
		testutil.Equal(t, "immature siacoins", expectedImmatureSC, immatureSC)
		testutil.Equal(t, "siafunds", 0, sf)
	}

	checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency)

	b := testutil.MineBlock(n.tipState(), nil, addr1)
	n.applyBlock(t, b)

	val := b.MinerPayouts[0].Value

	for range n.network.MaturityDelay {
		checkBalance(addr1, types.ZeroCurrency, val)
		n.mineTransactions(t)
	}

	checkBalance(addr1, val, types.ZeroCurrency)

	for range n.network.MaturityDelay {
		n.revertBlock(t)
		checkBalance(addr1, types.ZeroCurrency, val)
	}

	n.revertBlock(t)
	checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency)
}

func TestUnspentSiacoinOutputs(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	scID := n.genesis().Transactions[0].SiacoinOutputID(0)
	genesisOutput := n.genesis().Transactions[0].SiacoinOutputs[0]

	checkSiacoinOutputs := func(addr types.Address, expected ...explorer.SiacoinOutput) {
		t.Helper()

		scos, err := n.db.UnspentSiacoinOutputs(addr, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(scos)", len(expected), len(scos))

		for i := range scos {
			testutil.Equal(t, "Source", expected[i].Source, scos[i].Source)
			testutil.Equal(t, "SpentIndex", expected[i].SpentIndex, scos[i].SpentIndex)
			testutil.Equal(t, "SiacoinOutput", expected[i].SiacoinOutput, scos[i].SiacoinOutput)
		}
	}

	// only addr1 should have SC from genesis block
	checkSiacoinOutputs(addr1, explorer.SiacoinOutput{
		Source: explorer.SourceTransaction,
		SiacoinElement: types.SiacoinElement{
			ID:            scID,
			SiacoinOutput: genesisOutput,
		},
	})
	checkSiacoinOutputs(addr2)
	checkSiacoinOutputs(addr3)

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         scID,
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	txn2 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         txn1.SiacoinOutputID(0),
			UnlockConditions: uc2,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr3,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk2, &txn2)

	// net effect of txn1 and txn2 is to send addr1 output to addr3
	n.mineTransactions(t, txn1, txn2)

	// addr3 should have all the value now
	checkSiacoinOutputs(addr1)
	checkSiacoinOutputs(addr2)
	checkSiacoinOutputs(addr3, explorer.SiacoinOutput{
		Source: explorer.SourceTransaction,
		SiacoinElement: types.SiacoinElement{
			ID:            txn2.SiacoinOutputID(0),
			SiacoinOutput: txn2.SiacoinOutputs[0],
		},
	})

	n.revertBlock(t)

	// after revert, addr1 should have the output again and the others should
	// have nothing
	checkSiacoinOutputs(addr1, explorer.SiacoinOutput{
		Source: explorer.SourceTransaction,
		SiacoinElement: types.SiacoinElement{
			ID:            scID,
			SiacoinOutput: genesisOutput,
		},
	})
	checkSiacoinOutputs(addr2)
	checkSiacoinOutputs(addr3)
}

func TestUnspentSiafundOutputs(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	genesisOutput := n.genesis().Transactions[0].SiafundOutputs[0]
	sfID := n.genesis().Transactions[0].SiafundOutputID(0)

	checkSiafundOutputs := func(addr types.Address, expected ...explorer.SiafundOutput) {
		t.Helper()

		sfos, err := n.db.UnspentSiafundOutputs(addr, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfos)", len(expected), len(sfos))

		for i := range sfos {
			testutil.Equal(t, "SpentIndex", expected[i].SpentIndex, sfos[i].SpentIndex)
			testutil.Equal(t, "SiafundOutput", expected[i].SiafundOutput, sfos[i].SiafundOutput)
		}
	}

	// only addr1 should have SF from genesis block
	checkSiafundOutputs(addr1, explorer.SiafundOutput{
		SiafundElement: types.SiafundElement{
			ID:            sfID,
			SiafundOutput: genesisOutput,
		},
	})
	checkSiafundOutputs(addr2)
	checkSiafundOutputs(addr3)

	txn1 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         sfID,
			UnlockConditions: uc1,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	txn2 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         txn1.SiafundOutputID(0),
			UnlockConditions: uc2,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr3,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk2, &txn2)

	// net effect of txn1 and txn2 is to send addr1 output to addr3
	n.mineTransactions(t, txn1, txn2)

	// addr3 should have all the value now
	checkSiafundOutputs(addr1)
	checkSiafundOutputs(addr2)
	checkSiafundOutputs(addr3, explorer.SiafundOutput{
		SiafundElement: types.SiafundElement{
			ID:            txn2.SiafundOutputID(0),
			SiafundOutput: txn2.SiafundOutputs[0],
		},
	})

	n.revertBlock(t)

	// after revert, addr1 should have the output again and the others should
	// have nothing
	checkSiafundOutputs(addr1, explorer.SiafundOutput{
		SiafundElement: types.SiafundElement{
			ID:            sfID,
			SiafundOutput: genesisOutput,
		},
	})
	checkSiafundOutputs(addr2)
	checkSiafundOutputs(addr3)
}

func TestV2SiacoinOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	scID := n.genesis().Transactions[0].SiacoinOutputID(0)
	genesisOutput := n.genesis().Transactions[0].SiacoinOutputs[0]

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSCE(t, scID, nil, genesisOutput)

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, scID),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	n.mineV2Transactions(t, txn1)

	n.assertV2Transactions(t, txn1)

	// genesis output should be spent
	tip := n.tipState().Index
	n.assertSCE(t, scID, &tip, genesisOutput)

	// the output from txn1 should exist now that the block with txn1 was
	// mined
	n.assertSCE(t, txn1.SiacoinOutputID(txn1.ID(), 0), nil, txn1.SiacoinOutputs[0])

	n.revertBlock(t)

	// the genesis output should be unspent now because we reverted the block
	// containing txn1 which spent it
	n.assertSCE(t, scID, nil, genesisOutput)

	// the output from txn1 should not exist after txn1 reverted
	{
		sces, err := n.db.SiacoinElements([]types.SiacoinOutputID{txn1.SiacoinOutputID(txn1.ID(), 0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 0, len(sces))
	}
}

func TestV2EphemeralSiacoinOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()
	addr2Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc2)}

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	scID := n.genesis().Transactions[0].SiacoinOutputID(0)
	genesisOutput := n.genesis().Transactions[0].SiacoinOutputs[0]

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSCE(t, scID, nil, genesisOutput)

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, scID),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	txn2 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          txn1.EphemeralSiacoinOutput(0),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr2Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   txn1.SiacoinOutputs[0].Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk2, &txn2)

	n.mineV2Transactions(t, txn1, txn2)

	n.assertV2Transactions(t, txn1, txn2)

	tip := n.tipState().Index
	// genesis output should be spent
	n.assertSCE(t, scID, &tip, genesisOutput)

	// now that txn1 and txn2 are mined the outputs from them should exist
	n.assertSCE(t, txn1.SiacoinOutputID(txn1.ID(), 0), &tip, txn1.SiacoinOutputs[0])
	n.assertSCE(t, txn2.SiacoinOutputID(txn2.ID(), 0), nil, txn2.SiacoinOutputs[0])

	n.revertBlock(t)

	// genesis output should be unspent now that we reverted
	n.assertSCE(t, scID, nil, genesisOutput)

	// outputs from txn1 and txn2 should not exist because those transactions
	// were reverted
	{
		sces, err := n.db.SiacoinElements([]types.SiacoinOutputID{txn1.SiacoinOutputID(txn1.ID(), 0), txn2.SiacoinOutputID(txn2.ID(), 0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 0, len(sces))
	}
}

func TestV2SiafundOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	sfID := n.genesis().Transactions[0].SiafundOutputID(0)
	genesisOutput := n.genesis().Transactions[0].SiafundOutputs[0]

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSFE(t, sfID, nil, genesisOutput)

	txn1 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          getSFE(t, n.db, sfID),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	n.mineV2Transactions(t, txn1)

	n.assertV2Transactions(t, txn1)

	// genesis output should be spent
	tip := n.tipState().Index
	n.assertSFE(t, sfID, &tip, genesisOutput)

	// the output from txn1 should exist now that the block with txn1 was
	// mined
	n.assertSFE(t, txn1.SiafundOutputID(txn1.ID(), 0), nil, txn1.SiafundOutputs[0])

	n.revertBlock(t)

	// the genesis output should be unspent now because we reverted the block
	// containing txn1 which spent it
	n.assertSFE(t, sfID, nil, genesisOutput)

	// the output from txn1 should not exist after txn1 reverted
	{
		sfes, err := n.db.SiafundElements([]types.SiafundOutputID{txn1.SiafundOutputID(txn1.ID(), 0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 0, len(sfes))
	}
}

func TestV2EphemeralSiafundOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()
	addr2Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc2)}

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	sfID := n.genesis().Transactions[0].SiafundOutputID(0)
	genesisOutput := n.genesis().Transactions[0].SiafundOutputs[0]

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSFE(t, sfID, nil, genesisOutput)

	txn1 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          getSFE(t, n.db, sfID),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	txn2 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          txn1.EphemeralSiafundOutput(0),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr2Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: types.VoidAddress,
			Value:   txn1.SiafundOutputs[0].Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk2, &txn2)

	n.mineV2Transactions(t, txn1, txn2)

	n.assertV2Transactions(t, txn1, txn2)

	tip := n.tipState().Index
	// genesis output should be spent
	n.assertSFE(t, sfID, &tip, genesisOutput)

	// now that txn1 and txn2 are mined the outputs from them should exist
	n.assertSFE(t, txn1.SiafundOutputID(txn1.ID(), 0), &tip, txn1.SiafundOutputs[0])
	n.assertSFE(t, txn2.SiafundOutputID(txn2.ID(), 0), nil, txn2.SiafundOutputs[0])

	n.revertBlock(t)

	// genesis output should be unspent now that we reverted
	n.assertSFE(t, sfID, nil, genesisOutput)

	// outputs from txn1 and txn2 should not exist because those transactions
	// were reverted
	{
		sfes, err := n.db.SiafundElements([]types.SiafundOutputID{txn1.SiafundOutputID(txn1.ID(), 0), txn2.SiafundOutputID(txn2.ID(), 0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 0, len(sfes))
	}
}

func TestV2SiacoinBalance(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	checkBalance := func(addr types.Address, expectedSC, expectedImmatureSC types.Currency) {
		t.Helper()

		sc, immatureSC, sf, err := n.db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "siacoins", expectedSC, sc)
		testutil.Equal(t, "immature siacoins", expectedImmatureSC, immatureSC)
		testutil.Equal(t, "siafunds", 0, sf)
	}

	// only addr1 should have SC from genesis block
	checkBalance(types.VoidAddress, types.ZeroCurrency, types.ZeroCurrency)
	checkBalance(addr1, val, types.ZeroCurrency)
	checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency)

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   val,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	// send addr1 output to addr2
	b := testutil.MineV2Block(n.tipState(), nil, []types.V2Transaction{txn1}, types.VoidAddress)
	n.applyBlock(t, b)

	// addr2 should have SC and the void address should have immature SC from
	// block
	checkBalance(types.VoidAddress, types.ZeroCurrency, b.MinerPayouts[0].Value)
	checkBalance(addr1, types.ZeroCurrency, types.ZeroCurrency)
	checkBalance(addr2, val, types.ZeroCurrency)

	n.revertBlock(t)

	// after revert, addr1 should have funds again and the void address should
	// have nothing
	checkBalance(types.VoidAddress, types.ZeroCurrency, types.ZeroCurrency)
	checkBalance(addr1, val, types.ZeroCurrency)
	checkBalance(addr2, types.ZeroCurrency, types.ZeroCurrency)
}

func TestV2SiafundBalance(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiafundOutputs[0].Value

	checkBalance := func(addr types.Address, expectedSF uint64) {
		t.Helper()

		sc, immatureSC, sf, err := n.db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "siacoins", types.ZeroCurrency, sc)
		if addr != types.VoidAddress {
			testutil.Equal(t, "immature siacoins", types.ZeroCurrency, immatureSC)
		}
		testutil.Equal(t, "siafunds", expectedSF, sf)
	}

	// addr1 should have SF from genesis block
	checkBalance(types.VoidAddress, 0)
	checkBalance(addr1, val)
	checkBalance(addr2, 0)

	txn1 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          getSFE(t, n.db, n.genesis().Transactions[0].SiafundOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   val,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	// send addr1 SF to addr2
	n.mineV2Transactions(t, txn1)

	// addr2 should have SF now
	checkBalance(types.VoidAddress, 0)
	checkBalance(addr1, 0)
	checkBalance(addr2, val)

	n.revertBlock(t)

	// after revert, addr1 should have SF again
	checkBalance(types.VoidAddress, 0)
	checkBalance(addr1, val)
	checkBalance(addr2, 0)
}

func TestV2EphemeralSiacoinBalance(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()
	addr2Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc2)}

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	checkBalance := func(addr types.Address, expectedSC types.Currency) {
		t.Helper()

		sc, immatureSC, sf, err := n.db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "siacoins", expectedSC, sc)
		testutil.Equal(t, "immature siacoins", types.ZeroCurrency, immatureSC)
		testutil.Equal(t, "siafunds", 0, sf)
	}

	// only addr1 should have SC from genesis block
	checkBalance(addr1, val)
	checkBalance(addr2, types.ZeroCurrency)
	checkBalance(addr3, types.ZeroCurrency)

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   val,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	txn2 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          txn1.EphemeralSiacoinOutput(0),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr2Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr3,
			Value:   val,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk2, &txn2)

	// net effect of txn1 and txn2 is to send addr1 output to addr3
	n.mineV2Transactions(t, txn1, txn2)

	// addr3 should have all the value now
	checkBalance(addr1, types.ZeroCurrency)
	checkBalance(addr2, types.ZeroCurrency)
	checkBalance(addr3, val)

	n.revertBlock(t)

	// after revert, addr1 should have funds again and the others should
	// have nothing
	checkBalance(addr1, val)
	checkBalance(addr2, types.ZeroCurrency)
	checkBalance(addr3, types.ZeroCurrency)
}

func TestV2EphemeralSiafundBalance(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()
	addr2Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc2)}

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiafundOutputs[0].Value

	checkBalance := func(addr types.Address, expectedSF uint64) {
		t.Helper()

		sc, immatureSC, sf, err := n.db.Balance(addr)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "siacoins", types.ZeroCurrency, sc)
		testutil.Equal(t, "immature siacoins", types.ZeroCurrency, immatureSC)
		testutil.Equal(t, "siafunds", expectedSF, sf)
	}

	// only addr1 should have SF from genesis block
	checkBalance(addr1, val)
	checkBalance(addr2, 0)
	checkBalance(addr3, 0)

	txn1 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          getSFE(t, n.db, n.genesis().Transactions[0].SiafundOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   val,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	txn2 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          txn1.EphemeralSiafundOutput(0),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr2Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr3,
			Value:   val,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk2, &txn2)

	// net effect of txn1 and txn2 is to send addr1 output to addr3
	n.mineV2Transactions(t, txn1, txn2)

	// addr3 should have all the value now
	checkBalance(addr1, 0)
	checkBalance(addr2, 0)
	checkBalance(addr3, val)

	n.revertBlock(t)

	// after revert, addr1 should have funds again and the others should
	// have nothing
	checkBalance(addr1, val)
	checkBalance(addr2, 0)
	checkBalance(addr3, 0)
}

func TestV2UnspentSiacoinOutputs(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()
	addr2Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc2)}

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	scID := n.genesis().Transactions[0].SiacoinOutputID(0)
	genesisOutput := n.genesis().Transactions[0].SiacoinOutputs[0]

	checkSiacoinOutputs := func(addr types.Address, expected ...explorer.SiacoinOutput) {
		t.Helper()

		scos, err := n.db.UnspentSiacoinOutputs(addr, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(scos)", len(expected), len(scos))

		for i := range scos {
			testutil.Equal(t, "Source", expected[i].Source, scos[i].Source)
			testutil.Equal(t, "SpentIndex", expected[i].SpentIndex, scos[i].SpentIndex)
			testutil.Equal(t, "SiacoinOutput", expected[i].SiacoinOutput, scos[i].SiacoinOutput)
		}
	}

	// only addr1 should have SC from genesis block
	checkSiacoinOutputs(addr1, explorer.SiacoinOutput{
		Source: explorer.SourceTransaction,
		SiacoinElement: types.SiacoinElement{
			ID:            scID,
			SiacoinOutput: genesisOutput,
		},
	})
	checkSiacoinOutputs(addr2)
	checkSiacoinOutputs(addr3)

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	txn2 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          txn1.EphemeralSiacoinOutput(0),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr2Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr3,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk2, &txn2)

	// net effect of txn1 and txn2 is to send addr1 output to addr3
	n.mineV2Transactions(t, txn1, txn2)

	// addr3 should have all the value now
	checkSiacoinOutputs(addr1)
	checkSiacoinOutputs(addr2)
	checkSiacoinOutputs(addr3, explorer.SiacoinOutput{
		Source: explorer.SourceTransaction,
		SiacoinElement: types.SiacoinElement{
			ID:            txn2.SiacoinOutputID(txn2.ID(), 0),
			SiacoinOutput: txn2.SiacoinOutputs[0],
		},
	})

	n.revertBlock(t)

	// after revert, addr1 should have the output again and the others should
	// have nothing
	checkSiacoinOutputs(addr1, explorer.SiacoinOutput{
		Source: explorer.SourceTransaction,
		SiacoinElement: types.SiacoinElement{
			ID:            scID,
			SiacoinOutput: genesisOutput,
		},
	})
	checkSiacoinOutputs(addr2)
	checkSiacoinOutputs(addr3)
}

func TestV2UnspentSiafundOutputs(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()
	addr2Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc2)}

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	sfID := n.genesis().Transactions[0].SiafundOutputID(0)
	genesisOutput := n.genesis().Transactions[0].SiafundOutputs[0]

	checkSiafundOutputs := func(addr types.Address, expected ...explorer.SiafundOutput) {
		t.Helper()

		sfos, err := n.db.UnspentSiafundOutputs(addr, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfos)", len(expected), len(sfos))

		for i := range sfos {
			testutil.Equal(t, "SpentIndex", expected[i].SpentIndex, sfos[i].SpentIndex)
			testutil.Equal(t, "SiafundOutput", expected[i].SiafundOutput, sfos[i].SiafundOutput)
		}
	}

	// only addr1 should have SF from genesis block
	checkSiafundOutputs(addr1, explorer.SiafundOutput{
		SiafundElement: types.SiafundElement{
			ID:            sfID,
			SiafundOutput: genesisOutput,
		},
	})
	checkSiafundOutputs(addr2)
	checkSiafundOutputs(addr3)

	txn1 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          getSFE(t, n.db, n.genesis().Transactions[0].SiafundOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	txn2 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          txn1.EphemeralSiafundOutput(0),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr2Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr3,
			Value:   genesisOutput.Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk2, &txn2)

	// net effect of txn1 and txn2 is to send addr1 output to addr3
	n.mineV2Transactions(t, txn1, txn2)

	// addr3 should have all the value now
	checkSiafundOutputs(addr1)
	checkSiafundOutputs(addr2)
	checkSiafundOutputs(addr3, explorer.SiafundOutput{
		SiafundElement: types.SiafundElement{
			ID:            txn2.SiafundOutputID(txn2.ID(), 0),
			SiafundOutput: txn2.SiafundOutputs[0],
		},
	})

	n.revertBlock(t)

	// after revert, addr1 should have the output again and the others should
	// have nothing
	checkSiafundOutputs(addr1, explorer.SiafundOutput{
		SiafundElement: types.SiafundElement{
			ID:            sfID,
			SiafundOutput: genesisOutput,
		},
	})
	checkSiafundOutputs(addr2)
	checkSiafundOutputs(addr3)
}
