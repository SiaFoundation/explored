package sqlite_test

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap/zaptest"
)

type testChain struct {
	db    explorer.Store
	store *chain.DBStore

	blocks []types.Block
	states []consensus.State
}

func newTestChain(t *testing.T, v2 bool, modifyGenesis func(*consensus.Network, types.Block)) *testChain {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	var network *consensus.Network
	var genesisBlock types.Block
	if v2 {
		network, genesisBlock = ctestutil.V2Network()
	} else {
		network, genesisBlock = ctestutil.Network()
	}
	if v2 {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
	}
	if modifyGenesis != nil {
		modifyGenesis(network, genesisBlock)
	}

	store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	bs := consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(genesisBlock.Transactions))}
	_, au := consensus.ApplyBlock(network.GenesisState(), genesisBlock, bs, time.Time{})
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{{
		ApplyUpdate: au,
		Block:       genesisBlock,
		State:       genesisState,
	}}); err != nil {
		t.Fatal(err)
	}

	return &testChain{
		db:    db,
		store: store,

		blocks: []types.Block{genesisBlock},
		states: []consensus.State{genesisState},
	}
}

func (n *testChain) genesis() types.Block {
	return n.blocks[0]
}

func (n *testChain) tipState() consensus.State {
	return n.states[len(n.states)-1]
}

func (n *testChain) applyBlock(t *testing.T, b types.Block) {
	cs := n.tipState()
	bs := n.store.SupplementTipBlock(b)
	if cs.Index.Height != math.MaxUint64 {
		// don't validate genesis block
		if err := consensus.ValidateBlock(cs, b, bs); err != nil {
			t.Fatal(err)
		}
	}

	cs, au := consensus.ApplyBlock(cs, b, bs, time.Time{})
	if err := n.db.UpdateChainState(nil, []chain.ApplyUpdate{{
		ApplyUpdate: au,
		Block:       b,
		State:       cs,
	}}); err != nil {
		t.Fatal(err)
	}

	n.states = append(n.states, cs)
	n.blocks = append(n.blocks, b)
}

func (n *testChain) revertBlock(t *testing.T) {
	b := n.blocks[len(n.blocks)-1]
	prevState := n.states[len(n.states)-2]

	bs := n.store.SupplementTipBlock(b)
	ru := consensus.RevertBlock(prevState, b, bs)
	if err := n.db.UpdateChainState([]chain.RevertUpdate{{
		RevertUpdate: ru,
		Block:        b,
		State:        prevState,
	}}, nil); err != nil {
		t.Fatal(err)
	}

	n.states = n.states[:len(n.states)-1]
	n.blocks = n.blocks[:len(n.blocks)-1]
}

func (n *testChain) mineTransactions(t *testing.T, txns ...types.Transaction) {
	b := testutil.MineBlock(n.tipState(), txns, types.VoidAddress)
	n.applyBlock(t, b)
}

func (n *testChain) mineV2Transactions(t *testing.T, txns ...types.V2Transaction) {
	b := testutil.MineV2Block(n.tipState(), txns, types.VoidAddress)
	n.applyBlock(t, b)
}

func (n *testChain) assertTransactions(t *testing.T, expected ...types.Transaction) {
	t.Helper()

	for _, txn := range expected {
		txns, err := n.db.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 1, len(txns))

		testutil.CheckTransaction(t, txn, txns[0])
	}
}

func (n *testChain) assertV2Transactions(t *testing.T, expected ...types.V2Transaction) {
	t.Helper()

	for _, txn := range expected {
		txns, err := n.db.V2Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 1, len(txns))

		testutil.CheckV2Transaction(t, txn, txns[0])
	}
}

func (n *testChain) assertChainIndices(t *testing.T, txnID types.TransactionID, expected ...types.ChainIndex) {
	t.Helper()

	indices, err := n.db.TransactionChainIndices(txnID, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	} else if len(indices) != len(expected) {
		t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
	}

	for i := range indices {
		testutil.Equal(t, "index", expected[i], indices[i])
	}
}

func (n *testChain) assertV2ChainIndices(t *testing.T, txnID types.TransactionID, expected ...types.ChainIndex) {
	t.Helper()

	indices, err := n.db.V2TransactionChainIndices(txnID, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	} else if len(indices) != len(expected) {
		t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
	}

	for i := range indices {
		testutil.Equal(t, "index", expected[i], indices[i])
	}
}

// helper to assert the Siacoin element in the db has the right source, index and output
func (n *testChain) assertSCE(t *testing.T, scID types.SiacoinOutputID, index *types.ChainIndex, sco types.SiacoinOutput) {
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

// helper to assert the Siafund element in the db has the right source, index and output
func (n *testChain) assertSFE(t *testing.T, sfID types.SiafundOutputID, index *types.ChainIndex, sfo types.SiafundOutput) {
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

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSCE(t, scID, nil, n.genesis().Transactions[0].SiacoinOutputs[0])

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         scID,
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   n.genesis().Transactions[0].SiacoinOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	// genesis output should be spent
	tip := n.tipState().Index
	n.assertSCE(t, scID, &tip, n.genesis().Transactions[0].SiacoinOutputs[0])

	// the output from txn1 should exist now that the block with txn1 was
	// mined
	n.assertSCE(t, txn1.SiacoinOutputID(0), nil, txn1.SiacoinOutputs[0])

	n.revertBlock(t)

	// the genesis output should be unspent now because we reverted the block
	// containing txn1 which spent it
	n.assertSCE(t, scID, nil, n.genesis().Transactions[0].SiacoinOutputs[0])

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

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSCE(t, scID, nil, n.genesis().Transactions[0].SiacoinOutputs[0])

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         scID,
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   n.genesis().Transactions[0].SiacoinOutputs[0].Value,
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

	tip := n.tipState().Index
	// genesis output should be spent
	n.assertSCE(t, scID, &tip, n.genesis().Transactions[0].SiacoinOutputs[0])

	// now that txn1 and txn2 are mined the outputs from them should exist
	n.assertSCE(t, txn1.SiacoinOutputID(0), &tip, txn1.SiacoinOutputs[0])
	n.assertSCE(t, txn2.SiacoinOutputID(0), nil, txn2.SiacoinOutputs[0])

	n.revertBlock(t)

	// genesis output should be unspent now that we reverted
	n.assertSCE(t, scID, nil, n.genesis().Transactions[0].SiacoinOutputs[0])

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

func TestTransactionChainIndices(t *testing.T) {
	n := newTestChain(t, false, nil)

	txn1 := types.Transaction{
		ArbitraryData: [][]byte{{0}},
	}
	txn2 := types.Transaction{
		ArbitraryData: [][]byte{{0}, {1}},
	}

	// mine block with txn1 twice and txn2
	n.mineTransactions(t, txn1, txn1, txn2)
	cs1 := n.tipState()

	n.assertTransactions(t, txn1, txn2)
	// both transactions should only be in the first block
	n.assertChainIndices(t, txn1.ID(), cs1.Index)
	n.assertChainIndices(t, txn2.ID(), cs1.Index)

	// mine same block again
	n.mineTransactions(t, txn1, txn1, txn2)
	cs2 := n.tipState()

	// both transactions should be in the blocks
	n.assertTransactions(t, txn1, txn2)
	n.assertChainIndices(t, txn1.ID(), cs2.Index, cs1.Index)
	n.assertChainIndices(t, txn2.ID(), cs2.Index, cs1.Index)

	n.revertBlock(t)

	// after revert both transactions should only be in the first block
	n.assertTransactions(t, txn1, txn2)
	n.assertChainIndices(t, txn1.ID(), cs1.Index)
	n.assertChainIndices(t, txn2.ID(), cs1.Index)

	n.revertBlock(t)

	// after reverting the first block there should be no transactions
	{
		txns, err := n.db.Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 0, len(txns))
	}
	n.assertChainIndices(t, txn1.ID())
	n.assertChainIndices(t, txn2.ID())
}

func TestV2TransactionChainIndices(t *testing.T) {
	n := newTestChain(t, true, nil)

	txn1 := types.V2Transaction{
		ArbitraryData: []byte{0},
	}
	txn2 := types.V2Transaction{
		ArbitraryData: []byte{0, 1},
	}

	// mine block with txn1 twice and txn2
	n.mineV2Transactions(t, txn1, txn1, txn2)
	cs1 := n.tipState()

	n.assertV2Transactions(t, txn1, txn2)
	// both transactions should only be in the first block
	n.assertV2ChainIndices(t, txn1.ID(), cs1.Index)
	n.assertV2ChainIndices(t, txn2.ID(), cs1.Index)

	// mine same block again
	n.mineV2Transactions(t, txn1, txn1, txn2)
	cs2 := n.tipState()

	// both transactions should be in the blocks
	n.assertV2Transactions(t, txn1, txn2)
	n.assertV2ChainIndices(t, txn1.ID(), cs2.Index, cs1.Index)
	n.assertV2ChainIndices(t, txn2.ID(), cs2.Index, cs1.Index)

	n.revertBlock(t)

	// after revert both transactions should only be in the first block
	n.assertV2Transactions(t, txn1, txn2)
	n.assertV2ChainIndices(t, txn1.ID(), cs1.Index)
	n.assertV2ChainIndices(t, txn2.ID(), cs1.Index)

	n.revertBlock(t)

	// after reverting the first block there should be no transactions
	{
		txns, err := n.db.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 0, len(txns))
	}
	n.assertV2ChainIndices(t, txn1.ID())
	n.assertV2ChainIndices(t, txn2.ID())
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
