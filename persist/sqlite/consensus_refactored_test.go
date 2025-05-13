package sqlite_test

import (
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	proto2 "go.sia.tech/core/rhp/v2"
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

	network     *consensus.Network
	blocks      []types.Block
	supplements []consensus.V1BlockSupplement
	states      []consensus.State
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

		network:     network,
		blocks:      []types.Block{genesisBlock},
		supplements: []consensus.V1BlockSupplement{bs},
		states:      []consensus.State{genesisState},
	}
}

func (n *testChain) genesis() types.Block {
	return n.blocks[0]
}

func (n *testChain) tipState() consensus.State {
	return n.states[len(n.states)-1]
}

func (n *testChain) applyBlock(t *testing.T, b types.Block) {
	t.Helper()

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

	n.store.AddState(cs)
	n.store.AddBlock(b, &bs)
	n.store.ApplyBlock(cs, au)

	n.blocks = append(n.blocks, b)
	n.supplements = append(n.supplements, bs)
	n.states = append(n.states, cs)
}

func (n *testChain) revertBlock(t *testing.T) {
	b := n.blocks[len(n.blocks)-1]
	bs := n.supplements[len(n.supplements)-1]
	prevState := n.states[len(n.states)-2]

	ru := consensus.RevertBlock(prevState, b, bs)
	if err := n.db.UpdateChainState([]chain.RevertUpdate{{
		RevertUpdate: ru,
		Block:        b,
		State:        prevState,
	}}, nil); err != nil {
		t.Fatal(err)
	}

	n.store.RevertBlock(prevState, ru)

	n.blocks = n.blocks[:len(n.blocks)-1]
	n.supplements = n.supplements[:len(n.supplements)-1]
	n.states = n.states[:len(n.states)-1]
}

func (n *testChain) mineTransactions(t *testing.T, txns ...types.Transaction) {
	t.Helper()

	b := testutil.MineBlock(n.tipState(), txns, types.VoidAddress)
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

// assertSCE asserts the Siacoin element in the db has the right source, index and output
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

// assertSFE asserts the Siafund element in the db has the right source, index and output
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

// assertFCE asserts the contract element in the db has the right state and
// block/transaction indices
func (n *testChain) assertFCE(t *testing.T, fcID types.FileContractID, expected explorer.ExtendedFileContract) {
	t.Helper()

	fces, err := n.db.Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(fces)", 1, len(fces))

	fce := fces[0]
	// We aren't trying to compare a core type with an explorer type so we can
	// just directly compare.  If they are not equal a diff with field names will
	// be printed.
	testutil.Equal(t, "ExtendedFileContract", expected, fce)
}

// assertTransactionContracts asserts that the enhanced FileContracts
// (revisions = false) or FileContractRevisions (revisions = true) in a
// transaction retrieved from the explorer match the expected contracts.
func (n *testChain) assertTransactionContracts(t *testing.T, txnID types.TransactionID, revisions bool, expected ...explorer.ExtendedFileContract) {
	t.Helper()

	txns, err := n.db.Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(txns)", 1, len(txns))

	txn := txns[0]
	if !revisions {
		testutil.Equal(t, "len(txn.FileContracts)", len(expected), len(txn.FileContracts))
		for i := range expected {
			testutil.Equal(t, "ExtendedFileContract", expected[i], txn.FileContracts[i])
		}
	} else {
		testutil.Equal(t, "len(txn.FileContractRevisions)", len(expected), len(txn.FileContractRevisions))
		for i := range expected {
			testutil.Equal(t, "ExtendedFileContract", expected[i], txn.FileContractRevisions[i].ExtendedFileContract)
		}
	}
}

func (n *testChain) assertContractRevisions(t *testing.T, fcID types.FileContractID, expected ...explorer.ExtendedFileContract) {
	t.Helper()

	fces, err := n.db.ContractRevisions(fcID)
	if len(expected) == 0 {
		if !errors.Is(err, explorer.ErrContractNotFound) {
			t.Fatal("should have got contract not found error")
		}
		return
	} else if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(fces)", len(expected), len(fces))

	for i := range expected {
		testutil.Equal(t, "ExtendedFileContract", expected[i], fces[i])
	}
}

func prepareContract(addr types.Address, endHeight uint64) types.FileContract {
	rk := types.GeneratePrivateKey().PublicKey()
	rAddr := types.StandardUnlockHash(rk)
	hk := types.GeneratePrivateKey().PublicKey()
	hs := proto2.HostSettings{
		WindowSize: 1,
		Address:    types.StandardUnlockHash(hk),
	}
	sc := types.Siacoins(1)
	fc := proto2.PrepareContractFormation(rk, hk, sc.Mul64(5), sc.Mul64(5), endHeight, hs, rAddr)
	fc.UnlockHash = addr
	return fc
}

func (n *testChain) assertBlock(t *testing.T, cs consensus.State, block types.Block) {
	got, err := n.db.Block(block.ID())
	if err != nil {
		t.Fatal(err)
	}

	testutil.Equal(t, "ParentID", block.ParentID, got.ParentID)
	testutil.Equal(t, "Nonce", block.Nonce, got.Nonce)
	testutil.Equal(t, "Timestamp", block.Timestamp, got.Timestamp)
	testutil.Equal(t, "Height", cs.Index.Height, got.Height)

	testutil.Equal(t, "len(MinerPayouts)", len(block.MinerPayouts), len(got.MinerPayouts))
	for i, sco := range got.MinerPayouts {
		testutil.Equal(t, "Source", explorer.SourceMinerPayout, sco.Source)
		testutil.Equal(t, "SpentIndex", nil, sco.SpentIndex)
		testutil.Equal(t, "SiacoinOutput", block.MinerPayouts[i], sco.SiacoinOutput)
	}

	testutil.Equal(t, "len(Transactions)", len(block.Transactions), len(got.Transactions))
	for i, txn := range got.Transactions {
		testutil.CheckTransaction(t, block.Transactions[i], txn)
	}

	if block.V2 != nil {
		testutil.Equal(t, "Height", block.V2.Height, got.V2.Height)
		testutil.Equal(t, "Commitment", block.V2.Commitment, got.V2.Commitment)

		testutil.Equal(t, "len(V2Transactions)", len(block.V2.Transactions), len(got.V2.Transactions))
		for i, txn := range got.V2.Transactions {
			testutil.CheckV2Transaction(t, block.V2.Transactions[i], txn)
		}
	}
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

func TestTip(t *testing.T) {
	n := newTestChain(t, false, nil)

	checkTips := func() {
		t.Helper()

		tip, err := n.db.Tip()
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "tip", n.tipState().Index, tip)

		for _, state := range n.states {
			best, err := n.db.BestTip(state.Index.Height)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "best tip", state.Index, best)
		}
	}
	checkTips()

	n.mineTransactions(t)
	checkTips()

	n.mineTransactions(t)
	checkTips()

	n.revertBlock(t)
	checkTips()

	n.revertBlock(t)
	checkTips()
}

func TestMissingTip(t *testing.T) {
	n := newTestChain(t, false, nil)

	_, err := n.db.BestTip(n.tipState().Index.Height)
	if err != nil {
		t.Fatalf("error retrieving tip known to exist: %v", err)
	}

	_, err = n.db.BestTip(n.tipState().Index.Height + 1)
	if !errors.Is(err, explorer.ErrNoTip) {
		t.Fatalf("should have got ErrNoTip retrieving: %v", err)
	}
}

func TestMissingBlock(t *testing.T) {
	n := newTestChain(t, false, nil)

	id := n.tipState().Index.ID
	_, err := n.db.Block(id)
	if err != nil {
		t.Fatalf("error retrieving genesis block: %v", err)
	}

	id[0] ^= 255
	_, err = n.db.Block(id)
	if !errors.Is(err, explorer.ErrNoBlock) {
		t.Fatalf("did not get ErrNoBlock retrieving missing block: %v", err)
	}
}

func TestTransactionStorageProof(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := prepareContract(addr1, n.tipState().Index.Height+1)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	n.assertTransactions(t, txn1)

	sp := types.StorageProof{
		ParentID: txn1.FileContractID(0),
	}
	txn2 := types.Transaction{
		StorageProofs: []types.StorageProof{sp},
	}
	n.mineTransactions(t, txn2)

	n.assertTransactions(t, txn1, txn2)
}

func TestEventPayout(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, nil)

	b := testutil.MineBlock(n.tipState(), nil, addr1)
	n.applyBlock(t, b)

	{
		events, err := n.db.AddressEvents(addr1, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 1, len(events))

		ev0 := events[0].Data.(explorer.EventPayout)
		testutil.Equal(t, "event 0 output ID", n.tipState().Index.ID.MinerOutputID(0), ev0.SiacoinElement.ID)
		testutil.Equal(t, "event 0 output source", explorer.SourceMinerPayout, ev0.SiacoinElement.Source)
	}

	n.revertBlock(t)

	{
		events, err := n.db.AddressEvents(addr1, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 0, len(events))
	}
}

func TestBlock(t *testing.T) {
	n := newTestChain(t, false, nil)

	checkBlocks := func(count int) {
		t.Helper()

		testutil.Equal(t, "blocks", count, len(n.blocks))
		for i := range n.blocks {
			testutil.Equal(t, "block height", uint64(i), n.states[i].Index.Height)
			testutil.Equal(t, "block ID", n.blocks[i].ID(), n.states[i].Index.ID)
			n.assertBlock(t, n.states[i], n.blocks[i])
		}
	}

	checkBlocks(1)

	n.mineTransactions(t, types.Transaction{ArbitraryData: [][]byte{{0}}})

	checkBlocks(2)

	n.revertBlock(t)

	checkBlocks(1)
}

func coreToExplorerFC(fcID types.FileContractID, fc types.FileContract) explorer.ExtendedFileContract {
	var valid []explorer.ContractSiacoinOutput
	for i, sco := range fc.ValidProofOutputs {
		valid = append(valid, explorer.ContractSiacoinOutput{
			SiacoinOutput: sco,
			ID:            fcID.ValidOutputID(i),
		})
	}

	var missed []explorer.ContractSiacoinOutput
	for i, sco := range fc.MissedProofOutputs {
		missed = append(missed, explorer.ContractSiacoinOutput{
			SiacoinOutput: sco,
			ID:            fcID.MissedOutputID(i),
		})
	}

	return explorer.ExtendedFileContract{
		ID:                 fcID,
		Filesize:           fc.Filesize,
		FileMerkleRoot:     fc.FileMerkleRoot,
		WindowStart:        fc.WindowStart,
		WindowEnd:          fc.WindowEnd,
		Payout:             fc.Payout,
		ValidProofOutputs:  valid,
		MissedProofOutputs: missed,
		UnlockHash:         fc.UnlockHash,
		RevisionNumber:     fc.RevisionNumber,
	}
}

func TestFileContractValid(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := prepareContract(addr1, n.tipState().Index.Height+1)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.assertFCE(t, fce.ID, fce)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)

	sp := types.StorageProof{
		ParentID: txn1.FileContractID(0),
	}
	txn2 := types.Transaction{
		StorageProofs: []types.StorageProof{sp},
	}
	n.mineTransactions(t, txn2)

	tip := n.tipState().Index
	txnID := txn2.ID()

	// should be resolved
	fceResolved := fce
	fceResolved.Resolved = true
	fceResolved.Valid = true
	fceResolved.ProofIndex = &tip
	fceResolved.ProofTransactionID = &txnID

	n.assertFCE(t, fce.ID, fceResolved)
	n.assertTransactionContracts(t, txn1.ID(), false, fceResolved)

	n.revertBlock(t)

	// should have old FCE back
	n.assertFCE(t, fce.ID, fce)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)

	n.revertBlock(t)

	// FCE should not exist
	{
		fces, err := n.db.Contracts([]types.FileContractID{fce.ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", 0, len(fces))
	}

	n.assertContractRevisions(t, fce.ID)
}

func TestFileContractMissed(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := prepareContract(addr1, n.tipState().Index.Height+1)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()
	n.assertFCE(t, fce.ID, fce)

	for i := n.tipState().Index.Height; i < fc.WindowEnd; i++ {
		n.mineTransactions(t)
	}

	fceResolved := fce
	fceResolved.Resolved = true
	fceResolved.Valid = false

	n.assertFCE(t, fce.ID, fceResolved)
	n.assertTransactionContracts(t, txn1.ID(), false, fceResolved)

	n.revertBlock(t)

	// should have old FCE back
	n.assertFCE(t, fce.ID, fce)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)

	n.revertBlock(t)

	// FCE should not exist
	{
		fces, err := n.db.Contracts([]types.FileContractID{fce.ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", 0, len(fces))
	}

	n.assertContractRevisions(t, fce.ID)
}

func signRevisions(cs consensus.State, txn *types.Transaction, pks ...types.PrivateKey) {
	appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
		sig := key.SignHash(cs.WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{
			ParentID:       parentID,
			CoveredFields:  types.CoveredFields{WholeTransaction: true},
			PublicKeyIndex: pubkeyIndex,
			Signature:      sig[:],
		})
	}
	for i := range txn.FileContractRevisions {
		for j := range pks {
			appendSig(pks[j], uint64(j), types.Hash256(txn.FileContractRevisions[i].ParentID))
		}
	}
}

func TestFileContractRevision(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := prepareContract(addr1, n.tipState().Index.Height+3)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.assertFCE(t, fce.ID, fce)
	n.assertContractRevisions(t, fce.ID, fce)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)

	fcRevision1 := fc
	fcRevision1.RevisionNumber++
	txn2 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fce.ID,
			UnlockConditions: uc1,
			FileContract:     fcRevision1,
		}},
	}
	signRevisions(n.tipState(), &txn2, pk1)

	n.mineTransactions(t, txn2)

	fceRevision1 := fce
	fceRevision1.RevisionNumber = fcRevision1.RevisionNumber
	fceRevision1.TransactionID = txn2.ID()

	n.assertFCE(t, fce.ID, fceRevision1)
	n.assertContractRevisions(t, fce.ID, fce, fceRevision1)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)
	n.assertTransactionContracts(t, txn2.ID(), true, fceRevision1)

	// resolve contract unsuccessful
	for i := n.tipState().Index.Height; i < fc.WindowEnd; i++ {
		n.mineTransactions(t)
	}

	fce.Resolved = true
	fceRevision1.Resolved = true
	n.assertFCE(t, fce.ID, fceRevision1)
	n.assertContractRevisions(t, fce.ID, fce, fceRevision1)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)
	n.assertTransactionContracts(t, txn2.ID(), true, fceRevision1)

	// revert resolution of contract
	for i := n.tipState().Index.Height; i >= fc.WindowEnd; i-- {
		n.revertBlock(t)
	}
	n.revertBlock(t)

	fce.Resolved = false
	fceRevision1.Resolved = false
	n.assertFCE(t, fce.ID, fceRevision1)
	n.assertContractRevisions(t, fce.ID, fce, fceRevision1)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)
	n.assertTransactionContracts(t, txn2.ID(), true, fceRevision1)

	// revert revision of contract
	n.revertBlock(t)

	n.assertFCE(t, fce.ID, fce)
	n.assertContractRevisions(t, fce.ID, fce)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)

	n.revertBlock(t)

	{
		fces, err := n.db.Contracts([]types.FileContractID{fce.ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", 0, len(fces))
	}

	n.assertContractRevisions(t, fce.ID)
}

func TestFileContractMultipleRevisions(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := prepareContract(addr1, n.tipState().Index.Height+3)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.assertFCE(t, fce.ID, fce)
	n.assertContractRevisions(t, fce.ID, fce)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)

	fcRevision1 := fc
	fcRevision1.RevisionNumber++

	fcRevision2 := fcRevision1
	fcRevision2.RevisionNumber++

	txn2 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fce.ID,
			UnlockConditions: uc1,
			FileContract:     fcRevision1,
		}},
	}
	signRevisions(n.tipState(), &txn2, pk1)

	txn3 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fce.ID,
			UnlockConditions: uc1,
			FileContract:     fcRevision2,
		}},
	}
	signRevisions(n.tipState(), &txn3, pk1)

	n.mineTransactions(t, txn2, txn3)

	fceRevision1 := fce
	fceRevision1.RevisionNumber = fcRevision1.RevisionNumber
	fceRevision1.TransactionID = txn2.ID()

	fceRevision2 := fce
	fceRevision2.RevisionNumber = fcRevision2.RevisionNumber
	fceRevision2.TransactionID = txn3.ID()

	n.assertFCE(t, fce.ID, fceRevision2)
	n.assertContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)
	n.assertTransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.assertTransactionContracts(t, txn3.ID(), true, fceRevision2)

	// resolve contract unsuccessful
	for i := n.tipState().Index.Height; i < fc.WindowEnd; i++ {
		n.mineTransactions(t)
	}

	fce.Resolved = true
	fceRevision1.Resolved = true
	fceRevision2.Resolved = true
	n.assertFCE(t, fce.ID, fceRevision2)
	n.assertContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)
	n.assertTransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.assertTransactionContracts(t, txn3.ID(), true, fceRevision2)

	// revert resolution of contract
	for i := n.tipState().Index.Height; i >= fc.WindowEnd; i-- {
		n.revertBlock(t)
	}
	n.revertBlock(t)

	fce.Resolved = false
	fceRevision1.Resolved = false
	fceRevision2.Resolved = false
	n.assertFCE(t, fce.ID, fceRevision2)
	n.assertContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)
	n.assertTransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.assertTransactionContracts(t, txn3.ID(), true, fceRevision2)

	// revert revisions block
	n.revertBlock(t)

	n.assertFCE(t, fce.ID, fce)
	n.assertContractRevisions(t, fce.ID, fce)
	n.assertTransactionContracts(t, txn1.ID(), false, fce)

	n.revertBlock(t)

	{
		fces, err := n.db.Contracts([]types.FileContractID{fce.ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", 0, len(fces))
	}

	n.assertContractRevisions(t, fce.ID)
}

func TestFileContractsKey(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	assertContractsKey := func(pk types.PublicKey, expected ...explorer.ExtendedFileContract) {
		t.Helper()

		fces, err := n.db.ContractsKey(pk)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", len(expected), len(fces))

		for i := range expected {
			testutil.Equal(t, "ExtendedFileContract", expected[i], fces[i])
		}
	}
	unlockKey := func(pubkey types.PublicKey) types.UnlockKey {
		key := pubkey[:]
		return types.UnlockKey{
			Algorithm: types.SpecifierEd25519,
			Key:       key,
		}
	}
	ucContract1 := types.UnlockConditions{
		PublicKeys:         []types.UnlockKey{unlockKey(pk1.PublicKey()), unlockKey(pk2.PublicKey())},
		SignaturesRequired: 2,
	}

	fc := prepareContract(addr1, n.tipState().Index.Height+3)
	fc.UnlockHash = ucContract1.UnlockHash()

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	// we don't have the UnlockConditions and thus the public keys of the
	// renter and host until we have a revision, so we should not have
	// anything at this point
	n.assertFCE(t, fce.ID, fce)
	n.assertContractRevisions(t, fce.ID, fce)
	assertContractsKey(pk1.PublicKey())

	fcRevision1 := fc
	fcRevision1.RevisionNumber++
	txn2 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fce.ID,
			UnlockConditions: ucContract1,
			FileContract:     fcRevision1,
		}},
	}
	signRevisions(n.tipState(), &txn2, pk1, pk2)

	// after a revision is mined, then we should know the keys associated with
	// the contract
	n.mineTransactions(t, txn2)

	fceRevision1 := fce
	fceRevision1.RevisionNumber = fcRevision1.RevisionNumber
	fceRevision1.TransactionID = txn2.ID()

	// either key should be associated with the contract
	n.assertFCE(t, fce.ID, fceRevision1)
	n.assertContractRevisions(t, fce.ID, fce, fceRevision1)
	assertContractsKey(pk1.PublicKey(), fceRevision1)
	assertContractsKey(pk2.PublicKey(), fceRevision1)

	n.revertBlock(t)

	// if we revert we should keep the keys.  only reason to change them is if
	// we change the UnlockHash and can get the keys from the UnlockConditions
	// in a future revision
	n.assertFCE(t, fce.ID, fce)
	n.assertContractRevisions(t, fce.ID, fce)
	assertContractsKey(pk1.PublicKey(), fce)
	assertContractsKey(pk2.PublicKey(), fce)

	n.revertBlock(t)

	n.assertContractRevisions(t, fce.ID)
	assertContractsKey(pk1.PublicKey())
	assertContractsKey(pk2.PublicKey())
}

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
	fcRevision1.Filesize = proto2.SectorSize
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
	for i := n.tipState().Index.Height; i <= fc.WindowEnd; i++ {
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
