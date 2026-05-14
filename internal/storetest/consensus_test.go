package storetest

import (
	"errors"
	"math"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	proto2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
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

func newTestChain(t testing.TB, v2 bool, modifyGenesis func(*consensus.Network, types.Block)) *testChain {
	log := zaptest.NewLogger(t)

	db := openStore(t, log.Named("store"))

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
		network.HardforkV2.FinalCutHeight = 3
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

func (n *testChain) tipBlock() types.Block {
	return n.blocks[len(n.blocks)-1]
}

func (n *testChain) tipState() consensus.State {
	return n.states[len(n.states)-1]
}

func (n *testChain) applyBlock(t testing.TB, b types.Block) {
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

func (n *testChain) revertBlock(t testing.TB) {
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

func (n *testChain) mineTransactions(t testing.TB, txns ...types.Transaction) {
	t.Helper()

	b := testutil.MineBlock(n.tipState(), txns, types.VoidAddress)
	n.applyBlock(t, b)
}

func (n *testChain) assertTransactions(t testing.TB, expected ...types.Transaction) {
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

func (n *testChain) assertContractRevisions(t testing.TB, fcID types.FileContractID, expected ...explorer.ExtendedFileContract) {
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

func (n *testChain) assertEvents(t testing.TB, addr types.Address, expected ...explorer.Event) {
	t.Helper()

	events, err := n.db.AddressEvents(addr, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(events)", len(expected), len(events))

	for i := range expected {
		expected[i].Relevant = []types.Address{addr}
		expected[i].Confirmations = n.tipState().Index.Height - expected[i].Index.Height
		testutil.Equal(t, "Event", expected[i], events[i])
	}

	for i := range expected {
		events, err := n.db.Events([]types.Hash256{expected[i].ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(events)", 1, len(events))

		expected[i].Relevant = nil
		testutil.Equal(t, "Event", expected[i], events[0])
	}
}

func (n *testChain) getSCE(t testing.TB, scID types.SiacoinOutputID) explorer.SiacoinOutput {
	t.Helper()

	sces, err := n.db.SiacoinElements([]types.SiacoinOutputID{scID})
	if err != nil {
		t.Fatal(err)
	} else if len(sces) == 0 {
		t.Fatal("can't find sce")
	}
	sces[0].StateElement.MerkleProof = nil
	return sces[0]
}

func (n *testChain) getFCE(t testing.TB, fcID types.FileContractID) explorer.ExtendedFileContract {
	t.Helper()

	fces, err := n.db.Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fce")
	}
	return fces[0]
}

func (n *testChain) getTxn(t testing.TB, txnID types.TransactionID) explorer.Transaction {
	t.Helper()

	txns, err := n.db.Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	} else if len(txns) == 0 {
		t.Fatal("can't find txn")
	}
	return txns[0]
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

func (n *testChain) assertBlock(t testing.TB, cs consensus.State, block types.Block) {
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
