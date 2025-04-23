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

type node struct {
	db    explorer.Store
	store *chain.DBStore

	blocks []types.Block
	states []consensus.State
}

func newStoreRefactored(t *testing.T, v2 bool, f func(*consensus.Network, types.Block)) *node {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
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

	store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), network, genesisBlock)
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

	t.Cleanup(func() {
		db.Close()
	})
	return &node{
		db:    db,
		store: store,

		blocks: []types.Block{genesisBlock},
		states: []consensus.State{genesisState},
	}
}

func (n *node) genesis() types.Block {
	return n.blocks[0]
}

func (n *node) tipState() consensus.State {
	return n.states[len(n.states)-1]
}

func (n *node) applyBlock(t *testing.T, b types.Block) {
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

func (n *node) revertBlock(t *testing.T) {
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

	n.blocks = n.blocks[:len(n.blocks)-1]
}

func (n *node) assertTransaction(t *testing.T, expected ...types.Transaction) {
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

// helper to assert the Siacoin element in the db has the right source, index and output
func (n *node) assertSCE(t *testing.T, scID types.SiacoinOutputID, index *types.ChainIndex, sco types.SiacoinOutput) {
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

func TestSiacoinOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newStoreRefactored(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSCE(t, n.genesis().Transactions[0].SiacoinOutputID(0), nil, n.genesis().Transactions[0].SiacoinOutputs[0])

	scID := n.genesis().Transactions[0].SiacoinOutputID(0)
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

	b := testutil.MineBlock(n.tipState(), []types.Transaction{txn1}, types.VoidAddress)
	n.applyBlock(t, b)

	// genesis output should be spent
	tip := n.tipState().Index
	n.assertSCE(t, n.genesis().Transactions[0].SiacoinOutputID(0), &tip, n.genesis().Transactions[0].SiacoinOutputs[0])

	// the output from txn1 should exist now that the block with txn1 was
	// mined
	n.assertSCE(t, txn1.SiacoinOutputID(0), nil, txn1.SiacoinOutputs[0])

	n.revertBlock(t)

	// the genesis output should be unspent now because we reverted the block
	// containing txn1 which spent it
	n.assertSCE(t, n.genesis().Transactions[0].SiacoinOutputID(0), nil, n.genesis().Transactions[0].SiacoinOutputs[0])

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

	n := newStoreRefactored(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})

	// genesis output should be unspent
	// so spentIndex = nil
	n.assertSCE(t, n.genesis().Transactions[0].SiacoinOutputID(0), nil, n.genesis().Transactions[0].SiacoinOutputs[0])

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.genesis().Transactions[0].SiacoinOutputID(0),
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

	b := testutil.MineBlock(n.tipState(), []types.Transaction{txn1, txn2}, types.VoidAddress)
	n.applyBlock(t, b)

	tip := n.tipState().Index
	// genesis output should be spent
	n.assertSCE(t, n.genesis().Transactions[0].SiacoinOutputID(0), &tip, n.genesis().Transactions[0].SiacoinOutputs[0])

	// now that txn1 and txn2 are mined the outputs from them should exist
	n.assertSCE(t, txn1.SiacoinOutputID(0), &tip, txn1.SiacoinOutputs[0])
	n.assertSCE(t, txn2.SiacoinOutputID(0), nil, txn2.SiacoinOutputs[0])

	n.revertBlock(t)

	// genesis output should be unspent now that we reverted
	n.assertSCE(t, n.genesis().Transactions[0].SiacoinOutputID(0), nil, n.genesis().Transactions[0].SiacoinOutputs[0])

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
