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

func newStoreRefactored(t *testing.T, v2 bool, f func(*consensus.Network, types.Block)) (types.Block, consensus.State, *chain.DBStore, explorer.Store) {
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
	bs := consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(genesisBlock.Transactions))}
	_, au := applyUpdate(t, network.GenesisState(), bs, genesisBlock)
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{au}); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		db.Close()
		bdb.Close()
	})
	return genesisBlock, genesisState, store, db
}

func applyUpdate(t *testing.T, cs consensus.State, bs consensus.V1BlockSupplement, b types.Block) (consensus.State, chain.ApplyUpdate) {
	if cs.Index.Height != math.MaxUint64 {
		// don't validate genesis block
		if err := consensus.ValidateBlock(cs, b, bs); err != nil {
			t.Fatal(err)
		}
	}

	cs, au := consensus.ApplyBlock(cs, b, bs, time.Time{})
	return cs, chain.ApplyUpdate{
		ApplyUpdate: au,
		Block:       b,
		State:       cs,
	}
}

func revertUpdate(t *testing.T, prevState consensus.State, bs consensus.V1BlockSupplement, b types.Block) chain.RevertUpdate {
	ru := consensus.RevertBlock(prevState, b, bs)
	return chain.RevertUpdate{
		RevertUpdate: ru,
		Block:        b,
		State:        prevState,
	}
}

func TestSiacoinOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	genesisBlock, cs, store, db := newStoreRefactored(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})

	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())
	scID := genesisBlock.Transactions[0].SiacoinOutputID(0)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         scID,
			UnlockConditions: unlockConditions,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisBlock.Transactions[0].SiacoinOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(cs, pk1, &txn1)

	prevState := cs
	b := testutil.MineBlock(cs, []types.Transaction{txn1}, types.VoidAddress)
	cs, au := applyUpdate(t, cs, store.SupplementTipBlock(b), b)
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{au}); err != nil {
		t.Fatal(err)
	}

	{
		sces, err := db.SiacoinElements([]types.SiacoinOutputID{scID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 1, len(sces))

		sce := sces[0]
		testutil.Equal(t, "sce.Source", explorer.SourceTransaction, sce.Source)
		testutil.Equal(t, "sce.SpentIndex", cs.Index, *sce.SpentIndex)
		testutil.Equal(t, "sce.SiacoinElement.SiacoinOutput", genesisBlock.Transactions[0].SiacoinOutputs[0], sce.SiacoinOutput)
	}

	{
		sces, err := db.SiacoinElements([]types.SiacoinOutputID{txn1.SiacoinOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 1, len(sces))

		sce := sces[0]
		testutil.Equal(t, "sce.Source", explorer.SourceTransaction, sce.Source)
		testutil.Equal(t, "sce.SpentIndex", nil, sce.SpentIndex)
		testutil.Equal(t, "sce.SiacoinElement.SiacoinOutput", txn1.SiacoinOutputs[0], sce.SiacoinOutput)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 1, len(txns))

		testutil.CheckTransaction(t, txn1, txns[0])
	}

	ru := revertUpdate(t, prevState, store.SupplementTipBlock(b), b)
	if err := db.UpdateChainState([]chain.RevertUpdate{ru}, nil); err != nil {
		t.Fatal(err)
	}

	{
		sces, err := db.SiacoinElements([]types.SiacoinOutputID{scID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 1, len(sces))

		sce := sces[0]
		testutil.Equal(t, "sce.Source", explorer.SourceTransaction, sce.Source)
		testutil.Equal(t, "sce.SpentIndex", nil, sce.SpentIndex)
		testutil.Equal(t, "sce.SiacoinElement.SiacoinOutput", genesisBlock.Transactions[0].SiacoinOutputs[0], sce.SiacoinOutput)
	}

	{
		sces, err := db.SiacoinElements([]types.SiacoinOutputID{txn1.SiacoinOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 0, len(sces))
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 0, len(txns))
	}
}

func TestEphemeralSiacoinOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	genesisBlock, cs, store, db := newStoreRefactored(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})

	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         genesisBlock.Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisBlock.Transactions[0].SiacoinOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(cs, pk1, &txn1)

	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
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
	testutil.SignTransaction(cs, pk2, &txn2)

	prevState := cs
	b := testutil.MineBlock(cs, []types.Transaction{txn1, txn2}, types.VoidAddress)
	cs, au := applyUpdate(t, cs, store.SupplementTipBlock(b), b)
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{au}); err != nil {
		t.Fatal(err)
	}

	{
		sces, err := db.SiacoinElements([]types.SiacoinOutputID{genesisBlock.Transactions[0].SiacoinOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 1, len(sces))

		sce := sces[0]
		testutil.Equal(t, "sce.Source", explorer.SourceTransaction, sce.Source)
		testutil.Equal(t, "sce.SpentIndex", cs.Index, *sce.SpentIndex)
		testutil.Equal(t, "sce.SiacoinElement.SiacoinOutput", genesisBlock.Transactions[0].SiacoinOutputs[0], sce.SiacoinOutput)
	}

	{
		sces, err := db.SiacoinElements([]types.SiacoinOutputID{txn1.SiacoinOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 1, len(sces))

		sce := sces[0]
		testutil.Equal(t, "sce.Source", explorer.SourceTransaction, sce.Source)
		testutil.Equal(t, "sce.SpentIndex", cs.Index, *sce.SpentIndex)
		testutil.Equal(t, "sce.SiacoinElement.SiacoinOutput", txn1.SiacoinOutputs[0], sce.SiacoinOutput)
	}

	{
		sces, err := db.SiacoinElements([]types.SiacoinOutputID{txn2.SiacoinOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 1, len(sces))

		sce := sces[0]
		testutil.Equal(t, "sce.Source", explorer.SourceTransaction, sce.Source)
		testutil.Equal(t, "sce.SpentIndex", nil, sce.SpentIndex)
		testutil.Equal(t, "sce.SiacoinElement.SiacoinOutput", txn2.SiacoinOutputs[0], sce.SiacoinOutput)
	}

	ru := revertUpdate(t, prevState, store.SupplementTipBlock(b), b)
	if err := db.UpdateChainState([]chain.RevertUpdate{ru}, nil); err != nil {
		t.Fatal(err)
	}

	{
		sces, err := db.SiacoinElements([]types.SiacoinOutputID{genesisBlock.Transactions[0].SiacoinOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 1, len(sces))

		sce := sces[0]
		testutil.Equal(t, "sce.Source", explorer.SourceTransaction, sce.Source)
		testutil.Equal(t, "sce.SpentIndex", nil, sce.SpentIndex)
		testutil.Equal(t, "sce.SiacoinElement.SiacoinOutput", genesisBlock.Transactions[0].SiacoinOutputs[0], sce.SiacoinOutput)
	}

	{
		sces, err := db.SiacoinElements([]types.SiacoinOutputID{txn1.SiacoinOutputID(0), txn2.SiacoinOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sces)", 0, len(sces))
	}
}

func TestSiafundOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	genesisBlock, cs, store, db := newStoreRefactored(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})

	unlockConditions := types.StandardUnlockConditions(pk1.PublicKey())
	scID := genesisBlock.Transactions[0].SiafundOutputID(0)
	txn1 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         scID,
			UnlockConditions: unlockConditions,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   genesisBlock.Transactions[0].SiafundOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(cs, pk1, &txn1)

	prevState := cs
	b := testutil.MineBlock(cs, []types.Transaction{txn1}, types.VoidAddress)
	cs, au := applyUpdate(t, cs, store.SupplementTipBlock(b), b)
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{au}); err != nil {
		t.Fatal(err)
	}

	{
		sfes, err := db.SiafundElements([]types.SiafundOutputID{scID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 1, len(sfes))

		sfe := sfes[0]
		testutil.Equal(t, "sfe.SpentIndex", cs.Index, *sfe.SpentIndex)
		testutil.Equal(t, "sfe.SiafundElement.SiafundOutput", genesisBlock.Transactions[0].SiafundOutputs[0], sfe.SiafundOutput)
	}

	{
		sfes, err := db.SiafundElements([]types.SiafundOutputID{txn1.SiafundOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 1, len(sfes))

		sfe := sfes[0]
		testutil.Equal(t, "sfe.SpentIndex", nil, sfe.SpentIndex)
		testutil.Equal(t, "sfe.SiafundElement.SiafundOutput", txn1.SiafundOutputs[0], sfe.SiafundOutput)
	}

	ru := revertUpdate(t, prevState, store.SupplementTipBlock(b), b)
	if err := db.UpdateChainState([]chain.RevertUpdate{ru}, nil); err != nil {
		t.Fatal(err)
	}

	{
		sfes, err := db.SiafundElements([]types.SiafundOutputID{scID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 1, len(sfes))

		sfe := sfes[0]
		testutil.Equal(t, "sfe.SpentIndex", nil, sfe.SpentIndex)
		testutil.Equal(t, "sfe.SiafundElement.SiafundOutput", genesisBlock.Transactions[0].SiafundOutputs[0], sfe.SiafundOutput)
	}

	{
		sfes, err := db.SiafundElements([]types.SiafundOutputID{txn1.SiafundOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 0, len(sfes))
	}
}

func TestEphemeralSiafundOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	genesisBlock, cs, store, db := newStoreRefactored(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})

	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	txn1 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         genesisBlock.Transactions[0].SiafundOutputID(0),
			UnlockConditions: uc1,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr2,
			Value:   genesisBlock.Transactions[0].SiafundOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(cs, pk1, &txn1)

	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
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
	testutil.SignTransaction(cs, pk2, &txn2)

	prevState := cs
	b := testutil.MineBlock(cs, []types.Transaction{txn1, txn2}, types.VoidAddress)
	cs, au := applyUpdate(t, cs, store.SupplementTipBlock(b), b)
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{au}); err != nil {
		t.Fatal(err)
	}

	{
		sfes, err := db.SiafundElements([]types.SiafundOutputID{genesisBlock.Transactions[0].SiafundOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 1, len(sfes))

		sfe := sfes[0]
		testutil.Equal(t, "sfe.SpentIndex", cs.Index, *sfe.SpentIndex)
		testutil.Equal(t, "sfe.SiafundElement.SiafundOutput", genesisBlock.Transactions[0].SiafundOutputs[0], sfe.SiafundOutput)
	}

	{
		sfes, err := db.SiafundElements([]types.SiafundOutputID{txn1.SiafundOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 1, len(sfes))

		sfe := sfes[0]
		testutil.Equal(t, "sfe.SpentIndex", cs.Index, *sfe.SpentIndex)
		testutil.Equal(t, "sfe.SiafundElement.SiafundOutput", txn1.SiafundOutputs[0], sfe.SiafundOutput)
	}

	{
		sfes, err := db.SiafundElements([]types.SiafundOutputID{txn2.SiafundOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 1, len(sfes))

		sfe := sfes[0]
		testutil.Equal(t, "sfe.SpentIndex", nil, sfe.SpentIndex)
		testutil.Equal(t, "sfe.SiafundElement.SiafundOutput", txn2.SiafundOutputs[0], sfe.SiafundOutput)
	}

	ru := revertUpdate(t, prevState, store.SupplementTipBlock(b), b)
	if err := db.UpdateChainState([]chain.RevertUpdate{ru}, nil); err != nil {
		t.Fatal(err)
	}

	{
		sfes, err := db.SiafundElements([]types.SiafundOutputID{genesisBlock.Transactions[0].SiafundOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 1, len(sfes))

		sfe := sfes[0]
		testutil.Equal(t, "sfe.SpentIndex", nil, sfe.SpentIndex)
		testutil.Equal(t, "sfe.SiafundElement.SiafundOutput", genesisBlock.Transactions[0].SiafundOutputs[0], sfe.SiafundOutput)
	}

	{
		sfes, err := db.SiafundElements([]types.SiafundOutputID{txn1.SiafundOutputID(0), txn2.SiafundOutputID(0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(sfes)", 0, len(sfes))
	}
}

func TestTransactionChainIndices(t *testing.T) {
	_, cs, store, db := newStoreRefactored(t, false, nil)

	checkTransaction := func(expected types.Transaction) {
		txns, err := db.Transactions([]types.TransactionID{expected.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 1, len(txns))
		testutil.CheckTransaction(t, expected, txns[0])
	}

	txn1 := types.Transaction{
		ArbitraryData: [][]byte{{0}},
	}
	txn2 := types.Transaction{
		ArbitraryData: [][]byte{{0}, {1}},
	}

	genesisState := cs
	b1 := testutil.MineBlock(cs, []types.Transaction{txn1, txn2}, types.VoidAddress)
	cs, au := applyUpdate(t, cs, store.SupplementTipBlock(b1), b1)
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{au}); err != nil {
		t.Fatal(err)
	}

	checkTransaction(txn1)
	checkTransaction(txn2)
	checkChainIndices(t, db, txn1.ID(), []types.ChainIndex{cs.Index})
	checkChainIndices(t, db, txn2.ID(), []types.ChainIndex{cs.Index})

	prevState := cs
	b2 := testutil.MineBlock(cs, []types.Transaction{txn1, txn2}, types.VoidAddress)
	cs, au = applyUpdate(t, cs, store.SupplementTipBlock(b2), b2)
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{au}); err != nil {
		t.Fatal(err)
	}

	checkTransaction(txn1)
	checkTransaction(txn2)
	checkChainIndices(t, db, txn1.ID(), []types.ChainIndex{cs.Index, prevState.Index})
	checkChainIndices(t, db, txn2.ID(), []types.ChainIndex{cs.Index, prevState.Index})

	ru := revertUpdate(t, prevState, store.SupplementTipBlock(b2), b2)
	if err := db.UpdateChainState([]chain.RevertUpdate{ru}, nil); err != nil {
		t.Fatal(err)
	}

	checkTransaction(txn1)
	checkTransaction(txn2)
	checkChainIndices(t, db, txn1.ID(), []types.ChainIndex{prevState.Index})
	checkChainIndices(t, db, txn2.ID(), []types.ChainIndex{prevState.Index})

	ru = revertUpdate(t, genesisState, store.SupplementTipBlock(b1), b1)
	if err := db.UpdateChainState([]chain.RevertUpdate{ru}, nil); err != nil {
		t.Fatal(err)
	}

	{
		txns, err := db.Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 0, len(txns))
	}
	checkChainIndices(t, db, txn1.ID(), nil)
	checkChainIndices(t, db, txn2.ID(), nil)
}

func TestBlock(t *testing.T) {
	_, cs, store, db := newStoreRefactored(t, false, nil)

	checkBlock := func(expected types.Block) {
		got, err := db.Block(expected.ID())
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "ParentID", expected.ParentID, got.ParentID)
		testutil.Equal(t, "Nonce", expected.Nonce, got.Nonce)
		testutil.Equal(t, "Timestamp", expected.Timestamp, got.Timestamp)

		for i, mp := range expected.MinerPayouts {
			id := expected.ID().MinerOutputID(i)
			scos, err := db.SiacoinElements([]types.SiacoinOutputID{id})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "len(scos)", 1, len(scos))

			sco := scos[0]
			testutil.Equal(t, "Address", mp.Address, sco.SiacoinOutput.Address)
			testutil.Equal(t, "Value", mp.Value, sco.SiacoinOutput.Value)
			testutil.Equal(t, "ID", id, sco.ID)
			testutil.Equal(t, "SpentIndex", nil, sco.SpentIndex)
		}
		for i, txn := range expected.Transactions {
			txns, err := db.Transactions([]types.TransactionID{txn.ID()})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "len(txns)", 1, len(txns))
			testutil.CheckTransaction(t, txn, got.Transactions[i])
		}
	}

	txn1 := types.Transaction{
		ArbitraryData: [][]byte{{0}},
	}
	txn2 := types.Transaction{
		ArbitraryData: [][]byte{{0}, {1}},
	}

	genesisState := cs
	b1 := testutil.MineBlock(cs, []types.Transaction{txn1, txn2}, types.VoidAddress)
	cs, au := applyUpdate(t, cs, store.SupplementTipBlock(b1), b1)
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{au}); err != nil {
		t.Fatal(err)
	}

	checkBlock(b1)

	prevState := cs
	b2 := testutil.MineBlock(cs, []types.Transaction{txn1, txn2}, types.VoidAddress)
	cs, au = applyUpdate(t, cs, store.SupplementTipBlock(b2), b2)
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{au}); err != nil {
		t.Fatal(err)
	}

	checkBlock(b1)
	checkBlock(b2)

	ru := revertUpdate(t, prevState, store.SupplementTipBlock(b2), b2)
	if err := db.UpdateChainState([]chain.RevertUpdate{ru}, nil); err != nil {
		t.Fatal(err)
	}

	checkBlock(b1)
	if _, err := db.Block(b2.ID()); !errors.Is(err, explorer.ErrNoBlock) {
		t.Fatal("expected missing block error for b2", err)
	}

	ru = revertUpdate(t, genesisState, store.SupplementTipBlock(b1), b1)
	if err := db.UpdateChainState([]chain.RevertUpdate{ru}, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Block(b1.ID()); !errors.Is(err, explorer.ErrNoBlock) {
		t.Fatal("expected missing block error for b1", err)
	}
	if _, err := db.Block(b2.ID()); !errors.Is(err, explorer.ErrNoBlock) {
		t.Fatal("expected missing block error for b2", err)
	}
}
