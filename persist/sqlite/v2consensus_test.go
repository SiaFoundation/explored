package sqlite_test

import (
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
)

func getSCE(t *testing.T, db explorer.Store, scid types.SiacoinOutputID) types.SiacoinElement {
	sces, err := db.SiacoinElements([]types.SiacoinOutputID{scid})
	if err != nil {
		t.Fatal(err)
	} else if len(sces) == 0 {
		t.Fatal("can't find sce")
	}
	sce := sces[0]

	sce.SiacoinElement.MerkleProof, err = db.MerkleProof(sce.StateElement.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}

	return sce.SiacoinElement
}

func TestV2ArbitraryData(t *testing.T) {
	_, _, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
	})

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
	}

	txn2 := types.V2Transaction{
		ArbitraryData: []byte("world"),
	}

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1, txn2}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)
	prev := cm.Tip()

	{
		b, err := db.Block(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "v2 height", b.V2.Height, 1)
		testutil.CheckV2Transaction(t, txn1, b.V2.Transactions[0])
		testutil.CheckV2Transaction(t, txn2, b.V2.Transactions[1])
	}

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
		testutil.CheckV2Transaction(t, txn2, dbTxns[1])
	}

	txn3 := types.V2Transaction{
		ArbitraryData: []byte("12345"),
	}

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1, txn2, txn3}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		b, err := db.Block(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "v2 height", b.V2.Height, 2)
		testutil.CheckV2Transaction(t, txn1, b.V2.Transactions[0])
		testutil.CheckV2Transaction(t, txn2, b.V2.Transactions[1])
		testutil.CheckV2Transaction(t, txn3, b.V2.Transactions[2])
	}

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID(), txn3.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
		testutil.CheckV2Transaction(t, txn2, dbTxns[1])
		testutil.CheckV2Transaction(t, txn3, dbTxns[2])
	}

	testutil.CheckV2ChainIndices(t, db, txn1.ID(), []types.ChainIndex{cm.Tip(), prev})
	testutil.CheckV2ChainIndices(t, db, txn2.ID(), []types.ChainIndex{cm.Tip(), prev})
	testutil.CheckV2ChainIndices(t, db, txn3.ID(), []types.ChainIndex{cm.Tip()})
}

func TestV2MinerFee(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	_, genesisBlock, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
		MinerFee:      giftSC,
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
	}
	testutil.SignV2Transaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}
}

func TestV2FoundationAddress(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	_, genesisBlock, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
		network.HardforkFoundation.PrimaryAddress = addr1
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		MinerFee:             giftSC,
		NewFoundationAddress: &addr2,
	}
	testutil.SignV2Transaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}
}
