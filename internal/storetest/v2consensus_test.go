//go:build testing

package storetest

import (
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
)

func getSCE(t testing.TB, db explorer.Store, scid types.SiacoinOutputID) types.SiacoinElement {
	t.Helper()

	sces, err := db.SiacoinElements([]types.SiacoinOutputID{scid})
	if err != nil {
		t.Fatal(err)
	} else if len(sces) == 0 {
		t.Fatal("can't find sce")
	}
	return sces[0].SiacoinElement
}

func getSFE(t testing.TB, db explorer.Store, sfid types.SiafundOutputID) types.SiafundElement {
	t.Helper()

	sfes, err := db.SiafundElements([]types.SiafundOutputID{sfid})
	if err != nil {
		t.Fatal(err)
	} else if len(sfes) == 0 {
		t.Fatal("can't find sfe")
	}
	return sfes[0].SiafundElement
}

func getFCE(t testing.TB, db explorer.Store, fcid types.FileContractID) types.V2FileContractElement {
	t.Helper()

	fces, err := db.V2Contracts([]types.FileContractID{fcid})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fces")
	}
	return fces[0].V2FileContractElement
}

func getCIE(t testing.TB, db explorer.Store, bid types.BlockID) types.ChainIndexElement {
	t.Helper()

	b, err := db.Block(bid)
	if err != nil {
		t.Fatal(err)
	}

	merkleProof, err := db.MerkleProof(b.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}
	return types.ChainIndexElement{
		ID: bid,
		StateElement: types.StateElement{
			LeafIndex:   b.LeafIndex,
			MerkleProof: merkleProof,
		},
		ChainIndex: types.ChainIndex{ID: bid, Height: b.Height},
	}
}

func TestV2Block(t *testing.T) {
	n := newTestChain(t, true, nil)

	checkBlocks := func(count int) {
		t.Helper()

		testutil.Equal(t, "blocks", count, len(n.Blocks))
		for i := range n.Blocks {
			testutil.Equal(t, "block height", uint64(i), n.States[i].Index.Height)
			testutil.Equal(t, "block ID", n.Blocks[i].ID(), n.States[i].Index.ID)
			n.AssertBlock(t, n.States[i], n.Blocks[i])
		}
	}

	checkBlocks(1)

	n.MineV2Transactions(t, types.V2Transaction{ArbitraryData: []byte{0}})

	checkBlocks(2)

	n.RevertBlock(t)

	checkBlocks(1)
}

func TestV2ArbitraryData(t *testing.T) {
	n := newTestChain(t, true, nil)

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
	}

	txn2 := types.V2Transaction{
		ArbitraryData: []byte("world"),
	}

	n.MineV2Transactions(t, txn1, txn2)

	n.AssertV2Transactions(t, txn1, txn2)

	txn3 := types.V2Transaction{
		ArbitraryData: []byte("12345"),
	}

	n.MineV2Transactions(t, txn3)

	n.AssertV2Transactions(t, txn1, txn2, txn3)

	n.RevertBlock(t)
}

func TestV2MinerFee(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisTxn := n.Genesis().Transactions[0]

	txn1 := types.V2Transaction{
		MinerFee: genesisTxn.SiacoinOutputs[0].Value,
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, genesisTxn.SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
	}
	testutil.SignV2Transaction(n.TipState(), pk1, &txn1)

	n.MineV2Transactions(t, txn1)

	n.AssertV2Transactions(t, txn1)

	n.RevertBlock(t)
}

func TestV2FoundationAddress(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkFoundation.FailsafeAddress = addr1
		network.HardforkFoundation.PrimaryAddress = addr1
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisTxn := n.Genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	// we have to spend an output beloning to foundation address to change it
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, genesisTxn.SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		MinerFee:             genesisTxn.SiacoinOutputs[0].Value,
		NewFoundationAddress: &addr2,
	}
	testutil.SignV2Transaction(n.TipState(), pk1, &txn1)

	n.MineV2Transactions(t, txn1)

	n.AssertV2Transactions(t, txn1)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	// event for txn1
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.GetV2Txn(t, txn1.ID())),
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	// event for foundation payout
	scID := n.TipState().Index.ID.FoundationOutputID()

	ev2 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeFoundationSubsidy,
		Data:           explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      n.TipBlock().Timestamp,
	}

	n.AssertEvents(t, addr1, ev2, ev1, ev0)

	n.RevertBlock(t)
}

func TestV2Attestations(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	pk2 := types.GeneratePrivateKey()

	n := newTestChain(t, true, nil)

	ha1 := chain.V2HostAnnouncement{{
		Protocol: "http",
		Address:  "127.0.0.1:4444",
	}}
	ha2 := chain.V2HostAnnouncement{{
		Protocol: "http",
		Address:  "127.0.0.1:8888",
	}}

	otherAttestation := types.Attestation{
		PublicKey: pk1.PublicKey(),
		Key:       "hello",
		Value:     []byte("world"),
	}
	otherAttestation.Signature = pk1.SignHash(n.TipState().AttestationSigHash(otherAttestation))

	txn1 := types.V2Transaction{
		Attestations: []types.Attestation{ha1.ToAttestation(n.TipState(), pk1), otherAttestation},
	}
	testutil.SignV2Transaction(n.TipState(), pk1, &txn1)
	txn2 := types.V2Transaction{
		Attestations: []types.Attestation{ha2.ToAttestation(n.TipState(), pk2)},
	}
	testutil.SignV2Transaction(n.TipState(), pk1, &txn2)

	n.MineV2Transactions(t, txn1, txn2)

	n.AssertV2Transactions(t, txn1, txn2)

	n.RevertBlock(t)
}

func TestUnconfirmedEvents(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisTxn := n.Genesis().Transactions[0]

	// get the siacoin element from genesis
	sce := getSCE(t, n.DB, genesisTxn.SiacoinOutputID(0))

	// create a V1 unconfirmed transaction
	v1Txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         genesisTxn.SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr2, Value: types.Siacoins(50)},
			{Address: addr1, Value: sce.SiacoinOutput.Value.Sub(types.Siacoins(50))},
		},
	}
	testutil.SignTransaction(n.TipState(), pk1, &v1Txn)

	// mine the V1 transaction so we have a fresh utxo for V2
	n.MineTransactions(t, v1Txn)

	// get the new siacoin element
	sce2 := getSCE(t, n.DB, v1Txn.SiacoinOutputID(1))

	// create a V2 unconfirmed transaction
	v2Txn := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          sce2,
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: addr2, Value: types.Siacoins(10)},
			{Address: addr1, Value: sce2.SiacoinOutput.Value.Sub(types.Siacoins(10))},
		},
	}
	testutil.SignV2Transaction(n.TipState(), pk1, &v2Txn)

	// test both V1 and V2 together
	index := n.TipState().Index
	timestamp := types.CurrentTimestamp()
	events, err := n.DB.UnconfirmedEvents(index, timestamp, []types.Transaction{v1Txn}, []types.V2Transaction{v2Txn})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(events)", 2, len(events))

	// first event should be V1
	ev1 := events[0]
	testutil.Equal(t, "event ID", types.Hash256(v1Txn.ID()), ev1.ID)
	testutil.Equal(t, "event type", wallet.EventTypeV1Transaction, ev1.Type)
	testutil.Equal(t, "event index", index, ev1.Index)
	testutil.Equal(t, "maturity height", index.Height, ev1.MaturityHeight)
	evTxn1 := ev1.Data.(explorer.EventV1Transaction).Transaction
	testutil.Equal(t, "unconfirmed", true, evTxn1.Unconfirmed)
	testutil.Equal(t, "txn ID", v1Txn.ID(), evTxn1.ID)
	// verify siacoin input has address and value filled in from database
	testutil.Equal(t, "sci address", addr1, evTxn1.SiacoinInputs[0].Address)
	testutil.Equal(t, "sci value", sce.SiacoinOutput.Value, evTxn1.SiacoinInputs[0].Value)

	// second event should be V2
	ev2 := events[1]
	testutil.Equal(t, "event ID", types.Hash256(v2Txn.ID()), ev2.ID)
	testutil.Equal(t, "event type", wallet.EventTypeV2Transaction, ev2.Type)
	testutil.Equal(t, "event index", index, ev2.Index)
	testutil.Equal(t, "maturity height", index.Height, ev2.MaturityHeight)
	evTxn2 := explorer.V2Transaction(ev2.Data.(explorer.EventV2Transaction))
	testutil.Equal(t, "unconfirmed", true, evTxn2.Unconfirmed)
	testutil.Equal(t, "txn ID", v2Txn.ID(), evTxn2.ID)
}
