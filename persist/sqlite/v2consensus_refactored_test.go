package sqlite

import (
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	proto4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"lukechampine.com/frand"
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

func (n *testChain) mineV2Transactions(t testing.TB, txns ...types.V2Transaction) {
	t.Helper()

	b := testutil.MineV2Block(n.tipState(), txns, types.VoidAddress)
	n.applyBlock(t, b)
}

func (n *testChain) assertV2Transactions(t testing.TB, expected ...types.V2Transaction) {
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

func (n *testChain) assertV2ChainIndices(t testing.TB, txnID types.TransactionID, expected ...types.ChainIndex) {
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

func checkV2Contract(t testing.TB, expected explorer.V2FileContract, got explorer.V2FileContract) {
	t.Helper()

	testutil.Equal(t, "V2FileContract", expected.V2FileContractElement.V2FileContract, got.V2FileContractElement.V2FileContract)
	testutil.Equal(t, "TransactionID", expected.TransactionID, got.TransactionID)
	testutil.Equal(t, "RenewedFrom", expected.RenewedFrom, got.RenewedFrom)
	testutil.Equal(t, "RenewedTo", expected.RenewedTo, got.RenewedTo)
	testutil.Equal(t, "ConfirmationIndex", expected.ConfirmationIndex, got.ConfirmationIndex)
	testutil.Equal(t, "ConfirmationTransactionID", expected.ConfirmationTransactionID, got.ConfirmationTransactionID)
	testutil.Equal(t, "ResolutionType", expected.ResolutionType, got.ResolutionType)
	testutil.Equal(t, "ResolutionIndex", expected.ResolutionIndex, got.ResolutionIndex)
	testutil.Equal(t, "ResolutionTransactionID", expected.ResolutionTransactionID, got.ResolutionTransactionID)
}

// assertV2FCE asserts the contract element in the db has the right state and
// block/transaction indices
func (n *testChain) assertV2FCE(t testing.TB, fcID types.FileContractID, expected explorer.V2FileContract) {
	t.Helper()

	fces, err := n.db.V2Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(fces)", 1, len(fces))

	checkV2Contract(t, expected, fces[0])
}

// assertNoV2FCE asserts the contract element in the db has the right state and
// block/transaction indices
func (n *testChain) assertNoV2FCE(t testing.TB, fcIDs ...types.FileContractID) {
	t.Helper()

	fces, err := n.db.V2Contracts(fcIDs)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(fces)", 0, len(fces))
}

// assertV2TransactionContracts asserts that the enhanced FileContracts
// in a v2 transaction retrieved from the explorer match the expected
// contracts.
func (n *testChain) assertV2TransactionContracts(t testing.TB, txnID types.TransactionID, revisions bool, expected ...explorer.V2FileContract) {
	t.Helper()

	txns, err := n.db.V2Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(txns)", 1, len(txns))

	txn := txns[0]
	if !revisions {
		testutil.Equal(t, "len(txn.FileContracts)", len(expected), len(txn.FileContracts))
		for i := range expected {
			checkV2Contract(t, expected[i], txn.FileContracts[i])
		}
	} else {
		testutil.Equal(t, "len(txn.FileContractRevisions)", len(expected), len(txn.FileContractRevisions))
		for i := range expected {
			checkV2Contract(t, expected[i], txn.FileContractRevisions[i].Revision)
		}
	}
}

// assertV2TransactionResolutions asserts that the enhanced
// FileContractResolutions in a v2 transaction retrieved from the explorer
// match the expected resolutions.
func (n *testChain) assertV2TransactionResolutions(t testing.TB, txnID types.TransactionID, expected ...explorer.V2FileContractResolution) {
	t.Helper()

	txns, err := n.db.V2Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(txns)", 1, len(txns))

	txn := txns[0]
	testutil.Equal(t, "len(txn.FileContractResolutions)", len(expected), len(txn.FileContractResolutions))
	for i := range expected {
		fcr := txn.FileContractResolutions[i]

		checkV2Contract(t, expected[i].Parent, fcr.Parent)
		testutil.Equal(t, "Type", expected[i].Type, fcr.Type)
		if expectedRenewal, ok := expected[i].Resolution.(*explorer.V2FileContractRenewal); ok {
			// handle manually to ignore StateElement
			if gotRenewal, ok := fcr.Resolution.(*explorer.V2FileContractRenewal); ok {
				gotRenewal.NewContract.StateElement = types.StateElement{}
				txn.FileContractResolutions[i].Resolution = gotRenewal
				testutil.Equal(t, "Resolution", expectedRenewal, gotRenewal)
			} else {
				t.Fatalf("wrong type %T vs %T", expected[i].Resolution, fcr.Resolution)
			}
		} else {
			testutil.Equal(t, "Resolution", expected[i].Resolution, fcr.Resolution)
		}
	}
}

func (n *testChain) assertV2ContractRevisions(t testing.TB, fcID types.FileContractID, expected ...explorer.V2FileContract) {
	t.Helper()

	fces, err := n.db.V2ContractRevisions(fcID)
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
		checkV2Contract(t, expected[i], fces[i])
	}
}

func (n *testChain) getV2FCE(t testing.TB, fcID types.FileContractID) explorer.V2FileContract {
	t.Helper()

	fces, err := n.db.V2Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fce")
	}
	fces[0].V2FileContractElement.StateElement.MerkleProof = nil
	return fces[0]
}

func (n *testChain) getV2Txn(t testing.TB, txnID types.TransactionID) explorer.V2Transaction {
	t.Helper()

	txns, err := n.db.V2Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	} else if len(txns) == 0 {
		t.Fatal("can't find txn")
	}
	return txns[0]
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

func TestV2Block(t *testing.T) {
	n := newTestChain(t, true, nil)

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

	n.mineV2Transactions(t, types.V2Transaction{ArbitraryData: []byte{0}})

	checkBlocks(2)

	n.revertBlock(t)

	checkBlocks(1)
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
	b := testutil.MineV2Block(n.tipState(), []types.V2Transaction{txn1}, types.VoidAddress)
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

func prepareV2Contract(renterPK, hostPK types.PrivateKey, proofHeight uint64) (types.V2FileContract, types.Currency) {
	fc, _ := proto4.NewContract(proto4.HostPrices{}, proto4.RPCFormContractParams{
		ProofHeight:     proofHeight,
		Allowance:       types.Siacoins(5),
		RenterAddress:   types.StandardUnlockConditions(renterPK.PublicKey()).UnlockHash(),
		Collateral:      types.Siacoins(5),
		RenterPublicKey: renterPK.PublicKey(),
	}, hostPK.PublicKey(), types.StandardUnlockConditions(hostPK.PublicKey()).UnlockHash())
	fc.ExpirationHeight = fc.ProofHeight + 1

	payout := fc.RenterOutput.Value.Add(fc.HostOutput.Value).Add(consensus.State{}.V2FileContractTax(fc))
	return fc, payout
}

func coreToV2ExplorerFC(fcID types.FileContractID, fc types.V2FileContract) explorer.V2FileContract {
	return explorer.V2FileContract{
		V2FileContractElement: types.V2FileContractElement{
			ID:             fcID,
			V2FileContract: fc,
		},
	}
}

func TestV2FileContractProof(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	renterPK := types.GeneratePrivateKey()
	hostPK := types.GeneratePrivateKey()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := prepareV2Contract(renterPK, hostPK, n.tipState().Index.Height+1)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn1)

	n.mineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	sp := &types.V2StorageProof{
		ProofIndex: getCIE(t, n.db, n.tipState().Index.ID),
	}
	txn2 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fce.ID),
			Resolution: sp,
		}},
	}
	n.mineV2Transactions(t, txn2)

	tip := n.tipState().Index
	txnID := txn2.ID()
	resolutionType := explorer.V2ResolutionStorageProof

	// should be resolved
	fceResolved := fce
	fceResolved.ResolutionType = &resolutionType
	fceResolved.ResolutionIndex = &tip
	fceResolved.ResolutionTransactionID = &txnID

	n.assertV2FCE(t, fce.ID, fceResolved)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fceResolved)
	n.assertV2TransactionResolutions(t, txn2.ID(), explorer.V2FileContractResolution{
		Parent:     fceResolved,
		Type:       resolutionType,
		Resolution: sp,
	})

	n.revertBlock(t)

	// should have old FCE back
	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.revertBlock(t)

	// FCE should not exist after creation reverted
	n.assertNoV2FCE(t, fce.ID)
	n.assertV2ContractRevisions(t, fce.ID)
}

func TestV2FileContractMissed(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	renterPK := types.GeneratePrivateKey()
	hostPK := types.GeneratePrivateKey()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := prepareV2Contract(renterPK, hostPK, n.tipState().Index.Height+1)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn1)

	n.mineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.mineV2Transactions(t)

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	txn2 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fce.ID),
			Resolution: &types.V2FileContractExpiration{},
		}},
	}
	n.mineV2Transactions(t, txn2)

	tip := n.tipState().Index
	txnID := txn2.ID()
	resolutionType := explorer.V2ResolutionExpiration

	// should be resolved
	fceResolved := fce
	fceResolved.ResolutionType = &resolutionType
	fceResolved.ResolutionIndex = &tip
	fceResolved.ResolutionTransactionID = &txnID

	n.assertV2FCE(t, fce.ID, fceResolved)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fceResolved)
	n.assertV2TransactionResolutions(t, txn2.ID(), explorer.V2FileContractResolution{
		Parent:     fceResolved,
		Type:       resolutionType,
		Resolution: &types.V2FileContractExpiration{},
	})

	n.revertBlock(t)

	// revert resolution
	// should have old FCE back
	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.revertBlock(t)

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.revertBlock(t)

	// FCE should not exist after creation reverted
	n.assertNoV2FCE(t, fce.ID)
	n.assertV2ContractRevisions(t, fce.ID)
}

func TestV2FileContractRenewal(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	renterPK := types.GeneratePrivateKey()
	hostPK := types.GeneratePrivateKey()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := prepareV2Contract(renterPK, hostPK, n.tipState().Index.Height+2)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn1)

	n.mineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	finalRevision := fc
	finalRevision.RevisionNumber = types.MaxRevisionNumber
	newContract := fc
	newContract.ProofHeight++
	newContract.ExpirationHeight++
	renewal := &types.V2FileContractRenewal{
		NewContract:       newContract,
		FinalRenterOutput: finalRevision.RenterOutput,
		FinalHostOutput:   finalRevision.HostOutput,
		RenterRollover:    types.ZeroCurrency,
		HostRollover:      types.ZeroCurrency,
	}
	txn2 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, txn1.SiacoinOutputID(txn1.ID(), 0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   txn1.SiacoinOutputs[0].Value.Sub(payout),
		}},
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fce.ID),
			Resolution: renewal,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn2)

	n.mineV2Transactions(t, txn2)

	renewalTip1 := n.tipState().Index
	renewalTxnID1 := txn2.ID()
	renewalID1 := fce.ID.V2RenewalID()
	resolutionType := explorer.V2ResolutionRenewal

	// should be resolved
	fceResolved := fce
	fceResolved.ResolutionType = &resolutionType
	fceResolved.ResolutionIndex = &renewalTip1
	fceResolved.ResolutionTransactionID = &renewalTxnID1
	fceResolved.RenewedTo = &renewalID1

	fceRenewal1 := coreToV2ExplorerFC(renewalID1, renewal.NewContract)
	fceRenewal1.TransactionID = renewalTxnID1
	fceRenewal1.ConfirmationIndex = n.tipState().Index
	fceRenewal1.ConfirmationTransactionID = renewalTxnID1
	fceRenewal1.RenewedFrom = &fce.ID

	n.assertV2FCE(t, fce.ID, fceResolved)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fceResolved)
	n.assertV2FCE(t, renewalID1, fceRenewal1)

	renewal1 := explorer.V2FileContractRenewal{
		FinalRenterOutput: renewal.FinalRenterOutput,
		FinalHostOutput:   renewal.FinalHostOutput,
		RenterRollover:    renewal.RenterRollover,
		HostRollover:      renewal.HostRollover,
		NewContract:       fceRenewal1,
		RenterSignature:   renewal.RenterSignature,
		HostSignature:     renewal.HostSignature,
	}
	resolution1 := explorer.V2FileContractResolution{
		Parent:     fceResolved,
		Type:       resolutionType,
		Resolution: &renewal1,
	}
	n.assertV2TransactionResolutions(t, txn2.ID(), resolution1)

	// renew again
	txn3 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, txn1.SiacoinOutputID(txn2.ID(), 0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   txn2.SiacoinOutputs[0].Value.Sub(payout),
		}},
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fceRenewal1.ID),
			Resolution: renewal,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn3)

	n.mineV2Transactions(t, txn3)

	renewalTip2 := n.tipState().Index
	renewalTxnID2 := txn3.ID()

	renewalID2 := renewalID1.V2RenewalID()
	fceRenewal1.ResolutionType = &resolutionType
	fceRenewal1.ResolutionIndex = &renewalTip2
	fceRenewal1.ResolutionTransactionID = &renewalTxnID2
	fceRenewal1.RenewedTo = &renewalID2
	renewal1.NewContract = fceRenewal1

	fceRenewal2 := coreToV2ExplorerFC(renewalID2, renewal.NewContract)
	fceRenewal2.ConfirmationIndex = renewalTip2
	fceRenewal2.ConfirmationTransactionID = renewalTxnID2
	fceRenewal2.TransactionID = renewalTxnID2
	fceRenewal2.RenewedFrom = &renewalID1
	fceRenewal2.RenewedTo = nil
	renewal2 := renewal1
	renewal2.NewContract = fceRenewal2
	resolution2 := explorer.V2FileContractResolution{
		Parent:     fceRenewal1,
		Type:       resolutionType,
		Resolution: &renewal2,
	}

	n.assertV2FCE(t, fce.ID, fceResolved)
	n.assertV2FCE(t, renewalID1, fceRenewal1)
	n.assertV2FCE(t, renewalID2, fceRenewal2)
	n.assertV2TransactionResolutions(t, txn2.ID(), resolution1)
	n.assertV2TransactionResolutions(t, txn3.ID(), resolution2)

	n.revertBlock(t)

	// revert second renewal
	fceRenewal1.ResolutionType = nil
	fceRenewal1.ResolutionIndex = nil
	fceRenewal1.ResolutionTransactionID = nil
	fceRenewal1.RenewedTo = nil
	renewal1.NewContract = fceRenewal1

	n.assertV2FCE(t, fce.ID, fceResolved)
	n.assertV2FCE(t, renewalID1, fceRenewal1)
	n.assertNoV2FCE(t, renewalID2)
	n.assertV2TransactionResolutions(t, txn2.ID(), resolution1)

	n.revertBlock(t)

	// reverted first renewal
	// should have old FCE back
	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	// Renewal FCE should not exist after resolution reverted
	n.assertNoV2FCE(t, renewalID1, renewalID2)

	n.revertBlock(t)

	// FCE should not exist
	n.assertNoV2FCE(t, fce.ID, renewalID1, renewalID2)
	n.assertV2ContractRevisions(t, fce.ID)
}

func TestV2FileContractRevision(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	renterPK := types.GeneratePrivateKey()
	hostPK := types.GeneratePrivateKey()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := prepareV2Contract(renterPK, hostPK, n.tipState().Index.Height+2)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn1)

	n.mineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2ContractRevisions(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	fcRevision1 := fc
	fcRevision1.RevisionNumber++
	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.db, fce.ID),
			Revision: fcRevision1,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn2)

	n.mineV2Transactions(t, txn2)

	fceRevision1 := coreToV2ExplorerFC(fce.ID, txn2.FileContractRevisions[0].Revision)
	fceRevision1.TransactionID = txn2.ID()
	fceRevision1.ConfirmationIndex = fce.ConfirmationIndex
	fceRevision1.ConfirmationTransactionID = fce.ConfirmationTransactionID

	n.assertV2FCE(t, fce.ID, fceRevision1)
	n.assertV2ContractRevisions(t, fce.ID, fce, fceRevision1)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.assertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)

	n.mineV2Transactions(t)

	// resolve contract unsuccessful
	txn4 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fce.ID),
			Resolution: &types.V2FileContractExpiration{},
		}},
	}
	n.mineV2Transactions(t, txn4)

	tip := n.tipState().Index
	txnID := txn4.ID()
	resolutionType := explorer.V2ResolutionExpiration

	// should be resolved
	fce.ResolutionType = &resolutionType
	fce.ResolutionIndex = &tip
	fce.ResolutionTransactionID = &txnID
	fceRevision1.ResolutionType = &resolutionType
	fceRevision1.ResolutionIndex = &tip
	fceRevision1.ResolutionTransactionID = &txnID

	n.assertV2FCE(t, fce.ID, fceRevision1)
	n.assertV2ContractRevisions(t, fce.ID, fce, fceRevision1)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.assertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.assertV2TransactionResolutions(t, txn4.ID(), explorer.V2FileContractResolution{
		Parent:     fceRevision1,
		Type:       resolutionType,
		Resolution: &types.V2FileContractExpiration{},
	})

	// revert resolution of contract
	for i := n.tipState().Index.Height; i >= fc.ExpirationHeight; i-- {
		n.revertBlock(t)
	}

	fce.ResolutionType = nil
	fce.ResolutionIndex = nil
	fce.ResolutionTransactionID = nil
	fceRevision1.ResolutionType = nil
	fceRevision1.ResolutionIndex = nil
	fceRevision1.ResolutionTransactionID = nil

	n.assertV2FCE(t, fce.ID, fceRevision1)
	n.assertV2ContractRevisions(t, fce.ID, fce, fceRevision1)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.assertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)

	// revert revision of contract
	n.revertBlock(t)

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2ContractRevisions(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.revertBlock(t)

	n.assertNoV2FCE(t, fce.ID)
	n.assertContractRevisions(t, fce.ID)
}

func TestV2FileContractMultipleRevisions(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	renterPK := types.GeneratePrivateKey()
	hostPK := types.GeneratePrivateKey()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := prepareV2Contract(renterPK, hostPK, n.tipState().Index.Height+2)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn1)

	n.mineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2ContractRevisions(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	fcRevision1 := fc
	fcRevision1.RevisionNumber++

	fcRevision2 := fcRevision1
	fcRevision2.RevisionNumber++

	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.db, fce.ID),
			Revision: fcRevision1,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn2)

	txn3 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.db, fce.ID),
			Revision: fcRevision2,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn3)

	n.mineV2Transactions(t, txn2, txn3)

	fceRevision1 := coreToV2ExplorerFC(fce.ID, txn2.FileContractRevisions[0].Revision)
	fceRevision1.TransactionID = txn2.ID()
	fceRevision1.ConfirmationIndex = fce.ConfirmationIndex
	fceRevision1.ConfirmationTransactionID = fce.ConfirmationTransactionID

	fceRevision2 := coreToV2ExplorerFC(fce.ID, txn3.FileContractRevisions[0].Revision)
	fceRevision2.TransactionID = txn3.ID()
	fceRevision2.ConfirmationIndex = fce.ConfirmationIndex
	fceRevision2.ConfirmationTransactionID = fce.ConfirmationTransactionID

	n.assertV2FCE(t, fce.ID, fceRevision2)
	n.assertV2ContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.assertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.assertV2TransactionContracts(t, txn3.ID(), true, fceRevision2)

	n.mineV2Transactions(t)

	// resolve contract unsuccessful
	txn4 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fce.ID),
			Resolution: &types.V2FileContractExpiration{},
		}},
	}
	n.mineV2Transactions(t, txn4)

	tip := n.tipState().Index
	txnID := txn4.ID()
	resolutionType := explorer.V2ResolutionExpiration

	// should be resolved
	fce.ResolutionType = &resolutionType
	fce.ResolutionIndex = &tip
	fce.ResolutionTransactionID = &txnID
	fceRevision1.ResolutionType = &resolutionType
	fceRevision1.ResolutionIndex = &tip
	fceRevision1.ResolutionTransactionID = &txnID
	fceRevision2.ResolutionType = &resolutionType
	fceRevision2.ResolutionIndex = &tip
	fceRevision2.ResolutionTransactionID = &txnID

	n.assertV2FCE(t, fce.ID, fceRevision2)
	n.assertV2ContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.assertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.assertV2TransactionContracts(t, txn3.ID(), true, fceRevision2)
	n.assertV2TransactionResolutions(t, txn4.ID(), explorer.V2FileContractResolution{
		Parent:     fceRevision2,
		Type:       resolutionType,
		Resolution: &types.V2FileContractExpiration{},
	})

	// revert resolution of contract
	for i := n.tipState().Index.Height; i >= fc.ExpirationHeight; i-- {
		n.revertBlock(t)
	}

	fce.ResolutionType = nil
	fce.ResolutionIndex = nil
	fce.ResolutionTransactionID = nil
	fceRevision1.ResolutionType = nil
	fceRevision1.ResolutionIndex = nil
	fceRevision1.ResolutionTransactionID = nil
	fceRevision2.ResolutionType = nil
	fceRevision2.ResolutionIndex = nil
	fceRevision2.ResolutionTransactionID = nil

	n.assertV2FCE(t, fce.ID, fceRevision2)
	n.assertV2ContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.assertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.assertV2TransactionContracts(t, txn3.ID(), true, fceRevision2)

	// revert revisions block
	n.revertBlock(t)

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2ContractRevisions(t, fce.ID, fce)
	n.assertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.revertBlock(t)

	n.assertNoV2FCE(t, fce.ID)
	n.assertV2ContractRevisions(t, fce.ID)
}

func TestV2FileContractsKey(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	renterPK := types.GeneratePrivateKey()
	hostPK := types.GeneratePrivateKey()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	assertContractsKey := func(pk types.PublicKey, expected ...explorer.V2FileContract) {
		t.Helper()

		fces, err := n.db.V2ContractsKey(pk)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", len(expected), len(fces))

		for i := range expected {
			checkV2Contract(t, expected[i], fces[i])
		}
	}

	fc, payout := prepareV2Contract(renterPK, hostPK, n.tipState().Index.Height+2)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn1)

	n.mineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2ContractRevisions(t, fce.ID, fce)
	assertContractsKey(pk1.PublicKey())
	assertContractsKey(renterPK.PublicKey(), fce)
	assertContractsKey(hostPK.PublicKey(), fce)

	// change renter public key to pk1
	fcRevision1 := fc
	fcRevision1.RevisionNumber++
	fcRevision1.RenterPublicKey = pk1.PublicKey()

	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.db, fce.ID),
			Revision: fcRevision1,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn2)

	n.mineV2Transactions(t, txn2)

	fceRevision1 := coreToV2ExplorerFC(fce.ID, txn2.FileContractRevisions[0].Revision)
	fceRevision1.TransactionID = txn2.ID()
	fceRevision1.ConfirmationIndex = fce.ConfirmationIndex
	fceRevision1.ConfirmationTransactionID = fce.ConfirmationTransactionID

	// renter public key changed from renterPK to pk1 so we should not have
	// any contracts with renterPK
	n.assertV2FCE(t, fce.ID, fceRevision1)
	n.assertV2ContractRevisions(t, fce.ID, fce, fceRevision1)
	assertContractsKey(pk1.PublicKey(), fceRevision1)
	assertContractsKey(renterPK.PublicKey())
	assertContractsKey(hostPK.PublicKey(), fceRevision1)

	n.revertBlock(t)

	// revert revision so renterPK should have contract now and pk1 should not
	n.assertV2FCE(t, fce.ID, fce)
	n.assertV2ContractRevisions(t, fce.ID, fce)
	assertContractsKey(pk1.PublicKey())
	assertContractsKey(renterPK.PublicKey(), fce)
	assertContractsKey(hostPK.PublicKey(), fce)

	n.revertBlock(t)

	// revert formation of contract
	n.assertNoV2FCE(t, fce.ID)
	n.assertContractRevisions(t, fce.ID)
	assertContractsKey(pk1.PublicKey())
	assertContractsKey(renterPK.PublicKey())
	assertContractsKey(hostPK.PublicKey())
}

func TestEventV2Transaction(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	genesisTxn := n.genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	// txn1 - should be relevant to addr1 (due to input) and addr2 due to
	// sc output
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, genesisTxn.SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisTxn.SiacoinOutputs[0].Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	// txn2 - should be relevant to addr1 (due to input) and addr3 due to
	// sf output
	txn2 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          getSFE(t, n.db, genesisTxn.SiafundOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr3,
			Value:   genesisTxn.SiafundOutputs[0].Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn2)

	n.mineV2Transactions(t, txn1, txn2)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	// event for txn1
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.getV2Txn(t, txn1.ID())),
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}
	// event for txn2
	ev2 := explorer.Event{
		ID:             types.Hash256(txn2.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.getV2Txn(t, txn2.ID())),
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	// addr1 should be relevant to all transactions
	n.assertEvents(t, addr1, ev2, ev1, ev0)
	n.assertEvents(t, addr2, ev1)
	n.assertEvents(t, addr3, ev2)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}

	// genesis transaction still present but txn1 and txn2 reverted
	n.assertEvents(t, addr1, ev0)
	n.assertEvents(t, addr2)
	n.assertEvents(t, addr3)
}

func TestEventV2FileContract(t *testing.T) {
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
	genesisTxn := n.genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	// create file contract
	fc, payout := prepareV2Contract(pk1, pk2, n.tipState().Index.Height+1)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   genesisTxn.SiacoinOutputs[0].Value.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, pk1, pk2, &txn1)

	n.mineV2Transactions(t, txn1)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	// event for fc creation txn
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.getV2Txn(t, txn1.ID())),
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev1, ev0)
	n.assertEvents(t, addr2, ev1)

	fcID := txn1.V2FileContractID(txn1.ID(), 0)
	sp := &types.V2StorageProof{
		ProofIndex: getCIE(t, n.db, n.tipState().Index.ID),
	}
	txn2 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fcID),
			Resolution: sp,
		}},
	}
	n.mineV2Transactions(t, txn2)

	ev1.Data = explorer.EventV2Transaction(n.getV2Txn(t, txn1.ID()))
	// event for resolution txn
	ev2 := explorer.Event{
		ID:             types.Hash256(txn2.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.getV2Txn(t, txn2.ID())),
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	resolution := n.getV2Txn(t, txn2.ID()).FileContractResolutions[0]
	// event for renter output
	ev3 := explorer.Event{
		ID:    types.Hash256(fcID.V2RenterOutputID()),
		Index: n.tipState().Index,
		Type:  wallet.EventTypeV2ContractResolution,
		Data: explorer.EventV2ContractResolution{
			Resolution:     resolution,
			SiacoinElement: n.getSCE(t, fcID.V2RenterOutputID()),
			Missed:         false,
		},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}
	// event for host output
	ev4 := explorer.Event{
		ID:    types.Hash256(fcID.V2HostOutputID()),
		Index: n.tipState().Index,
		Type:  wallet.EventTypeV2ContractResolution,
		Data: explorer.EventV2ContractResolution{
			Resolution:     resolution,
			SiacoinElement: n.getSCE(t, fcID.V2HostOutputID()),
			Missed:         false,
		},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev3, ev2, ev1, ev0)
	n.assertEvents(t, addr2, ev4, ev2, ev1)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	ev1.Data = explorer.EventV2Transaction(n.getV2Txn(t, txn1.ID()))
	n.assertEvents(t, addr1, ev1, ev0)
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	n.assertEvents(t, addr1, ev0)
	n.assertEvents(t, addr2)
}

func TestV2ArbitraryData(t *testing.T) {
	n := newTestChain(t, true, nil)

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
	}

	txn2 := types.V2Transaction{
		ArbitraryData: []byte("world"),
	}

	n.mineV2Transactions(t, txn1, txn2)

	n.assertV2Transactions(t, txn1, txn2)

	txn3 := types.V2Transaction{
		ArbitraryData: []byte("12345"),
	}

	n.mineV2Transactions(t, txn3)

	n.assertV2Transactions(t, txn1, txn2, txn3)

	n.revertBlock(t)
}

func TestV2MinerFee(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisTxn := n.genesis().Transactions[0]

	txn1 := types.V2Transaction{
		MinerFee: genesisTxn.SiacoinOutputs[0].Value,
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, genesisTxn.SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	n.mineV2Transactions(t, txn1)

	n.assertV2Transactions(t, txn1)

	n.revertBlock(t)
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
	genesisTxn := n.genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	// we have to spend an output beloning to foundation address to change it
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, genesisTxn.SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		MinerFee:             genesisTxn.SiacoinOutputs[0].Value,
		NewFoundationAddress: &addr2,
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	n.mineV2Transactions(t, txn1)

	n.assertV2Transactions(t, txn1)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	// event for txn1
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.getV2Txn(t, txn1.ID())),
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	// event for foundation payout
	scID := n.tipState().Index.ID.FoundationOutputID()

	ev2 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeFoundationSubsidy,
		Data:           explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev2, ev1, ev0)

	n.revertBlock(t)
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
	otherAttestation.Signature = pk1.SignHash(n.tipState().AttestationSigHash(otherAttestation))

	txn1 := types.V2Transaction{
		Attestations: []types.Attestation{ha1.ToAttestation(n.tipState(), pk1), otherAttestation},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)
	txn2 := types.V2Transaction{
		Attestations: []types.Attestation{ha2.ToAttestation(n.tipState(), pk2)},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn2)

	n.mineV2Transactions(t, txn1, txn2)

	n.assertV2Transactions(t, txn1, txn2)

	n.revertBlock(t)
}

func TestV2HostScan(t *testing.T) {
	pk1 := types.GeneratePrivateKey()

	n := newTestChain(t, true, nil)

	assertHost := func(pubkey types.PublicKey, expected explorer.Host) {
		hosts, err := n.db.QueryHosts(explorer.HostQuery{PublicKeys: []types.PublicKey{pubkey}}, explorer.HostSortPublicKey, explorer.HostSortAsc, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(hosts)", 1, len(hosts))

		testutil.Equal(t, "Host", expected, hosts[0])
	}

	// announce a host
	const netAddr1 = "127.0.0.1:1234"
	ha1 := chain.V2HostAnnouncement{{
		Protocol: "http",
		Address:  netAddr1,
	}}

	txn1 := types.V2Transaction{
		Attestations: []types.Attestation{ha1.ToAttestation(n.tipState(), pk1)},
	}

	n.mineV2Transactions(t, txn1)

	hosts, err := n.db.HostsForScanning(time.Unix(0, 0), 100)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(hosts)", 1, len(hosts))

	now := types.CurrentTimestamp()
	settings := proto4.HostSettings{
		ProtocolVersion:    [3]uint8{1, 2, 3},
		AcceptingContracts: true,
		Prices: proto4.HostPrices{
			TipHeight: 123,
		},
	}
	// successful scan; should update settings and price table
	scan1 := explorer.HostScan{
		PublicKey:  hosts[0].PublicKey,
		Success:    true,
		Timestamp:  now,
		NextScan:   now.Add(time.Hour),
		V2Settings: settings,
	}

	if err := n.db.AddHostScans([]explorer.HostScan{scan1}...); err != nil {
		t.Fatal(err)
	}

	lastAnnouncement := n.tipBlock().Timestamp
	host1 := explorer.Host{
		V2:                     true,
		PublicKey:              hosts[0].PublicKey,
		V2NetAddresses:         []chain.NetAddress(ha1),
		KnownSince:             lastAnnouncement,
		LastScan:               scan1.Timestamp,
		LastScanSuccessful:     true,
		LastAnnouncement:       lastAnnouncement,
		NextScan:               scan1.NextScan,
		TotalScans:             1,
		SuccessfulInteractions: 1,
		FailedInteractions:     0,
		V2Settings:             settings,
	}
	assertHost(hosts[0].PublicKey, host1)

	now = types.CurrentTimestamp()
	// unsuccessful scan
	scan2 := explorer.HostScan{
		PublicKey: hosts[0].PublicKey,
		Success:   false,
		Timestamp: now,
		NextScan:  now.Add(time.Hour),
		Error: func() *string {
			x := "error"
			return &x
		}(),
	}

	if err := n.db.AddHostScans([]explorer.HostScan{scan2}...); err != nil {
		t.Fatal(err)
	}
	// previous settings and price table should be preserved in case of failure
	host1.LastScan = scan2.Timestamp
	host1.NextScan = scan2.NextScan
	host1.LastScanError = scan2.Error
	host1.LastScanSuccessful = false
	host1.TotalScans++
	host1.FailedInteractions++

	assertHost(hosts[0].PublicKey, host1)
}

func TestEventV2PayoutContract(t *testing.T) {
	// test to catch bug where slice returned by explorer.AppliedEvents did not
	// include miner payout events if there was any contract action in the
	// block besides resolutions because it mistakenly returned early
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

	// create file contract
	fc, payout := prepareV2Contract(pk1, pk1, n.tipState().Index.Height+1)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, pk1, pk1, &txn1)

	b := testutil.MineV2Block(n.tipState(), []types.V2Transaction{txn1}, addr2)
	n.applyBlock(t, b)

	scID := b.ID().MinerOutputID(0)
	ev1 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeMinerPayout,
		Data:           explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      b.Timestamp,
	}
	n.assertEvents(t, addr2, ev1)

	// see if confirmations number goes up when we mine another block
	n.mineTransactions(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)}
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)}
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	n.assertEvents(t, addr2)
}

func TestV2Metrics(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	renterPK := types.GeneratePrivateKey()
	hostPK := types.GeneratePrivateKey()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
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
		testutil.Equal(t, "TotalHosts", 0, got.TotalHosts)
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
	fc, payout := prepareV2Contract(renterPK, hostPK, n.tipState().Index.Height+2)
	fc.Capacity = proto4.SectorSize
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout.Mul64(2)),
		}},
		FileContracts: []types.V2FileContract{fc, fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn1)

	n.mineV2Transactions(t, txn1)

	// funds now locked in contract so circulating supply goes down
	circulatingSupply = circulatingSupply.Sub(payout.Mul64(2))
	metrics2 := explorer.Metrics{
		ActiveContracts:   2,
		CirculatingSupply: circulatingSupply,
	}
	assertMetrics(metrics2)

	// revise first contract
	fcID1 := txn1.V2FileContractID(txn1.ID(), 0)
	fcID2 := txn1.V2FileContractID(txn1.ID(), 1)
	fcRevision1 := fc
	fcRevision1.Filesize = proto4.SectorSize
	fcRevision1.RevisionNumber++
	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.db, fcID1),
			Revision: fcRevision1,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, renterPK, hostPK, &txn2)

	n.mineV2Transactions(t, txn2)

	metrics3 := explorer.Metrics{
		ActiveContracts:    2,
		StorageUtilization: fcRevision1.Filesize,
		CirculatingSupply:  circulatingSupply,
	}
	assertMetrics(metrics3)

	// resolve second contract successfully
	sp := &types.V2StorageProof{
		ProofIndex: getCIE(t, n.db, n.tipState().Index.ID),
	}
	txn3 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fcID1),
			Resolution: sp,
		}},
	}
	n.mineV2Transactions(t, txn3)

	// valid proof outputs created after proof successful
	var contractRevenue types.Currency
	contractRevenue = contractRevenue.Add(fc.RenterOutput.Value)
	contractRevenue = contractRevenue.Add(fc.HostOutput.Value)
	circulatingSupply = circulatingSupply.Add(fc.RenterOutput.Value)
	circulatingSupply = circulatingSupply.Add(fc.HostOutput.Value)
	metrics4 := explorer.Metrics{
		ActiveContracts:     1,
		SuccessfulContracts: 1,
		StorageUtilization:  0,
		CirculatingSupply:   circulatingSupply,
		ContractRevenue:     contractRevenue,
	}
	assertMetrics(metrics4)

	// resolve first contract unsuccessfully
	for i := n.tipState().Index.Height; i < fc.ExpirationHeight; i++ {
		n.mineV2Transactions(t)
	}
	txn4 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fcID2),
			Resolution: &types.V2FileContractExpiration{},
		}},
	}
	n.mineV2Transactions(t, txn4)

	// missed proof outputs created after failed resolution
	circulatingSupply = circulatingSupply.Add(fc.RenterOutput.Value)
	circulatingSupply = circulatingSupply.Add(fc.MissedHostOutput().Value)
	metrics5 := explorer.Metrics{
		ActiveContracts:     0,
		SuccessfulContracts: 1,
		FailedContracts:     1,
		CirculatingSupply:   circulatingSupply,
		ContractRevenue:     contractRevenue,
	}
	assertMetrics(metrics5)

	// go back to before failed resolution
	for i := n.tipState().Index.Height; i > fc.ExpirationHeight; i-- {
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

func BenchmarkV2Transactions(b *testing.B) {
	n := newTestChain(b, false, nil)

	// add a bunch of random transactions that are either empty, contain arbitrary
	// or contain a contract formation
	var ids []types.TransactionID
	err := n.db.transaction(func(tx *txn) error {
		fceStmt, err := tx.Prepare(`INSERT INTO v2_file_contract_elements(contract_id, block_id, transaction_id, leaf_index, capacity, filesize, file_merkle_root, proof_height, expiration_height, renter_output_address, renter_output_value, host_output_address, host_output_value, missed_host_value, total_collateral, renter_public_key, host_public_key, revision_number, renter_signature, host_signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}

		txnStmt, err := tx.Prepare(`INSERT INTO v2_transactions(transaction_id, miner_fee) VALUES (?, ?)`)
		if err != nil {
			return err
		}

		txnAttestationsStmt, err := tx.Prepare(`INSERT INTO v2_transaction_attestations(transaction_id, transaction_order, public_key, key, value, signature) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}

		txnContractsStmt, err := tx.Prepare(`INSERT INTO v2_transaction_file_contracts(transaction_id, transaction_order, contract_id) VALUES (?, ?, ?)`)
		if err != nil {
			return err
		}

		pubkey, key, value, sig := encode(types.GeneratePrivateKey().PublicKey()), "key", []byte("value"), encode(types.Signature{})

		bid := encode(n.tipState().Index.ID)
		leafIndex := encode(uint64(0))
		capacity, filesize, fileMerkleRoot, proofHeight, expirationHeight, renterOutputAddress, renterOutputValue, hostOutputAddress, hostOutputValue, missedHostValue, totalCollateral, renterPublicKey, hostPublicKey, revisionNumber, renterSignature, hostSignature := encode(uint64(0)), encode(uint64(0)), encode(types.Hash256{}), encode(uint64(0)), encode(uint64(0)), encode(types.Address{}), encode(types.ZeroCurrency), encode(types.Address{}), encode(types.ZeroCurrency), encode(types.ZeroCurrency), encode(types.ZeroCurrency), encode(types.GeneratePrivateKey().PublicKey()), encode(types.GeneratePrivateKey().PublicKey()), encode(uint64(0)), encode(types.Signature{}), encode(types.Signature{})
		for i := range 1_000_000 {
			if i%100_000 == 0 {
				b.Log("Inserted transaction:", i)
			}

			var txnID types.TransactionID
			frand.Read(txnID[:])
			ids = append(ids, txnID)

			result, err := txnStmt.Exec(encode(txnID), encode(types.ZeroCurrency))
			if err != nil {
				return err
			}
			txnDBID, err := result.LastInsertId()
			if err != nil {
				return err
			}

			switch i % 3 {
			case 0:
				// empty transaction
			case 1:
				// transaction with attestation
				if _, err = txnAttestationsStmt.Exec(txnDBID, 0, pubkey, key, value, sig); err != nil {
					return err
				}
			case 2:
				// transaction with file contract formation
				var fcID types.FileContractID
				frand.Read(fcID[:])

				result, err = fceStmt.Exec(encode(fcID), bid, encode(txnID), leafIndex, capacity, filesize, fileMerkleRoot, proofHeight, expirationHeight, renterOutputAddress, renterOutputValue, hostOutputAddress, hostOutputValue, missedHostValue, totalCollateral, renterPublicKey, hostPublicKey, revisionNumber, renterSignature, hostSignature)
				if err != nil {
					return err
				}
				fcDBID, err := result.LastInsertId()
				if err != nil {
					return err
				}
				if _, err := txnContractsStmt.Exec(txnDBID, 0, fcDBID); err != nil {
					return err
				}
			}
		}
		return nil
	})

	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for _, limit := range []int{10, 100, 1000} {
		b.Run(strconv.Itoa(limit)+" transactions", func(b *testing.B) {
			offset := frand.Intn(len(ids) - limit)
			txnIDs := ids[offset : offset+limit]
			for b.Loop() {
				txns, err := n.db.V2Transactions(txnIDs)
				if err != nil {
					b.Fatal(err)
				}
				testutil.Equal(b, "len(txns)", limit, len(txns))
			}
		})
	}
}
