package testchain

import (
	"errors"
	"math"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	proto2 "go.sia.tech/core/rhp/v2"
	proto4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
)

// Chain wraps an in-memory chain.DBStore alongside an explorer.Store backend,
// recording the applied blocks/states/supplements for use by tests and
// benchmarks.
type Chain struct {
	DB    explorer.Store
	Store *chain.DBStore

	Network     *consensus.Network
	Blocks      []types.Block
	Supplements []consensus.V1BlockSupplement
	States      []consensus.State
}

// New constructs a Chain backed by db. The genesis block is applied to db
// before returning. If modifyGenesis is non-nil it can mutate the network or
// genesis block in place before genesis is applied.
func New(t testing.TB, db explorer.Store, v2 bool, modifyGenesis func(*consensus.Network, types.Block)) *Chain {
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

	return &Chain{
		DB:    db,
		Store: store,

		Network:     network,
		Blocks:      []types.Block{genesisBlock},
		Supplements: []consensus.V1BlockSupplement{bs},
		States:      []consensus.State{genesisState},
	}
}

// Genesis returns the genesis block of the chain.
func (c *Chain) Genesis() types.Block { return c.Blocks[0] }

// TipBlock returns the most recently applied block.
func (c *Chain) TipBlock() types.Block { return c.Blocks[len(c.Blocks)-1] }

// TipState returns the consensus state at the tip.
func (c *Chain) TipState() consensus.State { return c.States[len(c.States)-1] }

// ApplyBlock validates and applies b on top of the current tip.
func (c *Chain) ApplyBlock(t testing.TB, b types.Block) {
	t.Helper()

	cs := c.TipState()
	bs := c.Store.SupplementTipBlock(b)
	if cs.Index.Height != math.MaxUint64 {
		// don't validate genesis block
		if err := consensus.ValidateBlock(cs, b, bs); err != nil {
			t.Fatal(err)
		}
	}

	cs, au := consensus.ApplyBlock(cs, b, bs, time.Time{})
	if err := c.DB.UpdateChainState(nil, []chain.ApplyUpdate{{
		ApplyUpdate: au,
		Block:       b,
		State:       cs,
	}}); err != nil {
		t.Fatal(err)
	}

	c.Store.AddState(cs)
	c.Store.AddBlock(b, &bs)
	c.Store.ApplyBlock(cs, au)

	c.Blocks = append(c.Blocks, b)
	c.Supplements = append(c.Supplements, bs)
	c.States = append(c.States, cs)
}

// RevertBlock reverts the tip block.
func (c *Chain) RevertBlock(t testing.TB) {
	b := c.Blocks[len(c.Blocks)-1]
	bs := c.Supplements[len(c.Supplements)-1]
	prevState := c.States[len(c.States)-2]

	ru := consensus.RevertBlock(prevState, b, bs)
	if err := c.DB.UpdateChainState([]chain.RevertUpdate{{
		RevertUpdate: ru,
		Block:        b,
		State:        prevState,
	}}, nil); err != nil {
		t.Fatal(err)
	}

	c.Store.RevertBlock(prevState, ru)

	c.Blocks = c.Blocks[:len(c.Blocks)-1]
	c.Supplements = c.Supplements[:len(c.Supplements)-1]
	c.States = c.States[:len(c.States)-1]
}

// MineTransactions mines a block containing the given transactions on top of
// the tip and applies it.
func (c *Chain) MineTransactions(t testing.TB, txns ...types.Transaction) {
	t.Helper()

	b := testutil.MineBlock(c.TipState(), txns, types.VoidAddress)
	c.ApplyBlock(t, b)
}

// AssertTransactions fails the test unless each expected transaction can be
// retrieved from the store and matches the expected form.
func (c *Chain) AssertTransactions(t testing.TB, expected ...types.Transaction) {
	t.Helper()

	for _, txn := range expected {
		txns, err := c.DB.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 1, len(txns))

		testutil.CheckTransaction(t, txn, txns[0])
	}
}

// AssertContractRevisions fails the test unless ContractRevisions(fcID)
// returns exactly the expected revisions in order.
func (c *Chain) AssertContractRevisions(t testing.TB, fcID types.FileContractID, expected ...explorer.ExtendedFileContract) {
	t.Helper()

	fces, err := c.DB.ContractRevisions(fcID)
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

// AssertEvents fails the test unless the events for addr match expected.
func (c *Chain) AssertEvents(t testing.TB, addr types.Address, expected ...explorer.Event) {
	t.Helper()

	events, err := c.DB.AddressEvents(addr, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(events)", len(expected), len(events))

	for i := range expected {
		expected[i].Relevant = []types.Address{addr}
		expected[i].Confirmations = c.TipState().Index.Height - expected[i].Index.Height
		testutil.Equal(t, "Event", expected[i], events[i])
	}

	for i := range expected {
		events, err := c.DB.Events([]types.Hash256{expected[i].ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(events)", 1, len(events))

		expected[i].Relevant = nil
		testutil.Equal(t, "Event", expected[i], events[0])
	}
}

// GetSCE returns the siacoin output with the given id without the merkle
// proof.
func (c *Chain) GetSCE(t testing.TB, scID types.SiacoinOutputID) explorer.SiacoinOutput {
	t.Helper()

	sces, err := c.DB.SiacoinElements([]types.SiacoinOutputID{scID})
	if err != nil {
		t.Fatal(err)
	} else if len(sces) == 0 {
		t.Fatal("can't find sce")
	}
	sces[0].StateElement.MerkleProof = nil
	return sces[0]
}

// GetFCE returns the file contract with the given id.
func (c *Chain) GetFCE(t testing.TB, fcID types.FileContractID) explorer.ExtendedFileContract {
	t.Helper()

	fces, err := c.DB.Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fce")
	}
	return fces[0]
}

// GetTxn returns the transaction with the given id.
func (c *Chain) GetTxn(t testing.TB, txnID types.TransactionID) explorer.Transaction {
	t.Helper()

	txns, err := c.DB.Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	} else if len(txns) == 0 {
		t.Fatal("can't find txn")
	}
	return txns[0]
}

// AssertBlock fails the test unless the stored block matches block at state cs.
func (c *Chain) AssertBlock(t testing.TB, cs consensus.State, block types.Block) {
	got, err := c.DB.Block(block.ID())
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

// PrepareContract builds a v1 FileContract suitable for tests, payable to addr
// with proof window starting at endHeight.
func PrepareContract(addr types.Address, endHeight uint64) types.FileContract {
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

// PrepareV2Contract builds a v2 FileContract suitable for tests and returns
// it along with the total payout.
func PrepareV2Contract(renterPK, hostPK types.PrivateKey, proofHeight uint64) (types.V2FileContract, types.Currency) {
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

// MineV2Transactions mines a block containing only the given v2 transactions.
func (c *Chain) MineV2Transactions(t testing.TB, txns ...types.V2Transaction) {
	t.Helper()

	b := testutil.MineV2Block(c.TipState(), nil, txns, types.VoidAddress)
	c.ApplyBlock(t, b)
}

// AssertV2Transactions fails the test unless each expected v2 transaction can
// be retrieved from the store and matches its on-chain form.
func (c *Chain) AssertV2Transactions(t testing.TB, expected ...types.V2Transaction) {
	t.Helper()

	for _, txn := range expected {
		txns, err := c.DB.V2Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 1, len(txns))

		testutil.CheckV2Transaction(t, txn, txns[0])
	}
}

// GetV2FCE returns the v2 file contract with the given id without the merkle
// proof.
func (c *Chain) GetV2FCE(t testing.TB, fcID types.FileContractID) explorer.V2FileContract {
	t.Helper()

	fces, err := c.DB.V2Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fce")
	}
	fces[0].V2FileContractElement.StateElement.MerkleProof = nil
	return fces[0]
}

// GetV2Txn returns the v2 transaction with the given id.
func (c *Chain) GetV2Txn(t testing.TB, txnID types.TransactionID) explorer.V2Transaction {
	t.Helper()

	txns, err := c.DB.V2Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	} else if len(txns) == 0 {
		t.Fatal("can't find txn")
	}
	return txns[0]
}

// AssertChainIndices fails the test unless TransactionChainIndices returns
// exactly the expected indices for txnID.
func (c *Chain) AssertChainIndices(t testing.TB, txnID types.TransactionID, expected ...types.ChainIndex) {
	t.Helper()

	indices, err := c.DB.TransactionChainIndices(txnID, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	} else if len(indices) != len(expected) {
		t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
	}

	for i := range indices {
		testutil.Equal(t, "index", expected[i], indices[i])
	}
}

// AssertV2ChainIndices fails the test unless V2TransactionChainIndices returns
// exactly the expected indices for txnID.
func (c *Chain) AssertV2ChainIndices(t testing.TB, txnID types.TransactionID, expected ...types.ChainIndex) {
	t.Helper()

	indices, err := c.DB.V2TransactionChainIndices(txnID, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	} else if len(indices) != len(expected) {
		t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
	}

	for i := range indices {
		testutil.Equal(t, "index", expected[i], indices[i])
	}
}

// AssertSCE asserts the siacoin element in the db has the right source, index,
// and output.
func (c *Chain) AssertSCE(t testing.TB, scID types.SiacoinOutputID, index *types.ChainIndex, sco types.SiacoinOutput) {
	t.Helper()

	sces, err := c.DB.SiacoinElements([]types.SiacoinOutputID{scID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(sces)", 1, len(sces))

	sce := sces[0]
	testutil.Equal(t, "sce.Source", explorer.SourceTransaction, sce.Source)
	testutil.Equal(t, "sce.SpentIndex", index, sce.SpentIndex)
	testutil.Equal(t, "sce.SiacoinElement.SiacoinOutput", sco, sce.SiacoinOutput)
}

// AssertSFE asserts the siafund element in the db has the right index and
// output.
func (c *Chain) AssertSFE(t testing.TB, sfID types.SiafundOutputID, index *types.ChainIndex, sfo types.SiafundOutput) {
	t.Helper()

	sfes, err := c.DB.SiafundElements([]types.SiafundOutputID{sfID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(sfes)", 1, len(sfes))

	sfe := sfes[0]
	testutil.Equal(t, "sfe.SpentIndex", index, sfe.SpentIndex)
	testutil.Equal(t, "sfe.SiafundElement.SiafundOutput", sfo, sfe.SiafundOutput)
}

// AssertFCE asserts the contract element in the db has the right state and
// block/transaction indices.
func (c *Chain) AssertFCE(t testing.TB, fcID types.FileContractID, expected explorer.ExtendedFileContract) {
	t.Helper()

	fces, err := c.DB.Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(fces)", 1, len(fces))

	testutil.Equal(t, "ExtendedFileContract", expected, fces[0])
}

// AssertTransactionContracts asserts that the enhanced FileContracts
// (revisions = false) or FileContractRevisions (revisions = true) in a
// transaction retrieved from the explorer match the expected contracts.
func (c *Chain) AssertTransactionContracts(t testing.TB, txnID types.TransactionID, revisions bool, expected ...explorer.ExtendedFileContract) {
	t.Helper()

	txns, err := c.DB.Transactions([]types.TransactionID{txnID})
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

// CheckV2Contract compares two V2FileContracts field by field.
func CheckV2Contract(t testing.TB, expected explorer.V2FileContract, got explorer.V2FileContract) {
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

// AssertV2FCE asserts the v2 contract element in the db matches expected.
func (c *Chain) AssertV2FCE(t testing.TB, fcID types.FileContractID, expected explorer.V2FileContract) {
	t.Helper()

	fces, err := c.DB.V2Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(fces)", 1, len(fces))

	CheckV2Contract(t, expected, fces[0])
}

// AssertNoV2FCE asserts no v2 contracts exist for the given ids.
func (c *Chain) AssertNoV2FCE(t testing.TB, fcIDs ...types.FileContractID) {
	t.Helper()

	fces, err := c.DB.V2Contracts(fcIDs)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(fces)", 0, len(fces))
}

// AssertV2TransactionContracts asserts that the enhanced FileContracts in a v2
// transaction match the expected contracts.
func (c *Chain) AssertV2TransactionContracts(t testing.TB, txnID types.TransactionID, revisions bool, expected ...explorer.V2FileContract) {
	t.Helper()

	txns, err := c.DB.V2Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(txns)", 1, len(txns))

	txn := txns[0]
	if !revisions {
		testutil.Equal(t, "len(txn.FileContracts)", len(expected), len(txn.FileContracts))
		for i := range expected {
			CheckV2Contract(t, expected[i], txn.FileContracts[i])
		}
	} else {
		testutil.Equal(t, "len(txn.FileContractRevisions)", len(expected), len(txn.FileContractRevisions))
		for i := range expected {
			CheckV2Contract(t, expected[i], txn.FileContractRevisions[i].Revision)
		}
	}
}

// AssertV2TransactionResolutions asserts that the enhanced
// FileContractResolutions in a v2 transaction match the expected resolutions.
func (c *Chain) AssertV2TransactionResolutions(t testing.TB, txnID types.TransactionID, expected ...explorer.V2FileContractResolution) {
	t.Helper()

	txns, err := c.DB.V2Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(txns)", 1, len(txns))

	txn := txns[0]
	testutil.Equal(t, "len(txn.FileContractResolutions)", len(expected), len(txn.FileContractResolutions))
	for i := range expected {
		fcr := txn.FileContractResolutions[i]

		CheckV2Contract(t, expected[i].Parent, fcr.Parent)
		testutil.Equal(t, "Type", expected[i].Type, fcr.Type)
		if expectedRenewal, ok := expected[i].Resolution.(*explorer.V2FileContractRenewal); ok {
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

// AssertV2ContractRevisions fails the test unless V2ContractRevisions returns
// exactly the expected revisions for fcID.
func (c *Chain) AssertV2ContractRevisions(t testing.TB, fcID types.FileContractID, expected ...explorer.V2FileContract) {
	t.Helper()

	fces, err := c.DB.V2ContractRevisions(fcID)
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
		CheckV2Contract(t, expected[i], fces[i])
	}
}
