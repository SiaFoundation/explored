package sqlite

import (
	"errors"
	"testing"

	"go.sia.tech/core/consensus"
	proto4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
)

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
