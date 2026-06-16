//go:build testing

package storetest

import (
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testchain"
	"go.sia.tech/explored/internal/testutil"
)

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
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := testchain.PrepareV2Contract(renterPK, hostPK, n.TipState().Index.Height+1)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, n.Genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn1)

	n.MineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	sp := &types.V2StorageProof{
		ProofIndex: getCIE(t, n.DB, n.TipState().Index.ID),
	}
	txn2 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.DB, fce.ID),
			Resolution: sp,
		}},
	}
	n.MineV2Transactions(t, txn2)

	tip := n.TipState().Index
	txnID := txn2.ID()
	resolutionType := explorer.V2ResolutionStorageProof

	// should be resolved
	fceResolved := fce
	fceResolved.ResolutionType = &resolutionType
	fceResolved.ResolutionIndex = &tip
	fceResolved.ResolutionTransactionID = &txnID

	n.AssertV2FCE(t, fce.ID, fceResolved)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fceResolved)
	n.AssertV2TransactionResolutions(t, txn2.ID(), explorer.V2FileContractResolution{
		Parent:     fceResolved,
		Type:       resolutionType,
		Resolution: sp,
	})

	n.RevertBlock(t)

	// should have old FCE back
	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.RevertBlock(t)

	// FCE should not exist after creation reverted
	n.AssertNoV2FCE(t, fce.ID)
	n.AssertV2ContractRevisions(t, fce.ID)
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
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := testchain.PrepareV2Contract(renterPK, hostPK, n.TipState().Index.Height+1)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, n.Genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn1)

	n.MineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.MineV2Transactions(t)

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	txn2 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.DB, fce.ID),
			Resolution: &types.V2FileContractExpiration{},
		}},
	}
	n.MineV2Transactions(t, txn2)

	tip := n.TipState().Index
	txnID := txn2.ID()
	resolutionType := explorer.V2ResolutionExpiration

	// should be resolved
	fceResolved := fce
	fceResolved.ResolutionType = &resolutionType
	fceResolved.ResolutionIndex = &tip
	fceResolved.ResolutionTransactionID = &txnID

	n.AssertV2FCE(t, fce.ID, fceResolved)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fceResolved)
	n.AssertV2TransactionResolutions(t, txn2.ID(), explorer.V2FileContractResolution{
		Parent:     fceResolved,
		Type:       resolutionType,
		Resolution: &types.V2FileContractExpiration{},
	})

	n.RevertBlock(t)

	// revert resolution
	// should have old FCE back
	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.RevertBlock(t)

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.RevertBlock(t)

	// FCE should not exist after creation reverted
	n.AssertNoV2FCE(t, fce.ID)
	n.AssertV2ContractRevisions(t, fce.ID)
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
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := testchain.PrepareV2Contract(renterPK, hostPK, n.TipState().Index.Height+2)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, n.Genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn1)

	n.MineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

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
			Parent:          getSCE(t, n.DB, txn1.SiacoinOutputID(txn1.ID(), 0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   txn1.SiacoinOutputs[0].Value.Sub(payout),
		}},
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.DB, fce.ID),
			Resolution: renewal,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn2)

	n.MineV2Transactions(t, txn2)

	renewalTip1 := n.TipState().Index
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
	fceRenewal1.ConfirmationIndex = n.TipState().Index
	fceRenewal1.ConfirmationTransactionID = renewalTxnID1
	fceRenewal1.RenewedFrom = &fce.ID

	n.AssertV2FCE(t, fce.ID, fceResolved)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fceResolved)
	n.AssertV2FCE(t, renewalID1, fceRenewal1)

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
	n.AssertV2TransactionResolutions(t, txn2.ID(), resolution1)

	// renew again
	txn3 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, txn1.SiacoinOutputID(txn2.ID(), 0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   txn2.SiacoinOutputs[0].Value.Sub(payout),
		}},
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.DB, fceRenewal1.ID),
			Resolution: renewal,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn3)

	n.MineV2Transactions(t, txn3)

	renewalTip2 := n.TipState().Index
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

	n.AssertV2FCE(t, fce.ID, fceResolved)
	n.AssertV2FCE(t, renewalID1, fceRenewal1)
	n.AssertV2FCE(t, renewalID2, fceRenewal2)
	n.AssertV2TransactionResolutions(t, txn2.ID(), resolution1)
	n.AssertV2TransactionResolutions(t, txn3.ID(), resolution2)

	n.RevertBlock(t)

	// revert second renewal
	fceRenewal1.ResolutionType = nil
	fceRenewal1.ResolutionIndex = nil
	fceRenewal1.ResolutionTransactionID = nil
	fceRenewal1.RenewedTo = nil
	renewal1.NewContract = fceRenewal1

	n.AssertV2FCE(t, fce.ID, fceResolved)
	n.AssertV2FCE(t, renewalID1, fceRenewal1)
	n.AssertNoV2FCE(t, renewalID2)
	n.AssertV2TransactionResolutions(t, txn2.ID(), resolution1)

	n.RevertBlock(t)

	// reverted first renewal
	// should have old FCE back
	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	// Renewal FCE should not exist after resolution reverted
	n.AssertNoV2FCE(t, renewalID1, renewalID2)

	n.RevertBlock(t)

	// FCE should not exist
	n.AssertNoV2FCE(t, fce.ID, renewalID1, renewalID2)
	n.AssertV2ContractRevisions(t, fce.ID)
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
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := testchain.PrepareV2Contract(renterPK, hostPK, n.TipState().Index.Height+2)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, n.Genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn1)

	n.MineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2ContractRevisions(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	fcRevision1 := fc
	fcRevision1.RevisionNumber++
	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.DB, fce.ID),
			Revision: fcRevision1,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn2)

	n.MineV2Transactions(t, txn2)

	fceRevision1 := coreToV2ExplorerFC(fce.ID, txn2.FileContractRevisions[0].Revision)
	fceRevision1.TransactionID = txn2.ID()
	fceRevision1.ConfirmationIndex = fce.ConfirmationIndex
	fceRevision1.ConfirmationTransactionID = fce.ConfirmationTransactionID

	n.AssertV2FCE(t, fce.ID, fceRevision1)
	n.AssertV2ContractRevisions(t, fce.ID, fce, fceRevision1)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.AssertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)

	n.MineV2Transactions(t)

	// resolve contract unsuccessful
	txn4 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.DB, fce.ID),
			Resolution: &types.V2FileContractExpiration{},
		}},
	}
	n.MineV2Transactions(t, txn4)

	tip := n.TipState().Index
	txnID := txn4.ID()
	resolutionType := explorer.V2ResolutionExpiration

	// should be resolved
	fce.ResolutionType = &resolutionType
	fce.ResolutionIndex = &tip
	fce.ResolutionTransactionID = &txnID
	fceRevision1.ResolutionType = &resolutionType
	fceRevision1.ResolutionIndex = &tip
	fceRevision1.ResolutionTransactionID = &txnID

	n.AssertV2FCE(t, fce.ID, fceRevision1)
	n.AssertV2ContractRevisions(t, fce.ID, fce, fceRevision1)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.AssertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.AssertV2TransactionResolutions(t, txn4.ID(), explorer.V2FileContractResolution{
		Parent:     fceRevision1,
		Type:       resolutionType,
		Resolution: &types.V2FileContractExpiration{},
	})

	// revert resolution of contract
	for i := n.TipState().Index.Height; i >= fc.ExpirationHeight; i-- {
		n.RevertBlock(t)
	}

	fce.ResolutionType = nil
	fce.ResolutionIndex = nil
	fce.ResolutionTransactionID = nil
	fceRevision1.ResolutionType = nil
	fceRevision1.ResolutionIndex = nil
	fceRevision1.ResolutionTransactionID = nil

	n.AssertV2FCE(t, fce.ID, fceRevision1)
	n.AssertV2ContractRevisions(t, fce.ID, fce, fceRevision1)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.AssertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)

	// revert revision of contract
	n.RevertBlock(t)

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2ContractRevisions(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.RevertBlock(t)

	n.AssertNoV2FCE(t, fce.ID)
	n.AssertContractRevisions(t, fce.ID)
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
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc, payout := testchain.PrepareV2Contract(renterPK, hostPK, n.TipState().Index.Height+2)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, n.Genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn1)

	n.MineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2ContractRevisions(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	fcRevision1 := fc
	fcRevision1.RevisionNumber++

	fcRevision2 := fcRevision1
	fcRevision2.RevisionNumber++

	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.DB, fce.ID),
			Revision: fcRevision1,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn2)

	txn3 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.DB, fce.ID),
			Revision: fcRevision2,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn3)

	n.MineV2Transactions(t, txn2, txn3)

	fceRevision1 := coreToV2ExplorerFC(fce.ID, txn2.FileContractRevisions[0].Revision)
	fceRevision1.TransactionID = txn2.ID()
	fceRevision1.ConfirmationIndex = fce.ConfirmationIndex
	fceRevision1.ConfirmationTransactionID = fce.ConfirmationTransactionID

	fceRevision2 := coreToV2ExplorerFC(fce.ID, txn3.FileContractRevisions[0].Revision)
	fceRevision2.TransactionID = txn3.ID()
	fceRevision2.ConfirmationIndex = fce.ConfirmationIndex
	fceRevision2.ConfirmationTransactionID = fce.ConfirmationTransactionID

	n.AssertV2FCE(t, fce.ID, fceRevision2)
	n.AssertV2ContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.AssertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.AssertV2TransactionContracts(t, txn3.ID(), true, fceRevision2)

	n.MineV2Transactions(t)

	// resolve contract unsuccessful
	txn4 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.DB, fce.ID),
			Resolution: &types.V2FileContractExpiration{},
		}},
	}
	n.MineV2Transactions(t, txn4)

	tip := n.TipState().Index
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

	n.AssertV2FCE(t, fce.ID, fceRevision2)
	n.AssertV2ContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.AssertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.AssertV2TransactionContracts(t, txn3.ID(), true, fceRevision2)
	n.AssertV2TransactionResolutions(t, txn4.ID(), explorer.V2FileContractResolution{
		Parent:     fceRevision2,
		Type:       resolutionType,
		Resolution: &types.V2FileContractExpiration{},
	})

	// revert resolution of contract
	for i := n.TipState().Index.Height; i >= fc.ExpirationHeight; i-- {
		n.RevertBlock(t)
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

	n.AssertV2FCE(t, fce.ID, fceRevision2)
	n.AssertV2ContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)
	n.AssertV2TransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.AssertV2TransactionContracts(t, txn3.ID(), true, fceRevision2)

	// revert revisions block
	n.RevertBlock(t)

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2ContractRevisions(t, fce.ID, fce)
	n.AssertV2TransactionContracts(t, txn1.ID(), false, fce)

	n.RevertBlock(t)

	n.AssertNoV2FCE(t, fce.ID)
	n.AssertV2ContractRevisions(t, fce.ID)
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
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	assertContractsKey := func(pk types.PublicKey, expected ...explorer.V2FileContract) {
		t.Helper()

		fces, err := n.DB.V2ContractsKey(pk, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", len(expected), len(fces))

		for i := range expected {
			testchain.CheckV2Contract(t, expected[i], fces[i])
		}
	}

	fc, payout := testchain.PrepareV2Contract(renterPK, hostPK, n.TipState().Index.Height+2)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, n.Genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn1)

	n.MineV2Transactions(t, txn1)

	fce := coreToV2ExplorerFC(txn1.V2FileContractID(txn1.ID(), 0), txn1.FileContracts[0])
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2ContractRevisions(t, fce.ID, fce)
	assertContractsKey(pk1.PublicKey())
	assertContractsKey(renterPK.PublicKey(), fce)
	assertContractsKey(hostPK.PublicKey(), fce)

	// change renter public key to pk1
	fcRevision1 := fc
	fcRevision1.RevisionNumber++
	fcRevision1.RenterPublicKey = pk1.PublicKey()

	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, n.DB, fce.ID),
			Revision: fcRevision1,
		}},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, renterPK, hostPK, &txn2)

	n.MineV2Transactions(t, txn2)

	fceRevision1 := coreToV2ExplorerFC(fce.ID, txn2.FileContractRevisions[0].Revision)
	fceRevision1.TransactionID = txn2.ID()
	fceRevision1.ConfirmationIndex = fce.ConfirmationIndex
	fceRevision1.ConfirmationTransactionID = fce.ConfirmationTransactionID

	// renter public key changed from renterPK to pk1 so we should not have
	// any contracts with renterPK
	n.AssertV2FCE(t, fce.ID, fceRevision1)
	n.AssertV2ContractRevisions(t, fce.ID, fce, fceRevision1)
	assertContractsKey(pk1.PublicKey(), fceRevision1)
	assertContractsKey(renterPK.PublicKey())
	assertContractsKey(hostPK.PublicKey(), fceRevision1)

	n.RevertBlock(t)

	// revert revision so renterPK should have contract now and pk1 should not
	n.AssertV2FCE(t, fce.ID, fce)
	n.AssertV2ContractRevisions(t, fce.ID, fce)
	assertContractsKey(pk1.PublicKey())
	assertContractsKey(renterPK.PublicKey(), fce)
	assertContractsKey(hostPK.PublicKey(), fce)

	n.RevertBlock(t)

	// revert formation of contract
	n.AssertNoV2FCE(t, fce.ID)
	n.AssertContractRevisions(t, fce.ID)
	assertContractsKey(pk1.PublicKey())
	assertContractsKey(renterPK.PublicKey())
	assertContractsKey(hostPK.PublicKey())
}
