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

func TestTransactionStorageProof(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+1)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.Genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	n.MineTransactions(t, txn1)

	n.AssertTransactions(t, txn1)

	sp := types.StorageProof{
		ParentID: txn1.FileContractID(0),
	}
	txn2 := types.Transaction{
		StorageProofs: []types.StorageProof{sp},
	}
	n.MineTransactions(t, txn2)

	n.AssertTransactions(t, txn1, txn2)
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
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+1)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.Genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	n.MineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertFCE(t, fce.ID, fce)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)

	sp := types.StorageProof{
		ParentID: txn1.FileContractID(0),
	}
	txn2 := types.Transaction{
		StorageProofs: []types.StorageProof{sp},
	}
	n.MineTransactions(t, txn2)

	tip := n.TipState().Index
	txnID := txn2.ID()

	// should be resolved
	fceResolved := fce
	fceResolved.Resolved = true
	fceResolved.Valid = true
	fceResolved.ProofIndex = &tip
	fceResolved.ProofTransactionID = &txnID

	n.AssertFCE(t, fce.ID, fceResolved)
	n.AssertTransactionContracts(t, txn1.ID(), false, fceResolved)

	n.RevertBlock(t)

	// should have old FCE back
	n.AssertFCE(t, fce.ID, fce)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)

	n.RevertBlock(t)

	// FCE should not exist
	{
		fces, err := n.DB.Contracts([]types.FileContractID{fce.ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", 0, len(fces))
	}

	n.AssertContractRevisions(t, fce.ID)
}

func TestFileContractMissed(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+1)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.Genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	n.MineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()
	n.AssertFCE(t, fce.ID, fce)

	for i := n.TipState().Index.Height; i < fc.WindowEnd; i++ {
		n.MineTransactions(t)
	}

	fceResolved := fce
	fceResolved.Resolved = true
	fceResolved.Valid = false

	n.AssertFCE(t, fce.ID, fceResolved)
	n.AssertTransactionContracts(t, txn1.ID(), false, fceResolved)

	n.RevertBlock(t)

	// should have old FCE back
	n.AssertFCE(t, fce.ID, fce)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)

	n.RevertBlock(t)

	// FCE should not exist
	{
		fces, err := n.DB.Contracts([]types.FileContractID{fce.ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", 0, len(fces))
	}

	n.AssertContractRevisions(t, fce.ID)
}

func TestFileContractFormationRevisionNumber(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+1)
	fc.RevisionNumber = 5
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.Genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	n.MineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertFCE(t, fce.ID, fce)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)
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
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+3)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.Genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	n.MineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertFCE(t, fce.ID, fce)
	n.AssertContractRevisions(t, fce.ID, fce)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)

	fcRevision1 := fc
	fcRevision1.RevisionNumber++
	txn2 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fce.ID,
			UnlockConditions: uc1,
			FileContract:     fcRevision1,
		}},
	}
	signRevisions(n.TipState(), &txn2, pk1)

	n.MineTransactions(t, txn2)

	fceRevision1 := fce
	fceRevision1.RevisionNumber = fcRevision1.RevisionNumber
	fceRevision1.TransactionID = txn2.ID()

	n.AssertFCE(t, fce.ID, fceRevision1)
	n.AssertContractRevisions(t, fce.ID, fce, fceRevision1)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)
	n.AssertTransactionContracts(t, txn2.ID(), true, fceRevision1)

	// resolve contract unsuccessful
	for i := n.TipState().Index.Height; i < fc.WindowEnd; i++ {
		n.MineTransactions(t)
	}

	fce.Resolved = true
	fceRevision1.Resolved = true
	n.AssertFCE(t, fce.ID, fceRevision1)
	n.AssertContractRevisions(t, fce.ID, fce, fceRevision1)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)
	n.AssertTransactionContracts(t, txn2.ID(), true, fceRevision1)

	// revert resolution of contract
	for i := n.TipState().Index.Height; i >= fc.WindowEnd; i-- {
		n.RevertBlock(t)
	}
	n.RevertBlock(t)

	fce.Resolved = false
	fceRevision1.Resolved = false
	n.AssertFCE(t, fce.ID, fceRevision1)
	n.AssertContractRevisions(t, fce.ID, fce, fceRevision1)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)
	n.AssertTransactionContracts(t, txn2.ID(), true, fceRevision1)

	// revert revision of contract
	n.RevertBlock(t)

	n.AssertFCE(t, fce.ID, fce)
	n.AssertContractRevisions(t, fce.ID, fce)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)

	n.RevertBlock(t)

	{
		fces, err := n.DB.Contracts([]types.FileContractID{fce.ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", 0, len(fces))
	}

	n.AssertContractRevisions(t, fce.ID)
}

func TestFileContractMultipleRevisions(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+3)
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.Genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	n.MineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	n.AssertFCE(t, fce.ID, fce)
	n.AssertContractRevisions(t, fce.ID, fce)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)

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
	signRevisions(n.TipState(), &txn2, pk1)

	txn3 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         fce.ID,
			UnlockConditions: uc1,
			FileContract:     fcRevision2,
		}},
	}
	signRevisions(n.TipState(), &txn3, pk1)

	n.MineTransactions(t, txn2, txn3)

	fceRevision1 := fce
	fceRevision1.RevisionNumber = fcRevision1.RevisionNumber
	fceRevision1.TransactionID = txn2.ID()

	fceRevision2 := fce
	fceRevision2.RevisionNumber = fcRevision2.RevisionNumber
	fceRevision2.TransactionID = txn3.ID()

	n.AssertFCE(t, fce.ID, fceRevision2)
	n.AssertContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)
	n.AssertTransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.AssertTransactionContracts(t, txn3.ID(), true, fceRevision2)

	// resolve contract unsuccessful
	for i := n.TipState().Index.Height; i < fc.WindowEnd; i++ {
		n.MineTransactions(t)
	}

	fce.Resolved = true
	fceRevision1.Resolved = true
	fceRevision2.Resolved = true
	n.AssertFCE(t, fce.ID, fceRevision2)
	n.AssertContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)
	n.AssertTransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.AssertTransactionContracts(t, txn3.ID(), true, fceRevision2)

	// revert resolution of contract
	for i := n.TipState().Index.Height; i >= fc.WindowEnd; i-- {
		n.RevertBlock(t)
	}
	n.RevertBlock(t)

	fce.Resolved = false
	fceRevision1.Resolved = false
	fceRevision2.Resolved = false
	n.AssertFCE(t, fce.ID, fceRevision2)
	n.AssertContractRevisions(t, fce.ID, fce, fceRevision1, fceRevision2)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)
	n.AssertTransactionContracts(t, txn2.ID(), true, fceRevision1)
	n.AssertTransactionContracts(t, txn3.ID(), true, fceRevision2)

	// revert revisions block
	n.RevertBlock(t)

	n.AssertFCE(t, fce.ID, fce)
	n.AssertContractRevisions(t, fce.ID, fce)
	n.AssertTransactionContracts(t, txn1.ID(), false, fce)

	n.RevertBlock(t)

	{
		fces, err := n.DB.Contracts([]types.FileContractID{fce.ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fces)", 0, len(fces))
	}

	n.AssertContractRevisions(t, fce.ID)
}

func TestFileContractsKey(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	assertContractsKey := func(pk types.PublicKey, expected ...explorer.ExtendedFileContract) {
		t.Helper()

		fces, err := n.DB.ContractsKey(pk, 0, 100)
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

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+3)
	fc.UnlockHash = ucContract1.UnlockHash()

	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         n.Genesis().Transactions[0].SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   val.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	n.MineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	// we don't have the UnlockConditions and thus the public keys of the
	// renter and host until we have a revision, so we should not have
	// anything at this point
	n.AssertFCE(t, fce.ID, fce)
	n.AssertContractRevisions(t, fce.ID, fce)
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
	signRevisions(n.TipState(), &txn2, pk1, pk2)

	// after a revision is mined, then we should know the keys associated with
	// the contract
	n.MineTransactions(t, txn2)

	fceRevision1 := fce
	fceRevision1.RevisionNumber = fcRevision1.RevisionNumber
	fceRevision1.TransactionID = txn2.ID()

	// either key should be associated with the contract
	n.AssertFCE(t, fce.ID, fceRevision1)
	n.AssertContractRevisions(t, fce.ID, fce, fceRevision1)
	assertContractsKey(pk1.PublicKey(), fceRevision1)
	assertContractsKey(pk2.PublicKey(), fceRevision1)

	n.RevertBlock(t)

	// if we revert we should keep the keys.  only reason to change them is if
	// we change the UnlockHash and can get the keys from the UnlockConditions
	// in a future revision
	n.AssertFCE(t, fce.ID, fce)
	n.AssertContractRevisions(t, fce.ID, fce)
	assertContractsKey(pk1.PublicKey(), fce)
	assertContractsKey(pk2.PublicKey(), fce)

	n.RevertBlock(t)

	n.AssertContractRevisions(t, fce.ID)
	assertContractsKey(pk1.PublicKey())
	assertContractsKey(pk2.PublicKey())
}
