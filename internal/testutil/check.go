package testutil

import (
	"reflect"
	"testing"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

// Check checks if two values of the same type are equal and fails otherwise.
func Check[T any](t *testing.T, desc string, expect, got T) {
	t.Helper()

	if !reflect.DeepEqual(expect, got) {
		t.Fatalf("expected %v %s, got %v", expect, desc, got)
	}
}

// CheckBalance checks that an address has the balances we expect.
func CheckBalance(t *testing.T, db explorer.Store, addr types.Address, expectSC, expectImmatureSC types.Currency, expectSF uint64) {
	t.Helper()

	sc, immatureSC, sf, err := db.Balance(addr)
	if err != nil {
		t.Fatal(err)
	}
	Check(t, "siacoins", expectSC, sc)
	Check(t, "immature siacoins", expectImmatureSC, immatureSC)
	Check(t, "siafunds", expectSF, sf)
}

// CheckTransaction checks the inputs and outputs of the retrieved transaction
// with the source transaction.
func CheckTransaction(t *testing.T, expectTxn types.Transaction, gotTxn explorer.Transaction) {
	t.Helper()

	Check(t, "siacoin inputs", len(expectTxn.SiacoinInputs), len(gotTxn.SiacoinInputs))
	Check(t, "siacoin outputs", len(expectTxn.SiacoinOutputs), len(gotTxn.SiacoinOutputs))
	Check(t, "siafund inputs", len(expectTxn.SiafundInputs), len(gotTxn.SiafundInputs))
	Check(t, "siafund outputs", len(expectTxn.SiafundOutputs), len(gotTxn.SiafundOutputs))

	for i := range expectTxn.SiacoinInputs {
		expectSci := expectTxn.SiacoinInputs[i]
		gotSci := gotTxn.SiacoinInputs[i]

		if gotSci.Value == types.ZeroCurrency {
			t.Fatal("invalid value")
		}
		Check(t, "parent ID", expectSci.ParentID, gotSci.ParentID)
		Check(t, "unlock conditions", expectSci.UnlockConditions, gotSci.UnlockConditions)
		Check(t, "address", expectSci.UnlockConditions.UnlockHash(), gotSci.Address)
	}
	for i := range expectTxn.SiacoinOutputs {
		expectSco := expectTxn.SiacoinOutputs[i]
		gotSco := gotTxn.SiacoinOutputs[i].SiacoinOutput

		Check(t, "address", expectSco.Address, gotSco.Address)
		Check(t, "value", expectSco.Value, gotSco.Value)
		Check(t, "source", explorer.SourceTransaction, gotTxn.SiacoinOutputs[i].Source)
	}
	for i := range expectTxn.SiafundInputs {
		expectSfi := expectTxn.SiafundInputs[i]
		gotSfi := gotTxn.SiafundInputs[i]

		if gotSfi.Value == 0 {
			t.Fatal("invalid value")
		}
		Check(t, "parent ID", expectSfi.ParentID, gotSfi.ParentID)
		Check(t, "claim address", expectSfi.ClaimAddress, gotSfi.ClaimAddress)
		Check(t, "unlock conditions", expectSfi.UnlockConditions, gotSfi.UnlockConditions)
		Check(t, "address", expectSfi.UnlockConditions.UnlockHash(), gotSfi.Address)
	}
	for i := range expectTxn.SiafundOutputs {
		expectSfo := expectTxn.SiafundOutputs[i]
		gotSfo := gotTxn.SiafundOutputs[i].SiafundOutput

		Check(t, "address", expectSfo.Address, gotSfo.Address)
		Check(t, "value", expectSfo.Value, gotSfo.Value)
	}
	for i := range expectTxn.ArbitraryData {
		Check(t, "miner fee", expectTxn.ArbitraryData[i], gotTxn.ArbitraryData[i])
	}
	for i := range expectTxn.MinerFees {
		Check(t, "miner fee", expectTxn.MinerFees[i], gotTxn.MinerFees[i])
	}
	for i := range expectTxn.Signatures {
		expectSig := expectTxn.Signatures[i]
		gotSig := gotTxn.Signatures[i]

		Check(t, "parent ID", expectSig.ParentID, gotSig.ParentID)
		Check(t, "public key index", expectSig.PublicKeyIndex, gotSig.PublicKeyIndex)
		Check(t, "timelock", expectSig.Timelock, gotSig.Timelock)
		Check(t, "signature", expectSig.Signature, gotSig.Signature)

		// reflect.DeepEqual treats empty slices as different from nil
		// slices so these will differ because the decoder is doing
		// cf.X = make([]uint64, d.ReadPrefix()) and the prefix is 0
		// testutil.Check(t, "covered fields", expectSig.CoveredFields, gotSig.CoveredFields)
	}
}

// CheckFC checks the retrieved file contract with the source file contract in
// addition to checking the resolved and valid fields.
func CheckFC(t *testing.T, revision, resolved, valid bool, expected types.FileContract, got explorer.FileContract) {
	t.Helper()

	Check(t, "resolved state", resolved, got.Resolved)
	Check(t, "valid state", valid, got.Valid)

	gotFC := got.FileContract
	Check(t, "filesize", expected.Filesize, gotFC.Filesize)
	Check(t, "file merkle root", expected.FileMerkleRoot, gotFC.FileMerkleRoot)
	Check(t, "window start", expected.WindowStart, gotFC.WindowStart)
	Check(t, "window end", expected.WindowEnd, gotFC.WindowEnd)
	if !revision {
		Check(t, "payout", expected.Payout, gotFC.Payout)
	}
	Check(t, "unlock hash", expected.UnlockHash, gotFC.UnlockHash)
	Check(t, "revision number", expected.RevisionNumber, gotFC.RevisionNumber)
	Check(t, "valid proof outputs", len(expected.ValidProofOutputs), len(gotFC.ValidProofOutputs))
	for i := range expected.ValidProofOutputs {
		Check(t, "valid proof output address", expected.ValidProofOutputs[i].Address, gotFC.ValidProofOutputs[i].Address)
		Check(t, "valid proof output value", expected.ValidProofOutputs[i].Value, gotFC.ValidProofOutputs[i].Value)
	}
	Check(t, "missed proof outputs", len(expected.MissedProofOutputs), len(gotFC.MissedProofOutputs))
	for i := range expected.MissedProofOutputs {
		Check(t, "missed proof output address", expected.MissedProofOutputs[i].Address, gotFC.MissedProofOutputs[i].Address)
		Check(t, "missed proof output value", expected.MissedProofOutputs[i].Value, gotFC.MissedProofOutputs[i].Value)
	}
}

// CheckMetrics checks the that the metrics from the DB match what we expect.
func CheckMetrics(t *testing.T, db explorer.Store, cm *chain.Manager, expected explorer.Metrics) {
	t.Helper()

	tip, err := db.Tip()
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.Metrics(tip.ID)
	if err != nil {
		t.Fatal(err)
	}

	Check(t, "index", cm.Tip(), got.Index)
	Check(t, "difficulty", cm.TipState().Difficulty, got.Difficulty)
	Check(t, "total hosts", expected.TotalHosts, got.TotalHosts)
	Check(t, "active contracts", expected.ActiveContracts, got.ActiveContracts)
	Check(t, "failed contracts", expected.FailedContracts, got.FailedContracts)
	Check(t, "successful contracts", expected.SuccessfulContracts, got.SuccessfulContracts)
	Check(t, "contract revenue", expected.ContractRevenue, got.ContractRevenue)
	Check(t, "storage utilization", expected.StorageUtilization, got.StorageUtilization)
	// don't check circulating supply here because it requires a lot of accounting
}

// CheckChainIndices checks that the chain indices that a transaction was in
// from the explorer match the expected chain indices.
func CheckChainIndices(t *testing.T, db explorer.Store, txnID types.TransactionID, expected []types.ChainIndex) {
	t.Helper()

	indices, err := db.TransactionChainIndices(txnID, 0, 100)
	switch {
	case err != nil:
		t.Fatal(err)
	case len(indices) != len(expected):
		t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
	}
	for i := range indices {
		Check(t, "index", expected[i], indices[i])
	}
}

// CheckFCRevisions checks that the revision numbers for the file contracts match.
func CheckFCRevisions(t *testing.T, revisionNumbers []uint64, fcs []types.FileContractElement) {
	t.Helper()

	Check(t, "number of revisions", len(revisionNumbers), len(fcs))
	for i := range revisionNumbers {
		Check(t, "revision number", revisionNumbers[i], fcs[i].FileContract.RevisionNumber)
	}
}
