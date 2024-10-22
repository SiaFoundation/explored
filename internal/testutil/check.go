package testutil

import (
	"reflect"
	"testing"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

// Equal checks if two values of the same type are equal and fails otherwise.
func Equal[T any](t *testing.T, desc string, expect, got T) {
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
	Equal(t, "siacoins", expectSC, sc)
	Equal(t, "immature siacoins", expectImmatureSC, immatureSC)
	Equal(t, "siafunds", expectSF, sf)
}

// CheckTransaction checks the inputs and outputs of the retrieved transaction
// with the source transaction.
func CheckTransaction(t *testing.T, expectTxn types.Transaction, gotTxn explorer.Transaction) {
	t.Helper()

	Equal(t, "siacoin inputs", len(expectTxn.SiacoinInputs), len(gotTxn.SiacoinInputs))
	for i := range expectTxn.SiacoinInputs {
		expected := expectTxn.SiacoinInputs[i]
		got := gotTxn.SiacoinInputs[i]

		if got.Value == types.ZeroCurrency {
			t.Fatal("invalid value")
		}
		Equal(t, "parent ID", expected.ParentID, got.ParentID)
		Equal(t, "unlock conditions", expected.UnlockConditions, got.UnlockConditions)
		Equal(t, "address", expected.UnlockConditions.UnlockHash(), got.Address)
	}

	Equal(t, "siacoin outputs", len(expectTxn.SiacoinOutputs), len(gotTxn.SiacoinOutputs))
	for i := range expectTxn.SiacoinOutputs {
		expected := expectTxn.SiacoinOutputs[i]
		got := gotTxn.SiacoinOutputs[i].SiacoinOutput

		Equal(t, "address", expected.Address, got.Address)
		Equal(t, "value", expected.Value, got.Value)
		Equal(t, "source", explorer.SourceTransaction, gotTxn.SiacoinOutputs[i].Source)
	}

	Equal(t, "siafund inputs", len(expectTxn.SiafundInputs), len(gotTxn.SiafundInputs))
	for i := range expectTxn.SiafundInputs {
		expected := expectTxn.SiafundInputs[i]
		got := gotTxn.SiafundInputs[i]

		if got.Value == 0 {
			t.Fatal("invalid value")
		}
		Equal(t, "parent ID", expected.ParentID, got.ParentID)
		Equal(t, "claim address", expected.ClaimAddress, got.ClaimAddress)
		Equal(t, "unlock conditions", expected.UnlockConditions, got.UnlockConditions)
		Equal(t, "address", expected.UnlockConditions.UnlockHash(), got.Address)
	}

	Equal(t, "siafund outputs", len(expectTxn.SiafundOutputs), len(gotTxn.SiafundOutputs))
	for i := range expectTxn.SiafundOutputs {
		expected := expectTxn.SiafundOutputs[i]
		got := gotTxn.SiafundOutputs[i].SiafundOutput

		Equal(t, "address", expected.Address, got.Address)
		Equal(t, "value", expected.Value, got.Value)
	}

	Equal(t, "arbitrary data", len(expectTxn.ArbitraryData), len(gotTxn.ArbitraryData))
	for i := range expectTxn.ArbitraryData {
		Equal(t, "arbitrary data", expectTxn.ArbitraryData[i], gotTxn.ArbitraryData[i])
	}

	Equal(t, "miner fees", len(expectTxn.MinerFees), len(gotTxn.MinerFees))
	for i := range expectTxn.MinerFees {
		Equal(t, "miner fee", expectTxn.MinerFees[i], gotTxn.MinerFees[i])
	}

	Equal(t, "signatures", len(expectTxn.Signatures), len(gotTxn.Signatures))
	for i := range expectTxn.Signatures {
		expected := expectTxn.Signatures[i]
		got := gotTxn.Signatures[i]

		Equal(t, "parent ID", expected.ParentID, got.ParentID)
		Equal(t, "public key index", expected.PublicKeyIndex, got.PublicKeyIndex)
		Equal(t, "timelock", expected.Timelock, got.Timelock)
		Equal(t, "signature", expected.Signature, got.Signature)

		// reflect.DeepCheck treats empty slices as different from nil
		// slices so these will differ because the decoder is doing
		// cf.X = make([]uint64, d.ReadPrefix()) and the prefix is 0
		// testutil.Equal(t, "covered fields", expected.CoveredFields, got.CoveredFields)
	}
}

// CheckV2Transaction checks the inputs and outputs of the retrieved transaction
// with the source transaction.
func CheckV2Transaction(t *testing.T, expectTxn types.V2Transaction, gotTxn explorer.V2Transaction) {
	t.Helper()

	Equal(t, "new foundation address", expectTxn.NewFoundationAddress, gotTxn.NewFoundationAddress)
	Equal(t, "miner fee", expectTxn.MinerFee, gotTxn.MinerFee)

	Equal(t, "siacoin outputs", len(expectTxn.SiacoinOutputs), len(gotTxn.SiacoinOutputs))
	for i := range expectTxn.SiacoinOutputs {
		expected := expectTxn.SiacoinOutputs[i]
		got := gotTxn.SiacoinOutputs[i].SiacoinOutput

		Equal(t, "address", expected.Address, got.Address)
		Equal(t, "value", expected.Value, got.Value)
	}

	Equal(t, "siafund outputs", len(expectTxn.SiafundOutputs), len(gotTxn.SiafundOutputs))
	for i := range expectTxn.SiafundOutputs {
		expected := expectTxn.SiafundOutputs[i]
		got := gotTxn.SiafundOutputs[i].SiafundOutput

		Equal(t, "address", expected.Address, got.Address)
		Equal(t, "value", expected.Value, got.Value)
	}

	Equal(t, "attestations", len(expectTxn.Attestations), len(gotTxn.Attestations))
	for i := range expectTxn.Attestations {
		expected := expectTxn.Attestations[i]
		got := gotTxn.Attestations[i]

		Equal(t, "public key", expected.PublicKey, got.PublicKey)
		Equal(t, "key", expected.Key, got.Key)
		Equal(t, "value", expected.Value, got.Value)
		Equal(t, "signature", expected.Signature, got.Signature)
	}

	var hostAnnouncements []chain.HostAnnouncement
	for _, attestation := range expectTxn.Attestations {
		var ha chain.HostAnnouncement
		if ha.FromAttestation(attestation) {
			hostAnnouncements = append(hostAnnouncements, ha)
		}
	}
	Equal(t, "host announcements", len(hostAnnouncements), len(gotTxn.HostAnnouncements))
	for i := range hostAnnouncements {
		expected := hostAnnouncements[i]
		got := gotTxn.HostAnnouncements[i]

		Equal(t, "net address", expected.NetAddress, got.NetAddress)
		Equal(t, "public key", expected.PublicKey, got.PublicKey)
	}

	Equal(t, "arbitrary data", len(expectTxn.ArbitraryData), len(gotTxn.ArbitraryData))
	for i := range expectTxn.ArbitraryData {
		Equal(t, "arbitrary data value", expectTxn.ArbitraryData[i], gotTxn.ArbitraryData[i])
	}
}

// CheckV2ChainIndices checks that the chain indices that a v2 transaction was
// in from the explorer match the expected chain indices.
func CheckV2ChainIndices(t *testing.T, db explorer.Store, txnID types.TransactionID, expected []types.ChainIndex) {
	t.Helper()

	indices, err := db.V2TransactionChainIndices(txnID, 0, 100)
	switch {
	case err != nil:
		t.Fatal(err)
	case len(indices) != len(expected):
		t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
	}
	for i := range indices {
		Equal(t, "index", expected[i], indices[i])
	}
}

// CheckFC checks the retrieved file contract with the source file contract in
// addition to checking the resolved and valid fields.
func CheckFC(t *testing.T, revision, resolved, valid bool, expected types.FileContract, got explorer.FileContract) {
	t.Helper()

	Equal(t, "resolved state", resolved, got.Resolved)
	Equal(t, "valid state", valid, got.Valid)

	gotFC := got.FileContract
	Equal(t, "filesize", expected.Filesize, gotFC.Filesize)
	Equal(t, "file merkle root", expected.FileMerkleRoot, gotFC.FileMerkleRoot)
	Equal(t, "window start", expected.WindowStart, gotFC.WindowStart)
	Equal(t, "window end", expected.WindowEnd, gotFC.WindowEnd)
	if !revision {
		Equal(t, "payout", expected.Payout, gotFC.Payout)
	}
	Equal(t, "unlock hash", expected.UnlockHash, gotFC.UnlockHash)
	Equal(t, "revision number", expected.RevisionNumber, gotFC.RevisionNumber)
	Equal(t, "valid proof outputs", len(expected.ValidProofOutputs), len(gotFC.ValidProofOutputs))
	for i := range expected.ValidProofOutputs {
		Equal(t, "valid proof output address", expected.ValidProofOutputs[i].Address, gotFC.ValidProofOutputs[i].Address)
		Equal(t, "valid proof output value", expected.ValidProofOutputs[i].Value, gotFC.ValidProofOutputs[i].Value)
	}
	Equal(t, "missed proof outputs", len(expected.MissedProofOutputs), len(gotFC.MissedProofOutputs))
	for i := range expected.MissedProofOutputs {
		Equal(t, "missed proof output address", expected.MissedProofOutputs[i].Address, gotFC.MissedProofOutputs[i].Address)
		Equal(t, "missed proof output value", expected.MissedProofOutputs[i].Value, gotFC.MissedProofOutputs[i].Value)
	}
}
