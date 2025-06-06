package testutil

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

// Equal checks if two values of the same type are equal and fails otherwise.
func Equal[T any](t testing.TB, desc string, expected, got T) {
	t.Helper()

	options := cmp.Options([]cmp.Option{
		cmpopts.EquateEmpty(),
		cmp.AllowUnexported(consensus.Work{}),
		cmp.Comparer(func(x, y types.StateElement) bool {
			return x.LeafIndex == y.LeafIndex && reflect.DeepEqual(x.MerkleProof, y.MerkleProof)
		}),
	})
	if !cmp.Equal(expected, got, options) {
		t.Fatalf("%s expected != got, diff: %s", desc, cmp.Diff(expected, got, options))
	}
}

// CheckTransaction checks the inputs and outputs of the retrieved transaction
// with the source transaction.
func CheckTransaction(t testing.TB, expectTxn types.Transaction, gotTxn explorer.Transaction) {
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

	Equal(t, "storage proofs", len(expectTxn.StorageProofs), len(gotTxn.StorageProofs))
	for i := range expectTxn.StorageProofs {
		expected := expectTxn.StorageProofs[i]
		got := gotTxn.StorageProofs[i]

		Equal(t, "parent ID", expected.ParentID, got.ParentID)
		Equal(t, "leaf", expected.Leaf, got.Leaf)
		Equal(t, "parent ID", expected.Proof, got.Proof)
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

	var hostAnnouncements []chain.HostAnnouncement
	for _, arb := range expectTxn.ArbitraryData {
		var ha chain.HostAnnouncement
		if ha.FromArbitraryData(arb) {
			hostAnnouncements = append(hostAnnouncements, ha)
		}
	}
	Equal(t, "host announcements", len(hostAnnouncements), len(gotTxn.HostAnnouncements))
	for i := range hostAnnouncements {
		expected := hostAnnouncements[i]
		got := gotTxn.HostAnnouncements[i]

		Equal(t, "public key", expected.PublicKey, got.PublicKey)
		Equal(t, "net address", expected.NetAddress, got.NetAddress)
	}
}

// CheckV2Transaction checks the inputs and outputs of the retrieved transaction
// with the source transaction.
func CheckV2Transaction(t testing.TB, expectTxn types.V2Transaction, gotTxn explorer.V2Transaction) {
	t.Helper()

	// checkV2FC checks the retrieved file contract with the source file contract
	// in addition to checking the resolved and valid fields.
	checkV2FC := func(expected types.V2FileContract, got explorer.V2FileContract) {
		t.Helper()

		gotFC := got.V2FileContractElement.V2FileContract
		Equal(t, "capacity", expected.Capacity, gotFC.Capacity)
		Equal(t, "filesize", expected.Filesize, gotFC.Filesize)
		Equal(t, "proof height", expected.ProofHeight, gotFC.ProofHeight)
		Equal(t, "expiration height", expected.ExpirationHeight, gotFC.ExpirationHeight)
		Equal(t, "renter output address", expected.RenterOutput.Address, gotFC.RenterOutput.Address)
		Equal(t, "renter output value", expected.RenterOutput.Address, gotFC.RenterOutput.Address)
		Equal(t, "host output address", expected.HostOutput.Address, gotFC.HostOutput.Address)
		Equal(t, "host output value", expected.HostOutput.Address, gotFC.HostOutput.Address)
		Equal(t, "missed host value", expected.MissedHostValue, gotFC.MissedHostValue)
		Equal(t, "total collateral", expected.TotalCollateral, gotFC.TotalCollateral)
		Equal(t, "renter public key", expected.RenterPublicKey, gotFC.RenterPublicKey)
		Equal(t, "host public key", expected.HostPublicKey, gotFC.HostPublicKey)
		Equal(t, "revision number", expected.RevisionNumber, gotFC.RevisionNumber)
		Equal(t, "renter signature", expected.RenterSignature, gotFC.RenterSignature)
		Equal(t, "host signature", expected.HostSignature, gotFC.HostSignature)
	}

	txnID := expectTxn.ID()
	Equal(t, "id", txnID, gotTxn.ID)
	Equal(t, "new foundation address", expectTxn.NewFoundationAddress, gotTxn.NewFoundationAddress)
	Equal(t, "miner fee", expectTxn.MinerFee, gotTxn.MinerFee)

	Equal(t, "siacoin inputs", len(expectTxn.SiacoinInputs), len(gotTxn.SiacoinInputs))
	for i := range expectTxn.SiacoinInputs {
		expected := expectTxn.SiacoinInputs[i]
		got := gotTxn.SiacoinInputs[i]

		Equal(t, "address", expected.Parent.SiacoinOutput.Address, got.Parent.SiacoinOutput.Address)
		Equal(t, "value", expected.Parent.SiacoinOutput.Value, got.Parent.SiacoinOutput.Value)
		Equal(t, "maturity height", expected.Parent.MaturityHeight, got.Parent.MaturityHeight)
		Equal(t, "id", expected.Parent.ID, got.Parent.ID)
		if expected.Parent.StateElement.LeafIndex != types.UnassignedLeafIndex {
			Equal(t, "leaf index", expected.Parent.StateElement.LeafIndex, got.Parent.StateElement.LeafIndex)
		}
		if len(got.SatisfiedPolicy.Preimages) == 0 {
			got.SatisfiedPolicy.Preimages = nil
		}
		Equal(t, "satisfied policy", expected.SatisfiedPolicy, got.SatisfiedPolicy)
	}

	Equal(t, "siacoin outputs", len(expectTxn.SiacoinOutputs), len(gotTxn.SiacoinOutputs))
	for i := range expectTxn.SiacoinOutputs {
		expected := expectTxn.SiacoinOutputs[i]
		got := gotTxn.SiacoinOutputs[i]

		Equal(t, "address", expected.Address, got.SiacoinOutput.Address)
		Equal(t, "value", expected.Value, got.SiacoinOutput.Value)
		Equal(t, "source", explorer.SourceTransaction, got.Source)
		Equal(t, "ID", expectTxn.SiacoinOutputID(txnID, i), got.ID)
	}

	Equal(t, "siafund inputs", len(expectTxn.SiafundInputs), len(gotTxn.SiafundInputs))
	for i := range expectTxn.SiafundInputs {
		expected := expectTxn.SiafundInputs[i]
		got := gotTxn.SiafundInputs[i]

		Equal(t, "address", expected.Parent.SiafundOutput.Address, got.Parent.SiafundOutput.Address)
		Equal(t, "value", expected.Parent.SiafundOutput.Value, got.Parent.SiafundOutput.Value)
		Equal(t, "claim address", expected.ClaimAddress, got.ClaimAddress)
		Equal(t, "id", expected.Parent.ID, got.Parent.ID)
		if expected.Parent.StateElement.LeafIndex != types.UnassignedLeafIndex {
			Equal(t, "leaf index", expected.Parent.StateElement.LeafIndex, got.Parent.StateElement.LeafIndex)
		}
		if len(got.SatisfiedPolicy.Preimages) == 0 {
			got.SatisfiedPolicy.Preimages = nil
		}
		Equal(t, "satisfied policy", expected.SatisfiedPolicy, got.SatisfiedPolicy)
	}

	Equal(t, "siafund outputs", len(expectTxn.SiafundOutputs), len(gotTxn.SiafundOutputs))
	for i := range expectTxn.SiafundOutputs {
		expected := expectTxn.SiafundOutputs[i]
		got := gotTxn.SiafundOutputs[i]

		Equal(t, "address", expected.Address, got.SiafundOutput.Address)
		Equal(t, "value", expected.Value, got.SiafundOutput.Value)
		Equal(t, "id", expectTxn.SiafundOutputID(txnID, i), got.ID)
	}

	Equal(t, "file contracts", len(expectTxn.FileContracts), len(gotTxn.FileContracts))
	for i := range expectTxn.FileContracts {
		expected := expectTxn.FileContracts[i]
		got := gotTxn.FileContracts[i]

		checkV2FC(expected, got)
		Equal(t, "id", expectTxn.V2FileContractID(txnID, i), got.ID)
	}

	Equal(t, "file contract revision", len(expectTxn.FileContractRevisions), len(gotTxn.FileContractRevisions))
	for i := range expectTxn.FileContractRevisions {
		expected := expectTxn.FileContractRevisions[i]
		got := gotTxn.FileContractRevisions[i]

		Equal(t, "parent ID", expected.Parent.ID, got.Parent.ID)
		Equal(t, "revision ID", expected.Parent.ID, got.Revision.ID)
		checkV2FC(expected.Parent.V2FileContract, got.Parent)
		checkV2FC(expected.Revision, got.Revision)
	}

	Equal(t, "file contract resolutions", len(expectTxn.FileContractResolutions), len(gotTxn.FileContractResolutions))
	for i := range expectTxn.FileContractResolutions {
		expected := expectTxn.FileContractResolutions[i]
		got := gotTxn.FileContractResolutions[i]

		checkV2FC(expected.Parent.V2FileContract, got.Parent)

		switch v := expected.Resolution.(type) {
		case *types.V2FileContractRenewal:
			if gotV, ok := got.Resolution.(*explorer.V2FileContractRenewal); !ok {
				t.Fatalf("expected V2FileContractRenewal, got %v", reflect.TypeOf(got.Resolution))
			} else {
				checkV2FC(v.NewContract, gotV.NewContract)

				Equal(t, "type", explorer.V2ResolutionRenewal, got.Type)
				Equal(t, "final renter output address", v.FinalRenterOutput.Address, gotV.FinalRenterOutput.Address)
				Equal(t, "final renter output value", v.FinalRenterOutput.Value, gotV.FinalRenterOutput.Value)
				Equal(t, "final host output address", v.FinalHostOutput.Address, gotV.FinalHostOutput.Address)
				Equal(t, "final host output value", v.FinalHostOutput.Value, gotV.FinalHostOutput.Value)
				Equal(t, "renter rollover", v.RenterRollover, gotV.RenterRollover)
				Equal(t, "host rollover", v.HostRollover, gotV.HostRollover)
				Equal(t, "renter signature", v.RenterSignature, gotV.RenterSignature)
				Equal(t, "host signature", v.HostSignature, gotV.HostSignature)
			}
		case *types.V2StorageProof:
			if gotV, ok := got.Resolution.(*types.V2StorageProof); !ok {
				t.Fatalf("expected V2StorageProof, got %v", reflect.TypeOf(got.Resolution))
			} else {
				Equal(t, "type", explorer.V2ResolutionStorageProof, got.Type)
				Equal(t, "proof index", v.ProofIndex, gotV.ProofIndex)
				Equal(t, "leaf", v.Leaf, gotV.Leaf)
				Equal(t, "proof", v.Proof, gotV.Proof)
			}
		case *types.V2FileContractExpiration:
			Equal(t, "type", explorer.V2ResolutionExpiration, got.Type)
			if _, ok := got.Resolution.(*types.V2FileContractExpiration); !ok {
				t.Fatalf("expected V2FileContractExpiration, got %v", reflect.TypeOf(got.Resolution))
			}
		default:
			t.Fatalf("invalid resolution type: %v", reflect.TypeOf(got.Resolution))
		}
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

	var hostAnnouncements []explorer.V2HostAnnouncement
	for _, attestation := range expectTxn.Attestations {
		var ha chain.V2HostAnnouncement
		if ha.FromAttestation(attestation) == nil {
			hostAnnouncements = append(hostAnnouncements, explorer.V2HostAnnouncement{
				V2HostAnnouncement: ha,
				PublicKey:          attestation.PublicKey,
			})
		}
	}
	Equal(t, "host announcements", len(hostAnnouncements), len(gotTxn.HostAnnouncements))
	for i := range hostAnnouncements {
		expected := []chain.NetAddress(hostAnnouncements[i].V2HostAnnouncement)
		got := []chain.NetAddress(gotTxn.HostAnnouncements[i].V2HostAnnouncement)

		Equal(t, "public key", hostAnnouncements[i].PublicKey, gotTxn.HostAnnouncements[i].PublicKey)
		Equal(t, "net addresses", len(expected), len(got))
		for j := range expected {
			Equal(t, "protocol", expected[j].Protocol, got[j].Protocol)
			Equal(t, "address", expected[j].Address, got[j].Address)
		}
	}

	Equal(t, "arbitrary data", len(expectTxn.ArbitraryData), len(gotTxn.ArbitraryData))
	for i := range expectTxn.ArbitraryData {
		Equal(t, "arbitrary data value", expectTxn.ArbitraryData[i], gotTxn.ArbitraryData[i])
	}
}
