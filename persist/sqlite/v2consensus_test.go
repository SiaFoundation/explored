package sqlite_test

import (
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
)

func getSCE(t *testing.T, db explorer.Store, scid types.SiacoinOutputID) types.SiacoinElement {
	t.Helper()

	sces, err := db.SiacoinElements([]types.SiacoinOutputID{scid})
	if err != nil {
		t.Fatal(err)
	} else if len(sces) == 0 {
		t.Fatal("can't find sce")
	}
	return sces[0].SiacoinElement
}

func getSFE(t *testing.T, db explorer.Store, sfid types.SiafundOutputID) types.SiafundElement {
	t.Helper()

	sfes, err := db.SiafundElements([]types.SiafundOutputID{sfid})
	if err != nil {
		t.Fatal(err)
	} else if len(sfes) == 0 {
		t.Fatal("can't find sfe")
	}
	return sfes[0].SiafundElement
}

func getFCE(t *testing.T, db explorer.Store, fcid types.FileContractID) types.V2FileContractElement {
	t.Helper()

	fces, err := db.V2Contracts([]types.FileContractID{fcid})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fces")
	}
	return fces[0].V2FileContractElement
}

func getCIE(t *testing.T, db explorer.Store, bid types.BlockID) types.ChainIndexElement {
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

func checkV2Transaction(t *testing.T, db explorer.Store, expected types.V2Transaction) {
	txns, err := db.V2Transactions([]types.TransactionID{expected.ID()})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(txns)", 1, len(txns))
	testutil.CheckV2Transaction(t, expected, txns[0])
}

func TestV2FileContractRenewedToFrom(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	_, genesisBlock, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	// Add a file contract that we will renew
	v1FC := testutil.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 105, types.VoidAddress)
	v2FC := types.V2FileContract{
		Capacity:         v1FC.Filesize,
		Filesize:         v1FC.Filesize,
		FileMerkleRoot:   v1FC.FileMerkleRoot,
		ProofHeight:      cm.Tip().Height + 3,
		ExpirationHeight: cm.Tip().Height + 4,
		RenterOutput:     v1FC.ValidProofOutputs[0],
		HostOutput:       v1FC.ValidProofOutputs[1],
		MissedHostValue:  v1FC.MissedProofOutputs[1].Value,
		TotalCollateral:  v1FC.ValidProofOutputs[0].Value,
		RenterPublicKey:  renterPublicKey,
		HostPublicKey:    hostPublicKey,
	}
	fcOut := v2FC.RenterOutput.Value.Add(v2FC.HostOutput.Value).Add(cm.TipState().V2FileContractTax(v2FC))

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   giftSC.Sub(fcOut),
			Address: addr1,
		}},
		FileContracts: []types.V2FileContract{v2FC},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn1)

	b1 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b1}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	tip1 := cm.Tip()

	v2FC0ID := txn1.V2FileContractID(txn1.ID(), 0)
	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
	}

	// Check that it is not resolved and does not have RenewedTo set before
	// renewing
	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fcs)", 1, len(fcs))

		fc := fcs[0]
		testutil.Equal(t, "confirmation index", tip1, fc.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn1.ID(), fc.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", nil, fc.ResolutionType)
		testutil.Equal(t, "resolution index", nil, fc.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", nil, fc.ResolutionTransactionID)
		testutil.Equal(t, "renewed from", nil, fc.RenewedFrom)
		testutil.Equal(t, "renewed to", nil, fc.RenewedTo)
	}

	// Renew contract
	v2FCFinalRevision := v2FC
	v2FCFinalRevision.Filesize--
	v2FCFinalRevision.RevisionNumber = types.MaxRevisionNumber
	v2FCNewContract := v2FC
	v2FCNewContract.RevisionNumber = 10
	renewal := &types.V2FileContractRenewal{
		NewContract:       v2FCNewContract,
		FinalRenterOutput: v2FCFinalRevision.RenterOutput,
		FinalHostOutput:   v2FCFinalRevision.HostOutput,
		RenterRollover:    types.ZeroCurrency,
		HostRollover:      types.ZeroCurrency,
	}
	sce1 := getSCE(t, db, txn1.SiacoinOutputID(txn1.ID(), 0))
	txn2 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          sce1,
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   sce1.SiacoinOutput.Value.Sub(fcOut),
		}},
		FileContractResolutions: []types.V2FileContractResolution{
			{
				Parent:     getFCE(t, db, v2FC0ID),
				Resolution: renewal,
			},
		},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn2)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	tip2 := cm.Tip()
	// We will revert back here when we undo the resolutions
	// This is the point after the first renewal, but before the second renewal
	prevState := cm.TipState()

	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID, v2FC0ID.V2RenewalID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fcs)", 2, len(fcs))

		fc := fcs[0]
		testutil.Equal(t, "confirmation index", tip1, fc.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn1.ID(), fc.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", explorer.V2ResolutionRenewal, *fc.ResolutionType)
		testutil.Equal(t, "resolution index", cm.Tip(), *fc.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", txn2.ID(), *fc.ResolutionTransactionID)
		testutil.Equal(t, "renewed from", nil, fc.RenewedFrom)
		testutil.Equal(t, "renewed to", v2FC0ID.V2RenewalID(), *fc.RenewedTo)

		fcr := fcs[1]
		testutil.Equal(t, "confirmation index", cm.Tip(), fcr.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn2.ID(), fcr.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", nil, fcr.ResolutionType)
		testutil.Equal(t, "resolution index", nil, fcr.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", nil, fcr.ResolutionTransactionID)
		testutil.Equal(t, "renewed from", v2FC0ID, *fcr.RenewedFrom)
		testutil.Equal(t, "renewed to", nil, fcr.RenewedTo)
	}

	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID.V2RenewalID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fcs)", 1, len(fcs))
	}

	// Renew again
	sce2 := getSCE(t, db, txn2.SiacoinOutputID(txn2.ID(), 0))
	txn3 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          sce2,
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   sce2.SiacoinOutput.Value.Sub(fcOut),
		}},
		FileContractResolutions: []types.V2FileContractResolution{
			{
				Parent:     getFCE(t, db, v2FC0ID.V2RenewalID()),
				Resolution: renewal,
			},
		},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn3)

	b3 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn3}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b3}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID.V2RenewalID(), v2FC0ID.V2RenewalID().V2RenewalID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(fcs)", 2, len(fcs))

		fcr := fcs[0]
		testutil.Equal(t, "confirmation index", tip2, fcr.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn2.ID(), fcr.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", explorer.V2ResolutionRenewal, *fcr.ResolutionType)
		testutil.Equal(t, "resolution index", cm.Tip(), *fcr.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", txn3.ID(), *fcr.ResolutionTransactionID)
		testutil.Equal(t, "renewed from", v2FC0ID, *fcr.RenewedFrom)
		testutil.Equal(t, "renewed to", v2FC0ID.V2RenewalID().V2RenewalID(), *fcr.RenewedTo)

		fcrr := fcs[1]
		testutil.Equal(t, "confirmation index", cm.Tip(), fcrr.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn3.ID(), fcrr.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", nil, fcrr.ResolutionType)
		testutil.Equal(t, "resolution index", nil, fcrr.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", nil, fcrr.ResolutionTransactionID)
		testutil.Equal(t, "renewed from", v2FC0ID.V2RenewalID(), *fcrr.RenewedFrom)
		testutil.Equal(t, "renewed to", nil, fcrr.RenewedTo)
	}

	// Revert the second renewal
	{
		state := prevState
		extra := cm.Tip().Height - state.Index.Height + 1

		var blocks []types.Block
		for i := uint64(0); i < extra; i++ {
			var bs consensus.V1BlockSupplement
			block := testutil.MineBlock(state, nil, types.VoidAddress)
			blocks = append(blocks, block)

			if err := consensus.ValidateBlock(state, block, bs); err != nil {
				t.Fatal(err)
			}
			state, _ = consensus.ApplyBlock(state, block, bs, time.Time{})
		}

		if err := cm.AddBlocks(blocks); err != nil {
			t.Fatal(err)
		}
		syncDB(t, db, cm)
	}

	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID, v2FC0ID.V2RenewalID(), v2FC0ID.V2RenewalID().V2RenewalID()})
		if err != nil {
			t.Fatal(err)
		}
		// Second renewal should not exist so we should only expect 2 results
		testutil.Equal(t, "len(fcs)", 2, len(fcs))

		fc := fcs[0]
		testutil.Equal(t, "confirmation index", tip1, fc.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn1.ID(), fc.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", explorer.V2ResolutionRenewal, *fc.ResolutionType)
		testutil.Equal(t, "resolution index", tip2, *fc.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", txn2.ID(), *fc.ResolutionTransactionID)
		testutil.Equal(t, "renewed from", nil, fc.RenewedFrom)
		testutil.Equal(t, "renewed to", v2FC0ID.V2RenewalID(), *fc.RenewedTo)

		fcr := fcs[1]
		testutil.Equal(t, "confirmation index", tip2, fcr.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn2.ID(), fcr.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", nil, fcr.ResolutionType)
		testutil.Equal(t, "resolution index", nil, fcr.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", nil, fcr.ResolutionTransactionID)
		testutil.Equal(t, "renewed from", v2FC0ID, *fcr.RenewedFrom)
		testutil.Equal(t, "renewed to", nil, fcr.RenewedTo)
	}
}
