package sqlite_test

import (
	"bytes"
	"math"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	rhp2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
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
	sce := sces[0]

	sce.SiacoinElement.StateElement.MerkleProof, err = db.MerkleProof(sce.StateElement.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}

	return sce.SiacoinElement
}

func getSFE(t *testing.T, db explorer.Store, sfid types.SiafundOutputID) types.SiafundElement {
	t.Helper()

	sfes, err := db.SiafundElements([]types.SiafundOutputID{sfid})
	if err != nil {
		t.Fatal(err)
	} else if len(sfes) == 0 {
		t.Fatal("can't find sfe")
	}
	sfe := sfes[0]

	sfe.SiafundElement.StateElement.MerkleProof, err = db.MerkleProof(sfe.StateElement.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}

	return sfe.SiafundElement
}

func getFCE(t *testing.T, db explorer.Store, fcid types.FileContractID) types.V2FileContractElement {
	t.Helper()

	fces, err := db.V2Contracts([]types.FileContractID{fcid})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fces")
	}
	fce := fces[0]

	fce.V2FileContractElement.StateElement.MerkleProof, err = db.MerkleProof(fce.V2FileContractElement.StateElement.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}

	return fce.V2FileContractElement
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

func TestV2ArbitraryData(t *testing.T) {
	_, _, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
	})

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
	}

	txn2 := types.V2Transaction{
		ArbitraryData: []byte("world"),
	}

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1, txn2}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)
	prev := cm.Tip()

	{
		b, err := db.Block(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "v2 height", b.V2.Height, 1)
		testutil.CheckV2Transaction(t, txn1, b.V2.Transactions[0])
		testutil.CheckV2Transaction(t, txn2, b.V2.Transactions[1])
	}

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
		testutil.CheckV2Transaction(t, txn2, dbTxns[1])
	}

	txn3 := types.V2Transaction{
		ArbitraryData: []byte("12345"),
	}

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1, txn2, txn3}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		b, err := db.Block(cm.Tip().ID)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "v2 height", b.V2.Height, 2)
		testutil.CheckV2Transaction(t, txn1, b.V2.Transactions[0])
		testutil.CheckV2Transaction(t, txn2, b.V2.Transactions[1])
		testutil.CheckV2Transaction(t, txn3, b.V2.Transactions[2])
	}

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID(), txn3.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
		testutil.CheckV2Transaction(t, txn2, dbTxns[1])
		testutil.CheckV2Transaction(t, txn3, dbTxns[2])
	}

	testutil.CheckV2ChainIndices(t, db, txn1.ID(), []types.ChainIndex{cm.Tip(), prev})
	testutil.CheckV2ChainIndices(t, db, txn2.ID(), []types.ChainIndex{cm.Tip(), prev})
	testutil.CheckV2ChainIndices(t, db, txn3.ID(), []types.ChainIndex{cm.Tip()})
}

func TestV2MinerFee(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	_, genesisBlock, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
		MinerFee:      giftSC,
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
	}
	testutil.SignV2Transaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}
}

func TestV2FoundationAddress(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	_, genesisBlock, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
		network.HardforkFoundation.FailsafeAddress = addr1
		network.HardforkFoundation.PrimaryAddress = addr1
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		MinerFee:             giftSC,
		NewFoundationAddress: &addr2,
	}
	testutil.SignV2Transaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}

	{
		events, err := db.AddressEvents(addr1, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 3, len(events))

		testutil.Equal(t, "event 0 type", "foundation", events[0].Type)
		testutil.Equal(t, "event 1 type", "v2Transaction", events[1].Type)
		testutil.Equal(t, "event 2 type", "v1Transaction", events[2].Type)
	}
}

func TestV2Attestations(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	pk2 := types.GeneratePrivateKey()

	_, genesisBlock, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value
	cs := cm.TipState()

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
	otherAttestation.Signature = pk1.SignHash(cs.AttestationSigHash(otherAttestation))

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		MinerFee:     giftSC,
		Attestations: []types.Attestation{ha1.ToAttestation(cs, pk1), otherAttestation, ha2.ToAttestation(cs, pk2)},
	}
	testutil.SignV2Transaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cs, []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		events, err := db.AddressEvents(addr1, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 2, len(events))

		testutil.CheckV2Transaction(t, txn1, explorer.V2Transaction(events[0].Data.(explorer.EventV2Transaction)))
		testutil.CheckTransaction(t, genesisBlock.Transactions[0], events[1].Data.(explorer.EventV1Transaction).Transaction)
	}

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}
}

func TestV2SiacoinOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	_, genesisBlock, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
		SiacoinOutputs: []types.SiacoinOutput{
			{
				Value:   giftSC.Div64(2),
				Address: addr1,
			},
			{
				Value:   giftSC.Div64(2),
				Address: addr2,
			},
		},
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
	}
	testutil.SignV2Transaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}

	testutil.CheckBalance(t, db, addr1, giftSC.Div64(2), types.ZeroCurrency, 0)
	testutil.CheckBalance(t, db, addr2, giftSC.Div64(2), types.ZeroCurrency, 0)
}

func TestV2SiafundOutput(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	_, genesisBlock, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
	})
	giftSF := genesisBlock.Transactions[0].SiafundOutputs[0].Value

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
		SiafundOutputs: []types.SiafundOutput{
			{
				Value:   giftSF / 2,
				Address: addr1,
			},
			{
				Value:   giftSF / 2,
				Address: addr2,
			},
		},
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          getSFE(t, db, genesisBlock.Transactions[0].SiafundOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
	}
	testutil.SignV2Transaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}

	testutil.CheckBalance(t, db, addr1, types.ZeroCurrency, types.ZeroCurrency, giftSF/2)
	testutil.CheckBalance(t, db, addr2, types.ZeroCurrency, types.ZeroCurrency, giftSF/2)
}

func TestV2FileContract(t *testing.T) {
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

	v1FC := testutil.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 105, types.VoidAddress)
	v1FC.Filesize = 65
	v2FC := types.V2FileContract{
		Capacity:         v1FC.Filesize,
		Filesize:         v1FC.Filesize,
		FileMerkleRoot:   v1FC.FileMerkleRoot,
		ProofHeight:      20,
		ExpirationHeight: 30,
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

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}

	txn2 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, txn1.SiacoinOutputID(txn1.ID(), 0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			// 1 for txn1, 2 for this transaction
			Value:   giftSC.Sub(fcOut.Mul64(3)),
			Address: addr1,
		}},

		FileContracts: []types.V2FileContract{v2FC, v2FC},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn2)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn2, dbTxns[0])
	}

	for i := cm.Tip().Height; i < v2FC.ExpirationHeight; i++ {
		if err := cm.AddBlocks([]types.Block{testutil.MineBlock(cm.TipState(), nil, types.VoidAddress)}); err != nil {
			t.Fatal(err)
		}
	}

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
		testutil.CheckV2Transaction(t, txn2, dbTxns[1])
	}
}

func TestV2FileContractRevert(t *testing.T) {
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
	prevState := cm.TipState()

	v1FC := testutil.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 105, types.VoidAddress)
	v1FC.Filesize = 65
	v2FC := types.V2FileContract{
		Capacity:         v1FC.Filesize,
		Filesize:         v1FC.Filesize,
		FileMerkleRoot:   v1FC.FileMerkleRoot,
		ProofHeight:      20,
		ExpirationHeight: 30,
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
			Value:   giftSC.Sub(fcOut).Sub(fcOut),
			Address: addr1,
		}},

		FileContracts: []types.V2FileContract{v2FC, v2FC},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn1)

	b1 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b1}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}

	{
		fcs, err := db.V2Contracts([]types.FileContractID{txn1.V2FileContractID(txn1.ID(), 0), txn1.V2FileContractID(txn1.ID(), 1)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
		testutil.CheckV2FC(t, txn1.FileContracts[1], fcs[1])
	}

	{
		fcs, err := db.V2ContractRevisions(txn1.V2FileContractID(txn1.ID(), 0))
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
	}

	// revert the block
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
		_, err := db.Block(b1.ID())
		if err == nil {
			t.Fatal("block should not exist")
		}
	}

	{
		fcs, err := db.V2Contracts([]types.FileContractID{txn1.V2FileContractID(txn1.ID(), 0)})
		if err != nil {
			t.Fatal(err)
		}
		if len(fcs) > 0 {
			t.Fatal("contract should not exist")
		}
	}

	// See if we can spend the genesis input that was spent in reverted block
	// We should be able to
	txn2 := txn1
	txn2.FileContracts = txn2.FileContracts[:1]
	txn2.SiacoinOutputs[0].Value = txn2.SiacoinOutputs[0].Value.Add(fcOut)
	txn2.SiacoinInputs[0].Parent = getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0))
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn2)
	b2 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b2}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		_, err := db.Block(b1.ID())
		if err == nil {
			t.Fatal("block should not exist")
		}
	}

	{
		b, err := db.Block(b2.ID())
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn2, b.V2.Transactions[0])
	}

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn2, dbTxns[0])
	}

	{
		fcs, err := db.V2Contracts([]types.FileContractID{txn2.V2FileContractID(txn2.ID(), 0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn2.FileContracts[0], fcs[0])
	}

	{
		fcs, err := db.V2ContractRevisions(txn2.V2FileContractID(txn2.ID(), 0))
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn2.FileContracts[0], fcs[0])
	}
}

func TestV2FileContractKey(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	renterPrivateKey1 := types.GeneratePrivateKey()
	renterPublicKey1 := renterPrivateKey1.PublicKey()

	renterPrivateKey2 := types.GeneratePrivateKey()
	renterPublicKey2 := renterPrivateKey2.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	_, genesisBlock, cm, db := newStore(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	v1FC := testutil.PrepareContractFormation(renterPublicKey1, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 105, types.VoidAddress)
	v1FC.Filesize = 65
	v2FC1 := types.V2FileContract{
		Capacity:         v1FC.Filesize,
		Filesize:         v1FC.Filesize,
		FileMerkleRoot:   v1FC.FileMerkleRoot,
		ProofHeight:      20,
		ExpirationHeight: 30,
		RenterOutput:     v1FC.ValidProofOutputs[0],
		HostOutput:       v1FC.ValidProofOutputs[1],
		MissedHostValue:  v1FC.MissedProofOutputs[1].Value,
		TotalCollateral:  v1FC.ValidProofOutputs[0].Value,
		RenterPublicKey:  renterPublicKey1,
		HostPublicKey:    hostPublicKey,
	}
	fcOut := v2FC1.RenterOutput.Value.Add(v2FC1.HostOutput.Value).Add(cm.TipState().V2FileContractTax(v2FC1))

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   giftSC.Sub(fcOut),
			Address: addr1,
		}},
		FileContracts: []types.V2FileContract{v2FC1},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey1, hostPrivateKey, &txn1)

	b1 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b1}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}

	{
		fcs, err := db.V2Contracts([]types.FileContractID{txn1.V2FileContractID(txn1.ID(), 0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
	}

	{
		fcs, err := db.V2ContractRevisions(txn1.V2FileContractID(txn1.ID(), 0))
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
	}

	v2FC2 := v2FC1
	v2FC2.RenterPublicKey = renterPublicKey2

	txn2 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, txn1.SiacoinOutputID(txn1.ID(), 0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   txn1.SiacoinOutputs[0].Value.Sub(fcOut),
			Address: addr1,
		}},
		FileContracts: []types.V2FileContract{v2FC2},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey2, hostPrivateKey, &txn2)

	b2 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b2}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn2, dbTxns[0])
	}

	{
		fcs, err := db.V2Contracts([]types.FileContractID{txn2.V2FileContractID(txn2.ID(), 0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn2.FileContracts[0], fcs[0])
	}

	{
		fcs, err := db.V2ContractRevisions(txn2.V2FileContractID(txn2.ID(), 0))
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn2.FileContracts[0], fcs[0])
	}

	{
		fcs, err := db.V2ContractsKey(renterPublicKey1)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
	}

	{
		fcs, err := db.V2ContractsKey(renterPublicKey2)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn2.FileContracts[0], fcs[0])
	}

	{
		fcs, err := db.V2ContractsKey(hostPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
		testutil.CheckV2FC(t, txn2.FileContracts[0], fcs[1])
	}
}

func TestV2FileContractRevision(t *testing.T) {
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

	v1FC := testutil.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 105, types.VoidAddress)
	v1FC.Filesize = 65
	v2FC := types.V2FileContract{
		Capacity:         v1FC.Filesize,
		Filesize:         v1FC.Filesize,
		FileMerkleRoot:   v1FC.FileMerkleRoot,
		ProofHeight:      20,
		ExpirationHeight: 30,
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

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	v2FCRevision := v2FC
	v2FCRevision.RevisionNumber++
	txn2 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   getFCE(t, db, txn1.V2FileContractID(txn1.ID(), 0)),
			Revision: v2FCRevision,
		}},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn2)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn2, dbTxns[0])
	}

	{
		fcs, err := db.V2Contracts([]types.FileContractID{txn1.V2FileContractID(txn1.ID(), 0)})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn2.FileContractRevisions[0].Revision, fcs[0])
	}

	{
		fcs, err := db.V2ContractRevisions(txn1.V2FileContractID(txn1.ID(), 0))
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
		testutil.CheckV2FC(t, txn2.FileContractRevisions[0].Revision, fcs[1])
	}

	{
		fcs, err := db.V2ContractsKey(renterPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn2.FileContractRevisions[0].Revision, fcs[0])
	}
}

func TestV2FileContractResolution(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

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

	v1FC := testutil.PrepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 105, addr2)
	v1FC.Filesize = 65

	data := make([]byte, 2*rhp2.LeafSize)
	data[0], data[rhp2.LeafSize] = 1, 1
	v1FC.FileMerkleRoot, _ = rhp2.ReaderRoot(bytes.NewReader(data))

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

	// use identical contracts except for revision number so it is apparent if
	// wrong data is retrieved
	v2FC0 := v2FC
	v2FC0.RevisionNumber = 0

	v2FC1 := v2FC
	v2FC1.RevisionNumber = 1

	v2FC2 := v2FC
	v2FC2.RevisionNumber = 2

	v2FC3 := v2FC
	v2FC3.RevisionNumber = 3

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, db, genesisBlock.Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   giftSC.Sub(fcOut.Mul64(4)),
			Address: addr1,
		}},
		FileContracts: []types.V2FileContract{v2FC0, v2FC1, v2FC2, v2FC3},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn1)

	b1 := testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b1}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	tip1 := cm.Tip()

	v2FC0ID := txn1.V2FileContractID(txn1.ID(), 0)
	v2FC1ID := txn1.V2FileContractID(txn1.ID(), 1)
	v2FC2ID := txn1.V2FileContractID(txn1.ID(), 2)
	v2FC3ID := txn1.V2FileContractID(txn1.ID(), 3)

	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID, v2FC1ID, v2FC2ID, v2FC3ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
		testutil.CheckV2FC(t, txn1.FileContracts[1], fcs[1])
		testutil.CheckV2FC(t, txn1.FileContracts[2], fcs[2])
		testutil.CheckV2FC(t, txn1.FileContracts[3], fcs[3])
	}

	// check that they are all not resolved before resolving
	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID, v2FC1ID, v2FC2ID, v2FC3ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, fc := range fcs {
			testutil.Equal(t, "confirmation index", tip1, fc.ConfirmationIndex)
			testutil.Equal(t, "confirmation transaction ID", txn1.ID(), fc.ConfirmationTransactionID)
			testutil.Equal(t, "resolution type", nil, fc.ResolutionType)
			testutil.Equal(t, "resolution index", nil, fc.ResolutionIndex)
			testutil.Equal(t, "resolution transaction ID", nil, fc.ResolutionTransactionID)
		}
	}

	// we will revert back here when we undo the resolutions
	prevState := cm.TipState()

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}

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
				Parent:     getFCE(t, db, v2FC1ID),
				Resolution: renewal,
			},
		},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn2)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn2}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn2, dbTxns[0])

		testutil.Equal(t, "confirmation index", tip1, dbTxns[0].FileContractResolutions[0].Parent.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn1.ID(), dbTxns[0].FileContractResolutions[0].Parent.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", explorer.V2ResolutionRenewal, *dbTxns[0].FileContractResolutions[0].Parent.ResolutionType)
		testutil.Equal(t, "resolution index", cm.Tip(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", txn2.ID(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionTransactionID)
	}

	b2 := testutil.MineV2Block(cm.TipState(), nil, types.VoidAddress)
	if err := cm.AddBlocks([]types.Block{b2}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	storageProof := &types.V2StorageProof{
		ProofIndex: getCIE(t, db, b2.ID()),
		Leaf:       [64]byte{1},
		Proof:      []types.Hash256{cm.TipState().StorageProofLeafHash([]byte{1})},
	}

	txn3 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{
			{
				Parent:     getFCE(t, db, v2FC2ID),
				Resolution: storageProof,
			},
		},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn3)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn3}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn3.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn3, dbTxns[0])
		testutil.Equal(t, "confirmation index", tip1, dbTxns[0].FileContractResolutions[0].Parent.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn1.ID(), dbTxns[0].FileContractResolutions[0].Parent.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", explorer.V2ResolutionStorageProof, *dbTxns[0].FileContractResolutions[0].Parent.ResolutionType)
		testutil.Equal(t, "resolution index", cm.Tip(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", txn3.ID(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionTransactionID)
	}

	txn4 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{
			{
				Parent:     getFCE(t, db, v2FC3ID),
				Resolution: new(types.V2FileContractExpiration),
			},
		},
	}
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn4)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn4}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn4.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn4, dbTxns[0])
		testutil.Equal(t, "confirmation index", tip1, dbTxns[0].FileContractResolutions[0].Parent.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn1.ID(), dbTxns[0].FileContractResolutions[0].Parent.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", explorer.V2ResolutionExpiration, *dbTxns[0].FileContractResolutions[0].Parent.ResolutionType)
		testutil.Equal(t, "resolution index", cm.Tip(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", txn4.ID(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionTransactionID)
	}

	{
		events, err := db.AddressEvents(addr2, 0, math.MaxInt64)
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 7, len(events))

		ev0 := events[0].Data.(explorer.EventV2ContractResolution)
		testutil.Equal(t, "event 0 parent ID", v2FC3ID, ev0.Resolution.Parent.ID)
		testutil.Equal(t, "event 0 output ID", v2FC3ID.V2RenterOutputID(), ev0.SiacoinElement.ID)
		testutil.Equal(t, "event 0 output source", explorer.SourceMissedProofOutput, ev0.SiacoinElement.Source)
		testutil.Equal(t, "event 0 missed", true, ev0.Missed)
		{
			dbTxns, err := db.V2Transactions([]types.TransactionID{txn4.ID()})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "event 0 resolution", dbTxns[0].FileContractResolutions[0], ev0.Resolution)
		}

		ev1 := events[1].Data.(explorer.EventV2ContractResolution)
		testutil.Equal(t, "event 1 parent ID", v2FC2ID, ev1.Resolution.Parent.ID)
		testutil.Equal(t, "event 1 output ID", v2FC2ID.V2RenterOutputID(), ev1.SiacoinElement.ID)
		testutil.Equal(t, "event 1 output source", explorer.SourceValidProofOutput, ev1.SiacoinElement.Source)
		testutil.Equal(t, "event 1 missed", false, ev1.Missed)
		{
			dbTxns, err := db.V2Transactions([]types.TransactionID{txn3.ID()})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "event 1 resolution", dbTxns[0].FileContractResolutions[0], ev1.Resolution)
		}

		ev2 := events[2].Data.(explorer.EventV2ContractResolution)
		testutil.Equal(t, "event 2 parent ID", v2FC1ID, ev2.Resolution.Parent.ID)
		testutil.Equal(t, "event 2 output ID", v2FC1ID.V2RenterOutputID(), ev2.SiacoinElement.ID)
		testutil.Equal(t, "event 2 output source", explorer.SourceValidProofOutput, ev2.SiacoinElement.Source)
		testutil.Equal(t, "event 2 missed", false, ev2.Missed)
		{
			dbTxns, err := db.V2Transactions([]types.TransactionID{txn2.ID()})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "event 2 resolution", dbTxns[0].FileContractResolutions[0], ev2.Resolution)
		}

		ev3 := events[3].Data.(explorer.EventV2Transaction)
		testutil.CheckV2Transaction(t, txn4, explorer.V2Transaction(ev3))

		ev4 := events[4].Data.(explorer.EventV2Transaction)
		testutil.CheckV2Transaction(t, txn3, explorer.V2Transaction(ev4))

		ev5 := events[5].Data.(explorer.EventV2Transaction)
		testutil.CheckV2Transaction(t, txn2, explorer.V2Transaction(ev5))

		ev6 := events[6].Data.(explorer.EventV2Transaction)
		testutil.CheckV2Transaction(t, txn1, explorer.V2Transaction(ev6))
	}

	{
		events, err := db.Events([]types.Hash256{types.Hash256(txn4.ID()), types.Hash256(txn3.ID()), types.Hash256(txn2.ID()), types.Hash256(txn1.ID())})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "events", 4, len(events))

		ev0 := events[0].Data.(explorer.EventV2Transaction)
		testutil.CheckV2Transaction(t, txn4, explorer.V2Transaction(ev0))

		ev1 := events[1].Data.(explorer.EventV2Transaction)
		testutil.CheckV2Transaction(t, txn3, explorer.V2Transaction(ev1))

		ev2 := events[2].Data.(explorer.EventV2Transaction)
		testutil.CheckV2Transaction(t, txn2, explorer.V2Transaction(ev2))

		ev3 := events[3].Data.(explorer.EventV2Transaction)
		testutil.CheckV2Transaction(t, txn1, explorer.V2Transaction(ev3))
	}

	// revert the block
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

	// check that they are all not resolved after reverting resolution
	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID, v2FC1ID, v2FC2ID, v2FC3ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, fc := range fcs {
			testutil.Equal(t, "confirmation index", tip1, fc.ConfirmationIndex)
			testutil.Equal(t, "confirmation transaction ID", txn1.ID(), fc.ConfirmationTransactionID)
			testutil.Equal(t, "resolution type", nil, fc.ResolutionType)
			testutil.Equal(t, "resolution index", nil, fc.ResolutionIndex)
			testutil.Equal(t, "resolution transaction ID", nil, fc.ResolutionTransactionID)
		}
	}

	{
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID, v2FC1ID, v2FC2ID, v2FC3ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
		testutil.CheckV2FC(t, txn1.FileContracts[1], fcs[1])
		testutil.CheckV2FC(t, txn1.FileContracts[2], fcs[2])
		testutil.CheckV2FC(t, txn1.FileContracts[3], fcs[3])
	}

	tip, err := db.BestTip(v2FC3.ProofHeight)
	if err != nil {
		t.Fatal(err)
	}
	storageProof.ProofIndex = getCIE(t, db, tip.ID)
	txn3.FileContractResolutions[0].Parent = getFCE(t, db, v2FC2ID)
	txn3.FileContractResolutions[0].Resolution = storageProof

	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn3)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn3}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn3.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn3, dbTxns[0])
		testutil.Equal(t, "confirmation index", tip1, dbTxns[0].FileContractResolutions[0].Parent.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn1.ID(), dbTxns[0].FileContractResolutions[0].Parent.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", explorer.V2ResolutionStorageProof, *dbTxns[0].FileContractResolutions[0].Parent.ResolutionType)
		testutil.Equal(t, "resolution index", cm.Tip(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", txn3.ID(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionTransactionID)
	}

	txn4.FileContractResolutions[0].Parent = getFCE(t, db, v2FC3ID)
	testutil.SignV2TransactionWithContracts(cm.TipState(), pk1, renterPrivateKey, hostPrivateKey, &txn4)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn4}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	syncDB(t, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn4.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn4, dbTxns[0])
		testutil.Equal(t, "confirmation index", tip1, dbTxns[0].FileContractResolutions[0].Parent.ConfirmationIndex)
		testutil.Equal(t, "confirmation transaction ID", txn1.ID(), dbTxns[0].FileContractResolutions[0].Parent.ConfirmationTransactionID)
		testutil.Equal(t, "resolution type", explorer.V2ResolutionExpiration, *dbTxns[0].FileContractResolutions[0].Parent.ResolutionType)
		testutil.Equal(t, "resolution index", cm.Tip(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionIndex)
		testutil.Equal(t, "resolution transaction ID", txn4.ID(), *dbTxns[0].FileContractResolutions[0].Parent.ResolutionTransactionID)
	}

	{
		// If we re-added the renewal after the revert this would fail because
		// the revision number for v2FC0 would be types.MaxRevisionNumber.
		fcs, err := db.V2Contracts([]types.FileContractID{v2FC0ID, v2FC1ID, v2FC2ID, v2FC3ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2FC(t, txn1.FileContracts[0], fcs[0])
		testutil.CheckV2FC(t, txn1.FileContracts[1], fcs[1])
		testutil.CheckV2FC(t, txn1.FileContracts[2], fcs[2])
		testutil.CheckV2FC(t, txn1.FileContracts[3], fcs[3])
	}
}
