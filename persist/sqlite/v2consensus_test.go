package sqlite_test

import (
	"math"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
)

func getSCE(t *testing.T, db explorer.Store, scid types.SiacoinOutputID) types.SiacoinElement {
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
		if v, ok := events[0].Data.(*explorer.EventV2Transaction); !ok {
			t.Fatal("expected EventV2Transaction")
		} else {
			testutil.Equal(t, "host announcements", 2, len(v.HostAnnouncements))
		}
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
		_, err := db.V2Contracts([]types.FileContractID{txn1.V2FileContractID(txn1.ID(), 0)})
		if err == nil {
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
