package sqlite

import (
	"fmt"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"lukechampine.com/frand"
)

func getSCE(t testing.TB, db explorer.Store, scid types.SiacoinOutputID) types.SiacoinElement {
	t.Helper()

	sces, err := db.SiacoinElements([]types.SiacoinOutputID{scid})
	if err != nil {
		t.Fatal(err)
	} else if len(sces) == 0 {
		t.Fatal("can't find sce")
	}
	return sces[0].SiacoinElement
}

func getSFE(t testing.TB, db explorer.Store, sfid types.SiafundOutputID) types.SiafundElement {
	t.Helper()

	sfes, err := db.SiafundElements([]types.SiafundOutputID{sfid})
	if err != nil {
		t.Fatal(err)
	} else if len(sfes) == 0 {
		t.Fatal("can't find sfe")
	}
	return sfes[0].SiafundElement
}

func getFCE(t testing.TB, db explorer.Store, fcid types.FileContractID) types.V2FileContractElement {
	t.Helper()

	fces, err := db.V2Contracts([]types.FileContractID{fcid})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fces")
	}
	return fces[0].V2FileContractElement
}

func getCIE(t testing.TB, db explorer.Store, bid types.BlockID) types.ChainIndexElement {
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

func (n *testChain) mineV2Transactions(t testing.TB, txns ...types.V2Transaction) {
	t.Helper()

	b := testutil.MineV2Block(n.tipState(), nil, txns, types.VoidAddress)
	n.applyBlock(t, b)
}

func (n *testChain) assertV2Transactions(t testing.TB, expected ...types.V2Transaction) {
	t.Helper()

	for _, txn := range expected {
		txns, err := n.db.V2Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 1, len(txns))

		testutil.CheckV2Transaction(t, txn, txns[0])
	}
}

func (n *testChain) getV2FCE(t testing.TB, fcID types.FileContractID) explorer.V2FileContract {
	t.Helper()

	fces, err := n.db.V2Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fce")
	}
	fces[0].V2FileContractElement.StateElement.MerkleProof = nil
	return fces[0]
}

func (n *testChain) getV2Txn(t testing.TB, txnID types.TransactionID) explorer.V2Transaction {
	t.Helper()

	txns, err := n.db.V2Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	} else if len(txns) == 0 {
		t.Fatal("can't find txn")
	}
	return txns[0]
}

func TestV2Block(t *testing.T) {
	n := newTestChain(t, true, nil)

	checkBlocks := func(count int) {
		t.Helper()

		testutil.Equal(t, "blocks", count, len(n.blocks))
		for i := range n.blocks {
			testutil.Equal(t, "block height", uint64(i), n.states[i].Index.Height)
			testutil.Equal(t, "block ID", n.blocks[i].ID(), n.states[i].Index.ID)
			n.assertBlock(t, n.states[i], n.blocks[i])
		}
	}

	checkBlocks(1)

	n.mineV2Transactions(t, types.V2Transaction{ArbitraryData: []byte{0}})

	checkBlocks(2)

	n.revertBlock(t)

	checkBlocks(1)
}

func TestV2ArbitraryData(t *testing.T) {
	n := newTestChain(t, true, nil)

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
	}

	txn2 := types.V2Transaction{
		ArbitraryData: []byte("world"),
	}

	n.mineV2Transactions(t, txn1, txn2)

	n.assertV2Transactions(t, txn1, txn2)

	txn3 := types.V2Transaction{
		ArbitraryData: []byte("12345"),
	}

	n.mineV2Transactions(t, txn3)

	n.assertV2Transactions(t, txn1, txn2, txn3)

	n.revertBlock(t)
}

func TestV2MinerFee(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisTxn := n.genesis().Transactions[0]

	txn1 := types.V2Transaction{
		MinerFee: genesisTxn.SiacoinOutputs[0].Value,
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, genesisTxn.SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	n.mineV2Transactions(t, txn1)

	n.assertV2Transactions(t, txn1)

	n.revertBlock(t)
}

func TestV2FoundationAddress(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkFoundation.FailsafeAddress = addr1
		network.HardforkFoundation.PrimaryAddress = addr1
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisTxn := n.genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	// we have to spend an output beloning to foundation address to change it
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, genesisTxn.SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		MinerFee:             genesisTxn.SiacoinOutputs[0].Value,
		NewFoundationAddress: &addr2,
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	n.mineV2Transactions(t, txn1)

	n.assertV2Transactions(t, txn1)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	// event for txn1
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.getV2Txn(t, txn1.ID())),
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	// event for foundation payout
	scID := n.tipState().Index.ID.FoundationOutputID()

	ev2 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeFoundationSubsidy,
		Data:           explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev2, ev1, ev0)

	n.revertBlock(t)
}

func TestV2Attestations(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	pk2 := types.GeneratePrivateKey()

	n := newTestChain(t, true, nil)

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
	otherAttestation.Signature = pk1.SignHash(n.tipState().AttestationSigHash(otherAttestation))

	txn1 := types.V2Transaction{
		Attestations: []types.Attestation{ha1.ToAttestation(n.tipState(), pk1), otherAttestation},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)
	txn2 := types.V2Transaction{
		Attestations: []types.Attestation{ha2.ToAttestation(n.tipState(), pk2)},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn2)

	n.mineV2Transactions(t, txn1, txn2)

	n.assertV2Transactions(t, txn1, txn2)

	n.revertBlock(t)
}

func BenchmarkV2Transactions(b *testing.B) {
	const nTransactions = 1_000_000

	n := newTestChain(b, false, nil)

	// add a bunch of random transactions that are either empty, contain arbitrary
	// or contain a contract formation
	var ids []types.TransactionID
	err := n.db.transaction(func(tx *txn) error {
		fceStmt, err := tx.Prepare(`INSERT INTO v2_file_contract_elements(contract_id, block_id, transaction_id, leaf_index, capacity, filesize, file_merkle_root, proof_height, expiration_height, renter_output_address, renter_output_value, host_output_address, host_output_value, missed_host_value, total_collateral, renter_public_key, host_public_key, revision_number, renter_signature, host_signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer fceStmt.Close()

		txnStmt, err := tx.Prepare(`INSERT INTO v2_transactions(transaction_id, miner_fee) VALUES (?, ?)`)
		if err != nil {
			return err
		}
		defer txnStmt.Close()

		txnAttestationsStmt, err := tx.Prepare(`INSERT INTO v2_transaction_attestations(transaction_id, transaction_order, public_key, key, value, signature) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer txnAttestationsStmt.Close()

		txnContractsStmt, err := tx.Prepare(`INSERT INTO v2_transaction_file_contracts(transaction_id, transaction_order, contract_id) VALUES (?, ?, ?)`)
		if err != nil {
			return err
		}
		defer txnContractsStmt.Close()

		pubkey, key, value, sig := encode(types.GeneratePrivateKey().PublicKey()), "key", []byte("value"), encode(types.Signature{})

		bid := encode(n.tipState().Index.ID)
		leafIndex := encode(uint64(0))
		capacity, filesize, fileMerkleRoot, proofHeight, expirationHeight, renterOutputAddress, renterOutputValue, hostOutputAddress, hostOutputValue, missedHostValue, totalCollateral, renterPublicKey, hostPublicKey, revisionNumber, renterSignature, hostSignature := encode(uint64(0)), encode(uint64(0)), encode(types.Hash256{}), encode(uint64(0)), encode(uint64(0)), encode(types.Address{}), encode(types.ZeroCurrency), encode(types.Address{}), encode(types.ZeroCurrency), encode(types.ZeroCurrency), encode(types.ZeroCurrency), encode(types.GeneratePrivateKey().PublicKey()), encode(types.GeneratePrivateKey().PublicKey()), encode(uint64(0)), encode(types.Signature{}), encode(types.Signature{})
		for i := range nTransactions {
			if i%(nTransactions/10) == 0 {
				b.Log("Inserted transaction:", i)
			}

			var txnID types.TransactionID
			frand.Read(txnID[:])
			ids = append(ids, txnID)

			result, err := txnStmt.Exec(encode(txnID), encode(types.ZeroCurrency))
			if err != nil {
				return err
			}
			txnDBID, err := result.LastInsertId()
			if err != nil {
				return err
			}

			switch i % 3 {
			case 0:
				// empty transaction
			case 1:
				// transaction with attestation
				if _, err = txnAttestationsStmt.Exec(txnDBID, 0, pubkey, key, value, sig); err != nil {
					return err
				}
			case 2:
				// transaction with file contract formation
				var fcID types.FileContractID
				frand.Read(fcID[:])

				result, err = fceStmt.Exec(encode(fcID), bid, encode(txnID), leafIndex, capacity, filesize, fileMerkleRoot, proofHeight, expirationHeight, renterOutputAddress, renterOutputValue, hostOutputAddress, hostOutputValue, missedHostValue, totalCollateral, renterPublicKey, hostPublicKey, revisionNumber, renterSignature, hostSignature)
				if err != nil {
					return err
				}
				fcDBID, err := result.LastInsertId()
				if err != nil {
					return err
				}
				if _, err := txnContractsStmt.Exec(txnDBID, 0, fcDBID); err != nil {
					return err
				}
			}
		}
		return nil
	})

	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for _, limit := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%d transactions", limit), func(b *testing.B) {
			for b.Loop() {
				offset := frand.Intn(len(ids) - limit)
				txnIDs := ids[offset : offset+limit]

				txns, err := n.db.V2Transactions(txnIDs)
				if err != nil {
					b.Fatal(err)
				}
				if len(txns) != limit {
					b.Fatalf("expected %d txns, got %d", limit, len(txns))
				}
			}
		})
	}
}
