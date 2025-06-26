package sqlite

import (
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
)

func TestEventPayout(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, nil)

	b := testutil.MineBlock(n.tipState(), nil, addr1)
	n.applyBlock(t, b)

	scID := b.ID().MinerOutputID(0)
	ev1 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeMinerPayout,
		Data:           explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      b.Timestamp,
	}
	n.assertEvents(t, addr1, ev1)

	// see if confirmations number goes up when we mine another block
	n.mineTransactions(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)}
	n.assertEvents(t, addr1, ev1)

	n.revertBlock(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)}
	n.assertEvents(t, addr1, ev1)

	n.revertBlock(t)

	n.assertEvents(t, addr1)
}

func TestEventFileContractValid(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
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

	fc := prepareContract(addr1, n.tipState().Index.Height+1)
	fc.ValidProofOutputs[0].Address = addr1
	fc.ValidProofOutputs[1].Address = addr2

	// create file contract
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         genesisTxn.SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   genesisTxn.SiacoinOutputs[0].Value.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	// event for fc creation txn
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		Data:           explorer.EventV1Transaction{Transaction: n.getTxn(t, txn1.ID())},
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev1, ev0)
	n.assertEvents(t, addr2, ev1)

	fcID := txn1.FileContractID(0)
	sp := types.StorageProof{
		ParentID: fcID,
	}
	txn2 := types.Transaction{
		StorageProofs: []types.StorageProof{sp},
	}
	n.mineTransactions(t, txn2)

	ev1.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, txn1.ID())}
	// event for resolution first valid proof output
	ev2 := explorer.Event{
		ID:    types.Hash256(fcID.ValidOutputID(0)),
		Index: n.tipState().Index,
		Type:  wallet.EventTypeV1ContractResolution,
		Data: explorer.EventV1ContractResolution{
			Missed:         false,
			Parent:         n.getFCE(t, fcID),
			SiacoinElement: n.getSCE(t, fcID.ValidOutputID(0)),
		},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}
	// event for resolution second valid proof output
	ev3 := explorer.Event{
		ID:    types.Hash256(fcID.ValidOutputID(1)),
		Index: n.tipState().Index,
		Type:  wallet.EventTypeV1ContractResolution,
		Data: explorer.EventV1ContractResolution{
			Missed:         false,
			Parent:         n.getFCE(t, fcID),
			SiacoinElement: n.getSCE(t, fcID.ValidOutputID(1)),
		},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev2, ev1, ev0)
	n.assertEvents(t, addr2, ev3, ev1)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	ev1.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, txn1.ID())}
	n.assertEvents(t, addr1, ev1, ev0)
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	n.assertEvents(t, addr1, ev0)
	n.assertEvents(t, addr2)
}

func TestEventFileContractMissed(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
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

	fc := prepareContract(addr1, n.tipState().Index.Height+1)
	fc.MissedProofOutputs[0].Address = addr1
	fc.MissedProofOutputs[1].Address = addr2

	// create file contract
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         genesisTxn.SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   genesisTxn.SiacoinOutputs[0].Value.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	n.mineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.tipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	// event for fc creation txn
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		Data:           explorer.EventV1Transaction{Transaction: n.getTxn(t, txn1.ID())},
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev1, ev0)
	n.assertEvents(t, addr2, ev1)

	for i := n.tipState().Index.Height; i < fc.WindowEnd; i++ {
		n.mineTransactions(t)
	}

	fcID := txn1.FileContractID(0)
	ev1.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, txn1.ID())}
	// event for resolution first missed proof output
	ev2 := explorer.Event{
		ID:    types.Hash256(fcID.MissedOutputID(0)),
		Index: n.tipState().Index,
		Type:  wallet.EventTypeV1ContractResolution,
		Data: explorer.EventV1ContractResolution{
			Missed:         true,
			Parent:         n.getFCE(t, fcID),
			SiacoinElement: n.getSCE(t, fcID.MissedOutputID(0)),
		},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}
	// event for resolution second missed proof output
	ev3 := explorer.Event{
		ID:    types.Hash256(fcID.MissedOutputID(1)),
		Index: n.tipState().Index,
		Type:  wallet.EventTypeV1ContractResolution,
		Data: explorer.EventV1ContractResolution{
			Missed:         true,
			Parent:         n.getFCE(t, fcID),
			SiacoinElement: n.getSCE(t, fcID.MissedOutputID(1)),
		},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev2, ev1, ev0)
	n.assertEvents(t, addr2, ev3, ev1)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	ev1.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, txn1.ID())}
	n.assertEvents(t, addr1, ev1, ev0)
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	n.assertEvents(t, addr1, ev0)
	n.assertEvents(t, addr2)
}

func TestEventTransaction(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
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

	// txn1 - should be relevant to addr1 (due to input) and addr2 due to
	// sc output
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         genesisTxn.SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisTxn.SiacoinOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	// txn2 - should be relevant to addr1 (due to input) and addr3 due to
	// sf output
	txn2 := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			ParentID:         genesisTxn.SiafundOutputID(0),
			UnlockConditions: uc1,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr3,
			Value:   genesisTxn.SiafundOutputs[0].Value,
		}},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn2)

	n.mineTransactions(t, txn1, txn2)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	// event for txn1
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		Data:           explorer.EventV1Transaction{Transaction: n.getTxn(t, txn1.ID())},
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}
	// event for txn2
	ev2 := explorer.Event{
		ID:             types.Hash256(txn2.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		Data:           explorer.EventV1Transaction{Transaction: n.getTxn(t, txn2.ID())},
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	// addr1 should be relevant to all transactions
	n.assertEvents(t, addr1, ev2, ev1, ev0)
	n.assertEvents(t, addr2, ev1)
	n.assertEvents(t, addr3, ev2)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}

	// genesis transaction still present but txn1 and txn2 reverted
	n.assertEvents(t, addr1, ev0)
	n.assertEvents(t, addr2)
	n.assertEvents(t, addr3)
}

func TestEventPayoutContract(t *testing.T) {
	// test to catch bug where slice returned by explorer.AppliedEvents did not
	// include miner payout events if there was any contract action in the
	// block besides resolutions because it mistakenly returned early
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisTxn := n.genesis().Transactions[0]

	fc := prepareContract(addr1, n.tipState().Index.Height+1)
	// create file contract
	txn1 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         genesisTxn.SiacoinOutputID(0),
			UnlockConditions: uc1,
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   genesisTxn.SiacoinOutputs[0].Value.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	testutil.SignTransaction(n.tipState(), pk1, &txn1)

	b := testutil.MineBlock(n.tipState(), []types.Transaction{txn1}, addr2)
	n.applyBlock(t, b)

	scID := b.ID().MinerOutputID(0)
	ev1 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeMinerPayout,
		Data:           explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      b.Timestamp,
	}
	n.assertEvents(t, addr2, ev1)

	// see if confirmations number goes up when we mine another block
	n.mineTransactions(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)}
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)}
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	n.assertEvents(t, addr2)
}

func TestEventV2Transaction(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	pk3 := types.GeneratePrivateKey()
	uc3 := types.StandardUnlockConditions(pk3.PublicKey())
	addr3 := uc3.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr1
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

	// txn1 - should be relevant to addr1 (due to input) and addr2 due to
	// sc output
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, genesisTxn.SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisTxn.SiacoinOutputs[0].Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn1)

	// txn2 - should be relevant to addr1 (due to input) and addr3 due to
	// sf output
	txn2 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          getSFE(t, n.db, genesisTxn.SiafundOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr3,
			Value:   genesisTxn.SiafundOutputs[0].Value,
		}},
	}
	testutil.SignV2Transaction(n.tipState(), pk1, &txn2)

	n.mineV2Transactions(t, txn1, txn2)

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
	// event for txn2
	ev2 := explorer.Event{
		ID:             types.Hash256(txn2.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.getV2Txn(t, txn2.ID())),
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	// addr1 should be relevant to all transactions
	n.assertEvents(t, addr1, ev2, ev1, ev0)
	n.assertEvents(t, addr2, ev1)
	n.assertEvents(t, addr3, ev2)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}

	// genesis transaction still present but txn1 and txn2 reverted
	n.assertEvents(t, addr1, ev0)
	n.assertEvents(t, addr2)
	n.assertEvents(t, addr3)
}

func TestEventV2FileContract(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
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

	// create file contract
	fc, payout := prepareV2Contract(pk1, pk2, n.tipState().Index.Height+1)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.db, n.genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   genesisTxn.SiacoinOutputs[0].Value.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, pk1, pk2, &txn1)

	n.mineV2Transactions(t, txn1)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	// event for fc creation txn
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.getV2Txn(t, txn1.ID())),
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev1, ev0)
	n.assertEvents(t, addr2, ev1)

	fcID := txn1.V2FileContractID(txn1.ID(), 0)
	sp := &types.V2StorageProof{
		ProofIndex: getCIE(t, n.db, n.tipState().Index.ID),
	}
	txn2 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.db, fcID),
			Resolution: sp,
		}},
	}
	n.mineV2Transactions(t, txn2)

	ev1.Data = explorer.EventV2Transaction(n.getV2Txn(t, txn1.ID()))
	// event for resolution txn
	ev2 := explorer.Event{
		ID:             types.Hash256(txn2.ID()),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.getV2Txn(t, txn2.ID())),
		MaturityHeight: n.tipState().Index.Height,
		Timestamp:      n.tipBlock().Timestamp,
	}

	resolution := n.getV2Txn(t, txn2.ID()).FileContractResolutions[0]
	// event for renter output
	ev3 := explorer.Event{
		ID:    types.Hash256(fcID.V2RenterOutputID()),
		Index: n.tipState().Index,
		Type:  wallet.EventTypeV2ContractResolution,
		Data: explorer.EventV2ContractResolution{
			Resolution:     resolution,
			SiacoinElement: n.getSCE(t, fcID.V2RenterOutputID()),
			Missed:         false,
		},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}
	// event for host output
	ev4 := explorer.Event{
		ID:    types.Hash256(fcID.V2HostOutputID()),
		Index: n.tipState().Index,
		Type:  wallet.EventTypeV2ContractResolution,
		Data: explorer.EventV2ContractResolution{
			Resolution:     resolution,
			SiacoinElement: n.getSCE(t, fcID.V2HostOutputID()),
			Missed:         false,
		},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      n.tipBlock().Timestamp,
	}

	n.assertEvents(t, addr1, ev3, ev2, ev1, ev0)
	n.assertEvents(t, addr2, ev4, ev2, ev1)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	ev1.Data = explorer.EventV2Transaction(n.getV2Txn(t, txn1.ID()))
	n.assertEvents(t, addr1, ev1, ev0)
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.getTxn(t, genesisTxn.ID())}
	n.assertEvents(t, addr1, ev0)
	n.assertEvents(t, addr2)
}

func TestEventV2PayoutContract(t *testing.T) {
	// test to catch bug where slice returned by explorer.AppliedEvents did not
	// include miner payout events if there was any contract action in the
	// block besides resolutions because it mistakenly returned early
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	pk2 := types.GeneratePrivateKey()
	uc2 := types.StandardUnlockConditions(pk2.PublicKey())
	addr2 := uc2.UnlockHash()

	n := newTestChain(t, true, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	val := n.genesis().Transactions[0].SiacoinOutputs[0].Value

	// create file contract
	fc, payout := prepareV2Contract(pk1, pk1, n.tipState().Index.Height+1)
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
	testutil.SignV2TransactionWithContracts(n.tipState(), pk1, pk1, pk1, &txn1)

	b := testutil.MineV2Block(n.tipState(), nil, []types.V2Transaction{txn1}, addr2)
	n.applyBlock(t, b)

	scID := b.ID().MinerOutputID(0)
	ev1 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.tipState().Index,
		Type:           wallet.EventTypeMinerPayout,
		Data:           explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)},
		MaturityHeight: n.tipState().MaturityHeight() - 1,
		Timestamp:      b.Timestamp,
	}
	n.assertEvents(t, addr2, ev1)

	// see if confirmations number goes up when we mine another block
	n.mineTransactions(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)}
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.getSCE(t, scID)}
	n.assertEvents(t, addr2, ev1)

	n.revertBlock(t)

	n.assertEvents(t, addr2)
}
