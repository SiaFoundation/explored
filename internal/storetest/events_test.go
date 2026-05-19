//go:build testing

package storetest

import (
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testchain"
	"go.sia.tech/explored/internal/testutil"
)

func TestEventPayout(t *testing.T) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()

	n := newTestChain(t, false, nil)

	b := testutil.MineBlock(n.TipState(), nil, addr1)
	n.ApplyBlock(t, b)

	scID := b.ID().MinerOutputID(0)
	ev1 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeMinerPayout,
		Data:           explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      b.Timestamp,
	}
	n.AssertEvents(t, addr1, ev1)

	// see if confirmations number goes up when we mine another block
	n.MineTransactions(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)}
	n.AssertEvents(t, addr1, ev1)

	n.RevertBlock(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)}
	n.AssertEvents(t, addr1, ev1)

	n.RevertBlock(t)

	n.AssertEvents(t, addr1)
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
	genesisTxn := n.Genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+1)
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
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	n.MineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	// event for fc creation txn
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		Data:           explorer.EventV1Transaction{Transaction: n.GetTxn(t, txn1.ID())},
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	n.AssertEvents(t, addr1, ev1, ev0)
	n.AssertEvents(t, addr2, ev1)

	fcID := txn1.FileContractID(0)
	sp := types.StorageProof{
		ParentID: fcID,
	}
	txn2 := types.Transaction{
		StorageProofs: []types.StorageProof{sp},
	}
	n.MineTransactions(t, txn2)

	ev1.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, txn1.ID())}
	// event for resolution first valid proof output
	ev2 := explorer.Event{
		ID:    types.Hash256(fcID.ValidOutputID(0)),
		Index: n.TipState().Index,
		Type:  wallet.EventTypeV1ContractResolution,
		Data: explorer.EventV1ContractResolution{
			Missed:         false,
			Parent:         n.GetFCE(t, fcID),
			SiacoinElement: n.GetSCE(t, fcID.ValidOutputID(0)),
		},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      n.TipBlock().Timestamp,
	}
	// event for resolution second valid proof output
	ev3 := explorer.Event{
		ID:    types.Hash256(fcID.ValidOutputID(1)),
		Index: n.TipState().Index,
		Type:  wallet.EventTypeV1ContractResolution,
		Data: explorer.EventV1ContractResolution{
			Missed:         false,
			Parent:         n.GetFCE(t, fcID),
			SiacoinElement: n.GetSCE(t, fcID.ValidOutputID(1)),
		},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      n.TipBlock().Timestamp,
	}

	n.AssertEvents(t, addr1, ev2, ev1, ev0)
	n.AssertEvents(t, addr2, ev3, ev1)

	n.RevertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	ev1.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, txn1.ID())}
	n.AssertEvents(t, addr1, ev1, ev0)
	n.AssertEvents(t, addr2, ev1)

	n.RevertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	n.AssertEvents(t, addr1, ev0)
	n.AssertEvents(t, addr2)
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
	genesisTxn := n.Genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+1)
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
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	n.MineTransactions(t, txn1)

	fce := coreToExplorerFC(txn1.FileContractID(0), fc)
	fce.TransactionID = txn1.ID()
	fce.ConfirmationIndex = n.TipState().Index
	fce.ConfirmationTransactionID = txn1.ID()

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	// event for fc creation txn
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		Data:           explorer.EventV1Transaction{Transaction: n.GetTxn(t, txn1.ID())},
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	n.AssertEvents(t, addr1, ev1, ev0)
	n.AssertEvents(t, addr2, ev1)

	for i := n.TipState().Index.Height; i < fc.WindowEnd; i++ {
		n.MineTransactions(t)
	}

	fcID := txn1.FileContractID(0)
	ev1.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, txn1.ID())}
	// event for resolution first missed proof output
	ev2 := explorer.Event{
		ID:    types.Hash256(fcID.MissedOutputID(0)),
		Index: n.TipState().Index,
		Type:  wallet.EventTypeV1ContractResolution,
		Data: explorer.EventV1ContractResolution{
			Missed:         true,
			Parent:         n.GetFCE(t, fcID),
			SiacoinElement: n.GetSCE(t, fcID.MissedOutputID(0)),
		},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      n.TipBlock().Timestamp,
	}
	// event for resolution second missed proof output
	ev3 := explorer.Event{
		ID:    types.Hash256(fcID.MissedOutputID(1)),
		Index: n.TipState().Index,
		Type:  wallet.EventTypeV1ContractResolution,
		Data: explorer.EventV1ContractResolution{
			Missed:         true,
			Parent:         n.GetFCE(t, fcID),
			SiacoinElement: n.GetSCE(t, fcID.MissedOutputID(1)),
		},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      n.TipBlock().Timestamp,
	}

	n.AssertEvents(t, addr1, ev2, ev1, ev0)
	n.AssertEvents(t, addr2, ev3, ev1)

	n.RevertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	ev1.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, txn1.ID())}
	n.AssertEvents(t, addr1, ev1, ev0)
	n.AssertEvents(t, addr2, ev1)

	n.RevertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	n.AssertEvents(t, addr1, ev0)
	n.AssertEvents(t, addr2)
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
	genesisTxn := n.Genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
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
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

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
	testutil.SignTransaction(n.TipState(), pk1, &txn2)

	n.MineTransactions(t, txn1, txn2)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	// event for txn1
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		Data:           explorer.EventV1Transaction{Transaction: n.GetTxn(t, txn1.ID())},
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}
	// event for txn2
	ev2 := explorer.Event{
		ID:             types.Hash256(txn2.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		Data:           explorer.EventV1Transaction{Transaction: n.GetTxn(t, txn2.ID())},
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	// addr1 should be relevant to all transactions
	n.AssertEvents(t, addr1, ev2, ev1, ev0)
	n.AssertEvents(t, addr2, ev1)
	n.AssertEvents(t, addr3, ev2)

	n.RevertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}

	// genesis transaction still present but txn1 and txn2 reverted
	n.AssertEvents(t, addr1, ev0)
	n.AssertEvents(t, addr2)
	n.AssertEvents(t, addr3)
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
	genesisTxn := n.Genesis().Transactions[0]

	fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+1)
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
	testutil.SignTransaction(n.TipState(), pk1, &txn1)

	b := testutil.MineBlock(n.TipState(), []types.Transaction{txn1}, addr2)
	n.ApplyBlock(t, b)

	scID := b.ID().MinerOutputID(0)
	ev1 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeMinerPayout,
		Data:           explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      b.Timestamp,
	}
	n.AssertEvents(t, addr2, ev1)

	// see if confirmations number goes up when we mine another block
	n.MineTransactions(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)}
	n.AssertEvents(t, addr2, ev1)

	n.RevertBlock(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)}
	n.AssertEvents(t, addr2, ev1)

	n.RevertBlock(t)

	n.AssertEvents(t, addr2)
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
	genesisTxn := n.Genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	// txn1 - should be relevant to addr1 (due to input) and addr2 due to
	// sc output
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, genesisTxn.SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr2,
			Value:   genesisTxn.SiacoinOutputs[0].Value,
		}},
	}
	testutil.SignV2Transaction(n.TipState(), pk1, &txn1)

	// txn2 - should be relevant to addr1 (due to input) and addr3 due to
	// sf output
	txn2 := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          getSFE(t, n.DB, genesisTxn.SiafundOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: addr3,
			Value:   genesisTxn.SiafundOutputs[0].Value,
		}},
	}
	testutil.SignV2Transaction(n.TipState(), pk1, &txn2)

	n.MineV2Transactions(t, txn1, txn2)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	// event for txn1
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.GetV2Txn(t, txn1.ID())),
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}
	// event for txn2
	ev2 := explorer.Event{
		ID:             types.Hash256(txn2.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.GetV2Txn(t, txn2.ID())),
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	// addr1 should be relevant to all transactions
	n.AssertEvents(t, addr1, ev2, ev1, ev0)
	n.AssertEvents(t, addr2, ev1)
	n.AssertEvents(t, addr3, ev2)

	n.RevertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}

	// genesis transaction still present but txn1 and txn2 reverted
	n.AssertEvents(t, addr1, ev0)
	n.AssertEvents(t, addr2)
	n.AssertEvents(t, addr3)
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
	genesisTxn := n.Genesis().Transactions[0]

	// event for transaction in genesis block
	ev0 := explorer.Event{
		ID:             types.Hash256(genesisTxn.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV1Transaction,
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	// create file contract
	fc, payout := testchain.PrepareV2Contract(pk1, pk2, n.TipState().Index.Height+1)
	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          getSCE(t, n.DB, n.Genesis().Transactions[0].SiacoinOutputID(0)),
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr1,
			Value:   genesisTxn.SiacoinOutputs[0].Value.Sub(payout),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, pk1, pk2, &txn1)

	n.MineV2Transactions(t, txn1)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	// event for fc creation txn
	ev1 := explorer.Event{
		ID:             types.Hash256(txn1.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.GetV2Txn(t, txn1.ID())),
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	n.AssertEvents(t, addr1, ev1, ev0)
	n.AssertEvents(t, addr2, ev1)

	fcID := txn1.V2FileContractID(txn1.ID(), 0)
	sp := &types.V2StorageProof{
		ProofIndex: getCIE(t, n.DB, n.TipState().Index.ID),
	}
	txn2 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent:     getFCE(t, n.DB, fcID),
			Resolution: sp,
		}},
	}
	n.MineV2Transactions(t, txn2)

	ev1.Data = explorer.EventV2Transaction(n.GetV2Txn(t, txn1.ID()))
	// event for resolution txn
	ev2 := explorer.Event{
		ID:             types.Hash256(txn2.ID()),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeV2Transaction,
		Data:           explorer.EventV2Transaction(n.GetV2Txn(t, txn2.ID())),
		MaturityHeight: n.TipState().Index.Height,
		Timestamp:      n.TipBlock().Timestamp,
	}

	resolution := n.GetV2Txn(t, txn2.ID()).FileContractResolutions[0]
	// event for renter output
	ev3 := explorer.Event{
		ID:    types.Hash256(fcID.V2RenterOutputID()),
		Index: n.TipState().Index,
		Type:  wallet.EventTypeV2ContractResolution,
		Data: explorer.EventV2ContractResolution{
			Resolution:     resolution,
			SiacoinElement: n.GetSCE(t, fcID.V2RenterOutputID()),
			Missed:         false,
		},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      n.TipBlock().Timestamp,
	}
	// event for host output
	ev4 := explorer.Event{
		ID:    types.Hash256(fcID.V2HostOutputID()),
		Index: n.TipState().Index,
		Type:  wallet.EventTypeV2ContractResolution,
		Data: explorer.EventV2ContractResolution{
			Resolution:     resolution,
			SiacoinElement: n.GetSCE(t, fcID.V2HostOutputID()),
			Missed:         false,
		},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      n.TipBlock().Timestamp,
	}

	n.AssertEvents(t, addr1, ev3, ev2, ev1, ev0)
	n.AssertEvents(t, addr2, ev4, ev2, ev1)

	n.RevertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	ev1.Data = explorer.EventV2Transaction(n.GetV2Txn(t, txn1.ID()))
	n.AssertEvents(t, addr1, ev1, ev0)
	n.AssertEvents(t, addr2, ev1)

	n.RevertBlock(t)

	ev0.Data = explorer.EventV1Transaction{Transaction: n.GetTxn(t, genesisTxn.ID())}
	n.AssertEvents(t, addr1, ev0)
	n.AssertEvents(t, addr2)
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
	val := n.Genesis().Transactions[0].SiacoinOutputs[0].Value

	// create file contract
	fc, payout := testchain.PrepareV2Contract(pk1, pk1, n.TipState().Index.Height+1)
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
	testutil.SignV2TransactionWithContracts(n.TipState(), pk1, pk1, pk1, &txn1)

	b := testutil.MineV2Block(n.TipState(), nil, []types.V2Transaction{txn1}, addr2)
	n.ApplyBlock(t, b)

	scID := b.ID().MinerOutputID(0)
	ev1 := explorer.Event{
		ID:             types.Hash256(scID),
		Index:          n.TipState().Index,
		Type:           wallet.EventTypeMinerPayout,
		Data:           explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)},
		MaturityHeight: n.TipState().MaturityHeight() - 1,
		Timestamp:      b.Timestamp,
	}
	n.AssertEvents(t, addr2, ev1)

	// see if confirmations number goes up when we mine another block
	n.MineTransactions(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)}
	n.AssertEvents(t, addr2, ev1)

	n.RevertBlock(t)

	// MerkleProof changes
	ev1.Data = explorer.EventPayout{SiacoinElement: n.GetSCE(t, scID)}
	n.AssertEvents(t, addr2, ev1)

	n.RevertBlock(t)

	n.AssertEvents(t, addr2)
}
