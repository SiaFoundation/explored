package sqlite

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testchain"
	"go.sia.tech/explored/internal/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"lukechampine.com/frand"
)

func newTestChain(t testing.TB, v2 bool, modifyGenesis func(*consensus.Network, types.Block)) *testchain.Chain {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	db, err := OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	return testchain.New(t, db, v2, modifyGenesis)
}

func BenchmarkTransactions(b *testing.B) {
	const nTransactions = 1_000_000

	n := newTestChain(b, false, nil)

	// add random transactions that are either empty, contain arbitrary
	// or contain a contract formation
	var ids []types.TransactionID
	err := n.DB.(*Store).transaction(func(tx *txn) error {
		fceStmt, err := tx.Prepare(`INSERT INTO file_contract_elements(block_id, transaction_id, contract_id, leaf_index, filesize, file_merkle_root, window_start, window_end, payout, unlock_hash, revision_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer fceStmt.Close()

		txnStmt, err := tx.Prepare(`INSERT INTO transactions(transaction_id) VALUES (?)`)
		if err != nil {
			return err
		}
		defer txnStmt.Close()

		txnArbitraryDataStmt, err := tx.Prepare(`INSERT INTO transaction_arbitrary_data(transaction_id, transaction_order, data) VALUES (?, ?, ?)`)
		if err != nil {
			return err
		}
		defer txnArbitraryDataStmt.Close()

		txnContractsStmt, err := tx.Prepare(`INSERT INTO transaction_file_contracts(transaction_id, transaction_order, contract_id) VALUES (?, ?, ?)`)
		if err != nil {
			return err
		}
		defer txnContractsStmt.Close()

		arbitraryData := make([]byte, 64)
		frand.Read(arbitraryData)

		bid := encode(n.TipState().Index.ID)
		leafIndex := encode(uint64(0))
		filesize, fileMerkleRoot, windowStart, windowEnd, payout, unlockHash, revisionNumber := encode(uint64(0)), encode(types.Hash256{}), encode(uint64(0)), encode(uint64(0)), encode(types.NewCurrency64(1)), encode(types.Address{}), encode(uint64(0))
		for i := range nTransactions {
			if i%(nTransactions/10) == 0 {
				b.Log("Inserted transaction:", i)
			}

			var txnID types.TransactionID
			frand.Read(txnID[:])
			ids = append(ids, txnID)

			result, err := txnStmt.Exec(encode(txnID))
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
				// transaction with arbitrary data
				if _, err = txnArbitraryDataStmt.Exec(txnDBID, 0, arbitraryData); err != nil {
					return err
				}
			case 2:
				// transaction with file contract formation
				var fcID types.FileContractID
				frand.Read(fcID[:])

				result, err = fceStmt.Exec(bid, encode(txnID), encode(fcID), leafIndex, filesize, fileMerkleRoot, windowStart, windowEnd, payout, unlockHash, revisionNumber)
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

	for _, limit := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%d transactions", limit), func(b *testing.B) {
			for b.Loop() {
				offset := frand.Intn(len(ids) - limit)
				txnIDs := ids[offset : offset+limit]

				txns, err := n.DB.Transactions(txnIDs)
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

func BenchmarkSiacoinOutputs(b *testing.B) {
	const nElements = 5_000_000

	addr1 := types.StandardUnlockConditions(types.GeneratePrivateKey().PublicKey()).UnlockHash()
	n := newTestChain(b, false, nil)

	// add a bunch of random outputs
	var ids []types.SiacoinOutputID
	err := n.DB.(*Store).transaction(func(tx *txn) error {
		stmt, err := tx.Prepare(`INSERT INTO siacoin_elements(block_id, output_id, leaf_index, spent_index, source, maturity_height, address, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		spentIndex := encode(n.TipState().Index)
		bid := encode(n.TipState().Index.ID)
		val := encode(types.NewCurrency64(1))

		var addr types.Address
		for i := range nElements {
			if i%(nElements/10) == 0 {
				b.Log("Inserted siacoin element:", i)
			}

			var scID types.SiacoinOutputID
			frand.Read(scID[:])
			ids = append(ids, scID)

			// label half of elements spent
			var spent any
			if i%2 == 0 {
				spent = spentIndex
			}
			// give each address three outputs
			if i%3 == 0 {
				frand.Read(addr[:])
			}
			if _, err := stmt.Exec(bid, encode(scID), encode(uint64(0)), spent, explorer.SourceTransaction, frand.Uint64n(144), encode(addr), val); err != nil {
				return err
			}
		}

		// give addr1 2000 outputs, 1000 of which are spent
		for i := range 2000 {
			// label half of elements spent
			var spent any
			if i%2 == 0 {
				spent = spentIndex
			}

			var scID types.SiacoinOutputID
			frand.Read(scID[:])

			if _, err := stmt.Exec(bid, encode(scID), encode(uint64(0)), spent, explorer.SourceTransaction, 0, encode(addr1), val); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		b.Fatal(err)
	}

	for _, limit := range []uint64{10, 100, 1000} {
		b.Run(fmt.Sprintf("%d unspent outputs", limit), func(b *testing.B) {
			for b.Loop() {
				offset := frand.Uint64n(1000 - limit + 1)

				sces, err := n.DB.UnspentSiacoinOutputs(addr1, offset, limit)
				if err != nil {
					b.Fatal(err)
				}
				if limit != uint64(len(sces)) {
					b.Fatalf("expected %d sces, got %d", limit, len(sces))
				}
			}
		})
	}

	for _, limit := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%d siacoin elements", limit), func(b *testing.B) {
			for b.Loop() {
				offset := frand.Intn(len(ids) - limit)
				scIDs := ids[offset : offset+limit]

				sces, err := n.DB.SiacoinElements(scIDs)
				if err != nil {
					b.Fatal(err)
				}
				if limit != len(sces) {
					b.Fatalf("expected %d sces, got %d", limit, len(sces))
				}
			}
		})
	}
}

func BenchmarkSiafundOutputs(b *testing.B) {
	const nElements = 5_000_000

	addr1 := types.StandardUnlockConditions(types.GeneratePrivateKey().PublicKey()).UnlockHash()
	n := newTestChain(b, false, nil)

	// add a bunch of random outputs
	var ids []types.SiafundOutputID
	err := n.DB.(*Store).transaction(func(tx *txn) error {
		stmt, err := tx.Prepare(`INSERT INTO siafund_elements(block_id, output_id, leaf_index, spent_index, claim_start, address, value) VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		spentIndex := encode(n.TipState().Index)
		bid := encode(n.TipState().Index.ID)
		val := encode(types.NewCurrency64(1))

		var addr types.Address
		for i := range nElements {
			if i%(nElements/10) == 0 {
				b.Log("Inserted siafund element:", i)
			}

			var sfID types.SiafundOutputID
			frand.Read(sfID[:])
			ids = append(ids, sfID)

			// label half of elements spent
			var spent any
			if i%2 == 0 {
				spent = spentIndex
			}
			// give each address three outputs
			if i%3 == 0 {
				frand.Read(addr[:])
			}
			if _, err := stmt.Exec(bid, encode(sfID), encode(uint64(0)), spent, val, encode(addr), val); err != nil {
				return err
			}
		}

		// give addr1 2000 outputs, 1000 of which are spent
		for i := range 2000 {
			// label half of elements spent
			var spent any
			if i%2 == 0 {
				spent = spentIndex
			}

			var sfID types.SiacoinOutputID
			frand.Read(sfID[:])

			if _, err := stmt.Exec(bid, encode(sfID), encode(uint64(0)), spent, val, encode(addr1), val); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		b.Fatal(err)
	}

	for _, limit := range []uint64{10, 100, 1000} {
		b.Run(fmt.Sprintf("%d unspent outputs", limit), func(b *testing.B) {
			for b.Loop() {
				offset := frand.Uint64n(1000 - limit + 1)

				sfes, err := n.DB.UnspentSiafundOutputs(addr1, offset, limit)
				if err != nil {
					b.Fatal(err)
				}
				if limit != uint64(len(sfes)) {
					b.Fatalf("expected %d sfes, got %d", limit, len(sfes))
				}
			}
		})
	}

	for _, limit := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%d siafund elements", limit), func(b *testing.B) {
			for b.Loop() {
				offset := frand.Intn(len(ids) - limit)
				scIDs := ids[offset : offset+limit]

				sfes, err := n.DB.SiafundElements(scIDs)
				if err != nil {
					b.Fatal(err)
				}
				if limit != len(sfes) {
					b.Fatalf("expected %d sfes, got %d", limit, len(sfes))
				}
			}
		})
	}
}

func BenchmarkAddressEvents(b *testing.B) {
	// adapted from https://github.com/SiaFoundation/walletd/blob/c3cc9d9b3efba616d20baa2962474d73f872f2ba/persist/sqlite/events_test.go
	runBenchmarkEvents := func(name string, addresses, eventsPerAddress int) {
		b.Run(name, func(b *testing.B) {
			n := newTestChain(b, false, nil)

			var addrs []types.Address
			err := n.DB.(*Store).transaction(func(tx *txn) error {
				txnStmt, err := tx.Prepare(`INSERT INTO transactions(transaction_id) VALUES (?)`)
				if err != nil {
					return err
				}
				defer txnStmt.Close()

				insertEventStmt, err := tx.Prepare(`INSERT INTO events (event_id, maturity_height, date_created, event_type, block_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (event_id) DO NOTHING RETURNING id`)
				if err != nil {
					b.Fatal(err)
				}
				defer insertEventStmt.Close()

				addrStmt, err := tx.Prepare(`INSERT INTO address_balance (address, siacoin_balance, immature_siacoin_balance, siafund_balance) VALUES ($1, $2, $2, 0) ON CONFLICT (address) DO UPDATE SET address=EXCLUDED.address RETURNING id`)
				if err != nil {
					b.Fatal(err)
				}
				defer addrStmt.Close()

				relevantAddrStmt, err := tx.Prepare(`INSERT INTO event_addresses (event_id, address_id, event_maturity_height) VALUES ($1, $2, $3) ON CONFLICT (event_id, address_id) DO NOTHING`)
				if err != nil {
					b.Fatal(err)
				}
				defer relevantAddrStmt.Close()

				v1TransactionEventStmt, err := tx.Prepare(`INSERT INTO v1_transaction_events (event_id, transaction_id) VALUES (?, ?)`)
				if err != nil {
					b.Fatal(err)
				}
				defer v1TransactionEventStmt.Close()

				for range addresses {
					addr := types.Address(frand.Entropy256())
					addrs = append(addrs, addr)
					bid := n.TipState().Index.ID

					var addressID int64
					err = addrStmt.QueryRow(encode(addr), encode(types.ZeroCurrency)).Scan(&addressID)
					if err != nil {
						b.Fatal(err)
					}

					now := time.Now()
					for i := range eventsPerAddress {
						ev := wallet.Event{
							ID:             types.Hash256(frand.Entropy256()),
							MaturityHeight: uint64(i + 1),
							Relevant:       []types.Address{addr},
							Type:           wallet.EventTypeV1Transaction,
						}

						result, err := txnStmt.Exec(encode(ev.ID))
						if err != nil {
							b.Fatal(err)
						}
						txnID, err := result.LastInsertId()
						if err != nil {
							b.Fatal(err)
						}

						var eventID int64
						if err := insertEventStmt.QueryRow(encode(ev.ID), ev.MaturityHeight, encode(now), ev.Type, encode(bid)).Scan(&eventID); err != nil {
							b.Fatal(err)
						} else if _, err := relevantAddrStmt.Exec(eventID, addressID, ev.MaturityHeight); err != nil {
							b.Fatal(err)
						} else if _, err := v1TransactionEventStmt.Exec(eventID, txnID); err != nil {
							b.Fatal(err)
						}
					}
				}
				return nil
			})
			if err != nil {
				b.Fatal(err)
			}

			i := 0
			for b.Loop() {
				const limit = 100
				offset := frand.Intn(eventsPerAddress - min(eventsPerAddress, limit) + 1)
				events, err := n.DB.AddressEvents(addrs[i%len(addrs)], uint64(offset), limit)
				if err != nil {
					b.Fatal(err)
				}
				if len(events) != min(limit, eventsPerAddress) {
					b.Fatalf("expected %d events, got %d", eventsPerAddress, len(events))
				}

				i++
			}
		})
	}

	benchmarks := []struct {
		addresses        int
		eventsPerAddress int
	}{
		{1, 1},
		{1, 10},
		{1, 1000},
		{10, 1},
		{10, 1000},
		{10, 100000},
		{100000, 1},
		{100000, 10},
	}
	for _, bm := range benchmarks {
		runBenchmarkEvents(fmt.Sprintf("%d addresses and %d transactions per address", bm.addresses, bm.eventsPerAddress), bm.addresses, bm.eventsPerAddress)
	}
}

func BenchmarkApplyRevert(b *testing.B) {
	const nBlocks = 20_000

	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	n := newTestChain(b, false, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 1_000_000
		network.HardforkV2.FinalCutHeight = 1_000_001
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisTxn := n.Genesis().Transactions[0]

	val := genesisTxn.SiacoinOutputs[0].Value
	scID := genesisTxn.SiacoinOutputID(0)

	generateBlock := func() types.Block {
		// transaction with random arbitrary data
		data := make([]byte, 16)
		frand.Read(data)
		txn1 := types.Transaction{
			ArbitraryData: [][]byte{data},
		}

		fc := testchain.PrepareContract(addr1, n.TipState().Index.Height+1)
		// create file contract
		txn2 := types.Transaction{
			SiacoinInputs: []types.SiacoinInput{{
				ParentID:         scID,
				UnlockConditions: uc1,
			}},
			SiacoinOutputs: []types.SiacoinOutput{{
				Address: addr1,
				Value:   val.Sub(fc.Payout),
			}},
			FileContracts: []types.FileContract{fc},
		}
		testutil.SignTransaction(n.TipState(), pk1, &txn2)

		scID = txn2.SiacoinOutputID(0)
		val = txn2.SiacoinOutputs[0].Value

		// txn3
		txn3 := types.V2Transaction{
			SiacoinInputs: []types.V2SiacoinInput{{
				// Parent:          getSCE(b, n.db, scID),
				Parent: types.SiacoinElement{
					ID: txn2.SiacoinOutputID(0),
					StateElement: types.StateElement{
						LeafIndex: types.UnassignedLeafIndex,
					},
					SiacoinOutput: txn2.SiacoinOutputs[0],
				},
				SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
			}},
			SiacoinOutputs: []types.SiacoinOutput{{
				Address: addr1,
				Value:   val,
			}},
		}
		testutil.SignV2Transaction(n.TipState(), pk1, &txn3)

		scID = txn3.SiacoinOutputID(txn3.ID(), 0)
		val = txn3.SiacoinOutputs[0].Value

		v2FC, payout := testchain.PrepareV2Contract(pk1, pk1, n.TipState().Index.Height+1)
		txn4 := types.V2Transaction{
			SiacoinInputs: []types.V2SiacoinInput{{
				Parent: types.SiacoinElement{
					ID: txn3.SiacoinOutputID(txn3.ID(), 0),
					StateElement: types.StateElement{
						LeafIndex: types.UnassignedLeafIndex,
					},
					SiacoinOutput: txn3.SiacoinOutputs[0],
				},
				SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
			}},
			SiacoinOutputs: []types.SiacoinOutput{{
				Address: addr1,
				Value:   val.Sub(payout),
			}},
			FileContracts: []types.V2FileContract{v2FC},
		}
		testutil.SignV2TransactionWithContracts(n.TipState(), pk1, pk1, pk1, &txn4)

		scID = txn4.SiacoinOutputID(txn4.ID(), 0)
		val = txn4.SiacoinOutputs[0].Value

		return testutil.MineV2Block(n.TipState(), []types.Transaction{txn1, txn2}, []types.V2Transaction{txn3, txn4}, types.VoidAddress)
	}

	for i := range nBlocks {
		if i%100 == 0 {
			b.Logf("Mined %d blocks", i)
		}

		n.ApplyBlock(b, generateBlock())
	}

	block := generateBlock()
	bs := n.Store.SupplementTipBlock(block)
	prevState := n.States[len(n.States)-1]

	if err := consensus.ValidateBlock(prevState, block, bs); err != nil {
		b.Fatal(err)
	}
	cs, au := consensus.ApplyBlock(prevState, block, bs, time.Time{})
	caus := []chain.ApplyUpdate{{
		ApplyUpdate: au,
		Block:       block,
		State:       cs,
	}}

	ru := consensus.RevertBlock(prevState, block, bs)
	crus := []chain.RevertUpdate{{
		RevertUpdate: ru,
		Block:        block,
		State:        prevState,
	}}

	b.Run("apply", func(b *testing.B) {
		log := zap.NewNop()
		for b.Loop() {
			err := n.DB.(*Store).transaction(func(tx *txn) error {
				utx := &updateTx{tx: tx}
				return explorer.UpdateChainState(utx, nil, caus, log)
			})
			if err != nil {
				b.Fatal(err)
			}

			b.StopTimer()
			err = n.DB.(*Store).transaction(func(tx *txn) error {
				utx := &updateTx{tx: tx}
				return explorer.UpdateChainState(utx, crus, nil, log)
			})
			if err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
		}
	})

	block = n.Blocks[len(n.Blocks)-1]
	bs = n.Supplements[len(n.Supplements)-1]
	prevState = n.States[len(n.States)-2]

	ru = consensus.RevertBlock(prevState, block, bs)
	crus = []chain.RevertUpdate{{
		RevertUpdate: ru,
		Block:        block,
		State:        prevState,
	}}

	if err := consensus.ValidateBlock(prevState, block, bs); err != nil {
		b.Fatal(err)
	}
	cs, au = consensus.ApplyBlock(prevState, block, bs, time.Time{})
	caus = []chain.ApplyUpdate{{
		ApplyUpdate: au,
		Block:       block,
		State:       cs,
	}}

	b.Run("revert", func(b *testing.B) {
		log := zap.NewNop()
		for b.Loop() {
			err := n.DB.(*Store).transaction(func(tx *txn) error {
				utx := &updateTx{tx: tx}
				return explorer.UpdateChainState(utx, crus, nil, log)
			})

			b.StopTimer()
			err = n.DB.(*Store).transaction(func(tx *txn) error {
				utx := &updateTx{tx: tx}
				return explorer.UpdateChainState(utx, nil, caus, log)
			})
			if err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
		}
	})
}
