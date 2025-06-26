package sqlite

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	proto2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"go.uber.org/zap/zaptest"
	"lukechampine.com/frand"
)

type testChain struct {
	db    *Store
	store *chain.DBStore

	network     *consensus.Network
	blocks      []types.Block
	supplements []consensus.V1BlockSupplement
	states      []consensus.State
}

func newTestChain(t testing.TB, v2 bool, modifyGenesis func(*consensus.Network, types.Block)) *testChain {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()

	db, err := OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	var network *consensus.Network
	var genesisBlock types.Block
	if v2 {
		network, genesisBlock = ctestutil.V2Network()
	} else {
		network, genesisBlock = ctestutil.Network()
	}
	if v2 {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
	}
	if modifyGenesis != nil {
		modifyGenesis(network, genesisBlock)
	}

	store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), network, genesisBlock, nil)
	if err != nil {
		t.Fatal(err)
	}

	bs := consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(genesisBlock.Transactions))}
	_, au := consensus.ApplyBlock(network.GenesisState(), genesisBlock, bs, time.Time{})
	if err := db.UpdateChainState(nil, []chain.ApplyUpdate{{
		ApplyUpdate: au,
		Block:       genesisBlock,
		State:       genesisState,
	}}); err != nil {
		t.Fatal(err)
	}

	return &testChain{
		db:    db,
		store: store,

		network:     network,
		blocks:      []types.Block{genesisBlock},
		supplements: []consensus.V1BlockSupplement{bs},
		states:      []consensus.State{genesisState},
	}
}

func (n *testChain) genesis() types.Block {
	return n.blocks[0]
}

func (n *testChain) tipBlock() types.Block {
	return n.blocks[len(n.blocks)-1]
}

func (n *testChain) tipState() consensus.State {
	return n.states[len(n.states)-1]
}

func (n *testChain) applyBlock(t testing.TB, b types.Block) {
	t.Helper()

	cs := n.tipState()
	bs := n.store.SupplementTipBlock(b)
	if cs.Index.Height != math.MaxUint64 {
		// don't validate genesis block
		if err := consensus.ValidateBlock(cs, b, bs); err != nil {
			t.Fatal(err)
		}
	}

	cs, au := consensus.ApplyBlock(cs, b, bs, time.Time{})
	if err := n.db.UpdateChainState(nil, []chain.ApplyUpdate{{
		ApplyUpdate: au,
		Block:       b,
		State:       cs,
	}}); err != nil {
		t.Fatal(err)
	}

	n.store.AddState(cs)
	n.store.AddBlock(b, &bs)
	n.store.ApplyBlock(cs, au)

	n.blocks = append(n.blocks, b)
	n.supplements = append(n.supplements, bs)
	n.states = append(n.states, cs)
}

func (n *testChain) revertBlock(t testing.TB) {
	b := n.blocks[len(n.blocks)-1]
	bs := n.supplements[len(n.supplements)-1]
	prevState := n.states[len(n.states)-2]

	ru := consensus.RevertBlock(prevState, b, bs)
	if err := n.db.UpdateChainState([]chain.RevertUpdate{{
		RevertUpdate: ru,
		Block:        b,
		State:        prevState,
	}}, nil); err != nil {
		t.Fatal(err)
	}

	n.store.RevertBlock(prevState, ru)

	n.blocks = n.blocks[:len(n.blocks)-1]
	n.supplements = n.supplements[:len(n.supplements)-1]
	n.states = n.states[:len(n.states)-1]
}

func (n *testChain) mineTransactions(t testing.TB, txns ...types.Transaction) {
	t.Helper()

	b := testutil.MineBlock(n.tipState(), txns, types.VoidAddress)
	n.applyBlock(t, b)
}

func (n *testChain) assertTransactions(t testing.TB, expected ...types.Transaction) {
	t.Helper()

	for _, txn := range expected {
		txns, err := n.db.Transactions([]types.TransactionID{txn.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 1, len(txns))

		testutil.CheckTransaction(t, txn, txns[0])
	}
}

func (n *testChain) assertContractRevisions(t testing.TB, fcID types.FileContractID, expected ...explorer.ExtendedFileContract) {
	t.Helper()

	fces, err := n.db.ContractRevisions(fcID)
	if len(expected) == 0 {
		if !errors.Is(err, explorer.ErrContractNotFound) {
			t.Fatal("should have got contract not found error")
		}
		return
	} else if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(fces)", len(expected), len(fces))

	for i := range expected {
		testutil.Equal(t, "ExtendedFileContract", expected[i], fces[i])
	}
}

func (n *testChain) assertEvents(t testing.TB, addr types.Address, expected ...explorer.Event) {
	t.Helper()

	events, err := n.db.AddressEvents(addr, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, "len(events)", len(expected), len(events))

	for i := range expected {
		expected[i].Relevant = []types.Address{addr}
		expected[i].Confirmations = n.tipState().Index.Height - expected[i].Index.Height
		testutil.Equal(t, "Event", expected[i], events[i])
	}

	for i := range expected {
		events, err := n.db.Events([]types.Hash256{expected[i].ID})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(events)", 1, len(events))

		expected[i].Relevant = nil
		testutil.Equal(t, "Event", expected[i], events[0])
	}
}

func (n *testChain) getSCE(t testing.TB, scID types.SiacoinOutputID) explorer.SiacoinOutput {
	t.Helper()

	sces, err := n.db.SiacoinElements([]types.SiacoinOutputID{scID})
	if err != nil {
		t.Fatal(err)
	} else if len(sces) == 0 {
		t.Fatal("can't find sce")
	}
	sces[0].StateElement.MerkleProof = nil
	return sces[0]
}

func (n *testChain) getFCE(t testing.TB, fcID types.FileContractID) explorer.ExtendedFileContract {
	t.Helper()

	fces, err := n.db.Contracts([]types.FileContractID{fcID})
	if err != nil {
		t.Fatal(err)
	} else if len(fces) == 0 {
		t.Fatal("can't find fce")
	}
	return fces[0]
}

func (n *testChain) getTxn(t testing.TB, txnID types.TransactionID) explorer.Transaction {
	t.Helper()

	txns, err := n.db.Transactions([]types.TransactionID{txnID})
	if err != nil {
		t.Fatal(err)
	} else if len(txns) == 0 {
		t.Fatal("can't find txn")
	}
	return txns[0]
}

func prepareContract(addr types.Address, endHeight uint64) types.FileContract {
	rk := types.GeneratePrivateKey().PublicKey()
	rAddr := types.StandardUnlockHash(rk)
	hk := types.GeneratePrivateKey().PublicKey()
	hs := proto2.HostSettings{
		WindowSize: 1,
		Address:    types.StandardUnlockHash(hk),
	}
	sc := types.Siacoins(1)
	fc := proto2.PrepareContractFormation(rk, hk, sc.Mul64(5), sc.Mul64(5), endHeight, hs, rAddr)
	fc.UnlockHash = addr
	return fc
}

func (n *testChain) assertBlock(t testing.TB, cs consensus.State, block types.Block) {
	got, err := n.db.Block(block.ID())
	if err != nil {
		t.Fatal(err)
	}

	testutil.Equal(t, "ParentID", block.ParentID, got.ParentID)
	testutil.Equal(t, "Nonce", block.Nonce, got.Nonce)
	testutil.Equal(t, "Timestamp", block.Timestamp, got.Timestamp)
	testutil.Equal(t, "Height", cs.Index.Height, got.Height)

	testutil.Equal(t, "len(MinerPayouts)", len(block.MinerPayouts), len(got.MinerPayouts))
	for i, sco := range got.MinerPayouts {
		testutil.Equal(t, "Source", explorer.SourceMinerPayout, sco.Source)
		testutil.Equal(t, "SpentIndex", nil, sco.SpentIndex)
		testutil.Equal(t, "SiacoinOutput", block.MinerPayouts[i], sco.SiacoinOutput)
	}

	testutil.Equal(t, "len(Transactions)", len(block.Transactions), len(got.Transactions))
	for i, txn := range got.Transactions {
		testutil.CheckTransaction(t, block.Transactions[i], txn)
	}

	if block.V2 != nil {
		testutil.Equal(t, "Height", block.V2.Height, got.V2.Height)
		testutil.Equal(t, "Commitment", block.V2.Commitment, got.V2.Commitment)

		testutil.Equal(t, "len(V2Transactions)", len(block.V2.Transactions), len(got.V2.Transactions))
		for i, txn := range got.V2.Transactions {
			testutil.CheckV2Transaction(t, block.V2.Transactions[i], txn)
		}
	}
}

func TestTip(t *testing.T) {
	n := newTestChain(t, false, nil)

	checkTips := func() {
		t.Helper()

		tip, err := n.db.Tip()
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "tip", n.tipState().Index, tip)

		for _, state := range n.states {
			best, err := n.db.BestTip(state.Index.Height)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "best tip", state.Index, best)
		}
	}
	checkTips()

	n.mineTransactions(t)
	checkTips()

	n.mineTransactions(t)
	checkTips()

	n.revertBlock(t)
	checkTips()

	n.revertBlock(t)
	checkTips()
}

func TestMissingTip(t *testing.T) {
	n := newTestChain(t, false, nil)

	_, err := n.db.BestTip(n.tipState().Index.Height)
	if err != nil {
		t.Fatalf("error retrieving tip known to exist: %v", err)
	}

	_, err = n.db.BestTip(n.tipState().Index.Height + 1)
	if !errors.Is(err, explorer.ErrNoTip) {
		t.Fatalf("should have got ErrNoTip retrieving: %v", err)
	}
}

func TestMissingBlock(t *testing.T) {
	n := newTestChain(t, false, nil)

	id := n.tipState().Index.ID
	_, err := n.db.Block(id)
	if err != nil {
		t.Fatalf("error retrieving genesis block: %v", err)
	}

	id[0] ^= 255
	_, err = n.db.Block(id)
	if !errors.Is(err, explorer.ErrNoBlock) {
		t.Fatalf("did not get ErrNoBlock retrieving missing block: %v", err)
	}
}

func TestBlock(t *testing.T) {
	n := newTestChain(t, false, nil)

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

	n.mineTransactions(t, types.Transaction{ArbitraryData: [][]byte{{0}}})

	checkBlocks(2)

	n.revertBlock(t)

	checkBlocks(1)
}

func BenchmarkTransactions(b *testing.B) {
	const nTransactions = 1_000_000

	n := newTestChain(b, false, nil)

	// add random transactions that are either empty, contain arbitrary
	// or contain a contract formation
	var ids []types.TransactionID
	err := n.db.transaction(func(tx *txn) error {
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

		bid := encode(n.tipState().Index.ID)
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

				txns, err := n.db.Transactions(txnIDs)
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
	err := n.db.transaction(func(tx *txn) error {
		stmt, err := tx.Prepare(`INSERT INTO siacoin_elements(block_id, output_id, leaf_index, spent_index, source, maturity_height, address, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		spentIndex := encode(n.tipState().Index)
		bid := encode(n.tipState().Index.ID)
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

				sces, err := n.db.UnspentSiacoinOutputs(addr1, offset, limit)
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

				sces, err := n.db.SiacoinElements(scIDs)
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
	err := n.db.transaction(func(tx *txn) error {
		stmt, err := tx.Prepare(`INSERT INTO siafund_elements(block_id, output_id, leaf_index, spent_index, claim_start, address, value) VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		spentIndex := encode(n.tipState().Index)
		bid := encode(n.tipState().Index.ID)
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

				sfes, err := n.db.UnspentSiafundOutputs(addr1, offset, limit)
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

				sfes, err := n.db.SiafundElements(scIDs)
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
			err := n.db.transaction(func(tx *txn) error {
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
					bid := n.tipState().Index.ID

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
				events, err := n.db.AddressEvents(addrs[i%len(addrs)], uint64(offset), limit)
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

func BenchmarkRevert(b *testing.B) {
	pk1 := types.GeneratePrivateKey()
	uc1 := types.StandardUnlockConditions(pk1.PublicKey())
	addr1 := uc1.UnlockHash()
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc1)}

	n := newTestChain(b, false, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 1_000_000
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	})
	genesisTxn := n.genesis().Transactions[0]

	val := genesisTxn.SiacoinOutputs[0].Value
	scID := genesisTxn.SiacoinOutputID(0)

	for i := range 20000 {
		if i%100 == 0 {
			b.Logf("Mined %d blocks", i)
		}

		// transaction with random arbitrary data
		data := make([]byte, 16)
		frand.Read(data)
		txn1 := types.Transaction{
			ArbitraryData: [][]byte{data},
		}

		fc := prepareContract(addr1, n.tipState().Index.Height+1)
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
		testutil.SignTransaction(n.tipState(), pk1, &txn2)

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
		testutil.SignV2Transaction(n.tipState(), pk1, &txn3)

		scID = txn3.SiacoinOutputID(txn3.ID(), 0)
		val = txn3.SiacoinOutputs[0].Value

		block := testutil.MineV2Block(n.tipState(), []types.Transaction{txn1, txn2}, []types.V2Transaction{txn3}, types.VoidAddress)
		n.applyBlock(b, block)
	}

	block := n.blocks[len(n.blocks)-1]
	bs := n.supplements[len(n.supplements)-1]
	prevState := n.states[len(n.states)-2]

	ru := consensus.RevertBlock(prevState, block, bs)
	crus := []chain.RevertUpdate{{
		RevertUpdate: ru,
		Block:        block,
		State:        prevState,
	}}

	b.ResetTimer()
	for range b.N {
		err := n.db.transaction(func(tx *txn) error {
			defer tx.Rollback()
			utx := &updateTx{
				tx: tx,
			}

			b.StartTimer()
			err := explorer.UpdateChainState(utx, crus, nil, n.db.log.Named("update"))
			b.StopTimer()

			if err != nil {
				return fmt.Errorf("failed to update chain state: %w", err)
			}
			return nil
		})
		if err != nil && !strings.Contains(err.Error(), "rolled back") {
			b.Fatal(err)
		}
	}
}
