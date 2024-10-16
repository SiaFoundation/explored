package sqlite_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	ctestutil "go.sia.tech/coreutils/testutil"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap/zaptest"
)

type consensusDB struct {
	sces   map[types.SiacoinOutputID]types.SiacoinElement
	sfes   map[types.SiafundOutputID]types.SiafundElement
	fces   map[types.FileContractID]types.FileContractElement
	v2fces map[types.FileContractID]types.V2FileContractElement
}

func (db *consensusDB) applyBlock(au consensus.ApplyUpdate) {
	for id, sce := range db.sces {
		au.UpdateElementProof(&sce.StateElement)
		db.sces[id] = sce
	}
	for id, sfe := range db.sfes {
		au.UpdateElementProof(&sfe.StateElement)
		db.sfes[id] = sfe
	}
	for id, fce := range db.fces {
		au.UpdateElementProof(&fce.StateElement)
		db.fces[id] = fce
	}
	for id, fce := range db.v2fces {
		au.UpdateElementProof(&fce.StateElement)
		db.v2fces[id] = fce
	}
	au.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
		if spent {
			delete(db.sces, types.SiacoinOutputID(sce.ID))
		} else {
			db.sces[types.SiacoinOutputID(sce.ID)] = sce
		}
	})
	au.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
		if spent {
			delete(db.sfes, types.SiafundOutputID(sfe.ID))
		} else {
			db.sfes[types.SiafundOutputID(sfe.ID)] = sfe
		}
	})
	au.ForEachFileContractElement(func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool) {
		if created {
			db.fces[types.FileContractID(fce.ID)] = fce
		} else if rev != nil {
			db.fces[types.FileContractID(fce.ID)] = *rev
		} else if resolved {
			delete(db.fces, types.FileContractID(fce.ID))
		}
	})
	au.ForEachV2FileContractElement(func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
		if created {
			db.v2fces[types.FileContractID(fce.ID)] = fce
		} else if rev != nil {
			db.v2fces[types.FileContractID(fce.ID)] = *rev
		} else if res != nil {
			delete(db.v2fces, types.FileContractID(fce.ID))
		}
	})
}

func (db *consensusDB) revertBlock(ru consensus.RevertUpdate) {
	ru.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
		if spent {
			db.sces[types.SiacoinOutputID(sce.ID)] = sce
		} else {
			delete(db.sces, types.SiacoinOutputID(sce.ID))
		}
	})
	ru.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
		if spent {
			db.sfes[types.SiafundOutputID(sfe.ID)] = sfe
		} else {
			delete(db.sfes, types.SiafundOutputID(sfe.ID))
		}
	})
	ru.ForEachFileContractElement(func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool) {
		if created {
			delete(db.fces, types.FileContractID(fce.ID))
		} else if rev != nil {
			db.fces[types.FileContractID(fce.ID)] = fce
		} else if resolved {
			db.fces[types.FileContractID(fce.ID)] = fce
		}
	})
	ru.ForEachV2FileContractElement(func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
		if created {
			delete(db.v2fces, types.FileContractID(fce.ID))
		} else if rev != nil {
			db.v2fces[types.FileContractID(fce.ID)] = fce
		} else if res != nil {
			db.v2fces[types.FileContractID(fce.ID)] = fce
		}
	})
	for id, sce := range db.sces {
		ru.UpdateElementProof(&sce.StateElement)
		db.sces[id] = sce
	}
	for id, sfe := range db.sfes {
		ru.UpdateElementProof(&sfe.StateElement)
		db.sfes[id] = sfe
	}
	for id, fce := range db.fces {
		ru.UpdateElementProof(&fce.StateElement)
		db.fces[id] = fce
	}
	for id, fce := range db.v2fces {
		ru.UpdateElementProof(&fce.StateElement)
		db.v2fces[id] = fce
	}
}

func (db *consensusDB) supplementTipBlock(b types.Block) (bs consensus.V1BlockSupplement) {
	bs = consensus.V1BlockSupplement{
		Transactions: make([]consensus.V1TransactionSupplement, len(b.Transactions)),
	}
	for i, txn := range b.Transactions {
		ts := &bs.Transactions[i]
		for _, sci := range txn.SiacoinInputs {
			if sce, ok := db.sces[sci.ParentID]; ok {
				ts.SiacoinInputs = append(ts.SiacoinInputs, sce)
			}
		}
		for _, sfi := range txn.SiafundInputs {
			if sfe, ok := db.sfes[sfi.ParentID]; ok {
				ts.SiafundInputs = append(ts.SiafundInputs, sfe)
			}
		}
		for _, fcr := range txn.FileContractRevisions {
			if fce, ok := db.fces[fcr.ParentID]; ok {
				ts.RevisedFileContracts = append(ts.RevisedFileContracts, fce)
			}
		}
	}
	return bs
}

func (db *consensusDB) ancestorTimestamp(types.BlockID) time.Time {
	return time.Time{}
}

// v2SyncDB is the same as syncDB but it updates the consensusDB `edb` to keep
// track of elements and update their proofs to make teseting easier.
func v2SyncDB(t *testing.T, edb *consensusDB, db *sqlite.Store, cm *chain.Manager) {
	index, err := db.Tip()
	if err != nil && !errors.Is(err, explorer.ErrNoTip) {
		t.Fatal(err)
	}

	for index != cm.Tip() {
		crus, caus, err := cm.UpdatesSince(index, 1000)
		if err != nil {
			t.Fatal(err)
		}

		if err := db.UpdateChainState(crus, caus); err != nil {
			t.Fatal("failed to process updates:", err)
		}

		if edb != nil {
			for _, cru := range crus {
				edb.revertBlock(cru.RevertUpdate)
			}
			for _, cau := range caus {
				edb.applyBlock(cau.ApplyUpdate)
			}
		}

		if len(crus) > 0 {
			index = crus[len(crus)-1].State.Index
		}
		if len(caus) > 0 {
			index = caus[len(caus)-1].State.Index
		}
	}
}

func newConsensusDB(n *consensus.Network, genesisBlock types.Block) (*consensusDB, consensus.State) {
	db := &consensusDB{
		sces:   make(map[types.SiacoinOutputID]types.SiacoinElement),
		sfes:   make(map[types.SiafundOutputID]types.SiafundElement),
		fces:   make(map[types.FileContractID]types.FileContractElement),
		v2fces: make(map[types.FileContractID]types.V2FileContractElement),
	}
	cs, au := consensus.ApplyBlock(n.GenesisState(), genesisBlock, db.supplementTipBlock(genesisBlock), time.Time{})
	db.applyBlock(au)
	return db, cs
}

func TestV2ArbitraryData(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	network, genesisBlock := ctestutil.V2Network()
	network.HardforkV2.AllowHeight = 1
	network.HardforkV2.RequireHeight = 2

	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
	}

	txn2 := types.V2Transaction{
		ArbitraryData: []byte("world"),
	}

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1, txn2}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	v2SyncDB(t, nil, db, cm)
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
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	network, genesisBlock := ctestutil.V2Network()
	network.HardforkV2.AllowHeight = 1
	network.HardforkV2.RequireHeight = 2

	genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	edb, _ := newConsensusDB(network, genesisBlock)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	txn1 := types.V2Transaction{
		ArbitraryData: []byte("hello"),
		MinerFee:      giftSC,
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          edb.sces[genesisBlock.Transactions[0].SiacoinOutputID(0)],
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
	}
	testutil.SignV2Transaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	v2SyncDB(t, edb, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}
}

func TestV2FoundationAddress(t *testing.T) {
	log := zaptest.NewLogger(t)
	dir := t.TempDir()
	db, err := sqlite.OpenDatabase(filepath.Join(dir, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()

	pk1 := types.GeneratePrivateKey()
	addr1 := types.StandardUnlockHash(pk1.PublicKey())
	addr1Policy := types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(types.StandardUnlockConditions(pk1.PublicKey()))}

	pk2 := types.GeneratePrivateKey()
	addr2 := types.StandardUnlockHash(pk2.PublicKey())

	network, genesisBlock := ctestutil.V2Network()
	network.HardforkFoundation.PrimaryAddress = addr1
	network.HardforkV2.AllowHeight = 1
	network.HardforkV2.RequireHeight = 2

	genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr1
	giftSC := genesisBlock.Transactions[0].SiacoinOutputs[0].Value

	edb, _ := newConsensusDB(network, genesisBlock)
	store, genesisState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	txn1 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          edb.sces[genesisBlock.Transactions[0].SiacoinOutputID(0)],
			SatisfiedPolicy: types.SatisfiedPolicy{Policy: addr1Policy},
		}},
		MinerFee:             giftSC,
		NewFoundationAddress: &addr2,
	}
	testutil.SignV2Transaction(cm.TipState(), pk1, &txn1)

	if err := cm.AddBlocks([]types.Block{testutil.MineV2Block(cm.TipState(), []types.V2Transaction{txn1}, types.VoidAddress)}); err != nil {
		t.Fatal(err)
	}
	v2SyncDB(t, edb, db, cm)

	{
		dbTxns, err := db.V2Transactions([]types.TransactionID{txn1.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.CheckV2Transaction(t, txn1, dbTxns[0])
	}
}
