//go:build testing

package storetest

import (
	"errors"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testchain"
	"go.sia.tech/explored/internal/testutil"
	"go.uber.org/zap/zaptest"
)

// testChain is the shared chain scaffolding from internal/testchain. Aliased
// here so tests can refer to it by the short package-local name.
type testChain = testchain.Chain

func newTestChain(t testing.TB, v2 bool, modifyGenesis func(*consensus.Network, types.Block)) *testChain {
	log := zaptest.NewLogger(t)
	return testchain.New(t, openStore(t, log.Named("store")), v2, modifyGenesis)
}

func TestTip(t *testing.T) {
	n := newTestChain(t, false, nil)

	checkTips := func() {
		t.Helper()

		tip, err := n.DB.Tip()
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "tip", n.TipState().Index, tip)

		for _, state := range n.States {
			best, err := n.DB.BestTip(state.Index.Height)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Equal(t, "best tip", state.Index, best)
		}
	}
	checkTips()

	n.MineTransactions(t)
	checkTips()

	n.MineTransactions(t)
	checkTips()

	n.RevertBlock(t)
	checkTips()

	n.RevertBlock(t)
	checkTips()
}

func TestMissingTip(t *testing.T) {
	n := newTestChain(t, false, nil)

	_, err := n.DB.BestTip(n.TipState().Index.Height)
	if err != nil {
		t.Fatalf("error retrieving tip known to exist: %v", err)
	}

	_, err = n.DB.BestTip(n.TipState().Index.Height + 1)
	if !errors.Is(err, explorer.ErrNoTip) {
		t.Fatalf("should have got ErrNoTip retrieving: %v", err)
	}
}

func TestMissingBlock(t *testing.T) {
	n := newTestChain(t, false, nil)

	id := n.TipState().Index.ID
	_, err := n.DB.Block(id)
	if err != nil {
		t.Fatalf("error retrieving genesis block: %v", err)
	}

	id[0] ^= 255
	_, err = n.DB.Block(id)
	if !errors.Is(err, explorer.ErrNoBlock) {
		t.Fatalf("did not get ErrNoBlock retrieving missing block: %v", err)
	}
}

func TestBlock(t *testing.T) {
	n := newTestChain(t, false, nil)

	checkBlocks := func(count int) {
		t.Helper()

		testutil.Equal(t, "blocks", count, len(n.Blocks))
		for i := range n.Blocks {
			testutil.Equal(t, "block height", uint64(i), n.States[i].Index.Height)
			testutil.Equal(t, "block ID", n.Blocks[i].ID(), n.States[i].Index.ID)
			n.AssertBlock(t, n.States[i], n.Blocks[i])
		}
	}

	checkBlocks(1)

	n.MineTransactions(t, types.Transaction{ArbitraryData: [][]byte{{0}}})

	checkBlocks(2)

	n.RevertBlock(t)

	checkBlocks(1)
}
