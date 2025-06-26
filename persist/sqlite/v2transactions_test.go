package sqlite

import (
	"math"
	"testing"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/internal/testutil"
)

func TestV2TransactionChainIndices(t *testing.T) {
	n := newTestChain(t, true, nil)

	txn1 := types.V2Transaction{
		ArbitraryData: []byte{0},
	}
	txn2 := types.V2Transaction{
		ArbitraryData: []byte{0, 1},
	}

	// mine block with txn1 twice and txn2
	n.mineV2Transactions(t, txn1, txn1, txn2)
	cs1 := n.tipState()

	n.assertV2Transactions(t, txn1, txn2)
	// both transactions should only be in the first block
	n.assertV2ChainIndices(t, txn1.ID(), cs1.Index)
	n.assertV2ChainIndices(t, txn2.ID(), cs1.Index)

	// mine same block again
	n.mineV2Transactions(t, txn1, txn1, txn2)
	cs2 := n.tipState()

	// both transactions should be in the blocks
	n.assertV2Transactions(t, txn1, txn2)
	n.assertV2ChainIndices(t, txn1.ID(), cs2.Index, cs1.Index)
	n.assertV2ChainIndices(t, txn2.ID(), cs2.Index, cs1.Index)

	n.revertBlock(t)

	// after revert both transactions should only be in the first block
	n.assertV2Transactions(t, txn1, txn2)
	n.assertV2ChainIndices(t, txn1.ID(), cs1.Index)
	n.assertV2ChainIndices(t, txn2.ID(), cs1.Index)

	n.revertBlock(t)

	// after reverting the first block there should be no transactions
	{
		txns, err := n.db.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 0, len(txns))
	}
	n.assertV2ChainIndices(t, txn1.ID())
	n.assertV2ChainIndices(t, txn2.ID())
}

func (n *testChain) assertV2ChainIndices(t testing.TB, txnID types.TransactionID, expected ...types.ChainIndex) {
	t.Helper()

	indices, err := n.db.V2TransactionChainIndices(txnID, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	} else if len(indices) != len(expected) {
		t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
	}

	for i := range indices {
		testutil.Equal(t, "index", expected[i], indices[i])
	}
}
