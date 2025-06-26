package sqlite

import (
	"math"
	"testing"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/internal/testutil"
)

func (n *testChain) assertChainIndices(t testing.TB, txnID types.TransactionID, expected ...types.ChainIndex) {
	t.Helper()

	indices, err := n.db.TransactionChainIndices(txnID, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	} else if len(indices) != len(expected) {
		t.Fatalf("expected %d indices, got %d", len(expected), len(indices))
	}

	for i := range indices {
		testutil.Equal(t, "index", expected[i], indices[i])
	}
}

func TestTransactionChainIndices(t *testing.T) {
	n := newTestChain(t, false, nil)

	txn1 := types.Transaction{
		ArbitraryData: [][]byte{{0}},
	}
	txn2 := types.Transaction{
		ArbitraryData: [][]byte{{0}, {1}},
	}

	// mine block with txn1 twice and txn2
	n.mineTransactions(t, txn1, txn1, txn2)
	cs1 := n.tipState()

	n.assertTransactions(t, txn1, txn2)
	// both transactions should only be in the first block
	n.assertChainIndices(t, txn1.ID(), cs1.Index)
	n.assertChainIndices(t, txn2.ID(), cs1.Index)

	// mine same block again
	n.mineTransactions(t, txn1, txn1, txn2)
	cs2 := n.tipState()

	// both transactions should be in the blocks
	n.assertTransactions(t, txn1, txn2)
	n.assertChainIndices(t, txn1.ID(), cs2.Index, cs1.Index)
	n.assertChainIndices(t, txn2.ID(), cs2.Index, cs1.Index)

	n.revertBlock(t)

	// after revert both transactions should only be in the first block
	n.assertTransactions(t, txn1, txn2)
	n.assertChainIndices(t, txn1.ID(), cs1.Index)
	n.assertChainIndices(t, txn2.ID(), cs1.Index)

	n.revertBlock(t)

	// after reverting the first block there should be no transactions
	{
		txns, err := n.db.Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 0, len(txns))
	}
	n.assertChainIndices(t, txn1.ID())
	n.assertChainIndices(t, txn2.ID())
}
