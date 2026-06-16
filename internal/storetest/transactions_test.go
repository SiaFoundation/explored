//go:build testing

package storetest

import (
	"testing"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/internal/testutil"
)

func TestTransactionChainIndices(t *testing.T) {
	n := newTestChain(t, false, nil)

	txn1 := types.Transaction{
		ArbitraryData: [][]byte{{0}},
	}
	txn2 := types.Transaction{
		ArbitraryData: [][]byte{{0}, {1}},
	}

	// mine block with txn1 twice and txn2
	n.MineTransactions(t, txn1, txn1, txn2)
	cs1 := n.TipState()

	n.AssertTransactions(t, txn1, txn2)
	// both transactions should only be in the first block
	n.AssertChainIndices(t, txn1.ID(), cs1.Index)
	n.AssertChainIndices(t, txn2.ID(), cs1.Index)

	// mine same block again
	n.MineTransactions(t, txn1, txn1, txn2)
	cs2 := n.TipState()

	// both transactions should be in the blocks
	n.AssertTransactions(t, txn1, txn2)
	n.AssertChainIndices(t, txn1.ID(), cs2.Index, cs1.Index)
	n.AssertChainIndices(t, txn2.ID(), cs2.Index, cs1.Index)

	n.RevertBlock(t)

	// after revert both transactions should only be in the first block
	n.AssertTransactions(t, txn1, txn2)
	n.AssertChainIndices(t, txn1.ID(), cs1.Index)
	n.AssertChainIndices(t, txn2.ID(), cs1.Index)

	n.RevertBlock(t)

	// after reverting the first block there should be no transactions
	{
		txns, err := n.DB.Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 0, len(txns))
	}
	n.AssertChainIndices(t, txn1.ID())
	n.AssertChainIndices(t, txn2.ID())
}
