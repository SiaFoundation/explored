//go:build testing

package storetest

import (
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
	n.MineV2Transactions(t, txn1, txn1, txn2)
	cs1 := n.TipState()

	n.AssertV2Transactions(t, txn1, txn2)
	// both transactions should only be in the first block
	n.AssertV2ChainIndices(t, txn1.ID(), cs1.Index)
	n.AssertV2ChainIndices(t, txn2.ID(), cs1.Index)

	// mine same block again
	n.MineV2Transactions(t, txn1, txn1, txn2)
	cs2 := n.TipState()

	// both transactions should be in the blocks
	n.AssertV2Transactions(t, txn1, txn2)
	n.AssertV2ChainIndices(t, txn1.ID(), cs2.Index, cs1.Index)
	n.AssertV2ChainIndices(t, txn2.ID(), cs2.Index, cs1.Index)

	n.RevertBlock(t)

	// after revert both transactions should only be in the first block
	n.AssertV2Transactions(t, txn1, txn2)
	n.AssertV2ChainIndices(t, txn1.ID(), cs1.Index)
	n.AssertV2ChainIndices(t, txn2.ID(), cs1.Index)

	n.RevertBlock(t)

	// after reverting the first block there should be no transactions
	{
		txns, err := n.DB.V2Transactions([]types.TransactionID{txn1.ID(), txn2.ID()})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Equal(t, "len(txns)", 0, len(txns))
	}
	n.AssertV2ChainIndices(t, txn1.ID())
	n.AssertV2ChainIndices(t, txn2.ID())
}
