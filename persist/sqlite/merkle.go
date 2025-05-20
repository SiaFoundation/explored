package sqlite

import (
	"math/bits"

	"go.sia.tech/core/types"
)

func merkleProof(tx *txn, leafIndex uint64) ([]types.Hash256, error) {
	var numLeaves uint64
	if err := tx.QueryRow("SELECT num_leaves FROM network_metrics ORDER BY height DESC LIMIT 1").Scan(decode(&numLeaves)); err != nil {
		return nil, err
	}

	pos := leafIndex
	stmt, err := tx.Prepare("SELECT value FROM state_tree WHERE row = ? AND column = ?")
	if err != nil {
		return nil, err
	}

	proof := make([]types.Hash256, bits.Len64(leafIndex^numLeaves)-1)
	for i := range proof {
		subtreeSize := uint64(1 << i)
		if leafIndex&(1<<i) == 0 {
			pos += subtreeSize
		} else {
			pos -= subtreeSize
		}
		// read hash (i, pos/subtreeSize)
		if err := stmt.QueryRow(i, pos/subtreeSize).Scan(decode(&proof[i])); err != nil {
			return nil, err
		}
	}
	return proof, nil
}

// MerkleProof implements explorer.Store.
func (s *Store) MerkleProof(leafIndex uint64) (proof []types.Hash256, err error) {
	err = s.transaction(func(tx *txn) error {
		proof, err = merkleProof(tx, leafIndex)
		return err
	})
	return
}
