package sqlite

import (
	"math/bits"

	"go.sia.tech/core/types"
)

// MerkleProof implements explorer.Store.
func (s *Store) MerkleProof(leafIndex uint64) (proof []types.Hash256, err error) {
	err = s.transaction(func(tx *txn) error {
		var numLeaves uint64
		if err := tx.QueryRow("SELECT COUNT(*) FROM state_tree WHERE i = 0").Scan(&numLeaves); err != nil {
			return err
		}

		pos := leafIndex
		stmt, err := tx.Prepare("SELECT hash FROM state_tree WHERE row = ? AND column = ?")
		if err != nil {
			return err
		}

		proof = make([]types.Hash256, bits.Len64(leafIndex^numLeaves)-1)
		for i := range proof {
			subtreeSize := uint64(1 << i)
			if leafIndex&(1<<i) == 0 {
				pos += subtreeSize
			} else {
				pos -= subtreeSize
			}
			// read hash (i, pos/subtreeSize)
			if err := stmt.QueryRow(i, pos/subtreeSize).Scan(decode(&proof[i])); err != nil {
				return err
			}
		}
		return nil
	})
	return
}
