package sqlite

import (
	"fmt"
	"math/bits"

	"go.sia.tech/core/types"
)

func fillElementProofs(tx *txn, indices []uint64) (proofs [][]types.Hash256, _ error) {
	if len(indices) == 0 {
		return nil, nil
	}

	var numLeaves uint64
	if err := tx.QueryRow(`SELECT num_leaves FROM network_metrics ORDER BY height DESC LIMIT 1`).Scan(decode(&numLeaves)); err != nil {
		return nil, fmt.Errorf("failed to query state tree leaves: %w", err)
	}

	stmt, err := tx.Prepare(`SELECT value FROM state_tree WHERE row=? AND column=?`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	data := make(map[uint64]map[uint64]types.Hash256)
	for _, leafIndex := range indices {
		proof := make([]types.Hash256, bits.Len64(leafIndex^numLeaves)-1)
		for j := range proof {
			row, col := uint64(j), (leafIndex>>j)^1

			// check if the hash is already in the cache
			if h, ok := data[row][col]; ok {
				proof[j] = h
				continue
			}

			// query the hash from the database
			if err := stmt.QueryRow(row, col).Scan(decode(&proof[j])); err != nil {
				return nil, fmt.Errorf("failed to query state element (%d,%d): %w", row, col, err)
			}

			// cache the hash
			if _, ok := data[row]; !ok {
				data[row] = make(map[uint64]types.Hash256)
			}
			data[row][col] = proof[j]
		}
		proofs = append(proofs, proof)
	}
	return
}

// MerkleProof implements explorer.Store.
func (s *Store) MerkleProof(leafIndex uint64) (proof []types.Hash256, err error) {
	err = s.transaction(func(tx *txn) error {
		proofs, err := fillElementProofs(tx, []uint64{leafIndex})
		if err != nil {
			return err
		} else if len(proofs) != 1 {
			return fmt.Errorf("expected 1 merkle proof, got %d", len(proofs))
		}
		proof = proofs[0]
		return nil
	})
	return
}
