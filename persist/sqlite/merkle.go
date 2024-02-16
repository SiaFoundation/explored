package sqlite

import (
	"math/bits"

	"go.sia.tech/core/types"
)

func (s *Store) updateLeaves(dbTxn txn, update consensusUpdate) error {
	modifyLeaf := func(stmt *loggedStmt, elem types.StateElement) error {
		pos := elem.LeafIndex
		for i, h := range elem.MerkleProof {
			subtreeSize := uint64(1 << i)
			if elem.LeafIndex&(1<<i) == 0 {
				pos += subtreeSize
			} else {
				pos -= subtreeSize
			}
			// write hash h to (i, pos/subtreeSize)
			encoded := dbEncode(h)
			if _, err := stmt.Exec(i, pos/subtreeSize, encoded, encoded); err != nil {
				return err
			}
		}
		if elem.LeafIndex+1 > s.numLeaves {
			s.numLeaves = elem.LeafIndex + 1
		}
		return nil
	}

	stmt, err := dbTxn.Prepare(`INSERT INTO merkle_proofs(i, j, hash) VALUES (?, ?, ?) ON CONFLICT (i, j) DO UPDATE SET hash = ?;`)
	if err != nil {
		return err
	}

	update.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		if err != nil {
			return
		}
		err = modifyLeaf(stmt, sce.StateElement)
		return
	})
	if err != nil {
		return err
	}

	update.ForEachSiafundElement(func(sce types.SiafundElement, spent bool) {
		if err != nil {
			return
		}
		err = modifyLeaf(stmt, sce.StateElement)
		return
	})
	if err != nil {
		return err
	}

	update.ForEachFileContractElement(func(sce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		if err != nil {
			return
		}
		err = modifyLeaf(stmt, sce.StateElement)
		return
	})
	if err != nil {
		return err
	}

	return nil
}

// MerkleProof implements explorer.Store.
func (s *Store) MerkleProof(leafIndex uint64) ([]types.Hash256, error) {
	proof := make([]types.Hash256, bits.Len64(leafIndex^s.numLeaves)-1)
	err := s.transaction(func(tx txn) error {
		pos := leafIndex
		stmt, err := tx.Prepare("SELECT hash FROM merkle_proofs WHERE i = ? AND j = ?")
		if err != nil {
			return err
		}
		for i := range proof {
			subtreeSize := uint64(1 << i)
			if leafIndex&(1<<i) == 0 {
				pos += subtreeSize
			} else {
				pos -= subtreeSize
			}
			// read hash (i, pos/subtreeSize)
			if err := stmt.QueryRow(i, pos/subtreeSize).Scan(dbDecode(&proof[i])); err != nil {
				return err
			}
		}
		return nil
	})
	return proof, err
}
