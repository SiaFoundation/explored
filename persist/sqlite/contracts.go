package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// Contracts implements explorer.Store.
func (s *Store) Contracts(ids []types.FileContractID) (result []explorer.FileContract, err error) {
	encodedIDs := func(ids []types.FileContractID) []any {
		result := make([]any, len(ids))
		for i, id := range ids {
			result[i] = dbEncode(id)
		}
		return result
	}

	err = s.transaction(func(tx txn) error {
		query := `SELECT fc1.contract_id, fc1.leaf_index, fc1.merkle_proof, fc1.resolved, fc1.valid, fc1.filesize, fc1.file_merkle_root, fc1.window_start, fc1.window_end, fc1.payout, fc1.unlock_hash, fc1.revision_number
		FROM file_contract_elements fc1
		WHERE fc1.contract_id IN (` + queryPlaceHolders(len(ids)) + `)
		AND fc1.revision_number = (SELECT max(revision_number) FROM file_contract_elements fc2 WHERE fc2.contract_id = fc1.contract_id)`
		rows, err := tx.Query(query, encodedIDs(ids)...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var fc explorer.FileContract
			if err := rows.Scan(dbDecode(&fc.StateElement.ID), dbDecode(&fc.StateElement.LeafIndex), dbDecode(&fc.StateElement.MerkleProof), &fc.Resolved, &fc.Valid, &fc.Filesize, dbDecode(&fc.FileMerkleRoot), &fc.WindowStart, &fc.WindowEnd, dbDecode(&fc.Payout), dbDecode(&fc.UnlockHash), &fc.RevisionNumber); err != nil {
				return fmt.Errorf("failed to scan transaction: %w", err)
			}
			result = append(result, fc)
		}
		return nil
	})
	return
}
