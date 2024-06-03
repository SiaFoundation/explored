package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

func encodedIDs(ids []types.FileContractID) []any {
	result := make([]any, len(ids))
	for i, id := range ids {
		result[i] = encode(id)
	}
	return result
}

// Contracts implements explorer.Store.
func (s *Store) Contracts(ids []types.FileContractID) (result []explorer.FileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		query := `SELECT fc1.id, fc1.contract_id, fc1.leaf_index, fc1.resolved, fc1.valid, fc1.filesize, fc1.file_merkle_root, fc1.window_start, fc1.window_end, fc1.payout, fc1.unlock_hash, fc1.revision_number
			FROM file_contract_elements fc1
			INNER JOIN last_contract_revision rev ON (rev.contract_element_id = fc1.id)
			WHERE rev.contract_id IN (` + queryPlaceHolders(len(ids)) + `)`
		rows, err := tx.Query(query, encodedIDs(ids)...)
		if err != nil {
			return err
		}
		defer rows.Close()

		var contractIDs []int64
		idContract := make(map[int64]explorer.FileContract)
		for rows.Next() {
			var contractID int64
			var fc explorer.FileContract
			if err := rows.Scan(&contractID, decode(&fc.StateElement.ID), decode(&fc.StateElement.LeafIndex), &fc.Resolved, &fc.Valid, &fc.Filesize, decode(&fc.FileMerkleRoot), &fc.WindowStart, &fc.WindowEnd, decode(&fc.Payout), decode(&fc.UnlockHash), decode(&fc.RevisionNumber)); err != nil {
				return fmt.Errorf("failed to scan transaction: %w", err)
			}

			idContract[contractID] = fc
			contractIDs = append(contractIDs, contractID)
		}

		proofOutputs, err := fileContractOutputs(tx, contractIDs)
		if err != nil {
			return fmt.Errorf("failed to get file contract outputs: %w", err)
		}
		for contractID, output := range proofOutputs {
			fc := idContract[contractID]
			fc.ValidProofOutputs = output.valid
			fc.MissedProofOutputs = output.missed
			result = append(result, fc)
		}

		return nil
	})

	return
}

// ContractsKey implements explorer.Store.
func (s *Store) ContractsKey(key []byte) (result []explorer.FileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		query := `SELECT fc1.id, fc1.contract_id, fc1.leaf_index, fc1.resolved, fc1.valid, fc1.filesize, fc1.file_merkle_root, fc1.window_start, fc1.window_end, fc1.payout, fc1.unlock_hash, fc1.revision_number
			FROM file_contract_elements fc1
			INNER JOIN last_contract_revision rev ON (rev.contract_element_id = fc1.id)
			WHERE rev.ed25519_renter_key = ? OR rev.ed25519_host_key = ?`
		rows, err := tx.Query(query, key, key)
		if err != nil {
			return err
		}
		defer rows.Close()

		var contractIDs []int64
		idContract := make(map[int64]explorer.FileContract)
		for rows.Next() {
			var contractID int64
			var fc explorer.FileContract
			if err := rows.Scan(&contractID, decode(&fc.StateElement.ID), decode(&fc.StateElement.LeafIndex), &fc.Resolved, &fc.Valid, &fc.Filesize, decode(&fc.FileMerkleRoot), &fc.WindowStart, &fc.WindowEnd, decode(&fc.Payout), decode(&fc.UnlockHash), decode(&fc.RevisionNumber)); err != nil {
				return fmt.Errorf("failed to scan transaction: %w", err)
			}

			idContract[contractID] = fc
			contractIDs = append(contractIDs, contractID)
		}

		proofOutputs, err := fileContractOutputs(tx, contractIDs)
		if err != nil {
			return fmt.Errorf("failed to get file contract outputs: %w", err)
		}
		for contractID, output := range proofOutputs {
			fc := idContract[contractID]
			fc.ValidProofOutputs = output.valid
			fc.MissedProofOutputs = output.missed
			result = append(result, fc)
		}

		return nil
	})

	return
}
