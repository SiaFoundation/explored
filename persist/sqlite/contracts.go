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
		query := `SELECT fc1.id, fc1.contract_id, fc1.leaf_index, fc1.resolved, fc1.valid, rev.confirmation_index, rev.confirmation_transaction_id, rev.proof_index, rev.proof_transaction_id, fc1.filesize, fc1.file_merkle_root, fc1.window_start, fc1.window_end, fc1.payout, fc1.unlock_hash, fc1.revision_number
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

			var confirmationIndex, proofIndex types.ChainIndex
			var confirmationTransactionID, proofTransactionID types.TransactionID
			if err := rows.Scan(&contractID, decode(&fc.StateElement.ID), decode(&fc.StateElement.LeafIndex), &fc.Resolved, &fc.Valid, decodeNull(&confirmationIndex), decodeNull(&confirmationTransactionID), decodeNull(&proofIndex), decodeNull(&proofTransactionID), decode(&fc.FileContract.Filesize), decode(&fc.FileContract.FileMerkleRoot), decode(&fc.FileContract.WindowStart), decode(&fc.FileContract.WindowEnd), decode(&fc.FileContract.Payout), decode(&fc.FileContract.UnlockHash), decode(&fc.FileContract.RevisionNumber)); err != nil {
				return fmt.Errorf("failed to scan transaction: %w", err)
			}

			if confirmationIndex != (types.ChainIndex{}) {
				fc.ConfirmationIndex = &confirmationIndex
			}
			if confirmationTransactionID != (types.TransactionID{}) {
				fc.ConfirmationTransactionID = &confirmationTransactionID
			}

			if proofIndex != (types.ChainIndex{}) {
				fc.ProofIndex = &proofIndex
			}
			if proofTransactionID != (types.TransactionID{}) {
				fc.ProofTransactionID = &proofTransactionID
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
			fc.FileContract.ValidProofOutputs = output.valid
			fc.FileContract.MissedProofOutputs = output.missed
			result = append(result, fc)
		}

		return nil
	})

	return
}

// ContractsKey implements explorer.Store.
func (s *Store) ContractsKey(key types.PublicKey) (result []explorer.FileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		query := `SELECT fc1.id, fc1.contract_id, fc1.leaf_index, fc1.resolved, fc1.valid, rev.confirmation_index, rev.confirmation_transaction_id, rev.proof_index, rev.proof_transaction_id, fc1.filesize, fc1.file_merkle_root, fc1.window_start, fc1.window_end, fc1.payout, fc1.unlock_hash, fc1.revision_number
			FROM file_contract_elements fc1
			INNER JOIN last_contract_revision rev ON (rev.contract_element_id = fc1.id)
			WHERE rev.ed25519_renter_key = ? OR rev.ed25519_host_key = ?`
		rows, err := tx.Query(query, encode(key), encode(key))
		if err != nil {
			return err
		}
		defer rows.Close()

		var contractIDs []int64
		idContract := make(map[int64]explorer.FileContract)
		for rows.Next() {
			var contractID int64
			var fc explorer.FileContract

			var confirmationIndex, proofIndex types.ChainIndex
			var confirmationTransactionID, proofTransactionID types.TransactionID
			if err := rows.Scan(&contractID, decode(&fc.StateElement.ID), decode(&fc.StateElement.LeafIndex), &fc.Resolved, &fc.Valid, decodeNull(&confirmationIndex), decodeNull(&confirmationTransactionID), decodeNull(&proofIndex), decodeNull(&proofTransactionID), decode(&fc.FileContract.Filesize), decode(&fc.FileContract.FileMerkleRoot), decode(&fc.FileContract.WindowStart), decode(&fc.FileContract.WindowEnd), decode(&fc.FileContract.Payout), decode(&fc.FileContract.UnlockHash), decode(&fc.FileContract.RevisionNumber)); err != nil {
				return fmt.Errorf("failed to scan transaction: %w", err)
			}

			if confirmationIndex != (types.ChainIndex{}) {
				fc.ConfirmationIndex = &confirmationIndex
			}
			if confirmationTransactionID != (types.TransactionID{}) {
				fc.ConfirmationTransactionID = &confirmationTransactionID
			}

			if proofIndex != (types.ChainIndex{}) {
				fc.ProofIndex = &proofIndex
			}
			if proofTransactionID != (types.TransactionID{}) {
				fc.ProofTransactionID = &proofTransactionID
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
			fc.FileContract.ValidProofOutputs = output.valid
			fc.FileContract.MissedProofOutputs = output.missed
			result = append(result, fc)
		}

		return nil
	})

	return
}
