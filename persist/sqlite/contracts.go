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

func scanFileContract(s scanner) (contractID int64, fc explorer.FileContract, err error) {
	var confirmationIndex, proofIndex types.ChainIndex
	var confirmationTransactionID, proofTransactionID types.TransactionID
	err = s.Scan(&contractID, decode(&fc.StateElement.ID), decode(&fc.StateElement.LeafIndex), &fc.Resolved, &fc.Valid, decodeNull(&confirmationIndex), decodeNull(&confirmationTransactionID), decodeNull(&proofIndex), decodeNull(&proofTransactionID), decode(&fc.FileContract.Filesize), decode(&fc.FileContract.FileMerkleRoot), decode(&fc.FileContract.WindowStart), decode(&fc.FileContract.WindowEnd), decode(&fc.FileContract.Payout), decode(&fc.FileContract.UnlockHash), decode(&fc.FileContract.RevisionNumber))

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

	return
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

			contractID, fc, err := scanFileContract(rows)
			if err != nil {
				return fmt.Errorf("failed to scan file contract: %w", err)
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

// ContractRevisions implements explorer.Store.
func (s *Store) ContractRevisions(id types.FileContractID) (revisions []explorer.FileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		query := `SELECT fc.id, fc.contract_id, fc.leaf_index, fc.resolved, fc.valid, rev.confirmation_index, rev.confirmation_transaction_id, rev.proof_index, rev.proof_transaction_id, fc.filesize, fc.file_merkle_root, fc.window_start, fc.window_end, fc.payout, fc.unlock_hash, fc.revision_number
			FROM file_contract_elements fc
			JOIN last_contract_revision rev ON (rev.contract_id = fc.contract_id)
			WHERE fc.contract_id = ?
			ORDER BY fc.revision_number ASC`
		rows, err := tx.Query(query, encode(id))
		if err != nil {
			return err
		}
		defer rows.Close()

		// fetch revisions
		type fce struct {
			ID           int64
			FileContract explorer.FileContract
		}
		var fces []fce
		var contractIDs []int64
		for rows.Next() {
			contractID, fc, err := scanFileContract(rows)
			if err != nil {
				return fmt.Errorf("failed to scan file contract: %w", err)
			}

			fces = append(fces, fce{ID: contractID, FileContract: fc})
			contractIDs = append(contractIDs, contractID)
		}

		// fetch corresponding outputs
		proofOutputs, err := fileContractOutputs(tx, contractIDs)
		if err != nil {
			return fmt.Errorf("failed to get file contract outputs: %w", err)
		}

		// merge outputs into revisions
		revisions = make([]explorer.FileContract, len(fces))
		for i, revision := range fces {
			output, found := proofOutputs[revision.ID]
			if !found {
				// contracts always have outputs
				return fmt.Errorf("missing proof outputs for contract %v", contractIDs[i])
			}
			revisions[i].FileContract.ValidProofOutputs = output.valid
			revisions[i].FileContract.MissedProofOutputs = output.missed
		}

		for i, fce := range fces {
			revisions[i] = fce.FileContract
		}

		if len(revisions) == 0 {
			return explorer.ErrContractNotFound
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
			contractID, fc, err := scanFileContract(rows)
			if err != nil {
				return fmt.Errorf("failed to scan file contract: %w", err)
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
