package postgres

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

// scanFileContractRow scans a file_contract_elements row into fc and returns
// the database id of the contract so callers can fetch proof outputs in a
// separate query (pgx forbids concurrent queries on a single connection).
func scanFileContractRow(s scanner) (fc explorer.ExtendedFileContract, contractID int64, err error) {
	var proofIndex types.ChainIndex
	var proofTransactionID types.TransactionID
	err = s.Scan(&contractID, decode(&fc.ID), &fc.Resolved, &fc.Valid, decode(&fc.TransactionID), decode(&fc.ConfirmationIndex.Height), decode(&fc.ConfirmationIndex.ID), decode(&fc.ConfirmationTransactionID), decodeNull(&proofIndex.Height), decodeNull(&proofIndex.ID), decodeNull(&proofTransactionID), decode(&fc.Filesize), decode(&fc.FileMerkleRoot), decode(&fc.WindowStart), decode(&fc.WindowEnd), decode(&fc.Payout), decode(&fc.UnlockHash), decode(&fc.RevisionNumber))
	if err != nil {
		return
	}
	if proofIndex != (types.ChainIndex{}) {
		fc.ProofIndex = &proofIndex
	}
	if proofTransactionID != (types.TransactionID{}) {
		fc.ProofTransactionID = &proofTransactionID
	}
	return
}

func scanFileContract(tx *txn, s scanner) (fc explorer.ExtendedFileContract, err error) {
	fc, contractID, err := scanFileContractRow(s)
	if err != nil {
		return
	}
	fc.ValidProofOutputs, fc.MissedProofOutputs, err = fileContractOutputs(tx, contractID)
	return
}

func getContracts(tx *txn, ids []types.FileContractID) (result []explorer.ExtendedFileContract, err error) {
	query := `SELECT fc1.id, fc1.contract_id, rev.resolved, rev.valid, fc1.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.proof_height, rev.proof_block_id, rev.proof_transaction_id, fc1.filesize, fc1.file_merkle_root, fc1.window_start, fc1.window_end, fc1.payout, fc1.unlock_hash, fc1.revision_number
			FROM file_contract_elements fc1
			INNER JOIN last_contract_revision rev ON rev.contract_element_id = fc1.id
			WHERE rev.contract_id IN (` + queryPlaceHolders(1, len(ids)) + `)`
	contractIDs, result, err := scanFileContracts(tx, query, encodedIDs(ids)...)
	if err != nil {
		return nil, err
	}
	return decorateFileContractOutputs(tx, contractIDs, result)
}

// scanFileContracts runs query and materializes the resulting rows into fcs.
// Returning the database row ids lets callers fetch the proof outputs in a
// separate pass without leaving the outer rows iterator open.
func scanFileContracts(tx *txn, query string, args ...any) (contractIDs []int64, fcs []explorer.ExtendedFileContract, err error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		fc, contractID, err := scanFileContractRow(rows)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to scan file contract: %w", err)
		}
		contractIDs = append(contractIDs, contractID)
		fcs = append(fcs, fc)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve file contract rows: %w", err)
	}
	return contractIDs, fcs, nil
}

func decorateFileContractOutputs(tx *txn, contractIDs []int64, fcs []explorer.ExtendedFileContract) ([]explorer.ExtendedFileContract, error) {
	for i, id := range contractIDs {
		valid, missed, err := fileContractOutputs(tx, id)
		if err != nil {
			return nil, fmt.Errorf("failed to get file contract outputs: %w", err)
		}
		fcs[i].ValidProofOutputs = valid
		fcs[i].MissedProofOutputs = missed
	}
	return fcs, nil
}

// Contracts implements explorer.Store.
func (s *Store) Contracts(ids []types.FileContractID) (result []explorer.ExtendedFileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		result, err = getContracts(tx, ids)
		return err
	})

	return
}

// ContractRevisions implements explorer.Store.
func (s *Store) ContractRevisions(id types.FileContractID) (revisions []explorer.ExtendedFileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		query := `SELECT fc.id, fc.contract_id, rev.resolved, rev.valid, fc.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.proof_height, rev.proof_block_id, rev.proof_transaction_id, fc.filesize, fc.file_merkle_root, fc.window_start, fc.window_end, fc.payout, fc.unlock_hash, fc.revision_number
			FROM file_contract_elements fc
			JOIN last_contract_revision rev ON rev.contract_id = fc.contract_id
			WHERE fc.contract_id = $1
			ORDER BY fc.revision_number ASC`
		contractIDs, fcs, err := scanFileContracts(tx, query, encode(id))
		if err != nil {
			return err
		}
		if len(fcs) == 0 {
			return explorer.ErrContractNotFound
		}
		revisions, err = decorateFileContractOutputs(tx, contractIDs, fcs)
		return err
	})
	return
}

// ContractsKey implements explorer.Store.
func (s *Store) ContractsKey(key types.PublicKey, offset, limit uint64) (result []explorer.ExtendedFileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		query := `SELECT fc1.id, fc1.contract_id, rev.resolved, rev.valid, fc1.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.proof_height, rev.proof_block_id, rev.proof_transaction_id, fc1.filesize, fc1.file_merkle_root, fc1.window_start, fc1.window_end, fc1.payout, fc1.unlock_hash, fc1.revision_number
			FROM file_contract_elements fc1
			INNER JOIN last_contract_revision rev ON rev.contract_element_id = fc1.id
			WHERE rev.ed25519_renter_key = $1 OR rev.ed25519_host_key = $2
			ORDER BY rev.confirmation_height ASC
			LIMIT $3 OFFSET $4`
		contractIDs, fcs, err := scanFileContracts(tx, query, encode(key), encode(key), limit, offset)
		if err != nil {
			return err
		}
		result, err = decorateFileContractOutputs(tx, contractIDs, fcs)
		return err
	})

	return
}
