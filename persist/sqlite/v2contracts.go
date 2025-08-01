package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

func scanV2FileContract(s scanner) (fce explorer.V2FileContract, err error) {
	var resolutionType sql.Null[explorer.V2Resolution]
	var resolutionIndex types.ChainIndex
	var resolutionTransactionID types.TransactionID
	var renewedFrom, renewedTo types.FileContractID

	fc := &fce.V2FileContractElement.V2FileContract
	if err = s.Scan(decode(&fce.TransactionID), decode(&fce.ConfirmationIndex.Height), decode(&fce.ConfirmationIndex.ID), decode(&fce.ConfirmationTransactionID), &resolutionType, decodeNull(&resolutionIndex.Height), decodeNull(&resolutionIndex.ID), decodeNull(&resolutionTransactionID), decodeNull(&renewedFrom), decodeNull(&renewedTo), decode(&fce.V2FileContractElement.ID), decode(&fce.V2FileContractElement.StateElement.LeafIndex), decode(&fc.Capacity), decode(&fc.Filesize), decode(&fc.FileMerkleRoot), decode(&fc.ProofHeight), decode(&fc.ExpirationHeight), decode(&fc.RenterOutput.Address), decode(&fc.RenterOutput.Value), decode(&fc.HostOutput.Address), decode(&fc.HostOutput.Value), decode(&fc.MissedHostValue), decode(&fc.TotalCollateral), decode(&fc.RenterPublicKey), decode(&fc.HostPublicKey), decode(&fc.RevisionNumber), decode(&fc.RenterSignature), decode(&fc.HostSignature)); err != nil {
		return
	}

	if resolutionType.Valid && resolutionType.V != explorer.V2ResolutionInvalid {
		fce.ResolutionType = &resolutionType.V
	}
	if resolutionIndex != (types.ChainIndex{}) {
		fce.ResolutionIndex = &resolutionIndex
	}
	if resolutionTransactionID != (types.TransactionID{}) {
		fce.ResolutionTransactionID = &resolutionTransactionID
	}
	if renewedFrom != (types.FileContractID{}) {
		fce.RenewedFrom = &renewedFrom
	}
	if renewedTo != (types.FileContractID{}) {
		fce.RenewedTo = &renewedTo
	}

	return
}

// V2Contracts implements explorer.Store.
func (s *Store) V2Contracts(ids []types.FileContractID) (result []explorer.V2FileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		stmt, err := tx.Prepare(`SELECT fc.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.resolution_type, rev.resolution_height, rev.resolution_block_id, rev.resolution_transaction_id, rev.renewed_from, rev.renewed_to, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
FROM v2_last_contract_revision rev
INNER JOIN v2_file_contract_elements fc ON rev.contract_element_id = fc.id
WHERE rev.contract_id = ?
`)
		if err != nil {
			return fmt.Errorf("failed to query file contracts: %w", err)
		}
		defer stmt.Close()

		var leafIndices []uint64
		for _, id := range ids {
			fc, err := scanV2FileContract(stmt.QueryRow(encode(id)))
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("failed to scan file contract: %w", err)
			} else if err == nil {
				leafIndices = append(leafIndices, fc.V2FileContractElement.StateElement.LeafIndex)
				result = append(result, fc)
			}
		}

		proofs, err := fillElementProofs(tx, leafIndices)
		if err != nil {
			return fmt.Errorf("failed to fill siafund output proofs: %w", err)
		}
		for i := range result {
			result[i].V2FileContractElement.StateElement.MerkleProof = proofs[i]
		}

		return nil
	})

	return
}

// V2ContractRevisions implements explorer.Store.
func (s *Store) V2ContractRevisions(id types.FileContractID) (revisions []explorer.V2FileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		query := `SELECT fc.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.resolution_type, rev.resolution_height, rev.resolution_block_id, rev.resolution_transaction_id, rev.renewed_from, rev.renewed_to, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
FROM v2_file_contract_elements fc
INNER JOIN v2_last_contract_revision rev ON rev.contract_id = fc.contract_id
WHERE fc.contract_id = ?
ORDER BY fc.revision_number ASC
`
		rows, err := tx.Query(query, encode(id))
		if err != nil {
			return fmt.Errorf("failed to query file contract revisions: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			fc, err := scanV2FileContract(rows)
			if err != nil {
				return fmt.Errorf("failed to scan file contract revision: %w", err)
			}

			revisions = append(revisions, fc)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to retrieve file contract rows: %w", err)
		}

		if len(revisions) == 0 {
			return explorer.ErrContractNotFound
		}
		return nil
	})
	return
}

// V2ContractsKey implements explorer.Store.
func (s *Store) V2ContractsKey(key types.PublicKey) (result []explorer.V2FileContract, err error) {
	err = s.transaction(func(tx *txn) error {
		encoded := encode(key)
		rows, err := tx.Query(`SELECT fc.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.resolution_type, rev.resolution_height, rev.resolution_block_id, rev.resolution_transaction_id, rev.renewed_from, rev.renewed_to, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
FROM v2_last_contract_revision rev
INNER JOIN v2_file_contract_elements fc ON rev.contract_element_id = fc.id
WHERE fc.renter_public_key = ? OR fc.host_public_key = ?
ORDER BY rev.confirmation_height ASC
`, encoded, encoded)
		if err != nil {
			return fmt.Errorf("failed to query file contracts using given pubkey: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			fc, err := scanV2FileContract(rows)
			if err != nil {
				return fmt.Errorf("failed to scan file contract: %w", err)
			}
			result = append(result, fc)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to retrieve file contract rows: %w", err)
		}

		return nil
	})

	return
}
