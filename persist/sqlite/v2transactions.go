package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

// V2TransactionChainIndices returns the chain indices of the blocks the v2
// transaction was included in. If the transaction has not been included in
// any blocks, the result will be nil,nil.
func (s *Store) V2TransactionChainIndices(txnID types.TransactionID, offset, limit uint64) (indices []types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT DISTINCT b.id, b.height FROM blocks b
INNER JOIN v2_block_transactions bt ON (bt.block_id = b.id)
INNER JOIN v2_transactions t ON (t.id = bt.transaction_id)
WHERE t.transaction_id = ?
ORDER BY b.height DESC 
LIMIT ? OFFSET ?`, encode(txnID), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query chain indices: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var index types.ChainIndex
			if err := rows.Scan(decode(&index.ID), decode(&index.Height)); err != nil {
				return fmt.Errorf("failed to scan chain index: %w", err)
			}
			indices = append(indices, index)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to retrieve chain index rows: %w", err)
		}
		return nil
	})
	return
}

// blockV2TransactionIDs returns the transaction id as a types.TransactionID
// for each v2 transaction in the block.
func blockV2TransactionIDs(tx *txn, blockID types.BlockID) (ids []types.TransactionID, err error) {
	rows, err := tx.Query(`SELECT t.transaction_id
FROM v2_block_transactions bt
INNER JOIN v2_transactions t ON (t.id = bt.transaction_id)
WHERE block_id = ? ORDER BY block_order ASC`, encode(blockID))
	if err != nil {
		return nil, fmt.Errorf("failed to query block transaction IDs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id types.TransactionID
		if err := rows.Scan(decode(&id)); err != nil {
			return nil, fmt.Errorf("failed to scan block transaction: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to retrieve chain index rows: %w", err)
	}
	return
}

// getV2Transactions fetches v2 transactions in the correct order using
// prepared statements.
func getV2Transactions(tx *txn, ids []types.TransactionID) ([]explorer.V2Transaction, error) {
	dbIDs, txns, err := getV2TransactionBase(tx, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to get base transactions: %w", err)
	} else if err := decorateV2Attestations(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get attestations: %w", err)
	} else if err := decorateV2SiacoinInputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get siacoin inputs: %w", err)
	} else if err := decorateV2SiacoinOutputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get siacoin outputs: %w", err)
	} else if err := decorateV2SiafundInputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get siafund inputs: %w", err)
	} else if err := decorateV2SiafundOutputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get siafund outputs: %w", err)
	} else if err := decorateV2FileContracts(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get file contracts: %w", err)
	} else if err := decorateV2FileContractRevisions(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get file contract revisions: %w", err)
	} else if err := decorateV2FileContractResolutions(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get file contract resolutions: %w", err)
	}

	// add host announcements if we have any
	for i := range txns {
		for _, attestation := range txns[i].Attestations {
			var ha chain.V2HostAnnouncement
			if ha.FromAttestation(attestation) == nil {
				txns[i].HostAnnouncements = append(txns[i].HostAnnouncements, explorer.V2HostAnnouncement{
					V2HostAnnouncement: ha,
					PublicKey:          attestation.PublicKey,
				})
			}
		}
	}
	return txns, nil
}

// getV2TransactionBase fetches the base transaction data for a given list of
// transaction IDs.
func getV2TransactionBase(tx *txn, txnIDs []types.TransactionID) ([]int64, []explorer.V2Transaction, error) {
	stmt, err := tx.Prepare(`SELECT id, transaction_id, new_foundation_address, miner_fee, arbitrary_data FROM v2_transactions WHERE transaction_id = ?`)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	var dbID int64
	dbIDs := make([]int64, 0, len(txnIDs))
	txns := make([]explorer.V2Transaction, 0, len(txnIDs))
	for _, id := range txnIDs {
		var txn explorer.V2Transaction
		var newFoundationAddress types.Address
		if err := stmt.QueryRow(encode(id)).Scan(&dbID, decode(&txn.ID), decodeNull(&newFoundationAddress), decode(&txn.MinerFee), &txn.ArbitraryData); errors.Is(err, sql.ErrNoRows) {
			continue
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to scan base transaction: %w", err)
		}
		if (newFoundationAddress != types.Address{}) {
			txn.NewFoundationAddress = &newFoundationAddress
		}

		dbIDs = append(dbIDs, dbID)
		txns = append(txns, txn)
	}
	return dbIDs, txns, nil
}

// decorateV2Attestations fills in the attestations for each
// transaction.
func decorateV2Attestations(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	stmt, err := tx.Prepare(`SELECT public_key, key, value, signature FROM v2_transaction_attestations WHERE transaction_id = ? ORDER BY transaction_order`)
	if err != nil {
		return fmt.Errorf("failed to prepare attestations statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query attestations: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var attestation types.Attestation
				if err := rows.Scan(decode(&attestation.PublicKey), &attestation.Key, &attestation.Value, decode(&attestation.Signature)); err != nil {
					return fmt.Errorf("failed to scan attestation: %w", err)
				}
				txns[i].Attestations = append(txns[i].Attestations, attestation)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve attestation rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateV2SiacoinInputs fills in the siacoin inputs for each
// transaction.
func decorateV2SiacoinInputs(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	stmt, err := tx.Prepare(`SELECT ts.satisfied_policy, sc.output_id, sc.leaf_index, sc.maturity_height, sc.address, sc.value
FROM siacoin_elements sc
INNER JOIN v2_transaction_siacoin_inputs ts ON (ts.parent_id = sc.id)
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare siacoin inputs statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query siacoin inputs: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var sci types.V2SiacoinInput
				if err := rows.Scan(decode(&sci.SatisfiedPolicy), decode(&sci.Parent.ID), decode(&sci.Parent.StateElement.LeafIndex), &sci.Parent.MaturityHeight, decode(&sci.Parent.SiacoinOutput.Address), decode(&sci.Parent.SiacoinOutput.Value)); err != nil {
					return fmt.Errorf("failed to scan siacoin inputs: %w", err)
				}

				txns[i].SiacoinInputs = append(txns[i].SiacoinInputs, sci)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve siacoin input rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateV2SiacoinOutputs fills in the siacoin outputs for each
// transaction.
func decorateV2SiacoinOutputs(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	stmt, err := tx.Prepare(`SELECT sc.output_id, sc.leaf_index, sc.spent_index, sc.source, sc.maturity_height, sc.address, sc.value
FROM siacoin_elements sc
INNER JOIN v2_transaction_siacoin_outputs ts ON (ts.output_id = sc.id)
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare siacoin outputs statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query siacoin outputs: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var spentIndex types.ChainIndex
				var sco explorer.SiacoinOutput
				if err := rows.Scan(decode(&sco.ID), decode(&sco.StateElement.LeafIndex), decodeNull(&spentIndex), &sco.Source, &sco.MaturityHeight, decode(&sco.SiacoinOutput.Address), decode(&sco.SiacoinOutput.Value)); err != nil {
					return fmt.Errorf("failed to scan siacoin output: %w", err)
				}

				if spentIndex != (types.ChainIndex{}) {
					sco.SpentIndex = &spentIndex
				}
				txns[i].SiacoinOutputs = append(txns[i].SiacoinOutputs, sco)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve siacoin output rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateV2SiafundInputs fills in the siacoin inputs for each
// transaction.
func decorateV2SiafundInputs(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	stmt, err := tx.Prepare(`SELECT ts.satisfied_policy, ts.claim_address, sf.output_id, sf.leaf_index, sf.address, sf.value
FROM siafund_elements sf
INNER JOIN v2_transaction_siafund_inputs ts ON (ts.parent_id = sf.id)
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare siacoin inputs statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query siacoin inputs: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var sfi types.V2SiafundInput
				if err := rows.Scan(decode(&sfi.SatisfiedPolicy), decode(&sfi.ClaimAddress), decode(&sfi.Parent.ID), decode(&sfi.Parent.StateElement.LeafIndex), decode(&sfi.Parent.SiafundOutput.Address), decode(&sfi.Parent.SiafundOutput.Value)); err != nil {
					return fmt.Errorf("failed to scan siacoin inputs: %w", err)
				}

				txns[i].SiafundInputs = append(txns[i].SiafundInputs, sfi)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve siafund input rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateV2SiafundOutputs fills in the siafund outputs for each
// transaction.
func decorateV2SiafundOutputs(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	stmt, err := tx.Prepare(`SELECT sf.output_id, sf.leaf_index, sf.spent_index, sf.claim_start, sf.address, sf.value
FROM siafund_elements sf
INNER JOIN v2_transaction_siafund_outputs ts ON (ts.output_id = sf.id)
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare siafund outputs statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query siafund outputs: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var spentIndex types.ChainIndex
				var sfo explorer.SiafundOutput
				if err := rows.Scan(decode(&sfo.ID), decode(&sfo.StateElement.LeafIndex), decodeNull(&spentIndex), decode(&sfo.ClaimStart), decode(&sfo.SiafundOutput.Address), decode(&sfo.SiafundOutput.Value)); err != nil {
					return fmt.Errorf("failed to scan siafund output: %w", err)
				}
				if spentIndex != (types.ChainIndex{}) {
					sfo.SpentIndex = &spentIndex
				}

				txns[i].SiafundOutputs = append(txns[i].SiafundOutputs, sfo)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve siafund output rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateV2FileContracts fills in the file contracts for each
// transaction.
func decorateV2FileContracts(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	stmt, err := tx.Prepare(`SELECT fc.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.resolution_type, rev.resolution_height, rev.resolution_block_id, rev.resolution_transaction_id, rev.renewed_from, rev.renewed_to, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
FROM v2_file_contract_elements fc
INNER JOIN v2_transaction_file_contracts ts ON (ts.contract_id = fc.id)
INNER JOIN v2_last_contract_revision rev ON (rev.contract_id = fc.contract_id)
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare file contracts statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query file contracts: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				fce, err := scanV2FileContract(rows)
				if err != nil {
					return fmt.Errorf("failed to scan file contract: %w", err)
				}

				txns[i].FileContracts = append(txns[i].FileContracts, fce)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve file contract rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateV2FileContractRevisions fills in the file contract revisions
// for each transaction.
func decorateV2FileContractRevisions(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	parentStmt, err := tx.Prepare(`SELECT fc.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.resolution_type, rev.resolution_height, rev.resolution_block_id, rev.resolution_transaction_id, rev.renewed_from, rev.renewed_to, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
FROM v2_file_contract_elements fc
INNER JOIN v2_transaction_file_contract_revisions ts ON (ts.parent_contract_id = fc.id)
INNER JOIN v2_last_contract_revision rev ON (rev.contract_id = fc.contract_id)
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare file contracts parent statement: %w", err)
	}
	defer parentStmt.Close()

	revisionStmt, err := tx.Prepare(`SELECT fc.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.resolution_type, rev.resolution_height, rev.resolution_block_id, rev.resolution_transaction_id, rev.renewed_from, rev.renewed_to, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
FROM v2_file_contract_elements fc
INNER JOIN v2_transaction_file_contract_revisions ts ON (ts.revision_contract_id = fc.id)
INNER JOIN v2_last_contract_revision rev ON (rev.contract_id = fc.contract_id)
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare file contracts revision statement: %w", err)
	}
	defer revisionStmt.Close()

	collectFileContracts := func(stmt *stmt, dbID int64) ([]explorer.V2FileContract, error) {
		rows, err := stmt.Query(dbID)
		if err != nil {
			return nil, fmt.Errorf("failed to query file contracts: %w", err)
		}
		defer rows.Close()

		var contracts []explorer.V2FileContract
		for rows.Next() {
			fce, err := scanV2FileContract(rows)
			if err != nil {
				return nil, fmt.Errorf("failed to scan file contract: %w", err)
			}
			contracts = append(contracts, fce)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("failed to retrieve file contract rows: %w", err)
		}
		return contracts, nil
	}

	for i, dbID := range dbIDs {
		parents, err := collectFileContracts(parentStmt, dbID)
		if err != nil {
			return fmt.Errorf("failed to collect parent contracts: %w", err)
		}

		revisions, err := collectFileContracts(revisionStmt, dbID)
		if err != nil {
			return fmt.Errorf("failed to collect contract revisions: %w", err)
		}

		for j := range parents {
			fcr := explorer.V2FileContractRevision{
				Parent: parents[j],
			}
			if j < len(revisions) {
				fcr.Revision = revisions[j]
			}

			txns[i].FileContractRevisions = append(txns[i].FileContractRevisions, fcr)
		}
	}

	return nil
}

// decorateV2FileContractResolutions fills in the file contract
// resolutions for each transaction.
func decorateV2FileContractResolutions(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	consolidatedStmt, err := tx.Prepare(`
        SELECT 
            parent_contract_id, resolution_type,
            renewal_new_contract_id,
            renewal_final_renter_output_address, renewal_final_renter_output_value,
            renewal_final_host_output_address, renewal_final_host_output_value,
            renewal_renter_rollover, renewal_host_rollover,
            renewal_renter_signature, renewal_host_signature,
            storage_proof_proof_index, storage_proof_leaf, storage_proof_proof
        FROM v2_transaction_file_contract_resolutions
        WHERE transaction_id = ?
        ORDER BY transaction_order
    `)
	if err != nil {
		return fmt.Errorf("failed to prepare consolidated statement: %w", err)
	}
	defer consolidatedStmt.Close()

	// get a v2 FC by id
	fcStmt, err := tx.Prepare(`SELECT fc.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.resolution_type, rev.resolution_height, rev.resolution_block_id, rev.resolution_transaction_id, rev.renewed_from, rev.renewed_to, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
FROM v2_file_contract_elements fc
INNER JOIN v2_last_contract_revision rev ON (rev.contract_id = fc.contract_id)
WHERE fc.id = ?`)
	if err != nil {
		return fmt.Errorf("failed to prepare file contracts statement: %w", err)
	}
	defer fcStmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := consolidatedStmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query file contract resolutions: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				// all
				var parentContractID, resolutionType int64
				// renewal
				var renewalNewContractID sql.NullInt64
				var finalRenterOutput, finalHostOutput types.SiacoinOutput
				var renewalRenterRollover, renewalHostRollover types.Currency
				var renewalRenterSignature, renewalHostSignature types.Signature
				// storage proof
				var storageProofProofIndex types.ChainIndexElement
				var storageProofProof []types.Hash256
				var storageProofLeaf []byte

				// Scan all fields, some of which may be NULL
				if err := rows.Scan(
					&parentContractID, &resolutionType,
					&renewalNewContractID,
					decodeNull(&finalRenterOutput.Address), decodeNull(&finalRenterOutput.Value),
					decodeNull(&finalHostOutput.Address), decodeNull(&finalHostOutput.Value),
					decodeNull(&renewalRenterRollover), decodeNull(&renewalHostRollover),
					decodeNull(&renewalRenterSignature), decodeNull(&renewalHostSignature),
					decodeNull(&storageProofProofIndex), &storageProofLeaf, decodeNull(&storageProofProof)); err != nil {
					return fmt.Errorf("failed to scan resolution metadata: %w", err)
				}

				// Retrieve parent contract element
				parent, err := scanV2FileContract(fcStmt.QueryRow(parentContractID))
				if err != nil {
					return fmt.Errorf("failed to scan file contract: %w", err)
				}

				fcr := explorer.V2FileContractResolution{
					Parent: parent,
					Type:   explorer.V2Resolution(resolutionType),
				}
				switch fcr.Type {
				case explorer.V2ResolutionRenewal:
					renewal := &explorer.V2FileContractRenewal{
						FinalRenterOutput: finalRenterOutput,
						FinalHostOutput:   finalHostOutput,
						RenterRollover:    renewalRenterRollover,
						HostRollover:      renewalHostRollover,
						RenterSignature:   renewalRenterSignature,
						HostSignature:     renewalHostSignature,
					}
					if renewalNewContractID.Valid {
						renewal.NewContract, err = scanV2FileContract(fcStmt.QueryRow(renewalNewContractID.Int64))
						if err != nil {
							return fmt.Errorf("failed to scan new contract: %w", err)
						}
					}
					fcr.Resolution = renewal
				case explorer.V2ResolutionStorageProof:
					proof := &types.V2StorageProof{
						ProofIndex: storageProofProofIndex,
						Proof:      storageProofProof,
						Leaf:       [64]byte(storageProofLeaf),
					}
					fcr.Resolution = proof
				case explorer.V2ResolutionExpiration:
					fcr.Resolution = new(types.V2FileContractExpiration)
				}

				// Append the resolution to the transaction.
				txns[i].FileContractResolutions = append(txns[i].FileContractResolutions, fcr)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve file contract resolution rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// V2Transactions implements explorer.Store.
func (s *Store) V2Transactions(ids []types.TransactionID) (results []explorer.V2Transaction, err error) {
	err = s.transaction(func(tx *txn) error {
		results, err = getV2Transactions(tx, ids)
		if err != nil {
			return fmt.Errorf("failed to get v2 transactions: %w", err)
		}
		return err
	})
	return
}
