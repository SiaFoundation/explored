package sqlite

import (
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
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var index types.ChainIndex
			if err := rows.Scan(decode(&index.ID), decode(&index.Height)); err != nil {
				return fmt.Errorf("failed to scan chain index: %w", err)
			}
			indices = append(indices, index)
		}
		return rows.Err()
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
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id types.TransactionID
		if err := rows.Scan(decode(&id)); err != nil {
			return nil, fmt.Errorf("failed to scan block transaction: %w", err)
		}
		ids = append(ids, id)
	}
	return
}

// getV2Transactions fetches v2 transactions in the correct order using
// prepared statements.
func getV2Transactions(tx *txn, ids []types.TransactionID) ([]explorer.V2Transaction, error) {
	dbIDs, txns, err := getV2TransactionBase(tx, ids)
	if err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get base transactions: %w", err)
	} else if err := fillV2TransactionAttestations(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get attestations: %w", err)
	} else if err := fillV2TransactionSiacoinInputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get siacoin inputs: %w", err)
	} else if err := fillV2TransactionSiacoinOutputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get siacoin outputs: %w", err)
	} else if err := fillV2TransactionSiafundInputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get siafund inputs: %w", err)
	} else if err := fillV2TransactionSiafundOutputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get siafund outputs: %w", err)
	} else if err := fillV2TransactionFileContracts(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get file contracts: %w", err)
	} else if err := fillV2TransactionFileContractRevisions(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get file contracts: %w", err)
	}

	// add host announcements if we have any
	for i := range txns {
		for _, attestation := range txns[i].Attestations {
			var ha chain.HostAnnouncement
			if ha.FromAttestation(attestation) {
				txns[i].HostAnnouncements = append(txns[i].HostAnnouncements, ha)
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
		return nil, nil, fmt.Errorf("getV2TransactionBase: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	var dbID int64
	dbIDs := make([]int64, 0, len(txnIDs))
	txns := make([]explorer.V2Transaction, 0, len(txnIDs))
	for _, id := range txnIDs {
		var txn explorer.V2Transaction
		var newFoundationAddress types.Address
		if err := stmt.QueryRow(encode(id)).Scan(&dbID, decode(&txn.ID), decodeNull(&newFoundationAddress), decode(&txn.MinerFee), &txn.ArbitraryData); err != nil {
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

// fillV2TransactionAttestations fills in the attestations for each
// transaction.
func fillV2TransactionAttestations(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
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
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// fillV2TransactionSiacoinInputs fills in the siacoin inputs for each
// transaction.
func fillV2TransactionSiacoinInputs(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
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
				if err := rows.Scan(decode(&sci.SatisfiedPolicy), decode(&sci.Parent.ID), decode(&sci.Parent.LeafIndex), &sci.Parent.MaturityHeight, decode(&sci.Parent.SiacoinOutput.Address), decode(&sci.Parent.SiacoinOutput.Value)); err != nil {
					return fmt.Errorf("failed to scan siacoin inputs: %w", err)
				}

				txns[i].SiacoinInputs = append(txns[i].SiacoinInputs, sci)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// fillV2TransactionSiacoinOutputs fills in the siacoin outputs for each
// transaction.
func fillV2TransactionSiacoinOutputs(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
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
				if err := rows.Scan(decode(&sco.StateElement.ID), decode(&sco.LeafIndex), decodeNull(&spentIndex), &sco.Source, &sco.MaturityHeight, decode(&sco.SiacoinOutput.Address), decode(&sco.SiacoinOutput.Value)); err != nil {
					return fmt.Errorf("failed to scan siacoin output: %w", err)
				}

				if spentIndex != (types.ChainIndex{}) {
					sco.SpentIndex = &spentIndex
				}
				txns[i].SiacoinOutputs = append(txns[i].SiacoinOutputs, sco)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// fillV2TransactionSiafundInputs fills in the siacoin inputs for each
// transaction.
func fillV2TransactionSiafundInputs(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
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
				if err := rows.Scan(decode(&sfi.SatisfiedPolicy), decode(&sfi.ClaimAddress), decode(&sfi.Parent.ID), decode(&sfi.Parent.LeafIndex), decode(&sfi.Parent.SiafundOutput.Address), decode(&sfi.Parent.SiafundOutput.Value)); err != nil {
					return fmt.Errorf("failed to scan siacoin inputs: %w", err)
				}

				txns[i].SiafundInputs = append(txns[i].SiafundInputs, sfi)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// fillV2TransactionSiafundOutputs fills in the siafund outputs for each
// transaction.
func fillV2TransactionSiafundOutputs(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
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
				if err := rows.Scan(decode(&sfo.StateElement.ID), decode(&sfo.StateElement.LeafIndex), decodeNull(&spentIndex), decode(&sfo.ClaimStart), decode(&sfo.SiafundOutput.Address), decode(&sfo.SiafundOutput.Value)); err != nil {
					return fmt.Errorf("failed to scan siafund output: %w", err)
				}
				if spentIndex != (types.ChainIndex{}) {
					sfo.SpentIndex = &spentIndex
				}

				txns[i].SiafundOutputs = append(txns[i].SiafundOutputs, sfo)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// fillV2TransactionFileContracts fills in the file contracts for each
// transaction.
func fillV2TransactionFileContracts(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	stmt, err := tx.Prepare(`SELECT fc.transaction_id, rev.confirmation_index, rev.confirmation_transaction_id, rev.resolution, rev.resolution_index, rev.resolution_transaction_id, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
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
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// fillV2TransactionFileContractRevisions fills in the file contracts for each
// transaction.
func fillV2TransactionFileContractRevisions(tx *txn, dbIDs []int64, txns []explorer.V2Transaction) error {
	parentStmt, err := tx.Prepare(`SELECT fc.transaction_id, rev.confirmation_index, rev.confirmation_transaction_id, rev.resolution, rev.resolution_index, rev.resolution_transaction_id, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
FROM v2_file_contract_elements fc
INNER JOIN v2_transaction_file_contract_revisions ts ON (ts.parent_contract_id = fc.id)
INNER JOIN v2_last_contract_revision rev ON (rev.contract_id = fc.contract_id)
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare file contracts parent statement: %w", err)
	}
	defer parentStmt.Close()

	revisionStmt, err := tx.Prepare(`SELECT fc.transaction_id, rev.confirmation_index, rev.confirmation_transaction_id, rev.resolution, rev.resolution_index, rev.resolution_transaction_id, fc.contract_id, fc.leaf_index, fc.capacity, fc.filesize, fc.file_merkle_root, fc.proof_height, fc.expiration_height, fc.renter_output_address, fc.renter_output_value, fc.host_output_address, fc.host_output_value, fc.missed_host_value, fc.total_collateral, fc.renter_public_key, fc.host_public_key, fc.revision_number, fc.renter_signature, fc.host_signature
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
		return contracts, nil
	}

	for i, dbID := range dbIDs {
		parents, err := collectFileContracts(parentStmt, dbID)
		if err != nil {
			return err
		}

		revisions, err := collectFileContracts(revisionStmt, dbID)
		if err != nil {
			return err
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

// V2Transactions implements explorer.Store.
func (s *Store) V2Transactions(ids []types.TransactionID) (results []explorer.V2Transaction, err error) {
	err = s.transaction(func(tx *txn) error {
		results, err = getV2Transactions(tx, ids)
		if err != nil {
			return fmt.Errorf("failed to get transactions: %w", err)
		}
		return err
	})
	return
}
