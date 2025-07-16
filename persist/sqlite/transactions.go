package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/explored/explorer"
)

// TransactionChainIndices returns the chain indices of the blocks the transaction
// was included in. If the transaction has not been included in any blocks, the
// result will be nil,nil.
func (s *Store) TransactionChainIndices(txnID types.TransactionID, offset, limit uint64) (indices []types.ChainIndex, err error) {
	err = s.transaction(func(tx *txn) error {
		rows, err := tx.Query(`SELECT DISTINCT b.id, b.height FROM blocks b
INNER JOIN block_transactions bt ON bt.block_id = b.id
INNER JOIN transactions t ON t.id = bt.transaction_id
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

// decorateMinerFees returns the miner fees for each transaction.
func decorateMinerFees(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT fee
FROM transaction_miner_fees
WHERE transaction_id = ?
ORDER BY transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var fee types.Currency
				if err := rows.Scan(decode(&fee)); err != nil {
					return fmt.Errorf("failed to scan: %w", err)
				}
				txns[i].MinerFees = append(txns[i].MinerFees, fee)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve miner fee rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateArbitraryData returns the arbitrary data for each transaction.
func decorateArbitraryData(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT data
FROM transaction_arbitrary_data
WHERE transaction_id = ?
ORDER BY transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var data []byte
				if err := rows.Scan(&data); err != nil {
					return fmt.Errorf("failed to scan: %w", err)
				}
				txns[i].ArbitraryData = append(txns[i].ArbitraryData, data)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve arbitrary data rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateSignatures returns the signatures for each transaction.
func decorateSignatures(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT parent_id, public_key_index, timelock, covered_fields, signature
FROM transaction_signatures
WHERE transaction_id = ?
ORDER BY transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var sig types.TransactionSignature
				if err := rows.Scan(decode(&sig.ParentID), &sig.PublicKeyIndex, decode(&sig.Timelock), decode(&sig.CoveredFields), &sig.Signature); err != nil {
					return fmt.Errorf("failed to scan: %w", err)
				}
				txns[i].Signatures = append(txns[i].Signatures, sig)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve signature rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateSiacoinOutputs returns the siacoin outputs for each transaction.
func decorateSiacoinOutputs(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT sc.output_id, sc.leaf_index, sc.spent_index, sc.source, sc.maturity_height, sc.address, sc.value
FROM siacoin_elements sc
INNER JOIN transaction_siacoin_outputs ts ON ts.output_id = sc.id
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
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

// decorateSiacoinInputs returns the siacoin inputs for each transaction.
func decorateSiacoinInputs(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT sc.output_id, ts.unlock_conditions, sc.value
FROM siacoin_elements sc
INNER JOIN transaction_siacoin_inputs ts ON ts.parent_id = sc.id
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var sci explorer.SiacoinInput
				if err := rows.Scan(decode(&sci.ParentID), decode(&sci.UnlockConditions), decode(&sci.Value)); err != nil {
					return fmt.Errorf("failed to scan: %w", err)
				}
				sci.Address = sci.UnlockConditions.UnlockHash()
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

// decorateSiafundInputs returns the siafund inputs for each transaction.
func decorateSiafundInputs(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT sf.output_id, ts.unlock_conditions, ts.claim_address, sf.value
FROM siafund_elements sf
INNER JOIN transaction_siafund_inputs ts ON ts.parent_id = sf.id
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var sfi explorer.SiafundInput
				if err := rows.Scan(decode(&sfi.ParentID), decode(&sfi.UnlockConditions), decode(&sfi.ClaimAddress), decode(&sfi.Value)); err != nil {
					return fmt.Errorf("failed to scan: %w", err)
				}
				sfi.Address = sfi.UnlockConditions.UnlockHash()
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

// decorateSiafundOutputs returns the siafund outputs for each transaction.
func decorateSiafundOutputs(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT sf.output_id, sf.leaf_index, sf.spent_index, sf.claim_start, sf.address, sf.value
FROM siafund_elements sf
INNER JOIN transaction_siafund_outputs ts ON ts.output_id = sf.id
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var spentIndex types.ChainIndex
				var sfo explorer.SiafundOutput
				if err := rows.Scan(decode(&sfo.ID), decode(&sfo.StateElement.LeafIndex), decodeNull(&spentIndex), decode(&sfo.ClaimStart), decode(&sfo.SiafundOutput.Address), decode(&sfo.SiafundOutput.Value)); err != nil {
					return fmt.Errorf("failed to scan: %w", err)
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

func fileContractOutputs(tx *txn, contractID int64) (valid []explorer.ContractSiacoinOutput, missed []explorer.ContractSiacoinOutput, err error) {
	validRows, err := tx.Query(`SELECT id, address, value
	FROM file_contract_valid_proof_outputs
	WHERE contract_id = ?
	ORDER BY contract_order ASC`, contractID)
	if err != nil {
		return nil, nil, err
	}
	defer validRows.Close()

	for validRows.Next() {
		var sco explorer.ContractSiacoinOutput
		if err := validRows.Scan(decode(&sco.ID), decode(&sco.Address), decode(&sco.Value)); err != nil {
			return nil, nil, fmt.Errorf("failed to scan valid proof output: %w", err)
		}
		valid = append(valid, sco)
	}
	if err := validRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to get valid contract rows: %w", err)
	}

	missedRows, err := tx.Query(`SELECT id, address, value
FROM file_contract_missed_proof_outputs
WHERE contract_id = ?
ORDER BY contract_order ASC`, contractID)
	if err != nil {
		return nil, nil, err
	}
	defer missedRows.Close()

	for missedRows.Next() {
		var sco explorer.ContractSiacoinOutput
		if err := missedRows.Scan(decode(&sco.ID), decode(&sco.Address), decode(&sco.Value)); err != nil {
			return nil, nil, fmt.Errorf("failed to scan valid proof output: %w", err)
		}
		missed = append(missed, sco)
	}
	if err := missedRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to get missed contract rows: %w", err)
	}

	return valid, missed, nil
}

// decorateFileContracts returns the file contracts for each transaction.
func decorateFileContracts(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT fc.id, fc.contract_id, rev.resolved, rev.valid, fc.transaction_id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.proof_height, rev.proof_block_id, rev.proof_transaction_id, fc.filesize, fc.file_merkle_root, fc.window_start, fc.window_end, fc.payout, fc.unlock_hash, fc.revision_number
FROM file_contract_elements fc
INNER JOIN transaction_file_contracts ts ON ts.contract_id = fc.id
INNER JOIN last_contract_revision rev ON rev.contract_id = fc.contract_id
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				fc, err := scanFileContract(tx, rows)
				if err != nil {
					return fmt.Errorf("failed to scan file contract: %w", err)
				}
				txns[i].FileContracts = append(txns[i].FileContracts, fc)
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

// decorateFileContractRevisions returns the file contract revisions for each transaction.
func decorateFileContractRevisions(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT fc.id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.proof_height, rev.proof_block_id, rev.proof_transaction_id, ts.parent_id, ts.unlock_conditions, fc.contract_id, rev.resolved, rev.valid, fc.transaction_id, fc.filesize, fc.file_merkle_root, fc.window_start, fc.window_end, fc.payout, fc.unlock_hash, fc.revision_number
FROM file_contract_elements fc
INNER JOIN transaction_file_contract_revisions ts ON ts.contract_id = fc.id
INNER JOIN last_contract_revision rev ON rev.contract_id = fc.contract_id
WHERE ts.transaction_id = ?
ORDER BY ts.transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var contractID int64
				var fc explorer.FileContractRevision

				var proofIndex types.ChainIndex
				var proofTransactionID types.TransactionID
				if err := rows.Scan(&contractID, decode(&fc.ConfirmationIndex.Height), decode(&fc.ConfirmationIndex.ID), decode(&fc.ConfirmationTransactionID), decodeNull(&proofIndex.Height), decodeNull(&proofIndex.ID), decodeNull(&proofTransactionID), decode(&fc.ParentID), decode(&fc.UnlockConditions), decode(&fc.ID), &fc.Resolved, &fc.Valid, decode(&fc.TransactionID), decode(&fc.ExtendedFileContract.Filesize), decode(&fc.ExtendedFileContract.FileMerkleRoot), decode(&fc.ExtendedFileContract.WindowStart), decode(&fc.ExtendedFileContract.WindowEnd), decode(&fc.ExtendedFileContract.Payout), decode(&fc.ExtendedFileContract.UnlockHash), decode(&fc.ExtendedFileContract.RevisionNumber)); err != nil {
					return fmt.Errorf("failed to scan file contract: %w", err)
				}
				fc.ValidProofOutputs, fc.MissedProofOutputs, err = fileContractOutputs(tx, contractID)
				if err != nil {
					return fmt.Errorf("failed to get contract proof outputs: %w", err)
				}

				if proofIndex != (types.ChainIndex{}) {
					fc.ProofIndex = &proofIndex
				}
				if proofTransactionID != (types.TransactionID{}) {
					fc.ProofTransactionID = &proofTransactionID
				}

				txns[i].FileContractRevisions = append(txns[i].FileContractRevisions, fc)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve file contract revision rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// decorateStorageProofs returns the storage proofs for each transaction.
func decorateStorageProofs(tx *txn, dbIDs []int64, txns []explorer.Transaction) error {
	stmt, err := tx.Prepare(`SELECT parent_id, leaf, proof
FROM transaction_storage_proofs
WHERE transaction_id = ?
ORDER BY transaction_order ASC`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, dbID := range dbIDs {
		err := func() error {
			rows, err := stmt.Query(dbID)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}
			defer rows.Close()

			for rows.Next() {
				var proof types.StorageProof
				leaf := make([]byte, 64)
				if err := rows.Scan(decode(&proof.ParentID), &leaf, decode(&proof.Proof)); err != nil {
					return fmt.Errorf("failed to scan: %w", err)
				}
				proof.Leaf = [64]byte(leaf)
				txns[i].StorageProofs = append(txns[i].StorageProofs, proof)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("failed to retrieve storage proof rows: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

type transactionID struct {
	id   types.TransactionID
	dbID int64
}

// blockTransactionIDs returns the database ID for each transaction in the
// block.
func blockTransactionIDs(tx *txn, blockID types.BlockID) (txnIDs []types.TransactionID, err error) {
	rows, err := tx.Query(`SELECT t.transaction_id
FROM block_transactions bt
INNER JOIN transactions t ON t.id = bt.transaction_id
WHERE block_id = ? ORDER BY block_order ASC`, encode(blockID))
	if err != nil {
		return nil, fmt.Errorf("failed to query block transaction IDs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var txnID types.TransactionID
		if err := rows.Scan(decode(&txnID)); err != nil {
			return nil, fmt.Errorf("failed to scan block transaction: %w", err)
		}
		txnIDs = append(txnIDs, txnID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed retrieve block transaction ID rows: %w", err)
	}

	return
}

// blockMinerPayouts returns the miner payouts for the block.
func blockMinerPayouts(tx *txn, blockID types.BlockID) ([]explorer.SiacoinOutput, error) {
	query := `SELECT sc.output_id, sc.leaf_index, sc.spent_index, sc.source, sc.maturity_height, sc.address, sc.value
FROM siacoin_elements sc
INNER JOIN miner_payouts mp ON mp.output_id = sc.id
WHERE mp.block_id = ?
ORDER BY mp.block_order ASC`
	rows, err := tx.Query(query, encode(blockID))
	if err != nil {
		return nil, fmt.Errorf("failed to query miner payout ids: %w", err)
	}
	defer rows.Close()

	var result []explorer.SiacoinOutput
	for rows.Next() {
		var spentIndex types.ChainIndex
		var output explorer.SiacoinOutput
		if err := rows.Scan(decode(&output.ID), decode(&output.StateElement.LeafIndex), decodeNull(&spentIndex), &output.Source, &output.MaturityHeight, decode(&output.SiacoinOutput.Address), decode(&output.SiacoinOutput.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan miner payout: %w", err)
		}
		if spentIndex != (types.ChainIndex{}) {
			output.SpentIndex = &spentIndex
		}
		result = append(result, output)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to retrieve miner payout rows: %w", err)
	}
	return result, rows.Err()
}

// transactionDatabaseIDs returns the database ID for each transaction.
func transactionDatabaseIDs(tx *txn, txnIDs []types.TransactionID) (dbIDs []int64, txns []explorer.Transaction, err error) {
	stmt, err := tx.Prepare(`SELECT id FROM transactions WHERE transaction_id = ?`)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, txnID := range txnIDs {
		var dbID int64
		if err := stmt.QueryRow(encode(txnID)).Scan(&dbID); errors.Is(err, sql.ErrNoRows) {
			continue
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to get transaction database ID: %w", err)
		}

		dbIDs = append(dbIDs, dbID)
		txns = append(txns, explorer.Transaction{
			ID: txnID,
		})
	}
	return
}

func getTransactions(tx *txn, ids []types.TransactionID) ([]explorer.Transaction, error) {
	dbIDs, txns, err := transactionDatabaseIDs(tx, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to get base transactions: %w", err)
	} else if err := decorateArbitraryData(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get arbitrary data: %w", err)
	} else if err := decorateMinerFees(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get miner fees: %w", err)
	} else if err := decorateSignatures(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get signatures: %w", err)
	} else if err := decorateSiacoinInputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get siacoin inputs: %w", err)
	} else if err := decorateSiacoinOutputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get siacoin outputs: %w", err)
	} else if err := decorateSiafundInputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get siafund inputs: %w", err)
	} else if err := decorateSiafundOutputs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get siafund outputs: %w", err)
	} else if err := decorateFileContracts(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get file contracts: %w", err)
	} else if err := decorateFileContractRevisions(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get file contract revisions: %w", err)
	} else if err := decorateStorageProofs(tx, dbIDs, txns); err != nil {
		return nil, fmt.Errorf("failed to get storage proofs: %w", err)
	}

	for i := range txns {
		for _, arb := range txns[i].ArbitraryData {
			var ha chain.HostAnnouncement
			if ha.FromArbitraryData(arb) {
				txns[i].HostAnnouncements = append(txns[i].HostAnnouncements, ha)
			}
		}
	}

	return txns, nil
}

// Transactions implements explorer.Store.
func (s *Store) Transactions(ids []types.TransactionID) (results []explorer.Transaction, err error) {
	err = s.transaction(func(tx *txn) error {
		results, err = getTransactions(tx, ids)
		if err != nil {
			return fmt.Errorf("failed to get transactions: %w", err)
		}
		return err
	})
	return
}
