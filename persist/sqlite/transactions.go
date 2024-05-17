package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

// transactionMinerFee returns the miner fees for each transaction.
func transactionMinerFee(tx *txn, txnIDs []int64) (map[int64][]types.Currency, error) {
	query := `SELECT transaction_id, fee
FROM transaction_miner_fees
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]types.Currency)
	for rows.Next() {
		var txnID int64
		var fee types.Currency
		if err := rows.Scan(&txnID, decode(&fee)); err != nil {
			return nil, fmt.Errorf("failed to scan arbitrary data: %w", err)
		}
		result[txnID] = append(result[txnID], fee)
	}
	return result, nil
}

// transactionArbitraryData returns the arbitrary data for each transaction.
func transactionArbitraryData(tx *txn, txnIDs []int64) (map[int64][][]byte, error) {
	query := `SELECT transaction_id, data
FROM transaction_arbitrary_data
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][][]byte)
	for rows.Next() {
		var txnID int64
		var data []byte
		if err := rows.Scan(&txnID, &data); err != nil {
			return nil, fmt.Errorf("failed to scan arbitrary data: %w", err)
		}
		result[txnID] = append(result[txnID], data)
	}
	return result, nil
}

// transactionSignatures returns the signatures for each transaction.
func transactionSignatures(tx *txn, txnIDs []int64) (map[int64][]types.TransactionSignature, error) {
	query := `SELECT transaction_id, parent_id, public_key_index, timelock, covered_fields, signature
FROM transaction_signatures
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]types.TransactionSignature)
	for rows.Next() {
		var txnID int64
		var sig types.TransactionSignature
		if err := rows.Scan(&txnID, decode(&sig.ParentID), &sig.PublicKeyIndex, &sig.Timelock, decode(&sig.CoveredFields), &sig.Signature); err != nil {
			return nil, fmt.Errorf("failed to scan signature: %w", err)
		}
		result[txnID] = append(result[txnID], sig)
	}
	return result, nil
}

// transactionSiacoinOutputs returns the siacoin outputs for each transaction.
func transactionSiacoinOutputs(tx *txn, txnIDs []int64) (map[int64][]explorer.SiacoinOutput, error) {
	query := `SELECT ts.transaction_id, sc.output_id, sc.leaf_index, sc.source, sc.maturity_height, sc.address, sc.value
FROM siacoin_elements sc
INNER JOIN transaction_siacoin_outputs ts ON (ts.output_id = sc.id)
WHERE ts.transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY ts.transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, fmt.Errorf("failed to query siacoin output ids: %w", err)
	}
	defer rows.Close()

	// map transaction ID to output list
	result := make(map[int64][]explorer.SiacoinOutput)
	for rows.Next() {
		var txnID int64
		var sco explorer.SiacoinOutput
		if err := rows.Scan(&txnID, decode(&sco.StateElement.ID), decode(&sco.LeafIndex), &sco.Source, &sco.MaturityHeight, decode(&sco.SiacoinOutput.Address), decode(&sco.SiacoinOutput.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan siacoin output: %w", err)
		}
		result[txnID] = append(result[txnID], sco)
	}
	return result, nil
}

// transactionSiacoinInputs returns the siacoin inputs for each transaction.
func transactionSiacoinInputs(tx *txn, txnIDs []int64) (map[int64][]types.SiacoinInput, error) {
	query := `SELECT transaction_id, parent_id, unlock_conditions
FROM transaction_siacoin_inputs
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]types.SiacoinInput)
	for rows.Next() {
		var txnID int64
		var sci types.SiacoinInput
		if err := rows.Scan(&txnID, decode(&sci.ParentID), decode(&sci.UnlockConditions)); err != nil {
			return nil, fmt.Errorf("failed to scan siacoin input: %w", err)
		}
		result[txnID] = append(result[txnID], sci)
	}
	return result, nil
}

// transactionSiafundInputs returns the siafund inputs for each transaction.
func transactionSiafundInputs(tx *txn, txnIDs []int64) (map[int64][]types.SiafundInput, error) {
	query := `SELECT transaction_id, parent_id, unlock_conditions, claim_address
FROM transaction_siafund_inputs
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]types.SiafundInput)
	for rows.Next() {
		var txnID int64
		var sfi types.SiafundInput
		if err := rows.Scan(&txnID, decode(&sfi.ParentID), decode(&sfi.UnlockConditions), decode(&sfi.ClaimAddress)); err != nil {
			return nil, fmt.Errorf("failed to scan siafund input: %w", err)
		}
		result[txnID] = append(result[txnID], sfi)
	}
	return result, nil
}

// transactionSiafundOutputs returns the siafund outputs for each transaction.
func transactionSiafundOutputs(tx *txn, txnIDs []int64) (map[int64][]explorer.SiafundOutput, error) {
	query := `SELECT ts.transaction_id, sf.output_id, sf.leaf_index, sf.claim_start, sf.address, sf.value
FROM siafund_elements sf
INNER JOIN transaction_siafund_outputs ts ON (ts.output_id = sf.id)
WHERE ts.transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY ts.transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, fmt.Errorf("failed to query siafund output ids: %w", err)
	}
	defer rows.Close()

	// map transaction ID to output list
	result := make(map[int64][]explorer.SiafundOutput)
	for rows.Next() {
		var txnID int64
		var sfo explorer.SiafundOutput
		if err := rows.Scan(&txnID, decode(&sfo.StateElement.ID), decode(&sfo.StateElement.LeafIndex), decode(&sfo.ClaimStart), decode(&sfo.SiafundOutput.Address), decode(&sfo.SiafundOutput.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan siafund output: %w", err)
		}
		result[txnID] = append(result[txnID], sfo)
	}
	return result, nil
}

type fileContractProofOutputs struct {
	valid  []types.SiacoinOutput
	missed []types.SiacoinOutput
}

func fileContractOutputs(tx *txn, contractIDs []int64) (map[int64]fileContractProofOutputs, error) {
	result := make(map[int64]fileContractProofOutputs)

	validQuery := `SELECT contract_id, address, value
FROM file_contract_valid_proof_outputs
WHERE contract_id IN (` + queryPlaceHolders(len(contractIDs)) + `)
ORDER BY contract_order`
	validRows, err := tx.Query(validQuery, queryArgs(contractIDs)...)
	if err != nil {
		return nil, err
	}
	defer validRows.Close()

	for validRows.Next() {
		var contractID int64
		var sco types.SiacoinOutput
		if err := validRows.Scan(&contractID, decode(&sco.Address), decode(&sco.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan valid proof output: %w", err)
		}

		r := result[contractID]
		r.valid = append(r.valid, sco)
		result[contractID] = r
	}

	missedQuery := `SELECT contract_id, address, value
FROM file_contract_missed_proof_outputs
WHERE contract_id IN (` + queryPlaceHolders(len(contractIDs)) + `)
ORDER BY contract_order`
	missedRows, err := tx.Query(missedQuery, queryArgs(contractIDs)...)
	if err != nil {
		return nil, err
	}
	defer missedRows.Close()

	for missedRows.Next() {
		var contractID int64
		var sco types.SiacoinOutput
		if err := missedRows.Scan(&contractID, decode(&sco.Address), decode(&sco.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan missed proof output: %w", err)
		}

		r := result[contractID]
		r.missed = append(r.missed, sco)
		result[contractID] = r
	}

	return result, nil
}

type contractOrder struct {
	txnID            int64
	transactionOrder int64
}

// transactionFileContracts returns the file contracts for each transaction.
func transactionFileContracts(tx *txn, txnIDs []int64) (map[int64][]explorer.FileContract, error) {
	query := `SELECT ts.transaction_id, fc.id, fc.contract_id, fc.leaf_index, fc.resolved, fc.valid, fc.filesize, fc.file_merkle_root, fc.window_start, fc.window_end, fc.payout, fc.unlock_hash, fc.revision_number
FROM file_contract_elements fc
INNER JOIN transaction_file_contracts ts ON (ts.contract_id = fc.id)
WHERE ts.transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY ts.transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, fmt.Errorf("failed to query contract output ids: %w", err)
	}
	defer rows.Close()

	var contractIDs []int64
	// map transaction ID to contract list
	result := make(map[int64][]explorer.FileContract)
	// map contract ID to transaction ID
	contractTransaction := make(map[int64]contractOrder)
	for rows.Next() {
		var txnID, contractID int64
		var fc explorer.FileContract
		if err := rows.Scan(&txnID, &contractID, decode(&fc.StateElement.ID), decode(&fc.StateElement.LeafIndex), &fc.Resolved, &fc.Valid, &fc.Filesize, decode(&fc.FileMerkleRoot), &fc.WindowStart, &fc.WindowEnd, decode(&fc.Payout), decode(&fc.UnlockHash), &fc.RevisionNumber); err != nil {
			return nil, fmt.Errorf("failed to scan file contract: %w", err)
		}

		result[txnID] = append(result[txnID], fc)
		contractIDs = append(contractIDs, contractID)
		contractTransaction[contractID] = contractOrder{txnID, int64(len(result[txnID])) - 1}
	}

	proofOutputs, err := fileContractOutputs(tx, contractIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get file contract outputs: %w", err)
	}
	for contractID, output := range proofOutputs {
		index := contractTransaction[contractID]
		result[index.txnID][index.transactionOrder].ValidProofOutputs = output.valid
		result[index.txnID][index.transactionOrder].MissedProofOutputs = output.missed
	}

	return result, nil
}

// transactionFileContracts returns the file contract revisions for each transaction.
func transactionFileContractRevisions(tx *txn, txnIDs []int64) (map[int64][]explorer.FileContractRevision, error) {
	query := `SELECT ts.transaction_id, fc.id, ts.parent_id, ts.unlock_conditions, fc.contract_id, fc.leaf_index, fc.resolved, fc.valid, fc.filesize, fc.file_merkle_root, fc.window_start, fc.window_end, fc.payout, fc.unlock_hash, fc.revision_number
FROM file_contract_elements fc
INNER JOIN transaction_file_contract_revisions ts ON (ts.contract_id = fc.id)
WHERE ts.transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY ts.transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, fmt.Errorf("failed to query contract output ids: %w", err)
	}
	defer rows.Close()

	var contractIDs []int64
	// map transaction ID to contract list
	result := make(map[int64][]explorer.FileContractRevision)
	// map contract ID to transaction ID
	contractTransaction := make(map[int64]contractOrder)
	for rows.Next() {
		var txnID, contractID int64
		var fc explorer.FileContractRevision
		if err := rows.Scan(&txnID, &contractID, decode(&fc.ParentID), decode(&fc.UnlockConditions), decode(&fc.StateElement.ID), decode(&fc.StateElement.LeafIndex), &fc.Resolved, &fc.Valid, &fc.Filesize, decode(&fc.FileMerkleRoot), &fc.WindowStart, &fc.WindowEnd, decode(&fc.Payout), decode(&fc.UnlockHash), &fc.RevisionNumber); err != nil {
			return nil, fmt.Errorf("failed to scan file contract: %w", err)
		}

		result[txnID] = append(result[txnID], fc)
		contractIDs = append(contractIDs, contractID)
		contractTransaction[contractID] = contractOrder{txnID, int64(len(result[txnID])) - 1}
	}

	proofOutputs, err := fileContractOutputs(tx, contractIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get file contract outputs: %w", err)
	}
	for contractID, output := range proofOutputs {
		index := contractTransaction[contractID]
		result[index.txnID][index.transactionOrder].ValidProofOutputs = output.valid
		result[index.txnID][index.transactionOrder].MissedProofOutputs = output.missed
	}

	return result, nil
}

// transactionStorageProofs returns the storage proofs for each transaction.
func transactionStorageProofs(tx *txn, txnIDs []int64) (map[int64][]types.StorageProof, error) {
	query := `SELECT transaction_id, parent_id, leaf, proof
FROM transaction_storage_proofs
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]types.StorageProof)
	for rows.Next() {
		var txnID int64
		var proof types.StorageProof
		if err := rows.Scan(&txnID, decode(&proof.ParentID), &proof.Leaf, decode(&proof.Proof)); err != nil {
			return nil, fmt.Errorf("failed to scan arbitrary data: %w", err)
		}
		result[txnID] = append(result[txnID], proof)
	}
	return result, nil
}

// blockTransactionIDs returns the database ID for each transaction in the
// block.
func blockTransactionIDs(tx *txn, blockID types.BlockID) (dbIDs []int64, err error) {
	rows, err := tx.Query(`SELECT transaction_id FROM block_transactions WHERE block_id = ? ORDER BY block_order`, encode(blockID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var dbID int64
		if err := rows.Scan(&dbID); err != nil {
			return nil, fmt.Errorf("failed to scan block transaction: %w", err)
		}
		dbIDs = append(dbIDs, dbID)
	}
	return
}

// blockMinerPayouts returns the miner payouts for the block.
func blockMinerPayouts(tx *txn, blockID types.BlockID) ([]explorer.SiacoinOutput, error) {
	query := `SELECT sc.output_id, sc.leaf_index, sc.source, sc.maturity_height, sc.address, sc.value
FROM siacoin_elements sc
INNER JOIN miner_payouts mp ON (mp.output_id = sc.id)
WHERE mp.block_id = ?
ORDER BY mp.block_order ASC`
	rows, err := tx.Query(query, encode(blockID))
	if err != nil {
		return nil, fmt.Errorf("failed to query miner payout ids: %w", err)
	}
	defer rows.Close()

	var result []explorer.SiacoinOutput
	for rows.Next() {
		var output explorer.SiacoinOutput
		if err := rows.Scan(decode(&output.StateElement.ID), decode(&output.StateElement.LeafIndex), &output.Source, &output.MaturityHeight, decode(&output.SiacoinOutput.Address), decode(&output.SiacoinOutput.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan miner payout: %w", err)
		}
		result = append(result, output)
	}
	return result, nil
}

// transactionDatabaseIDs returns the database ID for each transaction.
func transactionDatabaseIDs(tx *txn, txnIDs []types.TransactionID) (dbIDs []int64, err error) {
	encodedIDs := func(ids []types.TransactionID) []any {
		result := make([]any, len(ids))
		for i, id := range ids {
			result[i] = encode(id)
		}
		return result
	}

	query := `SELECT id FROM transactions WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)`
	rows, err := tx.Query(query, encodedIDs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var dbID int64
		if err := rows.Scan(&dbID); err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}
		dbIDs = append(dbIDs, dbID)
	}
	return
}

func getTransactions(tx *txn, dbIDs []int64) ([]explorer.Transaction, error) {
	txnArbitraryData, err := transactionArbitraryData(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get arbitrary data: %w", err)
	}

	txnMinerFees, err := transactionMinerFee(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get miner fees: %w", err)
	}

	txnSignatures, err := transactionSignatures(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get signatures: %w", err)
	}

	txnSiacoinInputs, err := transactionSiacoinInputs(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get siacoin inputs: %w", err)
	}

	txnSiacoinOutputs, err := transactionSiacoinOutputs(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get siacoin outputs: %w", err)
	}

	txnSiafundInputs, err := transactionSiafundInputs(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get siafund inputs: %w", err)
	}

	txnSiafundOutputs, err := transactionSiafundOutputs(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get siafund outputs: %w", err)
	}

	txnFileContracts, err := transactionFileContracts(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get file contracts: %w", err)
	}

	txnFileContractRevisions, err := transactionFileContractRevisions(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get file contract revisions: %w", err)
	}

	txnStorageProofs, err := transactionStorageProofs(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get storage proofs: %w", err)
	}

	var results []explorer.Transaction
	for _, dbID := range dbIDs {
		txn := explorer.Transaction{
			SiacoinInputs:         txnSiacoinInputs[dbID],
			SiacoinOutputs:        txnSiacoinOutputs[dbID],
			SiafundInputs:         txnSiafundInputs[dbID],
			SiafundOutputs:        txnSiafundOutputs[dbID],
			FileContracts:         txnFileContracts[dbID],
			FileContractRevisions: txnFileContractRevisions[dbID],
			StorageProofs:         txnStorageProofs[dbID],
			MinerFees:             txnMinerFees[dbID],
			ArbitraryData:         txnArbitraryData[dbID],
			Signatures:            txnSignatures[dbID],
		}
		results = append(results, txn)
	}
	return results, nil
}

// Transactions implements explorer.Store.
func (s *Store) Transactions(ids []types.TransactionID) (results []explorer.Transaction, err error) {
	err = s.transaction(func(tx *txn) error {
		dbIDs, err := transactionDatabaseIDs(tx, ids)
		if err != nil {
			return fmt.Errorf("failed to get transaction IDs: %w", err)
		}
		results, err = getTransactions(tx, dbIDs)
		if err != nil {
			return fmt.Errorf("failed to get transactions: %w", err)
		}
		return err
	})
	return
}
