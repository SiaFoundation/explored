package sqlite

import (
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
		if err := rows.Scan(&txnID, decode(&sig.ParentID), &sig.PublicKeyIndex, decode(&sig.Timelock), decode(&sig.CoveredFields), &sig.Signature); err != nil {
			return nil, fmt.Errorf("failed to scan signature: %w", err)
		}
		result[txnID] = append(result[txnID], sig)
	}
	return result, nil
}

// transactionSiacoinOutputs returns the siacoin outputs for each transaction.
func transactionSiacoinOutputs(tx *txn, txnIDs []int64) (map[int64][]explorer.SiacoinOutput, error) {
	query := `SELECT ts.transaction_id, sc.output_id, sc.leaf_index, sc.spent_index, sc.source, sc.maturity_height, sc.address, sc.value
FROM siacoin_elements sc
INNER JOIN transaction_siacoin_outputs ts ON ts.output_id = sc.id
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
		var spentIndex types.ChainIndex
		var sco explorer.SiacoinOutput
		if err := rows.Scan(&txnID, decode(&sco.ID), decode(&sco.StateElement.LeafIndex), decodeNull(&spentIndex), &sco.Source, &sco.MaturityHeight, decode(&sco.SiacoinOutput.Address), decode(&sco.SiacoinOutput.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan siacoin output: %w", err)
		}
		if spentIndex != (types.ChainIndex{}) {
			sco.SpentIndex = &spentIndex
		}
		result[txnID] = append(result[txnID], sco)
	}
	return result, nil
}

// transactionSiacoinInputs returns the siacoin inputs for each transaction.
func transactionSiacoinInputs(tx *txn, txnIDs []int64) (map[int64][]explorer.SiacoinInput, error) {
	query := `SELECT sc.id, ts.transaction_id, sc.output_id, ts.unlock_conditions, sc.value
FROM siacoin_elements sc
INNER JOIN transaction_siacoin_inputs ts ON ts.parent_id = sc.id
WHERE ts.transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY ts.transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]explorer.SiacoinInput)
	for rows.Next() {
		var dbID, txnID int64
		var sci explorer.SiacoinInput
		if err := rows.Scan(&dbID, &txnID, decode(&sci.ParentID), decode(&sci.UnlockConditions), decode(&sci.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan siacoin input: %w", err)
		}
		sci.Address = sci.UnlockConditions.UnlockHash()
		result[txnID] = append(result[txnID], sci)
	}
	return result, nil
}

// transactionSiafundInputs returns the siafund inputs for each transaction.
func transactionSiafundInputs(tx *txn, txnIDs []int64) (map[int64][]explorer.SiafundInput, error) {
	query := `SELECT ts.transaction_id, sf.output_id, ts.unlock_conditions, ts.claim_address, sf.value
FROM siafund_elements sf
INNER JOIN transaction_siafund_inputs ts ON ts.parent_id = sf.id
WHERE ts.transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY ts.transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]explorer.SiafundInput)
	for rows.Next() {
		var txnID int64
		var sfi explorer.SiafundInput
		if err := rows.Scan(&txnID, decode(&sfi.ParentID), decode(&sfi.UnlockConditions), decode(&sfi.ClaimAddress), decode(&sfi.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan siafund input: %w", err)
		}

		sfi.Address = sfi.UnlockConditions.UnlockHash()
		result[txnID] = append(result[txnID], sfi)
	}
	return result, nil
}

// transactionSiafundOutputs returns the siafund outputs for each transaction.
func transactionSiafundOutputs(tx *txn, txnIDs []int64) (map[int64][]explorer.SiafundOutput, error) {
	query := `SELECT ts.transaction_id, sf.output_id, sf.leaf_index, sf.spent_index, sf.claim_start, sf.address, sf.value
FROM siafund_elements sf
INNER JOIN transaction_siafund_outputs ts ON ts.output_id = sf.id
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
		var spentIndex types.ChainIndex
		var sfo explorer.SiafundOutput
		if err := rows.Scan(&txnID, decode(&sfo.ID), decode(&sfo.StateElement.LeafIndex), decodeNull(&spentIndex), decode(&sfo.ClaimStart), decode(&sfo.SiafundOutput.Address), decode(&sfo.SiafundOutput.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan siafund output: %w", err)
		}

		if spentIndex != (types.ChainIndex{}) {
			sfo.SpentIndex = &spentIndex
		}
		result[txnID] = append(result[txnID], sfo)
	}
	return result, nil
}

type fileContractProofOutputs struct {
	valid  []explorer.ContractSiacoinOutput
	missed []explorer.ContractSiacoinOutput
}

func fileContractOutputs(tx *txn, contractIDs []int64) (map[int64]fileContractProofOutputs, error) {
	result := make(map[int64]fileContractProofOutputs)

	validQuery := `SELECT contract_id, id, address, value
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
		var sco explorer.ContractSiacoinOutput
		if err := validRows.Scan(&contractID, decode(&sco.ID), decode(&sco.Address), decode(&sco.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan valid proof output: %w", err)
		}

		r := result[contractID]
		r.valid = append(r.valid, sco)
		result[contractID] = r
	}

	missedQuery := `SELECT contract_id, id, address, value
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
		var sco explorer.ContractSiacoinOutput
		if err := missedRows.Scan(&contractID, decode(&sco.ID), decode(&sco.Address), decode(&sco.Value)); err != nil {
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
func transactionFileContracts(tx *txn, txnIDs []int64) (map[int64][]explorer.ExtendedFileContract, error) {
	query := `SELECT ts.transaction_id, fc.id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.proof_height, rev.proof_block_id, rev.proof_transaction_id, fc.contract_id, fc.resolved, fc.valid, fc.transaction_id, fc.filesize, fc.file_merkle_root, fc.window_start, fc.window_end, fc.payout, fc.unlock_hash, fc.revision_number
FROM file_contract_elements fc
INNER JOIN transaction_file_contracts ts ON ts.contract_id = fc.id
INNER JOIN last_contract_revision rev ON rev.contract_id = fc.contract_id
WHERE ts.transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY ts.transaction_order ASC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, fmt.Errorf("failed to query contract output ids: %w", err)
	}
	defer rows.Close()

	var contractIDs []int64
	// map transaction ID to contract list
	result := make(map[int64][]explorer.ExtendedFileContract)
	// map contract ID to transaction ID
	contractTransaction := make(map[int64]contractOrder)
	for rows.Next() {
		var txnID, contractID int64
		var fc explorer.ExtendedFileContract

		var proofIndex types.ChainIndex
		var proofTransactionID types.TransactionID
		if err := rows.Scan(&txnID, &contractID, decode(&fc.ConfirmationIndex.Height), decode(&fc.ConfirmationIndex.ID), decode(&fc.ConfirmationTransactionID), decodeNull(&proofIndex.Height), decodeNull(&proofIndex.ID), decodeNull(&proofTransactionID), decode(&fc.ID), &fc.Resolved, &fc.Valid, decode(&fc.TransactionID), decode(&fc.Filesize), decode(&fc.FileMerkleRoot), decode(&fc.WindowStart), decode(&fc.WindowEnd), decode(&fc.Payout), decode(&fc.UnlockHash), decode(&fc.RevisionNumber)); err != nil {
			return nil, fmt.Errorf("failed to scan file contract: %w", err)
		}

		if proofIndex != (types.ChainIndex{}) {
			fc.ProofIndex = &proofIndex
		}
		if proofTransactionID != (types.TransactionID{}) {
			fc.ProofTransactionID = &proofTransactionID
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
	query := `SELECT ts.transaction_id, fc.id, rev.confirmation_height, rev.confirmation_block_id, rev.confirmation_transaction_id, rev.proof_height, rev.proof_block_id, rev.proof_transaction_id, ts.parent_id, ts.unlock_conditions, fc.contract_id, fc.resolved, fc.valid, fc.transaction_id, fc.filesize, fc.file_merkle_root, fc.window_start, fc.window_end, fc.payout, fc.unlock_hash, fc.revision_number
FROM file_contract_elements fc
INNER JOIN transaction_file_contract_revisions ts ON ts.contract_id = fc.id
INNER JOIN last_contract_revision rev ON rev.contract_id = fc.contract_id
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

		var proofIndex types.ChainIndex
		var proofTransactionID types.TransactionID
		if err := rows.Scan(&txnID, &contractID, decode(&fc.ConfirmationIndex.Height), decode(&fc.ConfirmationIndex.ID), decode(&fc.ConfirmationTransactionID), decodeNull(&proofIndex.Height), decodeNull(&proofIndex.ID), decodeNull(&proofTransactionID), decode(&fc.ParentID), decode(&fc.UnlockConditions), decode(&fc.ID), &fc.Resolved, &fc.Valid, decode(&fc.TransactionID), decode(&fc.ExtendedFileContract.Filesize), decode(&fc.ExtendedFileContract.FileMerkleRoot), decode(&fc.ExtendedFileContract.WindowStart), decode(&fc.ExtendedFileContract.WindowEnd), decode(&fc.ExtendedFileContract.Payout), decode(&fc.ExtendedFileContract.UnlockHash), decode(&fc.ExtendedFileContract.RevisionNumber)); err != nil {
			return nil, fmt.Errorf("failed to scan file contract: %w", err)
		}

		if proofIndex != (types.ChainIndex{}) {
			fc.ProofIndex = &proofIndex
		}
		if proofTransactionID != (types.TransactionID{}) {
			fc.ProofTransactionID = &proofTransactionID
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
		result[index.txnID][index.transactionOrder].ExtendedFileContract.ValidProofOutputs = output.valid
		result[index.txnID][index.transactionOrder].ExtendedFileContract.MissedProofOutputs = output.missed
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

		leaf := make([]byte, 64)
		if err := rows.Scan(&txnID, decode(&proof.ParentID), &leaf, decode(&proof.Proof)); err != nil {
			return nil, fmt.Errorf("failed to scan arbitrary data: %w", err)
		}
		proof.Leaf = [64]byte(leaf)

		result[txnID] = append(result[txnID], proof)
	}
	return result, nil
}

type transactionID struct {
	id   types.TransactionID
	dbID int64
}

// blockTransactionIDs returns the database ID for each transaction in the
// block.
func blockTransactionIDs(tx *txn, blockID types.BlockID) (idMap map[int64]transactionID, err error) {
	rows, err := tx.Query(`SELECT bt.transaction_id, block_order, t.transaction_id
FROM block_transactions bt
INNER JOIN transactions t ON t.id = bt.transaction_id
WHERE block_id = ? ORDER BY block_order ASC`, encode(blockID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	idMap = make(map[int64]transactionID)
	for rows.Next() {
		var dbID int64
		var blockOrder int64
		var txnID types.TransactionID
		if err := rows.Scan(&dbID, &blockOrder, decode(&txnID)); err != nil {
			return nil, fmt.Errorf("failed to scan block transaction: %w", err)
		}
		idMap[blockOrder] = transactionID{id: txnID, dbID: dbID}
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
	return result, nil
}

// transactionDatabaseIDs returns the database ID for each transaction.
func transactionDatabaseIDs(tx *txn, txnIDs []types.TransactionID) (dbIDs map[int64]transactionID, err error) {
	encodedIDs := func(ids []types.TransactionID) []any {
		result := make([]any, len(ids))
		for i, id := range ids {
			result[i] = encode(id)
		}
		return result
	}

	query := `SELECT id, transaction_id FROM transactions WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `) ORDER BY id`
	rows, err := tx.Query(query, encodedIDs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var i int64
	dbIDs = make(map[int64]transactionID)
	for rows.Next() {
		var dbID int64
		var txnID types.TransactionID
		if err := rows.Scan(&dbID, decode(&txnID)); err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}
		dbIDs[i] = transactionID{id: txnID, dbID: dbID}
		i++
	}
	return
}

func getTransactions(tx *txn, idMap map[int64]transactionID) ([]explorer.Transaction, error) {
	dbIDs := make([]int64, len(idMap))
	for order, id := range idMap {
		dbIDs[order] = id.dbID
	}

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
	for order, dbID := range dbIDs {
		txn := explorer.Transaction{
			ID:                    idMap[int64(order)].id,
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

		for _, arb := range txn.ArbitraryData {
			var ha chain.HostAnnouncement
			if ha.FromArbitraryData(arb) {
				txn.HostAnnouncements = append(txn.HostAnnouncements, ha)
			}
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
