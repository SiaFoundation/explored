package sqlite

import (
	"errors"
	"fmt"

	"go.sia.tech/core/types"
)

var (
	// ErrNoTip is returned when Tip() is unable to find any blocks in the
	// database and thus there is no tip. It does not mean there was an
	// error in the underlying database.
	ErrNoTip = errors.New("no tip found")
)

// transactionArbitraryData returns the arbitrary data for each transaction.
func transactionArbitraryData(tx txn, txnIDs []int64) (map[int64][][]byte, error) {
	query := `SELECT transaction_id, data
FROM transaction_arbitrary_data
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY transaction_order DESC`
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
			return nil, fmt.Errorf("failed to scan arbitrary data: %v", err)
		}
		result[txnID] = append(result[txnID], data)
	}
	return result, nil
}

// transactionSiacoinOutputs returns the siacoin outputs for each transaction.
func transactionSiacoinOutputs(tx txn, txnIDs []int64) (map[int64][]types.SiacoinOutput, error) {
	query := `SELECT ts.transaction_id, sc.address, sc.value
FROM siacoin_outputs sc
INNER JOIN transaction_siacoin_outputs ts ON (ts.output_id = sc.id)
WHERE ts.transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY ts.transaction_order DESC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, fmt.Errorf("failed to query siacoin output ids: %v", err)
	}
	defer rows.Close()

	// map transaction ID to output list
	result := make(map[int64][]types.SiacoinOutput)
	for rows.Next() {
		var txnID int64
		var sco types.SiacoinOutput
		if err := rows.Scan(&txnID, dbDecode(&sco.Address), dbDecode(&sco.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan siacoin output: %v", err)
		}
		result[txnID] = append(result[txnID], sco)
	}
	return result, nil
}

// transactionSiacoinInputs returns the siacoin inputs for each transaction.
func transactionSiacoinInputs(tx txn, txnIDs []int64) (map[int64][]types.SiacoinInput, error) {
	query := `SELECT transaction_id, parent_id, unlock_conditions
FROM transaction_siacoin_inputs
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY transaction_order DESC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]types.SiacoinInput)
	for rows.Next() {
		var txnID int64
		var sci types.SiacoinInput
		if err := rows.Scan(&txnID, dbDecode(&sci.ParentID), dbDecode(&sci.UnlockConditions)); err != nil {
			return nil, fmt.Errorf("failed to scan siacoin input: %v", err)
		}
		result[txnID] = append(result[txnID], sci)
	}
	return result, nil
}

// transactionSiafundInputs returns the siafund inputs for each transaction.
func transactionSiafundInputs(tx txn, txnIDs []int64) (map[int64][]types.SiafundInput, error) {
	query := `SELECT transaction_id, parent_id, unlock_conditions, claim_address
FROM transaction_siafund_inputs
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY transaction_order DESC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]types.SiafundInput)
	for rows.Next() {
		var txnID int64
		var sfi types.SiafundInput
		if err := rows.Scan(&txnID, dbDecode(&sfi.ParentID), dbDecode(&sfi.UnlockConditions), dbDecode(&sfi.ClaimAddress)); err != nil {
			return nil, fmt.Errorf("failed to scan siafund input: %v", err)
		}
		result[txnID] = append(result[txnID], sfi)
	}
	return result, nil
}

// transactionSiafundOutputs returns the siafund outputs for each transaction.
func transactionSiafundOutputs(tx txn, txnIDs []int64) (map[int64][]types.SiafundOutput, error) {
	query := `SELECT ts.transaction_id, sf.address, sf.value
FROM siafund_outputs sf
INNER JOIN transaction_siafund_outputs ts ON (ts.output_id = sf.id)
WHERE ts.transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)
ORDER BY ts.transaction_order DESC`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, fmt.Errorf("failed to query siafund output ids: %v", err)
	}
	defer rows.Close()

	// map transaction ID to output list
	result := make(map[int64][]types.SiafundOutput)
	for rows.Next() {
		var txnID int64
		var sfo types.SiafundOutput
		if err := rows.Scan(&txnID, dbDecode(&sfo.Address), dbDecode(&sfo.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan siafund output: %v", err)
		}
		result[txnID] = append(result[txnID], sfo)
	}
	return result, nil
}

// blockTransactionIDs returns the database ID for each transaction in the
// block.
func blockTransactionIDs(tx txn, blockID types.BlockID) (dbIDs []int64, err error) {
	rows, err := tx.Query(`SELECT transaction_id FROM block_transactions WHERE block_id = ? ORDER BY block_order`, dbEncode(blockID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var dbID int64
		if err := rows.Scan(&dbID); err != nil {
			return nil, fmt.Errorf("failed to scan block transaction: %v", err)
		}
		dbIDs = append(dbIDs, dbID)
	}
	return
}

// blockMinerPayouts returns the miner payouts for the block.
func blockMinerPayouts(tx txn, blockID types.BlockID) ([]types.SiacoinOutput, error) {
	query := `SELECT sc.address, sc.value
FROM siacoin_outputs sc
INNER JOIN miner_payouts mp ON (mp.output_id = sc.id)
WHERE block_id = ?
ORDER BY mp.block_order DESC`
	rows, err := tx.Query(query, dbEncode(blockID))
	if err != nil {
		return nil, fmt.Errorf("failed to query miner payout ids: %v", err)
	}
	defer rows.Close()

	var result []types.SiacoinOutput
	for rows.Next() {
		var output types.SiacoinOutput
		if err := rows.Scan(dbDecode(&output.Address), dbDecode(&output.Value)); err != nil {
			return nil, fmt.Errorf("failed to scan miner payout: %v", err)
		}
		result = append(result, output)
	}
	return result, nil
}

// transactionDatabaseIDs returns the database ID for each transaction.
func transactionDatabaseIDs(tx txn, txnIDs []types.TransactionID) (dbIDs []int64, err error) {
	encodedIDs := func(ids []types.TransactionID) []any {
		result := make([]any, len(ids))
		for i, id := range ids {
			result[i] = dbEncode(id)
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
			return nil, fmt.Errorf("failed to scan transaction: %v", err)
		}
		dbIDs = append(dbIDs, dbID)
	}
	return
}

func (s *Store) getTransactions(tx txn, dbIDs []int64) ([]types.Transaction, error) {
	txnArbitraryData, err := transactionArbitraryData(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get arbitrary data: %v", err)
	}

	txnSiacoinInputs, err := transactionSiacoinInputs(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get siacoin inputs: %v", err)
	}

	txnSiacoinOutputs, err := transactionSiacoinOutputs(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get siacoin outputs: %v", err)
	}

	txnSiafundInputs, err := transactionSiafundInputs(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get siafund inputs: %v", err)
	}

	txnSiafundOutputs, err := transactionSiafundOutputs(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getTransactions: failed to get siafund outputs: %v", err)
	}

	// TODO: file contracts
	// TODO: file contract revisions
	// TODO: storage proofs
	// TODO: signatures

	var results []types.Transaction
	for _, dbID := range dbIDs {
		txn := types.Transaction{
			ArbitraryData:  txnArbitraryData[dbID],
			SiacoinInputs:  txnSiacoinInputs[dbID],
			SiacoinOutputs: txnSiacoinOutputs[dbID],
			SiafundInputs:  txnSiafundInputs[dbID],
			SiafundOutputs: txnSiafundOutputs[dbID],
		}
		results = append(results, txn)
	}
	return results, nil
}

// Transactions implements explorer.Store.
func (s *Store) Transactions(ids []types.TransactionID) (results []types.Transaction, err error) {
	err = s.transaction(func(tx txn) error {
		dbIDs, err := transactionDatabaseIDs(tx, ids)
		if err != nil {
			return fmt.Errorf("failed to get transaction IDs: %v", err)
		}
		results, err = s.getTransactions(tx, dbIDs)
		if err != nil {
			return fmt.Errorf("failed to get transactions: %v", err)
		}
		return err
	})
	return
}
