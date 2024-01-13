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
FROM arbitrary_data
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
	rows, err := tx.Query(`SELECT address, value FROM miner_payouts WHERE block_id = ? ORDER BY block_order`, dbEncode(blockID))
	if err != nil {
		return nil, err
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

// Transactions implements explorer.Store.
func (s *Store) Transactions(ids []types.TransactionID) (results []types.Transaction, err error) {
	err = s.transaction(func(tx txn) error {
		dbIDs, err := transactionDatabaseIDs(tx, ids)
		if err != nil {
			return fmt.Errorf("failed to get transaction IDs: %v", err)
		}

		txnArbitraryData, err := transactionArbitraryData(tx, dbIDs)
		if err != nil {
			return fmt.Errorf("failed to get arbitrary data: %v", err)
		}

		// TODO: siacoin inputs
		// TODO: siacoin outputs
		// TODO: siafund inputs
		// TODO: siafund outputs
		// TODO: file contracts
		// TODO: file contract revisions
		// TODO: storage proofs
		// TODO: signatures

		for _, dbID := range dbIDs {
			var txn types.Transaction
			txn.ArbitraryData = txnArbitraryData[dbID]
			results = append(results, txn)
		}
		return nil
	})
	return
}
