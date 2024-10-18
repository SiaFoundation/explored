package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
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

// blockV2TransactionIDs returns the database ID for each v2 transaction in the
// block.
func blockV2TransactionIDs(tx *txn, blockID types.BlockID) (idMap map[int64]transactionID, err error) {
	rows, err := tx.Query(`SELECT bt.transaction_id, block_order, t.transaction_id
FROM v2_block_transactions bt
INNER JOIN v2_transactions t ON (t.id = bt.transaction_id)
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

// v2TransactionArbitraryData returns the arbitrary data for each v2 transaction.
func v2TransactionArbitraryData(tx *txn, txnIDs []int64) (map[int64][]byte, error) {
	query := `SELECT transaction_id, data
FROM v2_transaction_arbitrary_data
WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `)`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64][]byte)
	for rows.Next() {
		var txnID int64
		var data []byte
		if err := rows.Scan(&txnID, &data); err != nil {
			return nil, fmt.Errorf("failed to scan arbitrary data: %w", err)
		}
		result[txnID] = data
	}
	return result, nil
}

type v2Metadata struct {
	newFoundationAddress *types.Address
	minerFee             types.Currency
}

// v2TransactionMetadata returns the new foundation address and miner fee of a v2
// transaction.
func v2TransactionMetadata(tx *txn, txnIDs []int64) (map[int64]v2Metadata, error) {
	query := `SELECT id, new_foundation_address, miner_fee
FROM v2_transactions
WHERE id IN (` + queryPlaceHolders(len(txnIDs)) + `)`
	rows, err := tx.Query(query, queryArgs(txnIDs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64]v2Metadata)
	for rows.Next() {
		var txnID int64
		var fields v2Metadata
		var newFoundationAddress types.Address
		if err := rows.Scan(&txnID, decodeNull(&newFoundationAddress), decode(&fields.minerFee)); err != nil {
			return nil, fmt.Errorf("failed to scan new foundation address and miner fee: %w", err)
		}

		if (newFoundationAddress != types.Address{}) {
			fields.newFoundationAddress = &newFoundationAddress
		}

		result[txnID] = fields
	}
	return result, nil
}

func getV2Transactions(tx *txn, idMap map[int64]transactionID) ([]explorer.V2Transaction, error) {
	dbIDs := make([]int64, len(idMap))
	for order, id := range idMap {
		dbIDs[order] = id.dbID
	}

	txnMetadata, err := v2TransactionMetadata(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get metadata fields: %w", err)
	}

	txnArbitraryData, err := v2TransactionArbitraryData(tx, dbIDs)
	if err != nil {
		return nil, fmt.Errorf("getV2Transactions: failed to get arbitrary data: %w", err)
	}

	var results []explorer.V2Transaction
	for order, dbID := range dbIDs {
		metadata := txnMetadata[dbID]
		txn := explorer.V2Transaction{
			ID:                   idMap[int64(order)].id,
			ArbitraryData:        txnArbitraryData[dbID],
			NewFoundationAddress: metadata.newFoundationAddress,
			MinerFee:             metadata.minerFee,
		}

		// for _, attestation := range txn.Attestations {
		// 	var ha chain.HostAnnouncement
		// 	if ha.FromAttestation(attestation) {
		// 		txn.HostAnnouncements = append(txn.HostAnnouncements, ha)
		// 	}
		// }

		results = append(results, txn)
	}
	return results, nil
}

// v2TransactionDatabaseIDs returns the database ID for each transaction.
func v2TransactionDatabaseIDs(tx *txn, txnIDs []types.TransactionID) (dbIDs map[int64]transactionID, err error) {
	encodedIDs := func(ids []types.TransactionID) []any {
		result := make([]any, len(ids))
		for i, id := range ids {
			result[i] = encode(id)
		}
		return result
	}

	query := `SELECT id, transaction_id FROM v2_transactions WHERE transaction_id IN (` + queryPlaceHolders(len(txnIDs)) + `) ORDER BY id`
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

// V2Transactions implements explorer.Store.
func (s *Store) V2Transactions(ids []types.TransactionID) (results []explorer.V2Transaction, err error) {
	err = s.transaction(func(tx *txn) error {
		dbIDs, err := v2TransactionDatabaseIDs(tx, ids)
		if err != nil {
			return fmt.Errorf("failed to get transaction IDs: %w", err)
		}
		results, err = getV2Transactions(tx, dbIDs)
		if err != nil {
			return fmt.Errorf("failed to get transactions: %w", err)
		}
		return err
	})
	return
}
