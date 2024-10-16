package sqlite

import (
	"database/sql"
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

func addV2ArbitraryData(tx *txn, id int64, txn types.V2Transaction) error {
	stmt, err := tx.Prepare(`INSERT INTO v2_transaction_arbitrary_data(transaction_id, data) VALUES (?, ?)`)

	if err != nil {
		return fmt.Errorf("addV2ArbitraryData: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	if _, err := stmt.Exec(id, txn.ArbitraryData); err != nil {
		return fmt.Errorf("addV2ArbitraryData: failed to execute statement: %w", err)
	}
	return nil
}

func addV2Transactions(tx *txn, bid types.BlockID, txns []types.V2Transaction) (map[types.TransactionID]txnDBId, error) {
	checkTransactionStmt, err := tx.Prepare(`SELECT id FROM v2_transactions WHERE transaction_id = ?`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare check v2_transaction statement: %v", err)
	}
	defer checkTransactionStmt.Close()

	insertTransactionStmt, err := tx.Prepare(`INSERT INTO v2_transactions (transaction_id, new_foundation_address, miner_fee) VALUES (?, ?, ?)`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare insert v2_transaction statement: %v", err)
	}
	defer insertTransactionStmt.Close()

	blockTransactionsStmt, err := tx.Prepare(`INSERT INTO v2_block_transactions(block_id, transaction_id, block_order) VALUES (?, ?, ?);`)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare v2_block_transactions statement: %w", err)
	}
	defer blockTransactionsStmt.Close()

	txnDBIds := make(map[types.TransactionID]txnDBId)
	for i, txn := range txns {
		var exist bool
		var txnID int64
		if err := checkTransactionStmt.QueryRow(encode(txn.ID())).Scan(&txnID); err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("failed to insert v2 transaction ID: %w", err)
		} else if err == nil {
			exist = true
		}

		if !exist {
			var newFoundationAddress any
			if txn.NewFoundationAddress != nil {
				newFoundationAddress = encode(txn.NewFoundationAddress)
			}

			result, err := insertTransactionStmt.Exec(encode(txn.ID()), newFoundationAddress, encode(txn.MinerFee))
			if err != nil {
				return nil, fmt.Errorf("failed to insert into v2_transactions: %w", err)
			}
			txnID, err = result.LastInsertId()
			if err != nil {
				return nil, fmt.Errorf("failed to get v2 transaction ID: %w", err)
			}
		}
		txnDBIds[txn.ID()] = txnDBId{id: txnID, exist: exist}

		if _, err := blockTransactionsStmt.Exec(encode(bid), txnID, i); err != nil {
			return nil, fmt.Errorf("failed to insert into v2_block_transactions: %w", err)
		}
	}
	return txnDBIds, nil
}

func addV2TransactionFields(tx *txn, txns []types.V2Transaction, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64, fcDBIds map[explorer.DBFileContract]int64, v2TxnDBIds map[types.TransactionID]txnDBId) error {
	for _, txn := range txns {
		dbID, ok := v2TxnDBIds[txn.ID()]
		if !ok {
			panic(fmt.Errorf("txn %v should be in txnDBIds", txn.ID()))
		}

		// transaction already exists, don't reinsert its fields
		if dbID.exist {
			continue
		}

		if err := addV2ArbitraryData(tx, dbID.id, txn); err != nil {
			return fmt.Errorf("failed to add arbitrary data: %w", err)
		}
	}

	return nil
}
