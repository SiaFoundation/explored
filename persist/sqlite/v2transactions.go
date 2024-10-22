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
