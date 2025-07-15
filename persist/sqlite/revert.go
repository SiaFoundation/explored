package sqlite

import (
	"fmt"
	"strconv"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

func generateInClause(ids []int64) string {
	clause := ` (`
	for i, id := range ids {
		clause += strconv.FormatInt(id, 10)
		if i < len(ids)-1 {
			clause += ","
		}
	}
	clause += `)`
	return clause
}

func deleteEvents(tx *txn, bid types.BlockID) error {
	rows, err := tx.Query(`SELECT id FROM events WHERE block_id = ?`, encode(bid))
	if err != nil {
		return fmt.Errorf("failed to query event IDs: %w", err)
	}
	defer rows.Close()

	var dbIDs []int64
	for rows.Next() {
		var dbID int64
		if err := rows.Scan(&dbID); err != nil {
			return fmt.Errorf("failed to scan event ID: %w", err)
		}
		dbIDs = append(dbIDs, dbID)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to get event ID rows: %w", err)
	}

	clause := generateInClause(dbIDs)
	if _, err := tx.Exec(`DELETE FROM event_addresses WHERE event_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from event_addresses table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v1_transaction_events WHERE event_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v1_transaction_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_events WHERE event_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM payout_events WHERE event_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from payout_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v1_contract_resolution_events WHERE event_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v1_contract_resolution_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_contract_resolution_events WHERE event_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_contract_resolution_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM events WHERE id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from events table: %w", err)
	}
	return nil
}

func deleteLastContractRevisions(tx *txn, bid types.BlockID) error {
	if _, err := tx.Exec(`DELETE FROM last_contract_revision WHERE confirmation_block_id = ?;`, encode(bid)); err != nil {
		return fmt.Errorf("failed to delete from last_contract_revision: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_last_contract_revision WHERE confirmation_block_id = ?;`, encode(bid)); err != nil {
		return fmt.Errorf("failed to delete from v2_last_contract_revision: %w", err)
	}
	return nil
}

// deleteV1Transactions deletes the transactions from the database if they are
// not referenced in any blocks.
func deleteV1Transactions(tx *txn, bid types.BlockID) error {
	rows, err := tx.Query(`SELECT transaction_id AS id
FROM
	block_transactions
WHERE
	block_id = ?
	AND transaction_id NOT IN (
      SELECT transaction_id
      FROM block_transactions
      WHERE block_id != ?
);`, encode(bid), encode(bid))
	if err != nil {
		return fmt.Errorf("failed to query orphaned transaction IDs: %w", err)
	}
	defer rows.Close()

	var txnDBIDs []int64
	for rows.Next() {
		var txnDBID int64
		if err := rows.Scan(&txnDBID); err != nil {
			return fmt.Errorf("failed to scan transaction ID: %w", err)
		}
		txnDBIDs = append(txnDBIDs, txnDBID)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to get transaction ID rows: %w", err)
	}

	clause := generateInClause(txnDBIDs)
	if _, err := tx.Exec(`DELETE FROM block_transactions WHERE block_id = ?;`, encode(bid)); err != nil {
		return fmt.Errorf("failed to delete from block_transactions: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM transaction_arbitrary_data WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_arbitrary_data: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_miner_fees WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_miner_fees: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_signatures WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_signatures: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_storage_proofs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_storage_proofs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_siacoin_inputs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_siacoin_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_siacoin_outputs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_siacoin_outputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_siafund_inputs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_siafund_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_siafund_outputs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_siafund_outputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_file_contracts WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contracts: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_file_contract_revisions WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contract_revisions: %w", err)
	}

	// have to remove file contract elements because it depends on transactions table
	rows, err = tx.Query(`SELECT fce.id
FROM
    file_contract_elements AS fce
WHERE fce.block_id = ?`, encode(bid))
	if err != nil {
		return fmt.Errorf("failed to query file contract element IDs: %w", err)
	}
	defer rows.Close()

	var fceDBIDs []int64
	for rows.Next() {
		var fceDBID int64
		if err := rows.Scan(&fceDBID); err != nil {
			return fmt.Errorf("failed to scan contract ID: %w", err)
		}
		fceDBIDs = append(fceDBIDs, fceDBID)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to get contract ID rows: %w", err)
	}
	fceClause := generateInClause(fceDBIDs)

	if _, err := tx.Exec(`DELETE FROM file_contract_valid_proof_outputs WHERE contract_id IN` + fceClause); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contract_revisions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM file_contract_missed_proof_outputs WHERE contract_id IN` + fceClause); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contract_revisions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM file_contract_elements WHERE id IN` + fceClause); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contract_revisions: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM transactions WHERE id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from transactions: %w", err)
	}

	return nil
}

// deleteV2Transactions deletes the transactions from the database if they are
// not referenced in any blocks.
func deleteV2Transactions(tx *txn, bid types.BlockID) error {
	rows, err := tx.Query(`SELECT transaction_id AS id
FROM
    v2_block_transactions
WHERE
    block_id = ?
    AND transaction_id NOT IN (
      SELECT transaction_id
      FROM v2_block_transactions
      WHERE block_id != ?
);`, encode(bid), encode(bid))
	if err != nil {
		return fmt.Errorf("failed to query orphaned v2 transaction IDs: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("failed to scan v2 transaction ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to get v2 transaction ID rows: %w", err)
	}

	clause := generateInClause(ids)

	if _, err := tx.Exec(`DELETE FROM v2_block_transactions WHERE block_id = ?;`, encode(bid)); err != nil {
		return fmt.Errorf("failed to delete from v2_block_transactions: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM v2_transaction_siacoin_inputs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siacoin_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_siacoin_inputs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siacoin_outputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_siacoin_outputs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siacoin_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_siafund_inputs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siafund_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_siafund_outputs WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siafund_outputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_file_contracts WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_file_contracts: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_file_contract_revisions WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_file_contract_revisions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_file_contract_resolutions WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_file_contract_resolutions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_attestations WHERE transaction_id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_attestations: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_file_contract_elements WHERE block_id = ?;`, encode(bid)); err != nil {
		// have to remove file contract elements because it depends on transactions table
		return fmt.Errorf("failed to delete from v2_file_contract_elements: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transactions WHERE id IN` + clause); err != nil {
		return fmt.Errorf("failed to delete from v2_transactions: %w", err)
	}

	return nil
}

func deleteBlock(tx *txn, bid types.BlockID) error {
	encoded := encode(bid)
	if _, err := tx.Exec(`DELETE FROM network_metrics WHERE block_id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from network_metrics: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM miner_payouts WHERE block_id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from miner_payouts: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM siacoin_elements WHERE block_id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from siacoin_elements: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM siafund_elements WHERE block_id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from siafund_elements: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM blocks WHERE id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from blocks: %w", err)
	}
	return nil
}

func (ut *updateTx) RevertIndex(state explorer.UpdateState) error {
	if err := updateMaturedBalances(ut.tx, true, state.Metrics.Index.Height); err != nil {
		return fmt.Errorf("failed to update matured balances: updateMaturedBalances: %w", err)
	} else if err := addSiacoinElements(
		ut.tx,
		state.Metrics.Index,
		state.SpentSiacoinElements,
		append(state.NewSiacoinElements, state.EphemeralSiacoinElements...),
	); err != nil {
		return fmt.Errorf("failed to update siacoin output state: addSiacoinElements: %w", err)
	} else if err := addSiafundElements(
		ut.tx,
		state.Metrics.Index,
		state.SpentSiafundElements,
		append(state.NewSiafundElements, state.EphemeralSiafundElements...),
	); err != nil {
		return fmt.Errorf("failed to update siafund output state: addSiafundElements: %w", err)
	} else if err := updateBalances(ut.tx, state.Metrics.Index.Height, state.SpentSiacoinElements, state.NewSiacoinElements, state.SpentSiafundElements, state.NewSiafundElements); err != nil {
		return fmt.Errorf("failed to update balances: updateBalances: %w", err)
	} else if err := updateFileContractElements(ut.tx, true, state.Metrics.Index, state.Block, state.FileContractElements); err != nil {
		return fmt.Errorf("failed to update file contract state: updateFileContractElements: %w", err)
	} else if err := updateV2FileContractElements(ut.tx, true, state.Metrics.Index, state.Block, state.V2FileContractElements); err != nil {
		return fmt.Errorf("failed to add v2 file contracts: updateV2FileContractElements: %w", err)
	} else if err := updateFileContractIndices(ut.tx, true, state.Metrics.Index, state.FileContractElements); err != nil {
		return fmt.Errorf("failed to update file contract element indices: updateFileContractIndices: %w", err)
	} else if err := updateV2FileContractIndices(ut.tx, true, state.Metrics.Index, state.V2FileContractElements); err != nil {
		return fmt.Errorf("failed to update v2 file contract element indices: updateV2FileContractIndices: %w", err)
	} else if err := updateStateTree(ut.tx, state.TreeUpdates); err != nil {
		return fmt.Errorf("failed to update state tree: updateStateTree: %w", err)
	}

	bid := state.Block.ID()
	if err := deleteEvents(ut.tx, bid); err != nil {
		return fmt.Errorf("failed to delete events: deleteEvents: %w", err)
	} else if err := deleteLastContractRevisions(ut.tx, bid); err != nil {
		return fmt.Errorf("failed to delete from block transactions tables: deleteLastContractRevisions: %w", err)
	} else if err := deleteV1Transactions(ut.tx, bid); err != nil {
		return fmt.Errorf("failed to delete v1 transactions: deleteV1Transactions: %w", err)
	} else if err := deleteV2Transactions(ut.tx, bid); err != nil {
		return fmt.Errorf("failed to delete v2 transactions: deleteV2Transactions: %w", err)
	} else if err := deleteBlock(ut.tx, bid); err != nil {
		return fmt.Errorf("failed to delete block: deleteBlock: %w", err)
	}

	return nil
}
