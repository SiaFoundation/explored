package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

func deleteEvents(tx *txn, bid types.BlockID) error {
	if _, err := tx.Exec(`CREATE TEMP TABLE tmp_event_ids AS SELECT id FROM events WHERE block_id = ?;`, encode(bid)); err != nil {
		return fmt.Errorf("failed to create temporary table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM event_addresses WHERE event_id IN (SELECT id FROM tmp_event_ids);`); err != nil {
		return fmt.Errorf("failed to delete from event_addresses table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v1_transaction_events WHERE event_id IN (SELECT id FROM tmp_event_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v1_transaction_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_events WHERE event_id IN (SELECT id FROM tmp_event_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM payout_events WHERE event_id IN (SELECT id FROM tmp_event_ids);`); err != nil {
		return fmt.Errorf("failed to delete from payout_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v1_contract_resolution_events WHERE event_id IN (SELECT id FROM tmp_event_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v1_contract_resolution_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_contract_resolution_events WHERE event_id IN (SELECT id FROM tmp_event_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_contract_resolution_events table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM events WHERE id IN (SELECT id FROM tmp_event_ids);`); err != nil {
		return fmt.Errorf("failed to delete from events table: %w", err)
	} else if _, err := tx.Exec(`DROP TABLE tmp_event_ids;`); err != nil {
		return fmt.Errorf("failed to drop temporary table: %w", err)
	}
	return nil
}

func deleteBlockTransactionsLastRevisionss(tx *txn, bid types.BlockID) error {
	encoded := encode(bid)
	if _, err := tx.Exec(`DELETE FROM block_transactions WHERE block_id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from block_transactions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_block_transactions WHERE block_id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from v2_block_transactions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM last_contract_revision WHERE confirmation_block_id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from last_contract_revision: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_last_contract_revision WHERE confirmation_block_id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from v2_last_contract_revision: %w", err)
	}
	return nil
}

// deleteV1Transactions deletes the transactions from the database if they are
// not referenced in any blocks.
func deleteV1Transactions(tx *txn, bid types.BlockID, txns []types.Transaction) error {
	var ids []any
	for _, txn := range txns {
		ids = append(ids, encode(txn.ID()))
	}

	_, err := tx.Exec(`
CREATE TEMP TABLE tmp_transaction_ids AS
SELECT
    t.id
FROM
    transactions AS t
WHERE
    t.transaction_id IN (`+queryPlaceHolders(len(txns))+`)
    AND NOT EXISTS (
        SELECT
			1
        FROM
            block_transactions AS bt
        WHERE
            bt.transaction_id = t.id
    );`, ids...)
	if err != nil {
		return fmt.Errorf("failed to create temporary transactions table: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM transaction_arbitrary_data WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_arbitrary_data: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_miner_fees WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_miner_fees: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_signatures WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_signatures: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_storage_proofs WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_storage_proofs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_siacoin_inputs WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_siacoin_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_siacoin_outputs WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_siacoin_outputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_siafund_inputs WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_siafund_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_siafund_outputs WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_siafund_outputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_file_contracts WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contracts: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM transaction_file_contract_revisions WHERE transaction_id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contract_revisions: %w", err)
	}

	// have to remove file contract elements here due to ordering issues
	if _, err := tx.Exec(`
CREATE TEMP TABLE tmp_file_contract_element_ids AS
SELECT
	fce.id
FROM
	file_contract_elements AS fce
WHERE fce.block_id = ?`, encode(bid)); err != nil {
		return fmt.Errorf("failed to create temporary file_contract_elements table: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM file_contract_valid_proof_outputs WHERE contract_id IN (SELECT id FROM tmp_file_contract_element_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contract_revisions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM file_contract_missed_proof_outputs WHERE contract_id IN (SELECT id FROM tmp_file_contract_element_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contract_revisions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM file_contract_elements WHERE id IN (SELECT id FROM tmp_file_contract_element_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transaction_file_contract_revisions: %w", err)
	} else if _, err := tx.Exec(`DROP TABLE tmp_file_contract_element_ids;`); err != nil {
		return fmt.Errorf("failed to drop temporary file_contract_elements table: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM transactions WHERE id IN (SELECT id FROM tmp_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from transactions: %w", err)
	} else if _, err := tx.Exec(`DROP TABLE tmp_transaction_ids;`); err != nil {
		return fmt.Errorf("failed to drop temporary transactions table: %w", err)
	}

	return nil
}

// deleteV2Transactions deletes the transactions from the database if they are
// not referenced in any blocks.
func deleteV2Transactions(tx *txn, bid types.BlockID, txns []types.V2Transaction) error {
	var ids []any
	for _, txn := range txns {
		ids = append(ids, encode(txn.ID()))
	}

	_, err := tx.Exec(`
CREATE TEMP TABLE tmp_v2_transaction_ids AS
SELECT
    t.id
FROM
    v2_transactions AS t
WHERE
    t.transaction_id IN (`+queryPlaceHolders(len(txns))+`)
    AND NOT EXISTS (
        SELECT
			1
        FROM
            v2_block_transactions AS bt
        WHERE
            bt.transaction_id = t.id
    );`, ids...)
	if err != nil {
		return fmt.Errorf("failed to create temporary table: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM v2_transaction_siacoin_inputs WHERE transaction_id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siacoin_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_siacoin_inputs WHERE transaction_id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siacoin_outputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_siacoin_outputs WHERE transaction_id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siacoin_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_siafund_inputs WHERE transaction_id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siafund_inputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_siafund_outputs WHERE transaction_id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_siafund_outputs: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_file_contracts WHERE transaction_id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_file_contracts: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_file_contract_revisions WHERE transaction_id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_file_contract_revisions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_file_contract_resolutions WHERE transaction_id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_file_contract_resolutions: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transaction_attestations WHERE transaction_id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transaction_attestations: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_file_contract_elements WHERE block_id = ?;`, encode(bid)); err != nil {
		return fmt.Errorf("failed to delete from v2_file_contract_elements: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM v2_transactions WHERE id IN (SELECT id FROM tmp_v2_transaction_ids);`); err != nil {
		return fmt.Errorf("failed to delete from v2_transactions: %w", err)
	} else if _, err := tx.Exec(`DROP TABLE tmp_v2_transaction_ids;`); err != nil {
		return fmt.Errorf("failed to drop temporary table: %w", err)
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
	} else if _, err := tx.Exec(`DELETE FROM v2_file_contract_elements WHERE block_id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from v2_file_contract_elements: %w", err)
	} else if _, err := tx.Exec(`DELETE FROM blocks WHERE id = ?;`, encoded); err != nil {
		return fmt.Errorf("failed to delete from blocks: %w", err)
	}
	return nil
}

func (ut *updateTx) RevertIndex(state explorer.UpdateState) error {
	// if _, err := ut.tx.Exec(`PRAGMA defer_foreign_keys=ON;`); err != nil {
	// 	return fmt.Errorf("failed to foreign key checks: %w", err)
	// }

	// if _, err := ut.tx.Exec(`PRAGMA foreign_keys=OFF;`); err != nil {
	// 	return fmt.Errorf("failed to disable foreign key checks: %w", err)
	// }

	if err := updateMaturedBalances(ut.tx, true, state.Metrics.Index.Height); err != nil {
		return fmt.Errorf("RevertIndex: failed to update matured balances: %w", err)
	} else if _, err := addSiacoinElements(
		ut.tx,
		state.Metrics.Index,
		state.SpentSiacoinElements,
		append(state.NewSiacoinElements, state.EphemeralSiacoinElements...),
	); err != nil {
		return fmt.Errorf("RevertIndex: failed to update siacoin output state: %w", err)
	} else if _, err := addSiafundElements(
		ut.tx,
		state.Metrics.Index,
		state.SpentSiafundElements,
		append(state.NewSiafundElements, state.EphemeralSiafundElements...),
	); err != nil {
		return fmt.Errorf("RevertIndex: failed to update siafund output state: %w", err)
	} else if err := updateBalances(ut.tx, state.Metrics.Index.Height, state.SpentSiacoinElements, state.NewSiacoinElements, state.SpentSiafundElements, state.NewSiafundElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update balances: %w", err)
	} else if _, err := updateFileContractElements(ut.tx, true, state.Metrics.Index, state.Block, state.FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update file contract state: %w", err)
	} else if _, err := updateV2FileContractElements(ut.tx, true, state.Metrics.Index, state.Block, state.V2FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to add v2 file contracts: %w", err)
	} else if err := updateFileContractIndices(ut.tx, true, state.Metrics.Index, state.FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update file contract element indices: %w", err)
	} else if err := updateV2FileContractIndices(ut.tx, true, state.Metrics.Index, state.V2FileContractElements); err != nil {
		return fmt.Errorf("RevertIndex: failed to update v2 file contract element indices: %w", err)
	} else if err := updateStateTree(ut.tx, state.TreeUpdates); err != nil {
		return fmt.Errorf("RevertIndex: failed to update state tree: %w", err)
	}

	bid := state.Block.ID()
	if err := deleteEvents(ut.tx, bid); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete events: %w", err)
	} else if err := deleteBlockTransactionsLastRevisionss(ut.tx, bid); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete from block transactions tables: %w", err)
	} else if err := deleteV1Transactions(ut.tx, bid, state.Block.Transactions); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete v1 transactions: %w", err)
	} else if err := deleteV2Transactions(ut.tx, bid, state.Block.V2Transactions()); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete v2 transactions: %w", err)
	} else if err := deleteBlock(ut.tx, bid); err != nil {
		return fmt.Errorf("RevertIndex: failed to delete block: %w", err)
	}

	// if _, err := ut.tx.Exec(`PRAGMA foreign_key_check;`); err != nil {
	// 	return fmt.Errorf("failed to foreign key checks: %w", err)
	// }

	// if _, err := ut.tx.Exec(`PRAGMA foreign_keys=ON;`); err != nil {
	// 	return fmt.Errorf("failed to enable foreign key checks: %w", err)
	// }

	return nil
}
