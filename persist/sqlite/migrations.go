package sqlite

import (
	"fmt"

	"go.uber.org/zap"
)

func migrateV2(txn *txn, _ *zap.Logger) error {
	const createForeignKeyIndices = `
CREATE INDEX siacoin_elements_blocks_id_index ON siacoin_elements(block_id);
CREATE INDEX siafund_elements_blocks_id_index ON siafund_elements(block_id);
CREATE INDEX file_contract_elements_blocks_id_index ON file_contract_elements(block_id);
CREATE INDEX last_contract_revision_confirmation_block_id_index ON last_contract_revision(confirmation_block_id);
CREATE INDEX v2_file_contract_elements_blocks_id_index ON v2_file_contract_elements(block_id);
CREATE INDEX v2_last_contract_revision_confirmation_block_id_index ON v2_last_contract_revision(confirmation_block_id);
`
	_, err := txn.Exec(createForeignKeyIndices)
	return err
}

func migrateV3(txn *txn, log *zap.Logger) error {
	// initialization cycle issue if we do len(migrations)+1 here because
	// migrations refers to migrateV3 and migrateV3 refers to migrations
	// so we have to hardcode 3
	if err := resetChainState(txn, log, 3); err != nil {
		return fmt.Errorf("failed to reset chain state: %w", err)
	}
	return nil
}

func migrateV4(txn *txn, _ *zap.Logger) error {
	const createForeignKeyIndices = `
CREATE INDEX file_contract_elements_transactions_id_index ON file_contract_elements(transaction_id);
CREATE INDEX last_contract_revision_confirmation_transaction_id_index ON last_contract_revision(confirmation_transaction_id);
CREATE INDEX last_contract_revision_proof_transaction_id_index ON last_contract_revision(proof_transaction_id);
CREATE INDEX last_contract_revision_contract_element_id_index ON last_contract_revision(contract_element_id);
CREATE INDEX v1_transaction_events_transaction_id_index ON v1_transaction_events(transaction_id);
CREATE INDEX v2_transaction_events_transaction_id_index ON v2_transaction_events(transaction_id);
CREATE INDEX v2_file_contract_elements_transaction_id_index ON v2_file_contract_elements(transaction_id);
CREATE INDEX v2_last_contract_revision_confirmation_transaction_id_index ON v2_last_contract_revision(confirmation_transaction_id);
CREATE INDEX v2_last_contract_revision_resolution_transaction_id_index ON v2_last_contract_revision(resolution_transaction_id);
CREATE INDEX v2_last_contract_revision_contract_element_id_index ON v2_last_contract_revision(contract_element_id);

CREATE INDEX miner_payouts_output_id_index ON miner_payouts(output_id);
CREATE INDEX transaction_siacoin_inputs_parent_id_index ON transaction_siacoin_inputs(parent_id);
CREATE INDEX transaction_siacoin_outputs_output_id_index ON transaction_siacoin_outputs(output_id);
CREATE INDEX transaction_siafund_inputs_parent_id_index ON transaction_siafund_inputs(parent_id);
CREATE INDEX transaction_siafund_outputs_output_id_index ON transaction_siafund_outputs(output_id);
CREATE INDEX transaction_file_contracts_contract_id_index ON transaction_file_contracts(contract_id);
CREATE INDEX transaction_file_contract_revisions_contract_id_index ON transaction_file_contract_revisions(contract_id);
CREATE INDEX v2_transaction_siacoin_inputs_parent_id_index ON v2_transaction_siacoin_inputs(parent_id);
CREATE INDEX v2_transaction_siacoin_outputs_output_id_index ON v2_transaction_siacoin_outputs(output_id);
CREATE INDEX v2_transaction_siafund_inputs_parent_id_index ON v2_transaction_siafund_inputs(parent_id);
CREATE INDEX v2_transaction_siafund_outputs_output_id_index ON v2_transaction_siafund_outputs(output_id);
CREATE INDEX v2_transaction_file_contracts_contract_id_index ON v2_transaction_file_contracts(contract_id);
CREATE INDEX v2_transaction_file_contract_revisions_parent_contract_id_index ON v2_transaction_file_contract_revisions(parent_contract_id);
CREATE INDEX v2_transaction_file_contract_revisions_revision_contract_id_index ON v2_transaction_file_contract_revisions(revision_contract_id);
CREATE INDEX v2_transaction_file_contract_resolutions_parent_contract_id_index ON v2_transaction_file_contract_resolutions(parent_contract_id);
CREATE INDEX v2_transaction_file_contract_resolutions_renewal_new_contract_id_index ON v2_transaction_file_contract_resolutions(renewal_new_contract_id);
CREATE INDEX payout_events_output_id_index ON payout_events(output_id);
CREATE INDEX v1_contract_resolution_events_output_id_index ON v1_contract_resolution_events(output_id);
CREATE INDEX v1_contract_resolution_events_parent_id_index ON v1_contract_resolution_events(parent_id);
CREATE INDEX v2_contract_resolution_events_output_id_index ON v2_contract_resolution_events(output_id);
CREATE INDEX v2_contract_resolution_events_parent_id_index ON v2_contract_resolution_events(parent_id);
`
	_, err := txn.Exec(createForeignKeyIndices)
	return err
}

var migrations = []func(tx *txn, log *zap.Logger) error{
	migrateV2,
	migrateV3,
	migrateV4,
}
