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

func migrateV4(txn *txn, log *zap.Logger) error {
	const createNewTables = `
CREATE TABLE new_network_metrics (
	block_id BLOB PRIMARY KEY REFERENCES blocks(id) NOT NULL,

	height INTEGER NOT NULL,
	difficulty BLOB NOT NULL,
	siafund_tax_revenue BLOB NOT NULL,
	num_leaves BLOB NOT NULL,
	total_hosts INTEGER NOT NULL,
	active_contracts INTEGER NOT NULL,
	failed_contracts INTEGER NOT NULL,
	successful_contracts INTEGER NOT NULL,
	storage_utilization INTEGER NOT NULL,
	circulating_supply BLOB NOT NULL,
	contract_revenue BLOB NOT NULL
);

CREATE TABLE new_siacoin_elements (
	id INTEGER PRIMARY KEY,
	block_id BLOB REFERENCES blocks(id) NOT NULL,

	output_id BLOB UNIQUE NOT NULL,
	leaf_index BLOB NOT NULL,

	spent_index BLOB,
	source INTEGER NOT NULL,
	maturity_height INTEGER NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL
);

CREATE TABLE new_siafund_elements (
	id INTEGER PRIMARY KEY,
	block_id BLOB REFERENCES blocks(id) NOT NULL,

	output_id BLOB UNIQUE NOT NULL,
	leaf_index BLOB NOT NULL,

	spent_index BLOB,
	claim_start BLOB NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL
);

CREATE TABLE new_file_contract_elements (
	id INTEGER PRIMARY KEY,
	block_id BLOB REFERENCES blocks(id) NOT NULL,
	transaction_id BLOB REFERENCES transactions(transaction_id) NOT NULL,

	contract_id BLOB NOT NULL,
	leaf_index BLOB NOT NULL,

	filesize BLOB NOT NULL,
	file_merkle_root BLOB NOT NULL,
	window_start BLOB NOT NULL,
	window_end BLOB NOT NULL,
	payout BLOB NOT NULL,
	unlock_hash BLOB NOT NULL,
	revision_number BLOB NOT NULL,
	UNIQUE(contract_id, revision_number)
);

CREATE TABLE new_last_contract_revision (
	contract_id BLOB PRIMARY KEY NOT NULL,

	resolved INTEGER NOT NULL,
	valid INTEGER NOT NULL,

	ed25519_renter_key BLOB,
	ed25519_host_key BLOB,

    confirmation_height BLOB NOT NULL,
    confirmation_block_id BLOB NOT NULL REFERENCES blocks(id),
	confirmation_transaction_id BLOB NOT NULL REFERENCES transactions(transaction_id),

    proof_height BLOB,
    proof_block_id BLOB,
	proof_transaction_id BLOB REFERENCES transactions(transaction_id),

	contract_element_id INTEGER UNIQUE REFERENCES new_file_contract_elements(id) NOT NULL
);

CREATE TABLE new_file_contract_valid_proof_outputs (
	contract_id INTEGER REFERENCES new_file_contract_elements(id) NOT NULL,
	contract_order INTEGER NOT NULL,
	id BLOB NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL,
	UNIQUE(contract_id, contract_order)
);

CREATE TABLE new_file_contract_missed_proof_outputs (
	contract_id INTEGER REFERENCES new_file_contract_elements(id) NOT NULL,
	contract_order INTEGER NOT NULL,
	id BLOB NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL,
	UNIQUE(contract_id, contract_order)
);

CREATE TABLE new_miner_payouts (
	block_id BLOB REFERENCES blocks(id) NOT NULL,
	block_order INTEGER NOT NULL,
	output_id INTEGER REFERENCES new_siacoin_elements(id) NOT NULL,
	UNIQUE(block_id, block_order)
);

CREATE TABLE new_block_transactions (
	block_id BLOB REFERENCES blocks(id) NOT NULL,
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	block_order INTEGER NOT NULL,
	UNIQUE(block_id, block_order)
);

CREATE TABLE new_transaction_arbitrary_data (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	data BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_transaction_miner_fees (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	fee BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_transaction_signatures (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id BLOB NOT NULL,
	public_key_index INTEGER NOT NULL,
	timelock INTEGER NOT NULL,
	covered_fields BLOB NOT NULL,
	signature BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_transaction_storage_proofs (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id BLOB REFERENCES new_last_contract_revision(contract_id) NOT NULL,
	leaf BLOB NOT NULL,
	proof BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_transaction_siacoin_inputs (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id INTEGER REFERENCES new_siacoin_elements(id) NOT NULL,
	unlock_conditions BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_transaction_siacoin_outputs (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	output_id INTEGER REFERENCES new_siacoin_elements(id) NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_transaction_siafund_inputs (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id INTEGER REFERENCES new_siafund_elements(id) NOT NULL,
	unlock_conditions BLOB NOT NULL,
	claim_address BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_transaction_siafund_outputs (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	output_id INTEGER REFERENCES new_siafund_elements(id) NOT NULL, -- add an index to all foreign keys
	UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_transaction_file_contracts (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	contract_id INTEGER REFERENCES new_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
	UNIQUE(transaction_id, transaction_order)
);


CREATE TABLE new_transaction_file_contract_revisions (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	contract_id INTEGER REFERENCES new_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
	parent_id BLOB NOT NULL,
	unlock_conditions BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);


CREATE TABLE new_v2_block_transactions (
	block_id BLOB REFERENCES blocks(id) NOT NULL,
	block_order INTEGER NOT NULL,
	transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
	UNIQUE(block_id, block_order)
);

CREATE TABLE new_v2_transaction_siacoin_inputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    parent_id INTEGER REFERENCES new_siacoin_elements(id) NOT NULL,
    satisfied_policy BLOB NOT NULL,
    UNIQUE(transaction_id, transaction_order)
);


CREATE TABLE new_v2_transaction_siacoin_outputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    output_id INTEGER REFERENCES new_siacoin_elements(id) NOT NULL,
    UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_v2_transaction_siafund_inputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    parent_id INTEGER REFERENCES new_siafund_elements(id) NOT NULL,
    claim_address BLOB NOT NULL,
    satisfied_policy BLOB NOT NULL,
    UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_v2_transaction_siafund_outputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    output_id INTEGER REFERENCES new_siafund_elements(id) NOT NULL, -- add an index to all foreign keys
    UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_v2_transaction_file_contracts (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    contract_id INTEGER REFERENCES new_v2_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
    UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_v2_transaction_file_contract_revisions (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    parent_contract_id INTEGER REFERENCES new_v2_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
    revision_contract_id INTEGER REFERENCES new_v2_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
    UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_v2_transaction_file_contract_resolutions (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    parent_contract_id INTEGER REFERENCES new_v2_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys

    -- See explorer.V2Resolution for enum values.
    resolution_type INTEGER NOT NULL,

    -- V2FileContractRenewal
    renewal_new_contract_id INTEGER REFERENCES new_v2_file_contract_elements(id),
    renewal_final_renter_output_address BLOB,
    renewal_final_renter_output_value BLOB,
    renewal_final_host_output_address BLOB,
    renewal_final_host_output_value BLOB,
    renewal_renter_rollover BLOB,
    renewal_host_rollover BLOB,
    renewal_renter_signature BLOB,
    renewal_host_signature BLOB,

    -- V2StorageProof
    storage_proof_proof_index BLOB,
    storage_proof_leaf BLOB,
    storage_proof_proof BLOB,

    -- V2FileContractExpiration
    -- no fields

    UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_v2_transaction_attestations (
	transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	public_key BLOB NOT NULL,
	key TEXT NOT NULL,
	value BLOB NOT NULL,
	signature BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE TABLE new_events (
	id INTEGER PRIMARY KEY,
	block_id BLOB NOT NULL REFERENCES blocks(id),
	event_id BLOB UNIQUE NOT NULL,
	maturity_height INTEGER NOT NULL,
	date_created INTEGER NOT NULL,
	event_type TEXT NOT NULL
);

CREATE TABLE new_event_addresses (
	event_id INTEGER NOT NULL REFERENCES events (id),
	address_id INTEGER NOT NULL REFERENCES address_balance (id),
	event_maturity_height INTEGER NOT NULL, -- flattened from events to improve query performance
	PRIMARY KEY (event_id, address_id)
);


CREATE TABLE new_v1_transaction_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    transaction_id INTEGER REFERENCES transactions(id) NOT NULL
);

CREATE TABLE new_v2_transaction_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL
);

CREATE TABLE new_payout_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    output_id INTEGER REFERENCES new_siacoin_elements(id) NOT NULL
);

CREATE TABLE new_v1_contract_resolution_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    parent_id INTEGER REFERENCES new_file_contract_elements(id) NOT NULL,
    output_id INTEGER REFERENCES new_siacoin_elements(id) NOT NULL,
    missed INTEGER NOT NULL
);

CREATE TABLE new_v2_contract_resolution_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    parent_id INTEGER REFERENCES new_v2_file_contract_elements(id) NOT NULL,
    output_id INTEGER REFERENCES new_siacoin_elements(id) NOT NULL,
    missed INTEGER NOT NULL
);

CREATE TABLE new_v2_file_contract_elements (
    id INTEGER PRIMARY KEY,
    block_id BLOB REFERENCES blocks(id) NOT NULL,
    transaction_id BLOB REFERENCES v2_transactions(transaction_id) NOT NULL,

    contract_id BLOB NOT NULL,
    leaf_index BLOB NOT NULL,

    capacity BLOB NOT NULL,
    filesize BLOB NOT NULL,
    file_merkle_root BLOB NOT NULL,
    proof_height BLOB NOT NULL,
    expiration_height BLOB NOT NULL,
    renter_output_address BLOB NOT NULL,
    renter_output_value BLOB NOT NULL,
    host_output_address BLOB NOT NULL,
    host_output_value BLOB NOT NULL,
    missed_host_value BLOB NOT NULL,
    total_collateral BLOB NOT NULL,
    renter_public_key BLOB NOT NULL,
    host_public_key BLOB NOT NULL,
    revision_number BLOB NOT NULL,

    renter_signature BLOB NOT NULL,
    host_signature BLOB NOT NULL,

    UNIQUE(contract_id, revision_number)
);

CREATE TABLE new_v2_last_contract_revision (
    contract_id BLOB PRIMARY KEY NOT NULL,

    confirmation_height BLOB NOT NULL,
    confirmation_block_id BLOB NOT NULL REFERENCES blocks(id),
    confirmation_transaction_id BLOB NOT NULL REFERENCES v2_transactions(transaction_id),

    -- See explorer.V2Resolution for enum values.
    resolution_type INTEGER,
    resolution_height BLOB,
    resolution_block_id BLOB,
    resolution_transaction_id BLOB REFERENCES v2_transactions(transaction_id),
    renewed_from BLOB,
    renewed_to BLOB,

    contract_element_id INTEGER UNIQUE REFERENCES new_v2_file_contract_elements(id) NOT NULL
);
`

	const createIndices = `
CREATE INDEX network_metrics_height_index ON network_metrics(height);
CREATE INDEX siacoin_elements_blocks_id_index ON siacoin_elements(block_id);
CREATE INDEX siacoin_elements_maturity_height_index ON siacoin_elements(maturity_height);
CREATE INDEX siacoin_elements_output_id_index ON siacoin_elements(output_id);
CREATE INDEX siacoin_elements_address_spent_index ON siacoin_elements(address, spent_index);
CREATE INDEX siafund_elements_blocks_id_index ON siafund_elements(block_id);
CREATE INDEX siafund_elements_output_id_index ON siafund_elements(output_id);
CREATE INDEX siafund_elements_address_spent_index ON siafund_elements(address, spent_index);
CREATE INDEX file_contract_elements_blocks_id_index ON file_contract_elements(block_id);
CREATE INDEX file_contract_elements_transactions_id_index ON file_contract_elements(transaction_id);
CREATE INDEX file_contract_elements_contract_id_revision_number_index ON file_contract_elements(contract_id, revision_number);
CREATE INDEX last_contract_revision_confirmation_block_id_index ON last_contract_revision(confirmation_block_id);
CREATE INDEX last_contract_revision_confirmation_transaction_id_index ON last_contract_revision(confirmation_transaction_id);
CREATE INDEX last_contract_revision_proof_transaction_id_index ON last_contract_revision(proof_transaction_id);
CREATE INDEX last_contract_revision_contract_element_id_index ON last_contract_revision(contract_element_id);
CREATE INDEX file_contract_valid_proof_outputs_contract_id_index ON file_contract_valid_proof_outputs(contract_id);
CREATE INDEX file_contract_missed_proof_outputs_contract_id_index ON file_contract_missed_proof_outputs(contract_id);
CREATE INDEX miner_payouts_block_id_index ON miner_payouts(block_id);
CREATE INDEX miner_payouts_output_id_index ON miner_payouts(output_id);
CREATE INDEX block_transactions_block_id_index ON block_transactions(block_id);
CREATE INDEX block_transactions_transaction_id_index ON block_transactions(transaction_id);
CREATE INDEX block_transactions_transaction_id_block_id ON block_transactions(transaction_id, block_id);
CREATE INDEX transaction_arbitrary_data_transaction_id_index ON transaction_arbitrary_data(transaction_id);
CREATE INDEX transaction_miner_fees_transaction_id_index ON transaction_miner_fees(transaction_id);
CREATE INDEX transaction_signatures_transaction_id_index ON transaction_signatures(transaction_id);
CREATE INDEX transaction_storage_proofs_transaction_id_index ON transaction_storage_proofs(transaction_id);
CREATE INDEX transaction_storage_proofs_parent_id_index ON transaction_storage_proofs(parent_id);
CREATE INDEX transaction_siacoin_inputs_transaction_id_index ON transaction_siacoin_inputs(transaction_id);
CREATE INDEX transaction_siacoin_inputs_parent_id_index ON transaction_siacoin_inputs(parent_id);
CREATE INDEX transaction_siacoin_outputs_transaction_id_index ON transaction_siacoin_outputs(transaction_id);
CREATE INDEX transaction_siacoin_outputs_output_id_index ON transaction_siacoin_outputs(output_id);
CREATE INDEX transaction_siafund_inputs_transaction_id_index ON transaction_siafund_inputs(transaction_id);
CREATE INDEX transaction_siafund_inputs_parent_id_index ON transaction_siafund_inputs(parent_id);
CREATE INDEX transaction_siafund_outputs_transaction_id_index ON transaction_siafund_outputs(transaction_id);
CREATE INDEX transaction_siafund_outputs_output_id_index ON transaction_siafund_outputs(output_id);
CREATE INDEX transaction_file_contracts_transaction_id_index ON transaction_file_contracts(transaction_id);
CREATE INDEX transaction_file_contracts_contract_id_index ON transaction_file_contracts(contract_id);
CREATE INDEX transaction_file_contract_revisions_transaction_id_index ON transaction_file_contract_revisions(transaction_id);
CREATE INDEX transaction_file_contract_revisions_contract_id_index ON transaction_file_contract_revisions(contract_id);
CREATE INDEX v2_block_transactions_block_id_index ON v2_block_transactions(block_id);
CREATE INDEX v2_block_transactions_transaction_id_block_id ON v2_block_transactions(transaction_id, block_id);
CREATE INDEX v2_transaction_siacoin_inputs_transaction_id_index ON v2_transaction_siacoin_inputs(transaction_id);
CREATE INDEX v2_transaction_siacoin_inputs_parent_id_index ON v2_transaction_siacoin_inputs(parent_id);
CREATE INDEX v2_transaction_siacoin_outputs_transaction_id_index ON v2_transaction_siacoin_outputs(transaction_id);
CREATE INDEX v2_transaction_siacoin_outputs_output_id_index ON v2_transaction_siacoin_outputs(output_id);
CREATE INDEX v2_transaction_siafund_inputs_transaction_id_index ON v2_transaction_siafund_inputs(transaction_id);
CREATE INDEX v2_transaction_siafund_inputs_parent_id_index ON v2_transaction_siafund_inputs(parent_id);
CREATE INDEX v2_transaction_siafund_outputs_transaction_id_index ON v2_transaction_siafund_outputs(transaction_id);
CREATE INDEX v2_transaction_siafund_outputs_output_id_index ON v2_transaction_siafund_outputs(output_id);
CREATE INDEX v2_transaction_file_contracts_transaction_id_index ON v2_transaction_file_contracts(transaction_id);
CREATE INDEX v2_transaction_file_contracts_contract_id_index ON v2_transaction_file_contracts(contract_id);
CREATE INDEX v2_transaction_file_contract_revisions_transaction_id_index ON v2_transaction_file_contract_revisions(transaction_id);
CREATE INDEX v2_transaction_file_contract_revisions_parent_contract_id_index ON v2_transaction_file_contract_revisions(parent_contract_id);
CREATE INDEX v2_transaction_file_contract_revisions_revision_contract_id_index ON v2_transaction_file_contract_revisions(revision_contract_id);
CREATE INDEX v2_transaction_file_contract_resolutions_transaction_id_index ON v2_transaction_file_contract_resolutions(transaction_id);
CREATE INDEX v2_transaction_file_contract_resolutions_parent_contract_id_index ON v2_transaction_file_contract_resolutions(parent_contract_id);
CREATE INDEX v2_transaction_file_contract_resolutions_renewal_new_contract_id_index ON v2_transaction_file_contract_resolutions(renewal_new_contract_id);
CREATE INDEX v2_transaction_attestations_transaction_id_index ON v2_transaction_attestations(transaction_id);
CREATE INDEX events_block_id_index ON events (block_id);
CREATE INDEX events_maturity_height_id_index ON events (maturity_height DESC, id DESC);
CREATE INDEX event_addresses_event_id_index ON event_addresses (event_id);
CREATE INDEX event_addresses_address_id_index ON event_addresses (address_id);
CREATE INDEX event_addresses_event_id_address_id_event_maturity_height_event_id_index ON event_addresses (address_id, event_maturity_height DESC, event_id DESC);
CREATE INDEX v1_transaction_events_transaction_id_index ON v1_transaction_events(transaction_id);
CREATE INDEX v2_transaction_events_transaction_id_index ON v2_transaction_events(transaction_id);
CREATE INDEX payout_events_output_id_index ON payout_events(output_id);
CREATE INDEX v1_contract_resolution_events_output_id_index ON v1_contract_resolution_events(output_id);
CREATE INDEX v1_contract_resolution_events_parent_id_index ON v1_contract_resolution_events(parent_id);
CREATE INDEX v2_contract_resolution_events_output_id_index ON v2_contract_resolution_events(output_id);
CREATE INDEX v2_contract_resolution_events_parent_id_index ON v2_contract_resolution_events(parent_id);
CREATE INDEX v2_file_contract_elements_blocks_id_index ON v2_file_contract_elements(block_id);
CREATE INDEX v2_file_contract_elements_transaction_id_index ON v2_file_contract_elements(transaction_id);
CREATE INDEX v2_file_contract_elements_contract_id_revision_number_index ON v2_file_contract_elements(contract_id, revision_number);
CREATE INDEX v2_last_contract_revision_confirmation_block_id_index ON v2_last_contract_revision(confirmation_block_id);
CREATE INDEX v2_last_contract_revision_confirmation_transaction_id_index ON v2_last_contract_revision(confirmation_transaction_id);
CREATE INDEX v2_last_contract_revision_resolution_transaction_id_index ON v2_last_contract_revision(resolution_transaction_id);
CREATE INDEX v2_last_contract_revision_contract_element_id_index ON v2_last_contract_revision(contract_element_id);
`

	log.Info("Recreating tables")
	if _, err := txn.Exec(createNewTables); err != nil {
		return fmt.Errorf("failed to create new tables: %w", err)
	}

	tableNames := []string{"event_addresses", "v1_transaction_events", "v2_transaction_events", "payout_events", "v1_contract_resolution_events", "v2_contract_resolution_events", "events", "last_contract_revision", "v2_last_contract_revision", "block_transactions", "transaction_arbitrary_data", "transaction_miner_fees", "transaction_signatures", "transaction_storage_proofs", "transaction_siacoin_inputs", "transaction_siacoin_outputs", "transaction_siafund_inputs", "transaction_siafund_outputs", "transaction_file_contracts", "transaction_file_contract_revisions", "file_contract_valid_proof_outputs", "file_contract_missed_proof_outputs", "file_contract_elements", "v2_block_transactions", "v2_transaction_siacoin_inputs", "v2_transaction_siacoin_outputs", "v2_transaction_siafund_inputs", "v2_transaction_siafund_outputs", "v2_transaction_file_contracts", "v2_transaction_file_contract_revisions", "v2_transaction_file_contract_resolutions", "v2_transaction_attestations", "v2_file_contract_elements", "network_metrics", "miner_payouts", "siacoin_elements", "siafund_elements"}
	for _, tableName := range tableNames {
		newTableName := "new_" + tableName

		log.Info("Replacing old table", zap.String("name", tableName))
		if _, err := txn.Exec(fmt.Sprintf(`INSERT INTO %s SELECT * FROM %s;`, newTableName, tableName)); err != nil {
			return fmt.Errorf("failed to copy data into new %s: %w", tableName, err)
		}

		var countOld, countNew int64
		if err := txn.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, tableName)).Scan(&countOld); err != nil {
			return fmt.Errorf("failed to get old table %s row count: %w", tableName, err)
		} else if err := txn.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, newTableName)).Scan(&countNew); err != nil {
			return fmt.Errorf("failed to get old table %s row count: %w", tableName, err)
		} else if countOld != countNew {
			return fmt.Errorf("row count for %s differed: expected %d, got %d", tableName, countOld, countNew)
		}

		if _, err := txn.Exec(fmt.Sprintf(`DROP TABLE %s;`, tableName)); err != nil {
			return fmt.Errorf("failed to drop old %s: %w", tableName, err)
		} else if _, err := txn.Exec(fmt.Sprintf(`ALTER TABLE %s RENAME TO %s`, newTableName, tableName)); err != nil {
			return fmt.Errorf("failed to drop new table to %s: %w", tableName, err)
		}
	}

	log.Info("Creating indices")
	if _, err := txn.Exec(createIndices); err != nil {
		return fmt.Errorf("failed to create indices: %w", err)
	}

	return nil
}

var migrations = []func(tx *txn, log *zap.Logger) error{
	migrateV2,
	migrateV3,
	migrateV4,
}
