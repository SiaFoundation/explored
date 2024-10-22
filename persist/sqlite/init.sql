CREATE TABLE global_settings (
	id INTEGER PRIMARY KEY NOT NULL DEFAULT 0 CHECK (id = 0), -- enforce a single row
	db_version INTEGER NOT NULL -- used for migrations
);

CREATE TABLE blocks (
	id BLOB NOT NULL PRIMARY KEY,
	height INTEGER NOT NULL,
	parent_id BLOB NOT NULL,
	nonce BLOB NOT NULL,
	timestamp INTEGER NOT NULL,

	v2_height INTEGER,
	v2_commitment BLOB
);
CREATE INDEX blocks_height_index ON blocks(height);

CREATE TABLE network_metrics (
	block_id BLOB PRIMARY KEY REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,

	height INTEGER NOT NULL,
	difficulty BLOB NOT NULL,
	siafund_pool BLOB NOT NULL,
	num_leaves BLOB NOT NULL,
	total_hosts INTEGER NOT NULL,
	active_contracts INTEGER NOT NULL,
	failed_contracts INTEGER NOT NULL,
	successful_contracts INTEGER NOT NULL,
	storage_utilization INTEGER NOT NULL,
	circulating_supply BLOB NOT NULL,
	contract_revenue BLOB NOT NULL
);

CREATE INDEX network_metrics_height_index ON network_metrics(height);

CREATE TABLE address_balance (
	id INTEGER PRIMARY KEY,
	address BLOB UNIQUE NOT NULL,
	siacoin_balance BLOB NOT NULL,
	immature_siacoin_balance BLOB NOT NULL,
	siafund_balance BLOB NOT NULL
);

CREATE INDEX address_balance_address_index ON address_balance(address);

CREATE TABLE siacoin_elements (
	id INTEGER PRIMARY KEY,
	block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,

	output_id BLOB UNIQUE NOT NULL,
	leaf_index BLOB NOT NULL,

	spent_index BLOB,
	source INTEGER NOT NULL,
	maturity_height INTEGER NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL
);

CREATE INDEX siacoin_elements_maturity_height_index ON siacoin_elements(maturity_height);
CREATE INDEX siacoin_elements_output_id_index ON siacoin_elements(output_id);
CREATE INDEX siacoin_elements_address_spent_index ON siacoin_elements(address, spent_index);

CREATE TABLE siafund_elements (
	id INTEGER PRIMARY KEY,
	block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,

	output_id BLOB UNIQUE NOT NULL,
	leaf_index BLOB NOT NULL,

	spent_index BLOB,
	claim_start BLOB NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL
);

CREATE INDEX siafund_elements_output_id_index ON siafund_elements(output_id);
CREATE INDEX siafund_elements_address_spent_index ON siafund_elements(address, spent_index);

CREATE TABLE file_contract_elements (
	id INTEGER PRIMARY KEY,
	block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,
	transaction_id BLOB REFERENCES transactions(transaction_id) ON DELETE CASCADE NOT NULL,

	contract_id BLOB NOT NULL,
	leaf_index BLOB NOT NULL,

	resolved INTEGER NOT NULL,
	valid INTEGER NOT NULL,

	filesize BLOB NOT NULL,
	file_merkle_root BLOB NOT NULL,
	window_start BLOB NOT NULL,
	window_end BLOB NOT NULL,
	payout BLOB NOT NULL,
	unlock_hash BLOB NOT NULL,
	revision_number BLOB NOT NULL,
	UNIQUE(contract_id, revision_number)
);
CREATE INDEX file_contract_elements_contract_id_revision_number_index ON file_contract_elements(contract_id, revision_number);

CREATE TABLE last_contract_revision (
	contract_id BLOB PRIMARY KEY NOT NULL,

	ed25519_renter_key BLOB,
	ed25519_host_key BLOB,

	confirmation_index BLOB,
	confirmation_transaction_id BLOB REFERENCES transactions(transaction_id),

	proof_index BLOB,
	proof_transaction_id BLOB REFERENCES transactions(transaction_id),

	contract_element_id INTEGER UNIQUE REFERENCES file_contract_elements(id) ON DELETE CASCADE NOT NULL
);

CREATE TABLE file_contract_valid_proof_outputs (
	contract_id INTEGER REFERENCES file_contract_elements(id) ON DELETE CASCADE NOT NULL,
	contract_order INTEGER NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL,
	UNIQUE(contract_id, contract_order)
);

CREATE INDEX file_contract_valid_proof_outputs_contract_id_index ON file_contract_valid_proof_outputs(contract_id);

CREATE TABLE file_contract_missed_proof_outputs (
	contract_id INTEGER REFERENCES file_contract_elements(id) ON DELETE CASCADE NOT NULL,
	contract_order INTEGER NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL,
	UNIQUE(contract_id, contract_order)
);

CREATE INDEX file_contract_missed_proof_outputs_contract_id_index ON file_contract_missed_proof_outputs(contract_id);

CREATE TABLE miner_payouts (
	block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,
	block_order INTEGER NOT NULL,
	output_id INTEGER REFERENCES siacoin_elements(id) ON DELETE CASCADE NOT NULL,
	UNIQUE(block_id, block_order)
);

CREATE INDEX miner_payouts_block_id_index ON miner_payouts(block_id);

CREATE TABLE transactions (
	id INTEGER PRIMARY KEY,
	transaction_id BLOB UNIQUE NOT NULL
);
CREATE INDEX transactions_transaction_id_index ON transactions(transaction_id);

CREATE TABLE block_transactions (
	block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	block_order INTEGER NOT NULL,
	UNIQUE(block_id, block_order)
);
CREATE INDEX block_transactions_block_id_index ON block_transactions(block_id);
CREATE INDEX block_transactions_transaction_id_index ON block_transactions(transaction_id);
CREATE INDEX block_transactions_transaction_id_block_id ON block_transactions(transaction_id, block_id);

CREATE TABLE transaction_arbitrary_data (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	data BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_arbitrary_data_transaction_id_index ON transaction_arbitrary_data(transaction_id);

CREATE TABLE transaction_miner_fees (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	fee BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_miner_fees_transaction_id_index ON transaction_miner_fees(transaction_id);

CREATE TABLE transaction_signatures (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id BLOB NOT NULL,
	public_key_index INTEGER NOT NULL,
	timelock INTEGER NOT NULL,
	covered_fields BLOB NOT NULL,
	signature BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_signatures_transaction_id_index ON transaction_signatures(transaction_id);

CREATE TABLE transaction_storage_proofs (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id BLOB REFERENCES last_contract_revision(contract_id) ON DELETE CASCADE NOT NULL,
	leaf BLOB NOT NULL,
	proof BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_storage_proofs_transaction_id_index ON transaction_storage_proofs(transaction_id);
CREATE INDEX transaction_storage_proofs_parent_id_index ON transaction_storage_proofs(parent_id);

CREATE TABLE transaction_siacoin_inputs (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id BLOB NOT NULL, -- TODO: change this to a reference to the siacoin_element and join for queries
	unlock_conditions BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siacoin_inputs_transaction_id_index ON transaction_siacoin_inputs(transaction_id);

CREATE TABLE transaction_siacoin_outputs (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	output_id INTEGER REFERENCES siacoin_elements(id) ON DELETE CASCADE NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siacoin_outputs_transaction_id_index ON transaction_siacoin_outputs(transaction_id);

CREATE TABLE transaction_siafund_inputs (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id BLOB NOT NULL, -- TODO: change this to a reference to the siacoin_element and join for queries
	unlock_conditions BLOB NOT NULL,
	claim_address BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siafund_inputs_transaction_id_index ON transaction_siafund_inputs(transaction_id);

CREATE TABLE transaction_siafund_outputs (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	output_id INTEGER REFERENCES siafund_elements(id) ON DELETE CASCADE NOT NULL, -- add an index to all foreign keys
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siafund_outputs_transaction_id_index ON transaction_siafund_outputs(transaction_id);

CREATE TABLE transaction_file_contracts (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	contract_id INTEGER REFERENCES file_contract_elements(id) ON DELETE CASCADE NOT NULL, -- add an index to all foreign keys
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_file_contracts_transaction_id_index ON transaction_file_contracts(transaction_id);

CREATE TABLE transaction_file_contract_revisions (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	contract_id INTEGER REFERENCES file_contract_elements(id) ON DELETE CASCADE NOT NULL, -- add an index to all foreign keys
	parent_id BLOB NOT NULL,
	unlock_conditions BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_file_contract_revisions_transaction_id_index ON transaction_file_contract_revisions(transaction_id);

CREATE TABLE v2_transactions (
	id INTEGER PRIMARY KEY,
	transaction_id BLOB UNIQUE NOT NULL,

	new_foundation_address BLOB,
	miner_fee BLOB NOT NULL,
	arbitrary_data BLOB
);
CREATE INDEX v2_transactions_transaction_id_index ON v2_transactions(transaction_id);

CREATE TABLE v2_block_transactions (
	block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,
	block_order INTEGER NOT NULL,
	transaction_id INTEGER REFERENCES v2_transactions(id) ON DELETE CASCADE NOT NULL,
	UNIQUE(block_id, block_order)
);
CREATE INDEX v2_block_transactions_block_id_index ON v2_block_transactions(block_id);
CREATE INDEX v2_block_transactions_transaction_id_block_id ON v2_block_transactions(transaction_id, block_id);

CREATE TABLE v2_transaction_siacoin_outputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) ON DELETE CASCADE NOT NULL,
    transaction_order INTEGER NOT NULL,
    output_id INTEGER REFERENCES siacoin_elements(id) ON DELETE CASCADE NOT NULL,
    UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siacoin_outputs_transaction_id_index ON v2_transaction_siacoin_outputs(transaction_id);

CREATE TABLE v2_transaction_siafund_outputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) ON DELETE CASCADE NOT NULL,
    transaction_order INTEGER NOT NULL,
    output_id INTEGER REFERENCES siafund_elements(id) ON DELETE CASCADE NOT NULL, -- add an index to all foreign keys
    UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siafund_outputs_transaction_id_index ON v2_transaction_siafund_outputs(transaction_id);

CREATE TABLE v2_transaction_attestations (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	public_key BLOB NOT NULL,
	key TEXT NOT NULL,
	value BLOB NOT NULL,
	signature BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_attestations_transaction_id_index ON v2_transaction_attestations(transaction_id);

CREATE TABLE state_tree (
	row INTEGER NOT NULL,
	column INTEGER NOT NULL,
	value BLOB NOT NULL,
	PRIMARY KEY(row, column)
);

CREATE TABLE events (
	id INTEGER PRIMARY KEY,
	event_id BLOB UNIQUE NOT NULL,
	maturity_height INTEGER NOT NULL,
	date_created INTEGER NOT NULL,
	event_type TEXT NOT NULL,
	block_id BLOB NOT NULL REFERENCES blocks(id) ON DELETE CASCADE, -- add an index to all foreign keys
	height INTEGER NOT NULL
);
CREATE INDEX events_block_id_height_index ON events(block_id, height);

CREATE TABLE event_addresses (
	event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, 
	address_id INTEGER NOT NULL REFERENCES address_balance(id),
	PRIMARY KEY (event_id, address_id)
);
CREATE INDEX event_addresses_event_id_index ON event_addresses(event_id);
CREATE INDEX event_addresses_address_id_index ON event_addresses(address_id);

CREATE TABLE host_announcements (
	transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	public_key BLOB NOT NULL,
	net_address BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX host_announcements_transaction_id_index ON host_announcements(transaction_id);
CREATE INDEX host_announcements_public_key_index ON host_announcements(public_key);

CREATE TABLE transaction_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE NOT NULL,
    transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
    fee BLOB NOT NULL
);

CREATE TABLE contract_payout_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE NOT NULL,
    output_id INTEGER REFERENCES siacoin_elements(id) ON DELETE CASCADE NOT NULL,
    contract_id INTEGER REFERENCES file_contract_elements(id) ON DELETE CASCADE NOT NULL,
    missed INTEGER NOT NULL
);

CREATE TABLE miner_payout_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE NOT NULL,
    output_id INTEGER REFERENCES siacoin_elements(id) ON DELETE CASCADE NOT NULL
);

CREATE TABLE foundation_subsidy_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE NOT NULL,
    output_id INTEGER REFERENCES siacoin_elements(id) ON DELETE CASCADE NOT NULL
);

CREATE TABLE v2_host_announcements (
	transaction_id INTEGER REFERENCES v2_transactions(id) ON DELETE CASCADE NOT NULL,
	transaction_order INTEGER NOT NULL,
	public_key BLOB NOT NULL,
	net_address BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_host_announcements_transaction_id_index ON v2_host_announcements(transaction_id);
CREATE INDEX v2_host_announcements_public_key_index ON v2_host_announcements(public_key);

CREATE TABLE v2_transaction_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE NOT NULL,
    transaction_id INTEGER REFERENCES v2_transactions(id) ON DELETE CASCADE NOT NULL,
    fee BLOB NOT NULL
);

CREATE TABLE host_info (
    public_key BLOB PRIMARY KEY NOT NULL,
    net_address TEXT NOT NULL,
    country_code TEXT NOT NULL,
    known_since INTEGER NOT NULL,
    last_scan INTEGER NOT NULL,
    last_scan_successful INTEGER NOT NULL,
    last_announcement INTEGER NOT NULL,
    total_scans INTEGER NOT NULL,
    successful_interactions INTEGER NOT NULL,
    failed_interactions INTEGER NOT NULL,
    -- settings
    settings_accepting_contracts INTEGER NOT NULL,
    settings_max_download_batch_size BLOB NOT NULL,
    settings_max_duration BLOB NOT NULL,
    settings_max_revise_batch_size BLOB NOT NULL,
    settings_net_address TEXT NOT NULL,
    settings_remaining_storage BLOB NOT NULL,
    settings_sector_size BLOB NOT NULL,
    settings_total_storage BLOB NOT NULL,
    settings_address BLOB NOT NULL,
    settings_window_size BLOB NOT NULL,
    settings_collateral BLOB NOT NULL,
    settings_max_collateral BLOB NOT NULL,
    settings_base_rpc_price BLOB NOT NULL,
    settings_contract_price BLOB NOT NULL,
    settings_download_bandwidth_price BLOB NOT NULL,
    settings_sector_access_price BLOB NOT NULL,
    settings_storage_price BLOB NOT NULL,
    settings_upload_bandwidth_price BLOB NOT NULL,
    settings_ephemeral_account_expiry INTEGER NOT NULL,
    settings_max_ephemeral_account_balance BLOB NOT NULL,
    settings_revision_number BLOB NOT NULL,
    settings_version TEXT NOT NULL,
    settings_release TEXT NOT NULL,
    settings_sia_mux_port TEXT NOT NULL,
    -- price table
    price_table_uid BLOB NOT NULL,
    price_table_validity INTEGER NOT NULL,
    price_table_host_block_height BLOB NOT NULL,
    price_table_update_price_table_cost BLOB NOT NULL,
    price_table_account_balance_cost BLOB NOT NULL,
    price_table_fund_account_cost BLOB NOT NULL,
    price_table_latest_revision_cost BLOB NOT NULL,
    price_table_subscription_memory_cost BLOB NOT NULL,
    price_table_subscription_notification_cost BLOB NOT NULL,
    price_table_init_base_cost BLOB NOT NULL,
    price_table_memory_time_cost BLOB NOT NULL,
    price_table_download_bandwidth_cost BLOB NOT NULL,
    price_table_upload_bandwidth_cost BLOB NOT NULL,
    price_table_drop_sectors_base_cost BLOB NOT NULL,
    price_table_drop_sectors_unit_cost BLOB NOT NULL,
    price_table_has_sector_base_cost BLOB NOT NULL,
    price_table_read_base_cost BLOB NOT NULL,
    price_table_read_length_cost BLOB NOT NULL,
    price_table_renew_contract_cost BLOB NOT NULL,
    price_table_revision_base_cost BLOB NOT NULL,
    price_table_swap_sector_base_cost BLOB NOT NULL,
    price_table_write_base_cost BLOB  NOT NULL,
    price_table_write_length_cost BLOB NOT NULL,
    price_table_write_store_cost BLOB NOT NULL,
    price_table_txn_fee_min_recommended BLOB NOT NULL,
    price_table_txn_fee_max_recommended BLOB NOT NULL,
    price_table_contract_price BLOB NOT NULL,
    price_table_collateral_cost BLOB NOT NULL,
    price_table_max_collateral BLOB NOT NULL,
    price_table_max_duration BLOB NOT NULL,
    price_table_window_size BLOB NOT NULL,
    price_table_registry_entries_left BLOB NOT NULL,
    price_table_registry_entries_total BLOB NOT NULL
);


-- initialize the global settings table
INSERT INTO global_settings (id, db_version) VALUES (0, 0); -- should not be changed
