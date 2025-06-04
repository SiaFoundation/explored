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
	leaf_index BLOB NOT NULL,

	v2_height INTEGER,
	v2_commitment BLOB
);
CREATE INDEX blocks_height_index ON blocks(height);

CREATE TABLE network_metrics (
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
	block_id BLOB REFERENCES blocks(id) NOT NULL,

	output_id BLOB UNIQUE NOT NULL,
	leaf_index BLOB NOT NULL,

	spent_index BLOB,
	source INTEGER NOT NULL,
	maturity_height INTEGER NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL
);
CREATE INDEX siacoin_elements_blocks_id_index ON siacoin_elements(block_id);
CREATE INDEX siacoin_elements_maturity_height_index ON siacoin_elements(maturity_height);
CREATE INDEX siacoin_elements_output_id_index ON siacoin_elements(output_id);
CREATE INDEX siacoin_elements_address_spent_index ON siacoin_elements(address, spent_index);

CREATE TABLE siafund_elements (
	id INTEGER PRIMARY KEY,
	block_id BLOB REFERENCES blocks(id) NOT NULL,

	output_id BLOB UNIQUE NOT NULL,
	leaf_index BLOB NOT NULL,

	spent_index BLOB,
	claim_start BLOB NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL
);
CREATE INDEX siafund_elements_blocks_id_index ON siafund_elements(block_id);
CREATE INDEX siafund_elements_output_id_index ON siafund_elements(output_id);
CREATE INDEX siafund_elements_address_spent_index ON siafund_elements(address, spent_index);

CREATE TABLE file_contract_elements (
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
CREATE INDEX file_contract_elements_blocks_id_index ON file_contract_elements(block_id);
CREATE INDEX file_contract_elements_transactions_id_index ON file_contract_elements(transaction_id);
CREATE INDEX file_contract_elements_contract_id_revision_number_index ON file_contract_elements(contract_id, revision_number);

CREATE TABLE last_contract_revision (
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

	contract_element_id INTEGER UNIQUE REFERENCES file_contract_elements(id) NOT NULL
);
CREATE INDEX last_contract_revision_confirmation_block_id_index ON last_contract_revision(confirmation_block_id);
CREATE INDEX last_contract_revision_confirmation_transaction_id_index ON last_contract_revision(confirmation_transaction_id);
CREATE INDEX last_contract_revision_proof_transaction_id_index ON last_contract_revision(proof_transaction_id);
CREATE INDEX last_contract_revision_contract_element_id_index ON last_contract_revision(contract_element_id);

CREATE TABLE file_contract_valid_proof_outputs (
	contract_id INTEGER REFERENCES file_contract_elements(id) NOT NULL,
	contract_order INTEGER NOT NULL,
	id BLOB NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL,
	UNIQUE(contract_id, contract_order)
);

CREATE INDEX file_contract_valid_proof_outputs_contract_id_index ON file_contract_valid_proof_outputs(contract_id);

CREATE TABLE file_contract_missed_proof_outputs (
	contract_id INTEGER REFERENCES file_contract_elements(id) NOT NULL,
	contract_order INTEGER NOT NULL,
	id BLOB NOT NULL,
	address BLOB NOT NULL,
	value BLOB NOT NULL,
	UNIQUE(contract_id, contract_order)
);

CREATE INDEX file_contract_missed_proof_outputs_contract_id_index ON file_contract_missed_proof_outputs(contract_id);

CREATE TABLE miner_payouts (
	block_id BLOB REFERENCES blocks(id) NOT NULL,
	block_order INTEGER NOT NULL,
	output_id INTEGER REFERENCES siacoin_elements(id) NOT NULL,
	UNIQUE(block_id, block_order)
);
CREATE INDEX miner_payouts_block_id_index ON miner_payouts(block_id);

CREATE TABLE transactions (
	id INTEGER PRIMARY KEY,
	transaction_id BLOB UNIQUE NOT NULL
);
CREATE INDEX transactions_transaction_id_index ON transactions(transaction_id);

CREATE TABLE block_transactions (
	block_id BLOB REFERENCES blocks(id) NOT NULL,
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	block_order INTEGER NOT NULL,
	UNIQUE(block_id, block_order)
);
CREATE INDEX block_transactions_block_id_index ON block_transactions(block_id);
CREATE INDEX block_transactions_transaction_id_index ON block_transactions(transaction_id);
CREATE INDEX block_transactions_transaction_id_block_id ON block_transactions(transaction_id, block_id);

CREATE TABLE transaction_arbitrary_data (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	data BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_arbitrary_data_transaction_id_index ON transaction_arbitrary_data(transaction_id);

CREATE TABLE transaction_miner_fees (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	fee BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_miner_fees_transaction_id_index ON transaction_miner_fees(transaction_id);

CREATE TABLE transaction_signatures (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
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
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id BLOB REFERENCES last_contract_revision(contract_id) NOT NULL,
	leaf BLOB NOT NULL,
	proof BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_storage_proofs_transaction_id_index ON transaction_storage_proofs(transaction_id);
CREATE INDEX transaction_storage_proofs_parent_id_index ON transaction_storage_proofs(parent_id);

CREATE TABLE transaction_siacoin_inputs (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id INTEGER REFERENCES siacoin_elements(id) NOT NULL,
	unlock_conditions BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siacoin_inputs_transaction_id_index ON transaction_siacoin_inputs(transaction_id);

CREATE TABLE transaction_siacoin_outputs (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	output_id INTEGER REFERENCES siacoin_elements(id) NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siacoin_outputs_transaction_id_index ON transaction_siacoin_outputs(transaction_id);

CREATE TABLE transaction_siafund_inputs (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	parent_id INTEGER REFERENCES siafund_elements(id) NOT NULL,
	unlock_conditions BLOB NOT NULL,
	claim_address BLOB NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siafund_inputs_transaction_id_index ON transaction_siafund_inputs(transaction_id);

CREATE TABLE transaction_siafund_outputs (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	output_id INTEGER REFERENCES siafund_elements(id) NOT NULL, -- add an index to all foreign keys
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siafund_outputs_transaction_id_index ON transaction_siafund_outputs(transaction_id);

CREATE TABLE transaction_file_contracts (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	contract_id INTEGER REFERENCES file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_file_contracts_transaction_id_index ON transaction_file_contracts(transaction_id);

CREATE TABLE transaction_file_contract_revisions (
	transaction_id INTEGER REFERENCES transactions(id) NOT NULL,
	transaction_order INTEGER NOT NULL,
	contract_id INTEGER REFERENCES file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
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
	block_id BLOB REFERENCES blocks(id) NOT NULL,
	block_order INTEGER NOT NULL,
	transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
	UNIQUE(block_id, block_order)
);
CREATE INDEX v2_block_transactions_block_id_index ON v2_block_transactions(block_id);
CREATE INDEX v2_block_transactions_transaction_id_block_id ON v2_block_transactions(transaction_id, block_id);

CREATE TABLE v2_transaction_siacoin_inputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    parent_id INTEGER REFERENCES siacoin_elements(id) NOT NULL,
    satisfied_policy BLOB NOT NULL,
    UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siacoin_inputs_transaction_id_index ON v2_transaction_siacoin_inputs(transaction_id);

CREATE TABLE v2_transaction_siacoin_outputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    output_id INTEGER REFERENCES siacoin_elements(id) NOT NULL,
    UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siacoin_outputs_transaction_id_index ON v2_transaction_siacoin_outputs(transaction_id);

CREATE TABLE v2_transaction_siafund_inputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    parent_id INTEGER REFERENCES siafund_elements(id) NOT NULL,
    claim_address BLOB NOT NULL,
    satisfied_policy BLOB NOT NULL,
    UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siafund_inputs_transaction_id_index ON v2_transaction_siafund_inputs(transaction_id);

CREATE TABLE v2_transaction_siafund_outputs (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    output_id INTEGER REFERENCES siafund_elements(id) NOT NULL, -- add an index to all foreign keys
    UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siafund_outputs_transaction_id_index ON v2_transaction_siafund_outputs(transaction_id);

CREATE TABLE v2_transaction_file_contracts (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    contract_id INTEGER REFERENCES v2_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
    UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_file_contracts_transaction_id_index ON v2_transaction_file_contracts(transaction_id);

CREATE TABLE v2_transaction_file_contract_revisions (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    parent_contract_id INTEGER REFERENCES v2_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
    revision_contract_id INTEGER REFERENCES v2_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys
    UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_file_contract_revisions_transaction_id_index ON v2_transaction_file_contract_revisions(transaction_id);

CREATE TABLE v2_transaction_file_contract_resolutions (
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
    transaction_order INTEGER NOT NULL,
    parent_contract_id INTEGER REFERENCES v2_file_contract_elements(id) NOT NULL, -- add an index to all foreign keys

    -- See explorer.V2Resolution for enum values.
    resolution_type INTEGER NOT NULL,

    -- V2FileContractRenewal
    renewal_new_contract_id INTEGER REFERENCES v2_file_contract_elements(id),
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
CREATE INDEX v2_transaction_file_contract_resolutions_transaction_id_index ON v2_transaction_file_contract_resolutions(transaction_id);

CREATE TABLE v2_transaction_attestations (
	transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL,
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
	block_id BLOB NOT NULL REFERENCES blocks(id),
	event_id BLOB UNIQUE NOT NULL,
	maturity_height INTEGER NOT NULL,
	date_created INTEGER NOT NULL,
	event_type TEXT NOT NULL
);
CREATE INDEX events_block_id_idx ON events (block_id);
CREATE INDEX events_maturity_height_id_idx ON events (maturity_height DESC, id DESC);

CREATE TABLE event_addresses (
	event_id INTEGER NOT NULL REFERENCES events (id),
	address_id INTEGER NOT NULL REFERENCES address_balance (id),
	event_maturity_height INTEGER NOT NULL, -- flattened from events to improve query performance
	PRIMARY KEY (event_id, address_id)
);
CREATE INDEX event_addresses_event_id_idx ON event_addresses (event_id);
CREATE INDEX event_addresses_address_id_idx ON event_addresses (address_id);
CREATE INDEX event_addresses_event_id_address_id_event_maturity_height_event_id_idx ON event_addresses (address_id, event_maturity_height DESC, event_id DESC);

CREATE TABLE v1_transaction_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    transaction_id INTEGER REFERENCES transactions(id) NOT NULL
);
CREATE INDEX v1_transaction_events_transaction_id_index ON v1_transaction_events(transaction_id);

CREATE TABLE v2_transaction_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    transaction_id INTEGER REFERENCES v2_transactions(id) NOT NULL
);
CREATE INDEX v2_transaction_events_transaction_id_index ON v2_transaction_events(transaction_id);

CREATE TABLE payout_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    output_id INTEGER REFERENCES siacoin_elements(id) NOT NULL
);

CREATE TABLE v1_contract_resolution_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    parent_id INTEGER REFERENCES file_contract_elements(id) NOT NULL,
    output_id INTEGER REFERENCES siacoin_elements(id) NOT NULL,
    missed INTEGER NOT NULL
);

CREATE TABLE v2_contract_resolution_events (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) NOT NULL,
    parent_id INTEGER REFERENCES v2_file_contract_elements(id) NOT NULL,
    output_id INTEGER REFERENCES siacoin_elements(id) NOT NULL,
    missed INTEGER NOT NULL
);

CREATE TABLE v2_file_contract_elements (
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
CREATE INDEX v2_file_contract_elements_blocks_id_index ON v2_file_contract_elements(block_id);
CREATE INDEX v2_file_contract_elements_transaction_id_index ON v2_file_contract_elements(transaction_id);
CREATE INDEX v2_file_contract_elements_contract_id_revision_number_index ON v2_file_contract_elements(contract_id, revision_number);

CREATE TABLE v2_last_contract_revision (
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

    contract_element_id INTEGER UNIQUE REFERENCES v2_file_contract_elements(id) NOT NULL
);
CREATE INDEX v2_last_contract_revision_confirmation_block_id_index ON v2_last_contract_revision(confirmation_block_id);
CREATE INDEX v2_last_contract_revision_confirmation_transaction_id_index ON v2_last_contract_revision(confirmation_transaction_id);
CREATE INDEX v2_last_contract_revision_resolution_transaction_id_index ON v2_last_contract_revision(resolution_transaction_id);
CREATE INDEX v2_last_contract_revision_contract_element_id_index ON v2_last_contract_revision(contract_element_id);

CREATE TABLE host_info (
    public_key BLOB PRIMARY KEY NOT NULL,
    v2 INTEGER NOT NULL,
    net_address TEXT NOT NULL,
    country_code TEXT NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    known_since INTEGER NOT NULL,
    last_scan INTEGER NOT NULL,
    last_scan_successful INTEGER NOT NULL,
    last_scan_error TEXT NOT NULL,
    next_scan INTEGER NOT NULL,
    last_announcement INTEGER NOT NULL,
    total_scans INTEGER NOT NULL,
    successful_interactions INTEGER NOT NULL,
    failed_interactions INTEGER NOT NULL,
	-- number of failed interactions since the last successful interaction
    failed_interactions_streak INTEGER NOT NULL,
    -- settings
    settings_accepting_contracts INTEGER NOT NULL,
    settings_max_download_batch_size BLOB NOT NULL,
    settings_max_duration BLOB NOT NULL,
    settings_max_revise_batch_size BLOB NOT NULL,
    settings_net_address TEXT NOT NULL,
    settings_remaining_storage BLOB NOT NULL,
    settings_sector_size BLOB NOT NULL,
    settings_total_storage BLOB NOT NULL,
    settings_used_storage BLOB NOT NULL, -- needed so we can sort by this because there's no clean way of subtracting binary encoded uint64s (total and remaining storage) in sqlite
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
    price_table_registry_entries_total BLOB NOT NULL,
    -- rhp4 settings
    v2_settings_protocol_version BLOB NOT NULL,
    v2_settings_release TEXT NOT NULL,
    v2_settings_wallet_address BLOB NOT NULL,
    v2_settings_accepting_contracts INTEGER NOT NULL,
    v2_settings_max_collateral BLOB NOT NULL,
    v2_settings_max_contract_duration BLOB NOT NULL,
    v2_settings_remaining_storage BLOB NOT NULL,
    v2_settings_total_storage BLOB NOT NULL,
    v2_settings_used_storage BLOB NOT NULL, -- needed so we can sort by this because there's no clean way of subtracting binary encoded uint64s (total and remaining storage) in sqlite
    -- rhp4 prices
    v2_prices_contract_price BLOB NOT NULL,
    v2_prices_collateral_price BLOB NOT NULL,
    v2_prices_storage_price BLOB NOT NULL,
    v2_prices_ingress_price BLOB NOT NULL,
    v2_prices_egress_price BLOB NOT NULL,
    v2_prices_free_sector_price BLOB NOT NULL,
    v2_prices_tip_height BLOB NOT NULL,
    v2_prices_valid_until BLOB NOT NULL,
    v2_prices_signature BLOB NOT NULL
);
CREATE INDEX host_info_net_address ON host_info(net_address);
CREATE INDEX host_info_last_scan_last_successful_scan ON host_info(last_scan) WHERE last_scan_successful = true;

CREATE TABLE host_info_v2_netaddresses(
    public_key BLOB REFERENCES host_info(public_key) NOT NULL,
    netaddress_order INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    address TEXT NOT NULL,

    PRIMARY KEY(public_key, netaddress_order)
);

CREATE INDEX host_info_v2_netaddresses_public_key ON host_info_v2_netaddresses(public_key);
CREATE INDEX host_info_v2_netaddresses_address ON host_info_v2_netaddresses(address);
