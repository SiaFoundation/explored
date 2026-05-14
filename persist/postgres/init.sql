CREATE TABLE global_settings (
	id INTEGER PRIMARY KEY NOT NULL DEFAULT 0 CHECK (id = 0), -- enforce a single row
	db_version BIGINT NOT NULL -- used for migrations
);

CREATE TABLE blocks (
	id BYTEA NOT NULL PRIMARY KEY,
	height BIGINT NOT NULL,
	parent_id BYTEA NOT NULL,
	nonce BYTEA NOT NULL,
	timestamp BIGINT NOT NULL,
	leaf_index BYTEA NOT NULL,

	v2_height BIGINT,
	v2_commitment BYTEA
);
CREATE INDEX blocks_height_index ON blocks(height);

CREATE TABLE transactions (
	id BIGSERIAL PRIMARY KEY,
	transaction_id BYTEA UNIQUE NOT NULL
);
CREATE INDEX transactions_transaction_id_index ON transactions(transaction_id);

CREATE TABLE v2_transactions (
	id BIGSERIAL PRIMARY KEY,
	transaction_id BYTEA UNIQUE NOT NULL,

	new_foundation_address BYTEA,
	miner_fee BYTEA NOT NULL,
	arbitrary_data BYTEA
);
CREATE INDEX v2_transactions_transaction_id_index ON v2_transactions(transaction_id);

CREATE TABLE network_metrics (
	block_id BYTEA PRIMARY KEY REFERENCES blocks(id) NOT NULL,

	height BIGINT NOT NULL,
	difficulty BYTEA NOT NULL,
	siafund_tax_revenue BYTEA NOT NULL,
	num_leaves BYTEA NOT NULL,
	total_hosts BIGINT NOT NULL,
	active_contracts BIGINT NOT NULL,
	failed_contracts BIGINT NOT NULL,
	successful_contracts BIGINT NOT NULL,
	storage_utilization BIGINT NOT NULL,
	circulating_supply BYTEA NOT NULL,
	contract_revenue BYTEA NOT NULL
);
CREATE INDEX network_metrics_height_index ON network_metrics(height);

CREATE TABLE address_balance (
	id BIGSERIAL PRIMARY KEY,
	address BYTEA UNIQUE NOT NULL,
	siacoin_balance BYTEA NOT NULL,
	immature_siacoin_balance BYTEA NOT NULL,
	siafund_balance BYTEA NOT NULL
);
CREATE INDEX address_balance_address_index ON address_balance(address);
CREATE INDEX address_balance_siacoin_balance_index ON address_balance(siacoin_balance);
CREATE INDEX address_balance_siafund_balance_index ON address_balance(siafund_balance);

CREATE TABLE siacoin_elements (
	id BIGSERIAL PRIMARY KEY,
	block_id BYTEA REFERENCES blocks(id) NOT NULL,

	output_id BYTEA UNIQUE NOT NULL,
	leaf_index BYTEA NOT NULL,

	spent_index BYTEA,
	source BIGINT NOT NULL,
	maturity_height BIGINT NOT NULL,
	address BYTEA NOT NULL,
	value BYTEA NOT NULL
);
CREATE INDEX siacoin_elements_blocks_id_index ON siacoin_elements(block_id);
CREATE INDEX siacoin_elements_maturity_height_index ON siacoin_elements(maturity_height);
CREATE INDEX siacoin_elements_output_id_index ON siacoin_elements(output_id);
CREATE INDEX siacoin_elements_address_spent_index ON siacoin_elements(address, spent_index);

CREATE TABLE siafund_elements (
	id BIGSERIAL PRIMARY KEY,
	block_id BYTEA REFERENCES blocks(id) NOT NULL,

	output_id BYTEA UNIQUE NOT NULL,
	leaf_index BYTEA NOT NULL,

	spent_index BYTEA,
	claim_start BYTEA NOT NULL,
	address BYTEA NOT NULL,
	value BYTEA NOT NULL
);
CREATE INDEX siafund_elements_blocks_id_index ON siafund_elements(block_id);
CREATE INDEX siafund_elements_output_id_index ON siafund_elements(output_id);
CREATE INDEX siafund_elements_address_spent_index ON siafund_elements(address, spent_index);

CREATE TABLE file_contract_elements (
	id BIGSERIAL PRIMARY KEY,
	block_id BYTEA REFERENCES blocks(id) NOT NULL,
	transaction_id BYTEA REFERENCES transactions(transaction_id) NOT NULL,

	contract_id BYTEA NOT NULL,
	leaf_index BYTEA NOT NULL,

	filesize BYTEA NOT NULL,
	file_merkle_root BYTEA NOT NULL,
	window_start BYTEA NOT NULL,
	window_end BYTEA NOT NULL,
	payout BYTEA NOT NULL,
	unlock_hash BYTEA NOT NULL,
	revision_number BYTEA NOT NULL,
	UNIQUE(contract_id, revision_number)
);
CREATE INDEX file_contract_elements_blocks_id_index ON file_contract_elements(block_id);
CREATE INDEX file_contract_elements_transactions_id_index ON file_contract_elements(transaction_id);
CREATE INDEX file_contract_elements_contract_id_revision_number_index ON file_contract_elements(contract_id, revision_number);

CREATE TABLE v2_file_contract_elements (
	id BIGSERIAL PRIMARY KEY,
	block_id BYTEA REFERENCES blocks(id) NOT NULL,
	transaction_id BYTEA REFERENCES v2_transactions(transaction_id) NOT NULL,

	contract_id BYTEA NOT NULL,
	leaf_index BYTEA NOT NULL,

	capacity BYTEA NOT NULL,
	filesize BYTEA NOT NULL,
	file_merkle_root BYTEA NOT NULL,
	proof_height BYTEA NOT NULL,
	expiration_height BYTEA NOT NULL,
	renter_output_address BYTEA NOT NULL,
	renter_output_value BYTEA NOT NULL,
	host_output_address BYTEA NOT NULL,
	host_output_value BYTEA NOT NULL,
	missed_host_value BYTEA NOT NULL,
	total_collateral BYTEA NOT NULL,
	renter_public_key BYTEA NOT NULL,
	host_public_key BYTEA NOT NULL,
	revision_number BYTEA NOT NULL,

	renter_signature BYTEA NOT NULL,
	host_signature BYTEA NOT NULL,

	UNIQUE(contract_id, revision_number)
);
CREATE INDEX v2_file_contract_elements_blocks_id_index ON v2_file_contract_elements(block_id);
CREATE INDEX v2_file_contract_elements_transaction_id_index ON v2_file_contract_elements(transaction_id);
CREATE INDEX v2_file_contract_elements_contract_id_revision_number_index ON v2_file_contract_elements(contract_id, revision_number);

CREATE TABLE last_contract_revision (
	contract_id BYTEA PRIMARY KEY NOT NULL,

	resolved BOOLEAN NOT NULL,
	valid BOOLEAN NOT NULL,

	ed25519_renter_key BYTEA,
	ed25519_host_key BYTEA,

	confirmation_height BYTEA NOT NULL,
	confirmation_block_id BYTEA NOT NULL REFERENCES blocks(id),
	confirmation_transaction_id BYTEA NOT NULL REFERENCES transactions(transaction_id),

	proof_height BYTEA,
	proof_block_id BYTEA,
	proof_transaction_id BYTEA REFERENCES transactions(transaction_id),

	contract_element_id BIGINT UNIQUE REFERENCES file_contract_elements(id) NOT NULL
);
CREATE INDEX last_contract_revision_confirmation_block_id_index ON last_contract_revision(confirmation_block_id);
CREATE INDEX last_contract_revision_confirmation_transaction_id_index ON last_contract_revision(confirmation_transaction_id);
CREATE INDEX last_contract_revision_proof_transaction_id_index ON last_contract_revision(proof_transaction_id);
CREATE INDEX last_contract_revision_contract_element_id_index ON last_contract_revision(contract_element_id);

CREATE TABLE v2_last_contract_revision (
	contract_id BYTEA PRIMARY KEY NOT NULL,

	confirmation_height BYTEA NOT NULL,
	confirmation_block_id BYTEA NOT NULL REFERENCES blocks(id),
	confirmation_transaction_id BYTEA NOT NULL REFERENCES v2_transactions(transaction_id),

	-- See explorer.V2Resolution for enum values.
	resolution_type BIGINT,
	resolution_height BYTEA,
	resolution_block_id BYTEA,
	resolution_transaction_id BYTEA REFERENCES v2_transactions(transaction_id),
	renewed_from BYTEA,
	renewed_to BYTEA,

	contract_element_id BIGINT UNIQUE REFERENCES v2_file_contract_elements(id) NOT NULL
);
CREATE INDEX v2_last_contract_revision_confirmation_block_id_index ON v2_last_contract_revision(confirmation_block_id);
CREATE INDEX v2_last_contract_revision_confirmation_transaction_id_index ON v2_last_contract_revision(confirmation_transaction_id);
CREATE INDEX v2_last_contract_revision_resolution_transaction_id_index ON v2_last_contract_revision(resolution_transaction_id);
CREATE INDEX v2_last_contract_revision_contract_element_id_index ON v2_last_contract_revision(contract_element_id);

CREATE TABLE file_contract_valid_proof_outputs (
	contract_id BIGINT REFERENCES file_contract_elements(id) NOT NULL,
	contract_order BIGINT NOT NULL,
	id BYTEA NOT NULL,
	address BYTEA NOT NULL,
	value BYTEA NOT NULL,
	UNIQUE(contract_id, contract_order)
);
CREATE INDEX file_contract_valid_proof_outputs_contract_id_index ON file_contract_valid_proof_outputs(contract_id);

CREATE TABLE file_contract_missed_proof_outputs (
	contract_id BIGINT REFERENCES file_contract_elements(id) NOT NULL,
	contract_order BIGINT NOT NULL,
	id BYTEA NOT NULL,
	address BYTEA NOT NULL,
	value BYTEA NOT NULL,
	UNIQUE(contract_id, contract_order)
);
CREATE INDEX file_contract_missed_proof_outputs_contract_id_index ON file_contract_missed_proof_outputs(contract_id);

CREATE TABLE miner_payouts (
	block_id BYTEA REFERENCES blocks(id) NOT NULL,
	block_order BIGINT NOT NULL,
	output_id BIGINT REFERENCES siacoin_elements(id) NOT NULL,
	UNIQUE(block_id, block_order)
);
CREATE INDEX miner_payouts_block_id_index ON miner_payouts(block_id);
CREATE INDEX miner_payouts_output_id_index ON miner_payouts(output_id);

CREATE TABLE block_transactions (
	block_id BYTEA REFERENCES blocks(id) NOT NULL,
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	block_order BIGINT NOT NULL,
	UNIQUE(block_id, block_order)
);
CREATE INDEX block_transactions_block_id_index ON block_transactions(block_id);
CREATE INDEX block_transactions_transaction_id_index ON block_transactions(transaction_id);
CREATE INDEX block_transactions_transaction_id_block_id ON block_transactions(transaction_id, block_id);

CREATE TABLE transaction_arbitrary_data (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	data BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_arbitrary_data_transaction_id_index ON transaction_arbitrary_data(transaction_id);

CREATE TABLE transaction_miner_fees (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	fee BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_miner_fees_transaction_id_index ON transaction_miner_fees(transaction_id);

CREATE TABLE transaction_signatures (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	parent_id BYTEA NOT NULL,
	public_key_index BIGINT NOT NULL,
	timelock BYTEA NOT NULL,
	covered_fields BYTEA NOT NULL,
	signature BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_signatures_transaction_id_index ON transaction_signatures(transaction_id);

CREATE TABLE transaction_storage_proofs (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	parent_id BYTEA REFERENCES last_contract_revision(contract_id) NOT NULL,
	leaf BYTEA NOT NULL,
	proof BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_storage_proofs_transaction_id_index ON transaction_storage_proofs(transaction_id);
CREATE INDEX transaction_storage_proofs_parent_id_index ON transaction_storage_proofs(parent_id);

CREATE TABLE transaction_siacoin_inputs (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	parent_id BIGINT REFERENCES siacoin_elements(id) NOT NULL,
	unlock_conditions BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siacoin_inputs_transaction_id_index ON transaction_siacoin_inputs(transaction_id);
CREATE INDEX transaction_siacoin_inputs_parent_id_index ON transaction_siacoin_inputs(parent_id);

CREATE TABLE transaction_siacoin_outputs (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	output_id BIGINT REFERENCES siacoin_elements(id) NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siacoin_outputs_transaction_id_index ON transaction_siacoin_outputs(transaction_id);
CREATE INDEX transaction_siacoin_outputs_output_id_index ON transaction_siacoin_outputs(output_id);

CREATE TABLE transaction_siafund_inputs (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	parent_id BIGINT REFERENCES siafund_elements(id) NOT NULL,
	unlock_conditions BYTEA NOT NULL,
	claim_address BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siafund_inputs_transaction_id_index ON transaction_siafund_inputs(transaction_id);
CREATE INDEX transaction_siafund_inputs_parent_id_index ON transaction_siafund_inputs(parent_id);

CREATE TABLE transaction_siafund_outputs (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	output_id BIGINT REFERENCES siafund_elements(id) NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_siafund_outputs_transaction_id_index ON transaction_siafund_outputs(transaction_id);
CREATE INDEX transaction_siafund_outputs_output_id_index ON transaction_siafund_outputs(output_id);

CREATE TABLE transaction_file_contracts (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	contract_id BIGINT REFERENCES file_contract_elements(id) NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_file_contracts_transaction_id_index ON transaction_file_contracts(transaction_id);
CREATE INDEX transaction_file_contracts_contract_id_index ON transaction_file_contracts(contract_id);

CREATE TABLE transaction_file_contract_revisions (
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	contract_id BIGINT REFERENCES file_contract_elements(id) NOT NULL,
	parent_id BYTEA NOT NULL,
	unlock_conditions BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX transaction_file_contract_revisions_transaction_id_index ON transaction_file_contract_revisions(transaction_id);
CREATE INDEX transaction_file_contract_revisions_contract_id_index ON transaction_file_contract_revisions(contract_id);

CREATE TABLE v2_block_transactions (
	block_id BYTEA REFERENCES blocks(id) NOT NULL,
	block_order BIGINT NOT NULL,
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL,
	UNIQUE(block_id, block_order)
);
CREATE INDEX v2_block_transactions_block_id_index ON v2_block_transactions(block_id);
CREATE INDEX v2_block_transactions_transaction_id_block_id ON v2_block_transactions(transaction_id, block_id);

CREATE TABLE v2_transaction_siacoin_inputs (
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	parent_id BIGINT REFERENCES siacoin_elements(id) NOT NULL,
	satisfied_policy BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siacoin_inputs_transaction_id_index ON v2_transaction_siacoin_inputs(transaction_id);
CREATE INDEX v2_transaction_siacoin_inputs_parent_id_index ON v2_transaction_siacoin_inputs(parent_id);

CREATE TABLE v2_transaction_siacoin_outputs (
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	output_id BIGINT REFERENCES siacoin_elements(id) NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siacoin_outputs_transaction_id_index ON v2_transaction_siacoin_outputs(transaction_id);
CREATE INDEX v2_transaction_siacoin_outputs_output_id_index ON v2_transaction_siacoin_outputs(output_id);

CREATE TABLE v2_transaction_siafund_inputs (
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	parent_id BIGINT REFERENCES siafund_elements(id) NOT NULL,
	claim_address BYTEA NOT NULL,
	satisfied_policy BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siafund_inputs_transaction_id_index ON v2_transaction_siafund_inputs(transaction_id);
CREATE INDEX v2_transaction_siafund_inputs_parent_id_index ON v2_transaction_siafund_inputs(parent_id);

CREATE TABLE v2_transaction_siafund_outputs (
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	output_id BIGINT REFERENCES siafund_elements(id) NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_siafund_outputs_transaction_id_index ON v2_transaction_siafund_outputs(transaction_id);
CREATE INDEX v2_transaction_siafund_outputs_output_id_index ON v2_transaction_siafund_outputs(output_id);

CREATE TABLE v2_transaction_file_contracts (
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	contract_id BIGINT REFERENCES v2_file_contract_elements(id) NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_file_contracts_transaction_id_index ON v2_transaction_file_contracts(transaction_id);
CREATE INDEX v2_transaction_file_contracts_contract_id_index ON v2_transaction_file_contracts(contract_id);

CREATE TABLE v2_transaction_file_contract_revisions (
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	parent_contract_id BIGINT REFERENCES v2_file_contract_elements(id) NOT NULL,
	revision_contract_id BIGINT REFERENCES v2_file_contract_elements(id) NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_file_contract_revisions_transaction_id_index ON v2_transaction_file_contract_revisions(transaction_id);
CREATE INDEX v2_transaction_file_contract_revisions_parent_contract_id_index ON v2_transaction_file_contract_revisions(parent_contract_id);
CREATE INDEX v2_transaction_file_contract_revisions_revision_contract_id_index ON v2_transaction_file_contract_revisions(revision_contract_id);

CREATE TABLE v2_transaction_file_contract_resolutions (
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	parent_contract_id BIGINT REFERENCES v2_file_contract_elements(id) NOT NULL,

	-- See explorer.V2Resolution for enum values.
	resolution_type BIGINT NOT NULL,

	-- V2FileContractRenewal
	renewal_new_contract_id BIGINT REFERENCES v2_file_contract_elements(id),
	renewal_final_renter_output_address BYTEA,
	renewal_final_renter_output_value BYTEA,
	renewal_final_host_output_address BYTEA,
	renewal_final_host_output_value BYTEA,
	renewal_renter_rollover BYTEA,
	renewal_host_rollover BYTEA,
	renewal_renter_signature BYTEA,
	renewal_host_signature BYTEA,

	-- V2StorageProof
	storage_proof_proof_index BYTEA,
	storage_proof_leaf BYTEA,
	storage_proof_proof BYTEA,

	-- V2FileContractExpiration
	-- no fields

	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_file_contract_resolutions_transaction_id_index ON v2_transaction_file_contract_resolutions(transaction_id);
CREATE INDEX v2_transaction_file_contract_resolutions_parent_contract_id_index ON v2_transaction_file_contract_resolutions(parent_contract_id);
CREATE INDEX v2_transaction_file_contract_resolutions_renewal_new_contract_id_index ON v2_transaction_file_contract_resolutions(renewal_new_contract_id);

CREATE TABLE v2_transaction_attestations (
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL,
	transaction_order BIGINT NOT NULL,
	public_key BYTEA NOT NULL,
	key TEXT NOT NULL,
	value BYTEA NOT NULL,
	signature BYTEA NOT NULL,
	UNIQUE(transaction_id, transaction_order)
);
CREATE INDEX v2_transaction_attestations_transaction_id_index ON v2_transaction_attestations(transaction_id);

CREATE TABLE state_tree (
	row_id BIGINT NOT NULL,
	col_id BIGINT NOT NULL,
	value BYTEA NOT NULL,
	PRIMARY KEY(row_id, col_id)
);

CREATE TABLE events (
	id BIGSERIAL PRIMARY KEY,
	block_id BYTEA NOT NULL REFERENCES blocks(id),
	event_id BYTEA UNIQUE NOT NULL,
	maturity_height BIGINT NOT NULL,
	date_created BIGINT NOT NULL,
	event_type TEXT NOT NULL
);
CREATE INDEX events_block_id_index ON events (block_id);
CREATE INDEX events_maturity_height_id_index ON events (maturity_height DESC, id DESC);

CREATE TABLE event_addresses (
	event_id BIGINT NOT NULL REFERENCES events (id),
	address_id BIGINT NOT NULL REFERENCES address_balance (id),
	event_maturity_height BIGINT NOT NULL, -- flattened from events to improve query performance
	PRIMARY KEY (event_id, address_id)
);
CREATE INDEX event_addresses_event_id_index ON event_addresses (event_id);
CREATE INDEX event_addresses_address_id_index ON event_addresses (address_id);
CREATE INDEX event_addresses_event_id_address_id_event_maturity_height_event_id_index ON event_addresses (address_id, event_maturity_height DESC, event_id DESC);

CREATE TABLE v1_transaction_events (
	event_id BIGINT PRIMARY KEY REFERENCES events(id) NOT NULL,
	transaction_id BIGINT REFERENCES transactions(id) NOT NULL
);
CREATE INDEX v1_transaction_events_transaction_id_index ON v1_transaction_events(transaction_id);

CREATE TABLE v2_transaction_events (
	event_id BIGINT PRIMARY KEY REFERENCES events(id) NOT NULL,
	transaction_id BIGINT REFERENCES v2_transactions(id) NOT NULL
);
CREATE INDEX v2_transaction_events_transaction_id_index ON v2_transaction_events(transaction_id);

CREATE TABLE payout_events (
	event_id BIGINT PRIMARY KEY REFERENCES events(id) NOT NULL,
	output_id BIGINT REFERENCES siacoin_elements(id) NOT NULL
);
CREATE INDEX payout_events_output_id_index ON payout_events(output_id);

CREATE TABLE v1_contract_resolution_events (
	event_id BIGINT PRIMARY KEY REFERENCES events(id) NOT NULL,
	parent_id BIGINT REFERENCES file_contract_elements(id) NOT NULL,
	output_id BIGINT REFERENCES siacoin_elements(id) NOT NULL,
	missed BOOLEAN NOT NULL
);
CREATE INDEX v1_contract_resolution_events_output_id_index ON v1_contract_resolution_events(output_id);
CREATE INDEX v1_contract_resolution_events_parent_id_index ON v1_contract_resolution_events(parent_id);

CREATE TABLE v2_contract_resolution_events (
	event_id BIGINT PRIMARY KEY REFERENCES events(id) NOT NULL,
	parent_id BIGINT REFERENCES v2_file_contract_elements(id) NOT NULL,
	output_id BIGINT REFERENCES siacoin_elements(id) NOT NULL,
	missed BOOLEAN NOT NULL
);
CREATE INDEX v2_contract_resolution_events_output_id_index ON v2_contract_resolution_events(output_id);
CREATE INDEX v2_contract_resolution_events_parent_id_index ON v2_contract_resolution_events(parent_id);

CREATE TABLE host_info (
	public_key BYTEA PRIMARY KEY NOT NULL,
	v2 BOOLEAN NOT NULL,
	net_address TEXT NOT NULL,
	country_code TEXT NOT NULL,
	latitude DOUBLE PRECISION NOT NULL,
	longitude DOUBLE PRECISION NOT NULL,
	known_since BIGINT NOT NULL,
	last_scan BIGINT NOT NULL,
	last_scan_successful BOOLEAN NOT NULL,
	last_scan_error TEXT NOT NULL,
	next_scan BIGINT NOT NULL,
	last_announcement BIGINT NOT NULL,
	total_scans BIGINT NOT NULL,
	successful_interactions BIGINT NOT NULL,
	failed_interactions BIGINT NOT NULL,
	-- number of failed interactions since the last successful interaction
	failed_interactions_streak BIGINT NOT NULL,
	-- settings
	settings_accepting_contracts BOOLEAN NOT NULL,
	settings_max_download_batch_size BYTEA NOT NULL,
	settings_max_duration BYTEA NOT NULL,
	settings_max_revise_batch_size BYTEA NOT NULL,
	settings_net_address TEXT NOT NULL,
	settings_remaining_storage BYTEA NOT NULL,
	settings_sector_size BYTEA NOT NULL,
	settings_total_storage BYTEA NOT NULL,
	settings_used_storage BYTEA NOT NULL,
	settings_address BYTEA NOT NULL,
	settings_window_size BYTEA NOT NULL,
	settings_collateral BYTEA NOT NULL,
	settings_max_collateral BYTEA NOT NULL,
	settings_base_rpc_price BYTEA NOT NULL,
	settings_contract_price BYTEA NOT NULL,
	settings_download_bandwidth_price BYTEA NOT NULL,
	settings_sector_access_price BYTEA NOT NULL,
	settings_storage_price BYTEA NOT NULL,
	settings_upload_bandwidth_price BYTEA NOT NULL,
	settings_ephemeral_account_expiry BIGINT NOT NULL,
	settings_max_ephemeral_account_balance BYTEA NOT NULL,
	settings_revision_number BYTEA NOT NULL,
	settings_version TEXT NOT NULL,
	settings_release TEXT NOT NULL,
	settings_sia_mux_port TEXT NOT NULL,
	-- price table
	price_table_uid BYTEA NOT NULL,
	price_table_validity BIGINT NOT NULL,
	price_table_host_block_height BYTEA NOT NULL,
	price_table_update_price_table_cost BYTEA NOT NULL,
	price_table_account_balance_cost BYTEA NOT NULL,
	price_table_fund_account_cost BYTEA NOT NULL,
	price_table_latest_revision_cost BYTEA NOT NULL,
	price_table_subscription_memory_cost BYTEA NOT NULL,
	price_table_subscription_notification_cost BYTEA NOT NULL,
	price_table_init_base_cost BYTEA NOT NULL,
	price_table_memory_time_cost BYTEA NOT NULL,
	price_table_download_bandwidth_cost BYTEA NOT NULL,
	price_table_upload_bandwidth_cost BYTEA NOT NULL,
	price_table_drop_sectors_base_cost BYTEA NOT NULL,
	price_table_drop_sectors_unit_cost BYTEA NOT NULL,
	price_table_has_sector_base_cost BYTEA NOT NULL,
	price_table_read_base_cost BYTEA NOT NULL,
	price_table_read_length_cost BYTEA NOT NULL,
	price_table_renew_contract_cost BYTEA NOT NULL,
	price_table_revision_base_cost BYTEA NOT NULL,
	price_table_swap_sector_base_cost BYTEA NOT NULL,
	price_table_write_base_cost BYTEA NOT NULL,
	price_table_write_length_cost BYTEA NOT NULL,
	price_table_write_store_cost BYTEA NOT NULL,
	price_table_txn_fee_min_recommended BYTEA NOT NULL,
	price_table_txn_fee_max_recommended BYTEA NOT NULL,
	price_table_contract_price BYTEA NOT NULL,
	price_table_collateral_cost BYTEA NOT NULL,
	price_table_max_collateral BYTEA NOT NULL,
	price_table_max_duration BYTEA NOT NULL,
	price_table_window_size BYTEA NOT NULL,
	price_table_registry_entries_left BYTEA NOT NULL,
	price_table_registry_entries_total BYTEA NOT NULL,
	-- rhp4 settings
	v2_settings_protocol_version BYTEA NOT NULL,
	v2_settings_release TEXT NOT NULL,
	v2_settings_wallet_address BYTEA NOT NULL,
	v2_settings_accepting_contracts BOOLEAN NOT NULL,
	v2_settings_max_collateral BYTEA NOT NULL,
	v2_settings_max_contract_duration BYTEA NOT NULL,
	v2_settings_remaining_storage BYTEA NOT NULL,
	v2_settings_total_storage BYTEA NOT NULL,
	v2_settings_used_storage BYTEA NOT NULL,
	-- rhp4 prices
	v2_prices_contract_price BYTEA NOT NULL,
	v2_prices_collateral_price BYTEA NOT NULL,
	v2_prices_storage_price BYTEA NOT NULL,
	v2_prices_ingress_price BYTEA NOT NULL,
	v2_prices_egress_price BYTEA NOT NULL,
	v2_prices_free_sector_price BYTEA NOT NULL,
	v2_prices_tip_height BYTEA NOT NULL,
	v2_prices_valid_until BIGINT NOT NULL,
	v2_prices_signature BYTEA NOT NULL
);
CREATE INDEX host_info_net_address ON host_info(net_address);
CREATE INDEX host_info_last_scan_last_successful_scan ON host_info(last_scan) WHERE last_scan_successful;

CREATE TABLE host_info_v2_netaddresses(
	public_key BYTEA REFERENCES host_info(public_key) NOT NULL,
	netaddress_order BIGINT NOT NULL,
	protocol TEXT NOT NULL,
	address TEXT NOT NULL,

	PRIMARY KEY(public_key, netaddress_order)
);

CREATE INDEX host_info_v2_netaddresses_public_key ON host_info_v2_netaddresses(public_key);
CREATE INDEX host_info_v2_netaddresses_address ON host_info_v2_netaddresses(address);
