CREATE TABLE global_settings (
        id INTEGER PRIMARY KEY NOT NULL DEFAULT 0 CHECK (id = 0), -- enforce a single row
        db_version INTEGER NOT NULL -- used for migrations
);

CREATE TABLE blocks (
        id BLOB NOT NULL PRIMARY KEY,
        height INTEGER NOT NULL,
        parent_id BLOB NOT NULL,
        nonce BLOB NOT NULL,
        timestamp INTEGER NOT NULL
);

CREATE INDEX blocks_height_index ON blocks(height);

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

        spent INTEGER NOT NULL,
        source INTEGER NOT NULL,
        maturity_height INTEGER NOT NULL,
        address BLOB NOT NULL,
        value BLOB NOT NULL
);

CREATE INDEX siacoin_elements_output_id_index ON siacoin_elements(output_id);
CREATE INDEX siacoin_elements_address_spent_index ON siacoin_elements(address, spent);

CREATE TABLE siafund_elements (
        id INTEGER PRIMARY KEY,
        block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,

        output_id BLOB UNIQUE NOT NULL,
        leaf_index BLOB NOT NULL,

        spent INTEGER NOT NULL,
        claim_start BLOB NOT NULL,
        address BLOB NOT NULL,
        value BLOB NOT NULL
);

CREATE INDEX siafund_elements_output_id_index ON siafund_elements(output_id);
CREATE INDEX siafund_elements_address_spent_index ON siafund_elements(address, spent);

CREATE TABLE file_contract_elements (
        id INTEGER PRIMARY KEY,
        block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,

        contract_id BLOB NOT NULL,
        leaf_index BLOB NOT NULL,

        resolved INTEGER NOT NULL,
        valid INTEGER NOT NULL,

        filesize INTEGER NOT NULL,
        file_merkle_root BLOB NOT NULL,
        window_start INTEGER NOT NULL,
        window_end INTEGER NOT NULL,
        payout BLOB NOT NULL,
        unlock_hash BLOB NOT NULL,
        revision_number INTEGER NOT NULL,
        UNIQUE(contract_id, revision_number)
);

CREATE INDEX file_contract_elements_contract_id_index ON file_contract_elements(contract_id);

CREATE TABLE last_contract_revision (
        contract_id BLOB PRIMARY KEY NOT NULL,
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

CREATE TABLE transaction_siacoin_inputs (
        transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
        transaction_order INTEGER NOT NULL,
        parent_id BLOB NOT NULL,
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
        parent_id BLOB NOT NULL,
        unlock_conditions BLOB NOT NULL,
        claim_address BLOB NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_siafund_inputs_transaction_id_index ON transaction_siafund_inputs(transaction_id);

CREATE TABLE transaction_siafund_outputs (
        transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
        transaction_order INTEGER NOT NULL,
        output_id INTEGER REFERENCES siafund_elements(id) ON DELETE CASCADE NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_siafund_outputs_transaction_id_index ON transaction_siafund_outputs(transaction_id);

CREATE TABLE transaction_file_contracts (
        transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
        transaction_order INTEGER NOT NULL,
        contract_id INTEGER REFERENCES file_contract_elements(id) ON DELETE CASCADE NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_file_contracts_transaction_id_index ON transaction_file_contracts(transaction_id);

CREATE TABLE transaction_file_contract_revisions (
        transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
        transaction_order INTEGER NOT NULL,
        contract_id INTEGER REFERENCES file_contract_elements(id) ON DELETE CASCADE NOT NULL,
        parent_id BLOB NOT NULL,
        unlock_conditions BLOB NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_file_contract_revisions_transaction_id_index ON transaction_file_contract_revisions(transaction_id);

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
        block_id BLOB NOT NULL REFERENCES blocks(id) ON DELETE CASCADE,
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

-- initialize the global settings table
INSERT INTO global_settings (id, db_version) VALUES (0, 0); -- should not be changed
