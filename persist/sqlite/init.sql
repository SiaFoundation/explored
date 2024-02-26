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
        address BLOB PRIMARY KEY NOT NULL,
        siacoin_balance BLOB NOT NULL,
        siafund_balance BLOB NOT NULL
);

CREATE TABLE siacoin_elements (
        id INTEGER PRIMARY KEY,
        block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,

        output_id BLOB UNIQUE NOT NULL,
        leaf_index BLOB UNIQUE NOT NULL,
        merkle_proof BLOB UNIQUE NOT NULL,

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
        leaf_index BLOB UNIQUE NOT NULL,
        merkle_proof BLOB UNIQUE NOT NULL,

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
        merkle_proof BLOB NOT NULL,

        resolved INTEGER NOT NULL,
        valid INTEGER NOT NULL,

        filesize INTEGER NOT NULL,
        file_merkle_root BLOB NOT NULL,
        window_start INTEGER NOT NULL,
        window_end INTEGER NOT NULL,
        valid_proof_outputs INTEGER NOT NULL,
        missed_proof_outputs INTEGER NOT NULL,
        payout BLOB NOT NULL,
        unlock_hash BLOB NOT NULL,
        revision_number INTEGER NOT NULL,
        UNIQUE(contract_id, revision_number)
);

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
        parent_id BLOB UNIQUE NOT NULL,
        unlock_conditions BLOB UNIQUE NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX transaction_file_contract_revisions_transaction_id_index ON transaction_file_contract_revisions(transaction_id);

CREATE TABLE merkle_proofs (
        i INTEGER NOT NULL,
        j INTEGER NOT NULL,
        hash BLOB NOT NULL,
        PRIMARY KEY(i ,j)
);

-- initialize the global settings table
INSERT INTO global_settings (id, db_version) VALUES (0, 0); -- should not be changed
