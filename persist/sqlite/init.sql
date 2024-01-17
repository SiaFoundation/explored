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

CREATE TABLE miner_payouts (
        block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL,
        block_order INTEGER NOT NULL,
        address BLOB NOT NULL,
        value BLOB NOT NULL,
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

CREATE TABLE arbitrary_data (
        transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
        transaction_order INTEGER NOT NULL,
        data BLOB NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX arbitrary_data_transaction_id_index ON arbitrary_data(transaction_id);

CREATE TABLE siacoin_inputs (
        transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
        transaction_order INTEGER NOT NULL,
        parent_id BLOB NOT NULL,
        unlock_conditions BLOB NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX siacoin_inputs_transaction_id_index ON siacoin_inputs(transaction_id);

CREATE TABLE siacoin_outputs (
        transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
        transaction_order INTEGER NOT NULL,
        address BLOB NOT NULL,
        value BLOB NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX siacoin_outputs_transaction_id_index ON siacoin_outputs(transaction_id);

CREATE TABLE siafund_inputs (
        transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
        transaction_order INTEGER NOT NULL,
        parent_id BLOB NOT NULL,
        unlock_conditions BLOB NOT NULL,
        claim_address BLOB NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX siafund_inputs_transaction_id_index ON siafund_inputs(transaction_id);

CREATE TABLE siafund_outputs (
        transaction_id INTEGER REFERENCES transactions(id) ON DELETE CASCADE NOT NULL,
        transaction_order INTEGER NOT NULL,
        address BLOB NOT NULL,
        value BLOB NOT NULL,
        UNIQUE(transaction_id, transaction_order)
);

CREATE INDEX siafund_outputs_transaction_id_index ON siafund_outputs(transaction_id);

-- initialize the global settings table
INSERT INTO global_settings (id, db_version) VALUES (0, 0); -- should not be changed
