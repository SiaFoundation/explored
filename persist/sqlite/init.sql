CREATE TABLE global_settings (
        id INTEGER PRIMARY KEY NOT NULL DEFAULT 0 CHECK (id = 0), -- enforce a single row
        db_version INTEGER NOT NULL -- used for migrations
);

CREATE TABLE blocks (
        id BINARY(32) NOT NULL PRIMARY KEY,
        height INTEGER NOT NULL,
        parent_id BINARY(32) NOT NULL,
        nonce BINARY(8) NOT NULL,
        timestamp INTEGER NOT NULL
);

CREATE TABLE miner_payouts (
        block_id REFERENCES blocks(id) ON DELETE CASCADE,
        block_order INTEGER NOT NULL,
        address BINARY(32) NOT NULL,
        value BINARY(16) NOT NULL
);


-- initialize the global settings table
INSERT INTO global_settings (id, db_version) VALUES (0, 0); -- should not be changed
