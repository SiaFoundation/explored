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
        block_id BLOB REFERENCES blocks(id) ON DELETE CASCADE NOT NULL PRIMARY KEY,
        block_order INTEGER NOT NULL,
        address BLOB NOT NULL,
        value BLOB NOT NULL,
        UNIQUE(block_id, block_order)
);


-- initialize the global settings table
INSERT INTO global_settings (id, db_version) VALUES (0, 0); -- should not be changed
