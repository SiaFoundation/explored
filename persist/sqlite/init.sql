CREATE TABLE global_settings (
        id INTEGER PRIMARY KEY NOT NULL DEFAULT 0 CHECK (id = 0), -- enforce a single row
        db_version INTEGER NOT NULL -- used for migrations
);

CREATE TABLE Blocks (
        id BINARY(32) NOT NULL PRIMARY KEY,
        height INTEGER NOT NULL,
        parent_id BINARY(32) NOT NULL,
        nonce INTEGER NOT NULL,
        timestamp INTEGER NOT NULL
);

CREATE TABLE MinerPayouts (
        block_id REFERENCES Blocks(id),
        block_order INTEGER NOT NULL,
        address BINARY(32) NOT NULL,
        value BINARY(16) NOT NULL
);


-- initialize the global settings table
INSERT INTO global_settings (id, db_version) VALUES (0, 0); -- should not be changed
