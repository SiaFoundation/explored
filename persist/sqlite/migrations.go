package sqlite

import (
	"fmt"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
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
	stmt, err := txn.Prepare(`SELECT 1 FROM events WHERE event_id = ?`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	insertEventStmt, err := txn.Prepare(`INSERT INTO events (event_id, maturity_height, date_created, event_type, block_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (event_id) DO NOTHING RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare event statement: %w", err)
	}
	defer insertEventStmt.Close()

	addrStmt, err := txn.Prepare(`INSERT INTO address_balance (address, siacoin_balance, immature_siacoin_balance, siafund_balance) VALUES ($1, $2, $2, 0) ON CONFLICT (address) DO UPDATE SET address=EXCLUDED.address RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare address statement: %w", err)
	}
	defer addrStmt.Close()

	relevantAddrStmt, err := txn.Prepare(`INSERT INTO event_addresses (event_id, address_id, event_maturity_height) VALUES ($1, $2, $3) ON CONFLICT (event_id, address_id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("failed to prepare relevant address statement: %w", err)
	}
	defer relevantAddrStmt.Close()

	payoutEventStmt, err := txn.Prepare(`INSERT INTO payout_events (event_id, output_id) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare minerpayout event statement: %w", err)
	}
	defer payoutEventStmt.Close()

	rows, err := txn.Query(`SELECT
    miner_payouts.block_id,
    blocks.height,
    siacoin_elements.output_id,
    siacoin_elements.maturity_height,
    blocks.timestamp,
    siacoin_elements.address
FROM
    miner_payouts
JOIN
    blocks ON miner_payouts.block_id = blocks.id
JOIN
    siacoin_elements ON miner_payouts.output_id = siacoin_elements.id;
`)
	if err != nil {
		return fmt.Errorf("failed to query miner payouts: %w", err)
	}
	defer rows.Close()

	i := 0
	for rows.Next() {
		if i%100 == 0 {
			log.Info("Inserted miner payout event:", zap.Int("count", i))
		}
		var addr types.Address
		event := explorer.Event{Type: wallet.EventTypeMinerPayout}

		err := rows.Scan(decode(&event.Index.ID), decode(&event.Index.Height), decode(&event.ID), decode(&event.MaturityHeight), decode(&event.Timestamp), decode(&addr))
		if err != nil {
			return fmt.Errorf("failed to scan rows: %w", err)
		}

		var eventID int64
		err = insertEventStmt.QueryRow(encode(event.ID), event.MaturityHeight, encode(event.Timestamp), event.Type, encode(event.Index.ID)).Scan(&eventID)
		if err != nil {
			return fmt.Errorf("failed to add event: %w", err)
		}

		var addressID int64
		err = addrStmt.QueryRow(encode(addr), encode(types.ZeroCurrency)).Scan(&addressID)
		if err != nil {
			return fmt.Errorf("failed to get address: %w", err)
		}

		_, err = relevantAddrStmt.Exec(eventID, addressID, event.MaturityHeight)
		if err != nil {
			return fmt.Errorf("failed to add relevant address: %w", err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to get rows: %w", err)
	}

	return nil

}

var migrations = []func(tx *txn, log *zap.Logger) error{
	migrateV2,
	migrateV3,
}
