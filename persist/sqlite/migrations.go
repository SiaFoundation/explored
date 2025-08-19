package sqlite

import (
	"fmt"

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
	// initialization cycle issue if we do len(migrations)+1 here because
	// migrations refers to migrateV3 and migrateV3 refers to migrations
	// so we have to hardcode 3
	if err := resetChainState(txn, log, 3); err != nil {
		return fmt.Errorf("failed to reset chain state: %w", err)
	}
	return nil
}

func migrateV4(txn *txn, log *zap.Logger) error {
	if err := resetChainState(txn, log, 4); err != nil {
		return fmt.Errorf("failed to reset chain state: %w", err)
	}
	return nil
}

func migrateV5(tx *txn, _ *zap.Logger) error {
	_, err := tx.Exec(`CREATE INDEX address_balance_siacoin_balance_index ON address_balance(siacoin_balance);
CREATE INDEX address_balance_siafund_balance_index ON address_balance(siafund_balance);`)
	return err
}

var migrations = []func(tx *txn, log *zap.Logger) error{
	migrateV2,
	migrateV3,
	migrateV4,
	migrateV5,
}
