package sqlite

import "go.uber.org/zap"

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

var migrations = []func(tx *txn, log *zap.Logger) error{
	migrateV2,
}
