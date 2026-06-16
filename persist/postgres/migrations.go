package postgres

import (
	"go.uber.org/zap"
)

// migrations is the list of database migrations to run, in order. The initial
// schema in init.sql is version 1; migration 0 brings the database to
// version 2, migration 1 to version 3, etc.
var migrations = []func(tx *txn, log *zap.Logger) error{}
