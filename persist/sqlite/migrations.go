package sqlite

import "go.uber.org/zap"

var migrations []func(tx *txn, log *zap.Logger) error
