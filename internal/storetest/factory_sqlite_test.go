//go:build testing && !postgres

package storetest

import (
	"path/filepath"
	"testing"

	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap"
)

// openStore opens a backend store backed by SQLite. Build with
// `-tags postgres` to instead exercise the PostgreSQL backend.
func openStore(t testing.TB, log *zap.Logger) explorer.Store {
	db, err := sqlite.OpenDatabase(filepath.Join(t.TempDir(), "explored.sqlite3"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
