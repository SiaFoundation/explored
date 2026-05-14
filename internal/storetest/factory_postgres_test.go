//go:build postgres

package storetest

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/persist/postgres"
	"go.uber.org/zap"
)

func connectionInfoFromEnv() postgres.ConnectionInfo {
	port := 5432
	if p := os.Getenv("POSTGRES_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		host = "localhost"
	}
	sslmode := os.Getenv("POSTGRES_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}
	return postgres.ConnectionInfo{
		Host:     host,
		Port:     port,
		User:     os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		Database: os.Getenv("POSTGRES_DB"),
		SSLMode:  sslmode,
	}
}

// openStore opens a backend store backed by PostgreSQL. The test schema is
// dropped and recreated at the end of each test.
func openStore(t testing.TB, log *zap.Logger) explorer.Store {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := postgres.NewStore(ctx, connectionInfoFromEnv(), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Reset the schema so subsequent tests start clean. If this fails the
		// next test will see polluted state, so surface it as a test failure
		// rather than just logging it.
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dropCancel()
		if err := db.ResetForTesting(dropCtx); err != nil {
			t.Errorf("failed to reset schema: %v", err)
		}
		db.Close()
	})
	return db
}
