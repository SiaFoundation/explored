//go:build postgres

package postgres

import (
	"encoding/hex"
	"os"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/goleak"
	"lukechampine.com/frand"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func connectionInfoFromEnv() ConnectionInfo {
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
	return ConnectionInfo{
		Host:     host,
		Port:     port,
		User:     os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		Database: os.Getenv("POSTGRES_DB"),
		SSLMode:  sslmode,
	}
}

func TestEnsureDatabase(t *testing.T) {
	rBytes := frand.Entropy128()
	ci := connectionInfoFromEnv()
	ci.Database = "explored_test_" + hex.EncodeToString(rBytes[:])

	if err := ensureDatabase(t.Context(), ci); err != nil {
		t.Fatalf("failed to ensure database: %v", err)
	}

	// connect to the new database and drop it via the default `postgres` one.
	adminCI := ci
	adminCI.Database = "postgres"
	pool, err := pgxpool.New(t.Context(), adminCI.String())
	if err != nil {
		t.Fatalf("failed to connect to admin database: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(t.Context(), `DROP DATABASE `+pgx.Identifier{ci.Database}.Sanitize()); err != nil {
		t.Fatalf("failed to drop database: %v", err)
	}
}
