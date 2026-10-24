package testdb

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegis-ai/aegis/internal/store"
)

type Database struct {
	Store *store.Store
	Pool  *pgxpool.Pool
	dsn   string
	name  string
}

func New(t *testing.T) *Database {
	t.Helper()
	dsn := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL is required for PostgreSQL integration tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	name := "aegis_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{name}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", name)
	q.Set("application_name", name)
	u.RawQuery = q.Encode()
	db := &Database{Pool: pool, dsn: u.String(), name: name}
	db.Store = db.Connect(t)
	if err := db.Store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return db
}

func (db *Database) Connect(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(context.Background(), db.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func (db *Database) Exec(t *testing.T, query string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, db.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

// BlockHistory holds readers until every request has reached database state.
func (db *Database) BlockHistory(t *testing.T) func(int) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{db.name, "tool_calls"}.Sanitize()+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	return func(requests int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var blocked int
			err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM pg_stat_activity
				WHERE application_name = $1 AND wait_event_type = 'Lock'`, db.name).Scan(&blocked)
			if err != nil {
				t.Fatal(err)
			}
			if blocked >= requests {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("only %d of %d requests reached the database barrier", blocked, requests)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
