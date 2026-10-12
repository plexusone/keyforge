package sqlstore_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/registry/storetest"
	"github.com/plexusone/keyforge/sqlstore"
)

// postgresEnv names the variable that holds a connection string for a
// disposable PostgreSQL database. The PostgreSQL run is skipped without it.
const postgresEnv = "KEYFORGE_TEST_POSTGRES_DSN"

func TestSQLiteConformance(t *testing.T) {
	storetest.Run(t, func() registry.Store {
		s, err := sqlstore.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "registry.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
		return s
	})
}

func TestPostgresConformance(t *testing.T) {
	dsn := os.Getenv(postgresEnv)
	if dsn == "" {
		t.Skipf("%s is not set", postgresEnv)
	}
	storetest.Run(t, func() registry.Store {
		ctx := context.Background()
		// Each case runs against an empty registry.
		resetPostgres(t, dsn)
		s, err := sqlstore.OpenPostgres(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
		return s
	})
}

// resetPostgres drops everything in the public schema, so the next case starts
// from nothing.
func resetPostgres(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, q := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func seed(t *testing.T, s *sqlstore.Store, purpose keyforge.Purpose) (kekID envelope.ID, dek keyforge.DEKRecord) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	kekID = envelope.ID{1, 2, 3, 4}
	if err := s.CreateKEK(ctx, registry.KEK{
		ID: kekID, Purpose: purpose, Provider: "test", ProviderRef: "ref",
		State: registry.KeyActive, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddVersion(ctx, registry.VersionRecord{
		KEKID: kekID, Version: 1, State: registry.VersionPending, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionVersion(ctx, kekID, 1, registry.VersionActive, registry.TransitionOptions{At: now}); err != nil {
		t.Fatal(err)
	}
	dek, err := s.AdvanceDEK(ctx, purpose, "", 0, keyforge.DEKRecord{
		ID: envelope.ID{9, 9, 9}, Purpose: purpose, Epoch: 1, Algorithm: algorithm.AES256GCM,
		KEKID: kekID, KEKVersion: 1, Wrapped: []byte("wrapped"), CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return kekID, dek
}

func TestSQLitePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry.db")
	s, err := sqlstore.OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	kekID, dek := seed(t, s, "orders")
	if _, err := s.ReserveEncryptions(ctx, dek.ID, 10, 100); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Opening again runs the migration over an existing schema.
	s, err = sqlstore.OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	got, err := s.CurrentDEK(ctx, "orders", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != dek.ID || got.Reserved != 10 || string(got.Wrapped) != "wrapped" ||
		len(got.WrappedUnder) != 1 || got.WrappedUnder[0].KEKID != kekID {
		t.Fatalf("after reopen: %+v", got)
	}
	av, err := s.ActiveKEK(ctx, "orders")
	if err != nil || av.Ref.ID != kekID || av.Version != 1 {
		t.Fatalf("ActiveKEK = %+v, %v", av, err)
	}
}

// TestHandlesShareTheCap runs two stores over one database, as two replicas
// would, and checks that together they never grant more than the cap.
func TestHandlesShareTheCap(t *testing.T) {
	ctx := context.Background()
	open := func() *sqlstore.Store {
		t.Helper()
		var (
			s   *sqlstore.Store
			err error
		)
		if dsn := os.Getenv(postgresEnv); dsn != "" {
			s, err = sqlstore.OpenPostgres(ctx, dsn)
		} else {
			s, err = sqlstore.OpenSQLite(ctx, filepath.Join(dir(t), "registry.db"))
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
		return s
	}
	if dsn := os.Getenv(postgresEnv); dsn != "" {
		resetPostgres(t, dsn)
	}
	a := open()
	_, dek := seed(t, a, "orders")
	b := open()

	const limit = 600
	var (
		wg    sync.WaitGroup
		total atomic.Uint64
	)
	for _, s := range []*sqlstore.Store{a, b} {
		for range 6 {
			wg.Go(func() {
				for {
					n, err := s.ReserveEncryptions(ctx, dek.ID, 5, limit)
					if err != nil {
						t.Error(err)
						return
					}
					if n == 0 {
						return
					}
					total.Add(n)
				}
			})
		}
	}
	wg.Wait()
	if got := total.Load(); got != limit {
		t.Fatalf("granted %d, want exactly %d", got, limit)
	}
}

// dirs caches one directory per test so two handles open the same file.
var dirs sync.Map

func dir(t *testing.T) string {
	t.Helper()
	d, _ := dirs.LoadOrStore(t.Name(), t.TempDir())
	return d.(string)
}
