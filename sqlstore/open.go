package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
	_ "modernc.org/sqlite"             // registers the "sqlite" driver
)

// OpenSQLite opens, or creates, a SQLite database file and its schema. It is
// the store for a single host. The database uses write-ahead logging, waits for
// a busy lock rather than failing, enforces foreign keys, and begins write
// transactions immediately so that writers queue.
//
// Use ":memory:" for a database that lives as long as the store.
func OpenSQLite(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("sqlstore: a SQLite path is required")
	}
	q := url.Values{}
	q.Set("_txlock", "immediate")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	if path != ":memory:" {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(FULL)")
	}
	dsn := "file:" + strings.TrimPrefix(path, "file:") + "?" + q.Encode()
	if path == ":memory:" {
		dsn = "file::memory:?" + q.Encode()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: open sqlite: %w", err)
	}
	// One connection: SQLite serializes writers anyway, and a private
	// in-memory database exists per connection.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	return finish(ctx, db, SQLite)
}

// OpenPostgres opens a PostgreSQL database by connection string and creates its
// schema. It uses pgx.
func OpenPostgres(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return nil, errors.New("sqlstore: a PostgreSQL connection string is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: open postgres: %w", err)
	}
	return finish(ctx, db, Postgres)
}

func finish(ctx context.Context, db *sql.DB, d Dialect) (*Store, error) {
	s, err := New(db, d)
	if err != nil {
		return nil, errors.Join(err, db.Close())
	}
	s.owned = true
	if err := s.Ping(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("sqlstore: ping: %w", err), db.Close())
	}
	if err := s.Migrate(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return s, nil
}

// Backup writes a consistent copy of a SQLite registry to path, which must not
// exist. It is safe while the store is in use: the copy is a snapshot taken in
// one transaction, including what is still in the write-ahead log, so copying
// the database file by itself is not a backup.
//
// A restored registry is only usable with a keyring that holds the key
// versions it names, so a backup of the registry and a backup of the keyring
// belong together.
func (s *Store) Backup(ctx context.Context, path string) error {
	if s.dialect != SQLite {
		return fmt.Errorf("sqlstore: Backup supports SQLite only; back up PostgreSQL with its own tools")
	}
	if path == "" {
		return errors.New("sqlstore: a backup path is required")
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("sqlstore: backup %s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("sqlstore: backup: %w", err)
	}
	// VACUUM INTO takes a string literal, not a parameter, so the path is
	// quoted by doubling single quotes, which is SQLite's only escape.
	lit := "'" + strings.ReplaceAll(path, "'", "''") + "'"
	//nolint:gosec // G202: the only input is a quoted file path, and a parameter is not allowed here
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO "+lit); err != nil {
		return fmt.Errorf("sqlstore: backup: %w", err)
	}
	return nil
}
