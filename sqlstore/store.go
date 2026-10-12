// Package sqlstore is the SQL-backed [registry.Store], built on Ent. It
// supports SQLite, for a single host, and PostgreSQL, for a service shared by
// several replicas. Both pass the conformance suite in package storetest.
//
// The store holds wrapped keys and never a plaintext one. Every operation that
// changes state runs in one transaction, and a transaction that loses a race is
// retried, so callers see the same atomic behaviour as the in-memory store:
// among concurrent callers there is a single winner and the others converge on
// it.
//
// Serialization comes from the engine. On PostgreSQL every transaction runs at
// the serializable isolation level, and a serialization failure, a deadlock or
// a unique violation from a lost race is retried. On SQLite, transactions begin
// immediately, so writers queue behind one another, and the connection pool is
// held to a single connection.
package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	entdialect "entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/sqlstore/ent"
	"github.com/plexusone/keyforge/sqlstore/ent/datakey"
	"github.com/plexusone/keyforge/sqlstore/ent/kek"
	"github.com/plexusone/keyforge/sqlstore/ent/kekversion"
	"github.com/plexusone/keyforge/sqlstore/ent/sentinel"
	"github.com/plexusone/keyforge/sqlstore/ent/shred"
)

var _ registry.Store = (*Store)(nil)

// Dialect names a supported database engine.
type Dialect string

const (
	// SQLite is a single-file embedded database.
	SQLite Dialect = Dialect(entdialect.SQLite)
	// Postgres is PostgreSQL.
	Postgres Dialect = Dialect(entdialect.Postgres)
)

// maxAttempts bounds how often a transaction that lost a race is retried.
const maxAttempts = 16

// Store is a registry in a SQL database. It is safe for concurrent use.
type Store struct {
	client  *ent.Client
	db      *sql.DB
	dialect Dialect
	owned   bool
}

// New returns a store over an open database. The caller owns db and closes it.
// It does not create the schema: call [Store.Migrate] first.
func New(db *sql.DB, d Dialect) (*Store, error) {
	switch d {
	case SQLite, Postgres:
	default:
		return nil, fmt.Errorf("sqlstore: unsupported dialect %q", d)
	}
	drv := entsql.OpenDB(string(d), db)
	return &Store{client: ent.NewClient(ent.Driver(drv)), db: db, dialect: d}, nil
}

// Migrate creates or updates the schema so that it matches this version of the
// store. It is idempotent.
func (s *Store) Migrate(ctx context.Context) error {
	if err := s.client.Schema.Create(ctx); err != nil {
		return fmt.Errorf("sqlstore: migrate: %w", err)
	}
	return nil
}

// Close releases the store. It closes the database only if the store opened it.
func (s *Store) Close() error {
	if s.owned {
		return s.db.Close()
	}
	return nil
}

// Ping checks that the database answers.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// retryable reports whether err is a lost race that a fresh transaction should
// retry: a busy database, a serialization failure, a deadlock, or a unique
// violation from two writers inserting the same row.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	if ent.IsConstraintError(err) {
		return true
	}
	var st interface{ SQLState() string }
	if errors.As(err, &st) {
		switch st.SQLState() {
		case "40001", "40P01", "23505", "55P03":
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "SQLITE_LOCKED")
}

// tx runs fn in a transaction, retrying when it loses a race. fn may run more
// than once, so it must derive everything from the database.
func (s *Store) tx(ctx context.Context, fn func(tx *ent.Tx) error) error {
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = s.once(ctx, fn); err == nil || !retryable(err) {
			return err
		}
		// Linear backoff with jitter, so writers that collided do not collide
		// again in step.
		wait := time.Duration(attempt+1) * 5 * time.Millisecond
		wait += rand.N(wait) //nolint:gosec // G404: jitter for backoff, not a secret
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(wait):
		}
	}
	return err
}

func (s *Store) once(ctx context.Context, fn func(tx *ent.Tx) error) error {
	var opts *sql.TxOptions
	if s.dialect == Postgres {
		opts = &sql.TxOptions{Isolation: sql.LevelSerializable}
	}
	tx, err := s.client.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			return errors.Join(err, fmt.Errorf("sqlstore: rollback: %w", rerr))
		}
		return err
	}
	return tx.Commit()
}

// read runs fn against a read-only transaction so that a multi-query read sees
// one snapshot.
func (s *Store) read(ctx context.Context, fn func(tx *ent.Tx) error) error {
	return s.tx(ctx, fn)
}

func kekNotFound(id envelope.ID) error {
	return fmt.Errorf("%w: %s", keyforge.ErrKEKNotFound, id)
}

func dekNotFound(id envelope.ID) error {
	return fmt.Errorf("%w: %s", keyforge.ErrDEKNotFound, id)
}

func versionNotFound(id envelope.ID, version uint32) error {
	return fmt.Errorf("%w: %s version %d", registry.ErrVersionNotFound, id, version)
}

// optTime stores the zero time as NULL.
func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// timeOf reads an optional time, NULL being the zero time.
func timeOf(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return utc(*t)
}

// utc returns t in UTC. PostgreSQL returns a timestamp in the session's zone,
// and a registry read must not depend on where it runs.
func utc(t time.Time) time.Time { return t.UTC() }

func toKEK(e *ent.KEK) registry.KEK {
	return registry.KEK{
		ID: e.ID, Purpose: keyforge.Purpose(e.Purpose), Provider: e.Provider,
		ProviderRef: e.ProviderRef, State: registry.KeyState(e.State), CreatedAt: utc(e.CreatedAt),
	}
}

func toVersion(e *ent.KEKVersion) registry.VersionRecord {
	return registry.VersionRecord{
		KEKID: e.KekID, Version: e.Version, State: registry.VersionState(e.State),
		ProviderRef: e.ProviderRef, CreatedAt: utc(e.CreatedAt),
		ActivatedAt: timeOf(e.ActivatedAt), RotatedAt: timeOf(e.RotatedAt), RetireAfter: timeOf(e.RetireAfter),
	}
}

func toDEK(e *ent.DataKey) keyforge.DEKRecord {
	return keyforge.DEKRecord{
		ID: e.ID, Purpose: keyforge.Purpose(e.Purpose), Subject: e.Subject, Epoch: e.Epoch,
		Algorithm: algorithm.ID(e.Algorithm), KEKID: e.KekID, KEKVersion: e.KekVersion,
		Wrapped: slices.Clone(e.Wrapped), State: keyforge.DEKState(e.State), Reserved: e.Reserved,
		CreatedAt: utc(e.CreatedAt), WrappedUnder: slices.Clone(e.WrappedUnder),
	}
}

func toShred(e *ent.Shred) registry.ShredRecord {
	return registry.ShredRecord{
		Purpose: keyforge.Purpose(e.Purpose), Subject: e.Subject, RequestedAt: utc(e.RequestedAt),
		Versions: slices.Clone(e.Versions), DEKs: e.Deks, CompletedAt: timeOf(e.CompletedAt),
	}
}

// CreateKEK implements [registry.Store].
func (s *Store) CreateKEK(ctx context.Context, k registry.KEK) error {
	if err := k.Validate(); err != nil {
		return err
	}
	return s.tx(ctx, func(tx *ent.Tx) error {
		if ok, err := tx.KEK.Query().Where(kek.ID(k.ID)).Exist(ctx); err != nil {
			return err
		} else if ok {
			return fmt.Errorf("%w: %s", registry.ErrKEKExists, k.ID)
		}
		if k.State == registry.KeyActive {
			other, err := tx.KEK.Query().
				Where(kek.Purpose(string(k.Purpose)), kek.State(uint8(registry.KeyActive))).First(ctx)
			switch {
			case err == nil:
				return fmt.Errorf("%w: %q is served by %s", registry.ErrPurposeBound, string(k.Purpose), other.ID)
			case !ent.IsNotFound(err):
				return err
			}
		}
		return tx.KEK.Create().
			SetID(k.ID).SetPurpose(string(k.Purpose)).SetProvider(k.Provider).
			SetProviderRef(k.ProviderRef).SetState(uint8(k.State)).SetCreatedAt(k.CreatedAt).
			Exec(ctx)
	})
}

// GetKEK implements [registry.Store].
func (s *Store) GetKEK(ctx context.Context, id envelope.ID) (registry.KEK, error) {
	e, err := s.client.KEK.Get(ctx, id)
	if ent.IsNotFound(err) {
		return registry.KEK{}, kekNotFound(id)
	}
	if err != nil {
		return registry.KEK{}, err
	}
	return toKEK(e), nil
}

func (s *Store) activeKEK(ctx context.Context, c *ent.Client, purpose keyforge.Purpose) (*ent.KEK, error) {
	e, err := c.KEK.Query().Where(kek.Purpose(string(purpose)), kek.State(uint8(registry.KeyActive))).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, fmt.Errorf("%w: no active KEK for %q", keyforge.ErrKEKNotFound, string(purpose))
	}
	return e, err
}

// KEKForPurpose implements [registry.Store].
func (s *Store) KEKForPurpose(ctx context.Context, purpose keyforge.Purpose) (registry.KEK, error) {
	e, err := s.activeKEK(ctx, s.client, purpose)
	if err != nil {
		return registry.KEK{}, err
	}
	return toKEK(e), nil
}

// ListKEKs implements [registry.Store].
func (s *Store) ListKEKs(ctx context.Context) ([]registry.KEK, error) {
	es, err := s.client.KEK.Query().Order(kek.ByID()).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]registry.KEK, len(es))
	for i, e := range es {
		out[i] = toKEK(e)
	}
	return out, nil
}

// ActiveKEK implements [keyforge.Store].
func (s *Store) ActiveKEK(ctx context.Context, purpose keyforge.Purpose) (keyforge.KEKVersion, error) {
	var out keyforge.KEKVersion
	err := s.read(ctx, func(tx *ent.Tx) error {
		k, err := s.activeKEK(ctx, tx.Client(), purpose)
		if err != nil {
			if errors.Is(err, keyforge.ErrKEKNotFound) {
				return fmt.Errorf("%w: %q", keyforge.ErrNoActiveKEK, string(purpose))
			}
			return err
		}
		v, err := tx.KEKVersion.Query().
			Where(kekversion.KekID(k.ID), kekversion.State(uint8(registry.VersionActive))).Only(ctx)
		if ent.IsNotFound(err) {
			return fmt.Errorf("%w: %q has no active version", keyforge.ErrNoActiveKEK, string(purpose))
		}
		if err != nil {
			return err
		}
		out = keyforge.KEKVersion{Ref: toKEK(k).Ref(), Version: v.Version}
		return nil
	})
	return out, err
}

// KEK implements [keyforge.Store].
func (s *Store) KEK(ctx context.Context, id envelope.ID) (provider.KeyRef, error) {
	k, err := s.GetKEK(ctx, id)
	if err != nil {
		return provider.KeyRef{}, err
	}
	return k.Ref(), nil
}

// KEKVersionUsable implements [keyforge.Store].
func (s *Store) KEKVersionUsable(ctx context.Context, id envelope.ID, version uint32) (bool, error) {
	var usable bool
	err := s.read(ctx, func(tx *ent.Tx) error {
		v, err := tx.KEKVersion.Query().Where(kekversion.KekID(id), kekversion.Version(version)).Only(ctx)
		switch {
		case err == nil:
			usable = registry.VersionState(v.State).CanUnwrap()
			return nil
		case !ent.IsNotFound(err):
			return err
		}
		usable = false
		return s.requireKEK(ctx, tx, id)
	})
	return usable, err
}

func (s *Store) requireKEK(ctx context.Context, tx *ent.Tx, id envelope.ID) error {
	ok, err := tx.KEK.Query().Where(kek.ID(id)).Exist(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return kekNotFound(id)
	}
	return nil
}

// AddVersion implements [registry.Store].
func (s *Store) AddVersion(ctx context.Context, v registry.VersionRecord) error {
	if v.Version == 0 {
		return fmt.Errorf("%w: versions start at 1", registry.ErrInvalid)
	}
	if v.State != registry.VersionPending {
		return fmt.Errorf("%w: a new version is pending, not %s", registry.ErrInvalid, v.State)
	}
	return s.tx(ctx, func(tx *ent.Tx) error {
		if err := s.requireKEK(ctx, tx, v.KEKID); err != nil {
			return err
		}
		latest, err := tx.KEKVersion.Query().Where(kekversion.KekID(v.KEKID)).
			Order(kekversion.ByVersion(entsql.OrderDesc())).First(ctx)
		switch {
		case err == nil:
			if v.Version <= latest.Version {
				return fmt.Errorf("%w: version %d, latest is %d", registry.ErrVersionExists, v.Version, latest.Version)
			}
		case !ent.IsNotFound(err):
			return err
		}
		return tx.KEKVersion.Create().
			SetKekID(v.KEKID).SetVersion(v.Version).SetState(uint8(v.State)).
			SetProviderRef(v.ProviderRef).SetCreatedAt(v.CreatedAt).
			SetNillableActivatedAt(optTime(v.ActivatedAt)).SetNillableRotatedAt(optTime(v.RotatedAt)).
			SetNillableRetireAfter(optTime(v.RetireAfter)).
			Exec(ctx)
	})
}

// GetVersion implements [registry.Store].
func (s *Store) GetVersion(ctx context.Context, kekID envelope.ID, version uint32) (registry.VersionRecord, error) {
	var out registry.VersionRecord
	err := s.read(ctx, func(tx *ent.Tx) error {
		e, err := tx.KEKVersion.Query().Where(kekversion.KekID(kekID), kekversion.Version(version)).Only(ctx)
		switch {
		case err == nil:
			out = toVersion(e)
			return nil
		case !ent.IsNotFound(err):
			return err
		}
		if err := s.requireKEK(ctx, tx, kekID); err != nil {
			return err
		}
		return versionNotFound(kekID, version)
	})
	return out, err
}

// ListVersions implements [registry.Store].
func (s *Store) ListVersions(ctx context.Context, kekID envelope.ID) ([]registry.VersionRecord, error) {
	var out []registry.VersionRecord
	err := s.read(ctx, func(tx *ent.Tx) error {
		if err := s.requireKEK(ctx, tx, kekID); err != nil {
			return err
		}
		es, err := tx.KEKVersion.Query().Where(kekversion.KekID(kekID)).Order(kekversion.ByVersion()).All(ctx)
		if err != nil {
			return err
		}
		out = make([]registry.VersionRecord, len(es))
		for i, e := range es {
			out[i] = toVersion(e)
		}
		return nil
	})
	return out, err
}

func countDEKs(ctx context.Context, tx *ent.Tx, kekID envelope.ID, version uint32) (int, error) {
	return tx.DataKey.Query().Where(
		datakey.KekID(kekID), datakey.KekVersion(version),
		datakey.StateNEQ(uint8(keyforge.DEKDestroyed)),
	).Count(ctx)
}

// TransitionVersion implements [registry.Store].
func (s *Store) TransitionVersion(ctx context.Context, kekID envelope.ID, version uint32, to registry.VersionState, opts registry.TransitionOptions) error {
	if opts.At.IsZero() {
		return fmt.Errorf("%w: a transition needs a time", registry.ErrInvalid)
	}
	return s.tx(ctx, func(tx *ent.Tx) error {
		if err := s.requireKEK(ctx, tx, kekID); err != nil {
			return err
		}
		all, err := tx.KEKVersion.Query().Where(kekversion.KekID(kekID)).All(ctx)
		if err != nil {
			return err
		}
		idx := slices.IndexFunc(all, func(v *ent.KEKVersion) bool { return v.Version == version })
		if idx < 0 {
			return versionNotFound(kekID, version)
		}
		cur := all[idx]
		from := registry.VersionState(cur.State)
		if err := registry.CheckTransition(from, to); err != nil {
			return err
		}

		upd := tx.KEKVersion.UpdateOne(cur).SetState(uint8(to))
		var demote []*ent.KEKVersion

		switch {
		case from == registry.VersionActive && to == registry.VersionDecryptOnly:
			// A version stops being active by another being activated, so that
			// there is never a moment with none.
			return &registry.TransitionError{From: from, To: to}

		case to == registry.VersionActive:
			upd.SetActivatedAt(opts.At)
			if from == registry.VersionDecryptOnly {
				var latest uint32
				for _, v := range all {
					if registry.VersionState(v.State) == registry.VersionDecryptOnly {
						latest = max(latest, v.Version)
					}
				}
				if version != latest {
					return fmt.Errorf("%w: version %d, the most recent is %d", registry.ErrNoRollbackTarget, version, latest)
				}
			}
			for _, v := range all {
				if registry.VersionState(v.State) == registry.VersionActive && v.Version != version {
					demote = append(demote, v)
				}
			}

		case to == registry.VersionRetireRequested:
			if opts.RetireAfter.IsZero() || !opts.RetireAfter.After(opts.At) {
				return fmt.Errorf("%w: retirement needs a retire-after later than now", registry.ErrInvalid)
			}
			upd.SetRetireAfter(opts.RetireAfter)

		case from == registry.VersionRetireRequested && to == registry.VersionDecryptOnly:
			upd.ClearRetireAfter()

		case to == registry.VersionRetired:
			if from == registry.VersionRetireRequested && cur.RetireAfter != nil && opts.At.Before(*cur.RetireAfter) {
				return fmt.Errorf("%w: until %s", registry.ErrRetireDelay, cur.RetireAfter.Format(time.RFC3339))
			}
			if n, err := countDEKs(ctx, tx, kekID, version); err != nil {
				return err
			} else if n > 0 {
				return fmt.Errorf("%w: %d data keys", registry.ErrVersionReferenced, n)
			}

		case to == registry.VersionDestroyed:
			if n, err := countDEKs(ctx, tx, kekID, version); err != nil {
				return err
			} else if n > 0 {
				return fmt.Errorf("%w: %d data keys", registry.ErrVersionReferenced, n)
			}
		}

		// Demote first: the database allows one active version per KEK, and
		// checks it as each statement runs.
		for _, v := range demote {
			if err := tx.KEKVersion.UpdateOne(v).
				SetState(uint8(registry.VersionDecryptOnly)).SetRotatedAt(opts.At).Exec(ctx); err != nil {
				return err
			}
		}
		return upd.Exec(ctx)
	})
}

// CurrentDEK implements [keyforge.Store].
func (s *Store) CurrentDEK(ctx context.Context, purpose keyforge.Purpose, subject string) (keyforge.DEKRecord, error) {
	e, err := s.client.DataKey.Query().
		Where(datakey.Purpose(string(purpose)), datakey.Subject(subject), datakey.IsCurrent(true)).Only(ctx)
	if ent.IsNotFound(err) {
		return keyforge.DEKRecord{}, fmt.Errorf("%w: %q", keyforge.ErrDEKNotFound, string(purpose))
	}
	if err != nil {
		return keyforge.DEKRecord{}, err
	}
	return toDEK(e), nil
}

// GetDEK implements [keyforge.Store].
func (s *Store) GetDEK(ctx context.Context, id envelope.ID) (keyforge.DEKRecord, error) {
	e, err := s.client.DataKey.Get(ctx, id)
	if ent.IsNotFound(err) {
		return keyforge.DEKRecord{}, dekNotFound(id)
	}
	if err != nil {
		return keyforge.DEKRecord{}, err
	}
	return toDEK(e), nil
}

// usableVersion checks that a data key can be wrapped under a KEK version
// belonging to its purpose.
func (s *Store) usableVersion(ctx context.Context, tx *ent.Tx, kekID envelope.ID, version uint32, purpose keyforge.Purpose) error {
	k, err := tx.KEK.Get(ctx, kekID)
	if ent.IsNotFound(err) {
		return kekNotFound(kekID)
	}
	if err != nil {
		return err
	}
	if keyforge.Purpose(k.Purpose) != purpose {
		return fmt.Errorf("%w: KEK %s serves %q, not %q", registry.ErrInvalid, kekID, k.Purpose, string(purpose))
	}
	v, err := tx.KEKVersion.Query().Where(kekversion.KekID(kekID), kekversion.Version(version)).Only(ctx)
	if ent.IsNotFound(err) {
		return versionNotFound(kekID, version)
	}
	if err != nil {
		return err
	}
	if st := registry.VersionState(v.State); st != registry.VersionActive && st != registry.VersionDecryptOnly {
		return fmt.Errorf("%w: version %d is %s", registry.ErrVersionUnusable, version, st)
	}
	return nil
}

// AdvanceDEK implements [keyforge.Store].
func (s *Store) AdvanceDEK(ctx context.Context, purpose keyforge.Purpose, subject string, from uint32, next keyforge.DEKRecord) (keyforge.DEKRecord, error) {
	switch {
	case next.ID.IsZero(), len(next.Wrapped) == 0, !next.Algorithm.Valid():
		return keyforge.DEKRecord{}, fmt.Errorf("%w: data key record is incomplete", registry.ErrInvalid)
	case next.Purpose != purpose, next.Subject != subject, next.Epoch != from+1:
		return keyforge.DEKRecord{}, fmt.Errorf("%w: record is not epoch %d of %q", registry.ErrInvalid, from+1, string(purpose))
	}

	var out keyforge.DEKRecord
	err := s.tx(ctx, func(tx *ent.Tx) error {
		if err := s.usableVersion(ctx, tx, next.KEKID, next.KEKVersion, purpose); err != nil {
			return err
		}
		shredded, err := tx.Shred.Query().Where(shred.Purpose(string(purpose)), shred.Subject(subject)).Exist(ctx)
		if err != nil {
			return err
		}
		if shredded {
			return fmt.Errorf("%w: %q for %q", keyforge.ErrSubjectShredded, string(purpose), subject)
		}

		cur, err := tx.DataKey.Query().
			Where(datakey.Purpose(string(purpose)), datakey.Subject(subject), datakey.IsCurrent(true)).Only(ctx)
		switch {
		case err == nil:
			if cur.Epoch != from {
				out = toDEK(cur)
				return nil
			}
			// The database allows one current key per subject, so the old
			// one stops being current before the new one is inserted.
			upd := tx.DataKey.UpdateOne(cur).SetIsCurrent(false)
			if keyforge.DEKState(cur.State) == keyforge.DEKActive {
				upd.SetState(uint8(keyforge.DEKDecryptOnly))
			}
			if err := upd.Exec(ctx); err != nil {
				return err
			}
		case !ent.IsNotFound(err):
			return err
		case from != 0:
			return fmt.Errorf("%w: no current data key at epoch %d for %q", registry.ErrConflict, from, string(purpose))
		}

		if dup, err := tx.DataKey.Query().Where(datakey.ID(next.ID)).Exist(ctx); err != nil {
			return err
		} else if dup {
			return fmt.Errorf("%w: data key %s exists", registry.ErrInvalid, next.ID)
		}
		next.State = keyforge.DEKActive
		next.Reserved = 0
		next.WrappedUnder = []keyforge.KEKVersionRef{{KEKID: next.KEKID, Version: next.KEKVersion}}
		if err := tx.DataKey.Create().
			SetID(next.ID).SetPurpose(string(purpose)).SetSubject(subject).SetEpoch(next.Epoch).
			SetAlgorithm(uint8(next.Algorithm)).SetKekID(next.KEKID).SetKekVersion(next.KEKVersion).
			SetWrapped(slices.Clone(next.Wrapped)).SetState(uint8(next.State)).SetReserved(0).
			SetCreatedAt(next.CreatedAt).SetWrappedUnder(next.WrappedUnder).SetIsCurrent(true).
			Exec(ctx); err != nil {
			return err
		}
		out = next
		out.Wrapped = slices.Clone(next.Wrapped)
		return nil
	})
	return out, err
}

// ReserveEncryptions implements [keyforge.Store].
func (s *Store) ReserveEncryptions(ctx context.Context, id envelope.ID, n, limit uint64) (uint64, error) {
	var granted uint64
	err := s.tx(ctx, func(tx *ent.Tx) error {
		granted = 0
		e, err := tx.DataKey.Get(ctx, id)
		if ent.IsNotFound(err) {
			return dekNotFound(id)
		}
		if err != nil {
			return err
		}
		if keyforge.DEKState(e.State) != keyforge.DEKActive || e.Reserved >= limit || !e.IsCurrent {
			return nil
		}
		granted = min(n, limit-e.Reserved)
		return tx.DataKey.UpdateOne(e).SetReserved(e.Reserved + granted).Exec(ctx)
	})
	if err != nil {
		return 0, err
	}
	return granted, nil
}

// ListDEKs implements [registry.Store].
func (s *Store) ListDEKs(ctx context.Context, f registry.DEKFilter) ([]keyforge.DEKRecord, error) {
	q := s.client.DataKey.Query().Where(datakey.IDGT(f.After))
	if !f.KEKID.IsZero() {
		q = q.Where(datakey.KekID(f.KEKID))
	}
	if f.KEKVersion != 0 {
		q = q.Where(datakey.KekVersion(f.KEKVersion))
	}
	if f.Purpose != "" {
		q = q.Where(datakey.Purpose(string(f.Purpose)))
	}
	es, err := q.Order(datakey.ByID()).Limit(f.PageSize()).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]keyforge.DEKRecord, len(es))
	for i, e := range es {
		out[i] = toDEK(e)
	}
	return out, nil
}

// CountDEKs implements [registry.Store].
func (s *Store) CountDEKs(ctx context.Context, kekID envelope.ID, version uint32) (int, error) {
	var n int
	err := s.read(ctx, func(tx *ent.Tx) error {
		if err := s.requireKEK(ctx, tx, kekID); err != nil {
			return err
		}
		var err error
		n, err = countDEKs(ctx, tx, kekID, version)
		return err
	})
	return n, err
}

// CountDEKStates implements [registry.Store].
func (s *Store) CountDEKStates(ctx context.Context, purpose keyforge.Purpose) (map[keyforge.DEKState]int, error) {
	var rows []struct {
		State uint8 `json:"state"`
		Count int   `json:"count"`
	}
	err := s.client.DataKey.Query().Where(datakey.Purpose(string(purpose))).
		GroupBy(datakey.FieldState).Aggregate(ent.Count()).Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}
	out := make(map[keyforge.DEKState]int, len(rows))
	for _, r := range rows {
		out[keyforge.DEKState(r.State)] = r.Count
	}
	return out, nil
}

// RewrapDEK implements [registry.Store].
func (s *Store) RewrapDEK(ctx context.Context, r registry.Rewrap) error {
	if len(r.Wrapped) == 0 {
		return fmt.Errorf("%w: rewrap has no wrapped key", registry.ErrInvalid)
	}
	return s.tx(ctx, func(tx *ent.Tx) error {
		rec, err := tx.DataKey.Get(ctx, r.ID)
		if ent.IsNotFound(err) {
			return dekNotFound(r.ID)
		}
		if err != nil {
			return err
		}
		if keyforge.DEKState(rec.State) == keyforge.DEKDestroyed {
			return fmt.Errorf("%w: data key %s is destroyed", keyforge.ErrKeyUnusable, r.ID)
		}
		v, err := tx.KEKVersion.Query().Where(kekversion.KekID(r.ToKEKID), kekversion.Version(r.ToVersion)).Only(ctx)
		switch {
		case ent.IsNotFound(err):
			if err := s.requireKEK(ctx, tx, r.ToKEKID); err != nil {
				return err
			}
			return versionNotFound(r.ToKEKID, r.ToVersion)
		case err != nil:
			return err
		}
		if st := registry.VersionState(v.State); st != registry.VersionActive {
			return fmt.Errorf("%w: version %d is %s", registry.ErrVersionUnusable, r.ToVersion, st)
		}

		if rec.KekID == r.ToKEKID && rec.KekVersion == r.ToVersion {
			if bytes.Equal(rec.Wrapped, r.Wrapped) {
				return nil // already done: a resumed job repeats it
			}
			return fmt.Errorf("%w: data key %s is already wrapped under that version differently", registry.ErrConflict, r.ID)
		}
		if rec.KekID != r.FromKEKID || rec.KekVersion != r.FromVersion {
			return fmt.Errorf("%w: data key %s is wrapped under version %d, not %d", registry.ErrConflict, r.ID, rec.KekVersion, r.FromVersion)
		}
		hist := append(slices.Clone(rec.WrappedUnder), keyforge.KEKVersionRef{KEKID: r.ToKEKID, Version: r.ToVersion})
		return tx.DataKey.UpdateOne(rec).
			SetKekID(r.ToKEKID).SetKekVersion(r.ToVersion).SetWrapped(slices.Clone(r.Wrapped)).
			SetWrappedUnder(hist).Exec(ctx)
	})
}

// MarkDEK implements [registry.Store].
func (s *Store) MarkDEK(ctx context.Context, id envelope.ID, to keyforge.DEKState) error {
	return s.tx(ctx, func(tx *ent.Tx) error {
		rec, err := tx.DataKey.Get(ctx, id)
		if ent.IsNotFound(err) {
			return dekNotFound(id)
		}
		if err != nil {
			return err
		}
		from := keyforge.DEKState(rec.State)
		// Demotion is done by advancing the epoch, never directly.
		if to == keyforge.DEKDecryptOnly || to == keyforge.DEKActive {
			return &registry.DEKTransitionError{From: from, To: to}
		}
		if err := registry.CheckDEKTransition(from, to); err != nil {
			return err
		}
		upd := tx.DataKey.UpdateOne(rec).SetState(uint8(to))
		if to == keyforge.DEKDestroyed {
			// Destroying a data key removes its wrapped value. The record
			// stays, as the trail of what existed.
			upd.ClearWrapped()
		}
		return upd.Exec(ctx)
	})
}

// PutSentinel implements [registry.Store].
func (s *Store) PutSentinel(ctx context.Context, sn registry.Sentinel) error {
	if sn.Envelope == "" {
		return fmt.Errorf("%w: a sentinel needs an envelope", registry.ErrInvalid)
	}
	return s.tx(ctx, func(tx *ent.Tx) error {
		if err := s.requireKEK(ctx, tx, sn.KEKID); err != nil {
			return err
		}
		ok, err := tx.KEKVersion.Query().Where(kekversion.KekID(sn.KEKID), kekversion.Version(sn.Version)).Exist(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return versionNotFound(sn.KEKID, sn.Version)
		}
		have, err := tx.Sentinel.Query().Where(sentinel.KekID(sn.KEKID), sentinel.Version(sn.Version)).Only(ctx)
		switch {
		case err == nil:
			if have.Envelope == sn.Envelope {
				return nil
			}
			return fmt.Errorf("%w: version %d already has a different sentinel", registry.ErrConflict, sn.Version)
		case !ent.IsNotFound(err):
			return err
		}
		return tx.Sentinel.Create().
			SetKekID(sn.KEKID).SetVersion(sn.Version).SetEnvelope(sn.Envelope).SetCreatedAt(sn.CreatedAt).
			Exec(ctx)
	})
}

// GetSentinel implements [registry.Store].
func (s *Store) GetSentinel(ctx context.Context, kekID envelope.ID, version uint32) (registry.Sentinel, error) {
	var out registry.Sentinel
	err := s.read(ctx, func(tx *ent.Tx) error {
		if err := s.requireKEK(ctx, tx, kekID); err != nil {
			return err
		}
		e, err := tx.Sentinel.Query().Where(sentinel.KekID(kekID), sentinel.Version(version)).Only(ctx)
		if ent.IsNotFound(err) {
			return fmt.Errorf("%w: %s version %d", registry.ErrSentinelNotFound, kekID, version)
		}
		if err != nil {
			return err
		}
		out = registry.Sentinel{KEKID: e.KekID, Version: e.Version, Envelope: e.Envelope, CreatedAt: utc(e.CreatedAt)}
		return nil
	})
	return out, err
}

// ListSentinels implements [registry.Store].
func (s *Store) ListSentinels(ctx context.Context, kekID envelope.ID) ([]registry.Sentinel, error) {
	var out []registry.Sentinel
	err := s.read(ctx, func(tx *ent.Tx) error {
		if err := s.requireKEK(ctx, tx, kekID); err != nil {
			return err
		}
		es, err := tx.Sentinel.Query().Where(sentinel.KekID(kekID)).Order(sentinel.ByVersion()).All(ctx)
		if err != nil {
			return err
		}
		out = make([]registry.Sentinel, len(es))
		for i, e := range es {
			out[i] = registry.Sentinel{KEKID: e.KekID, Version: e.Version, Envelope: e.Envelope, CreatedAt: utc(e.CreatedAt)}
		}
		return nil
	})
	return out, err
}

func shredNotFound(purpose keyforge.Purpose, subject string) error {
	return fmt.Errorf("%w: %q for %q", registry.ErrShredNotFound, string(purpose), subject)
}

// ShredSubject implements [registry.Store].
func (s *Store) ShredSubject(ctx context.Context, purpose keyforge.Purpose, subject string, at time.Time) (registry.ShredRecord, error) {
	if subject == "" {
		return registry.ShredRecord{}, fmt.Errorf("%w: a shred needs a subject", registry.ErrInvalid)
	}
	if at.IsZero() {
		return registry.ShredRecord{}, fmt.Errorf("%w: a shred needs a time", registry.ErrInvalid)
	}
	var out registry.ShredRecord
	err := s.tx(ctx, func(tx *ent.Tx) error {
		have, err := tx.Shred.Query().Where(shred.Purpose(string(purpose)), shred.Subject(subject)).Only(ctx)
		switch {
		case err == nil:
			out = toShred(have)
			return nil
		case !ent.IsNotFound(err):
			return err
		}

		deks, err := tx.DataKey.Query().Where(datakey.Purpose(string(purpose)), datakey.Subject(subject)).All(ctx)
		if err != nil {
			return err
		}
		seen := map[keyforge.KEKVersionRef]bool{}
		versions := []keyforge.KEKVersionRef{}
		for _, d := range deks {
			for _, w := range d.WrappedUnder {
				if !seen[w] {
					seen[w] = true
					versions = append(versions, w)
				}
			}
		}
		slices.SortFunc(versions, func(a, b keyforge.KEKVersionRef) int {
			if c := bytes.Compare(a.KEKID[:], b.KEKID[:]); c != 0 {
				return c
			}
			return cmpUint32(a.Version, b.Version)
		})
		if len(deks) > 0 {
			if err := tx.DataKey.Update().
				Where(datakey.Purpose(string(purpose)), datakey.Subject(subject)).
				SetState(uint8(keyforge.DEKDestroyed)).ClearWrapped().SetIsCurrent(false).
				Exec(ctx); err != nil {
				return err
			}
		}
		c := tx.Shred.Create().
			SetPurpose(string(purpose)).SetSubject(subject).SetRequestedAt(at).
			SetVersions(versions).SetDeks(len(deks))
		if len(versions) == 0 {
			c.SetCompletedAt(at)
		}
		e, err := c.Save(ctx)
		if err != nil {
			return err
		}
		out = toShred(e)
		return nil
	})
	return out, err
}

func cmpUint32(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// GetShred implements [registry.Store].
func (s *Store) GetShred(ctx context.Context, purpose keyforge.Purpose, subject string) (registry.ShredRecord, error) {
	e, err := s.client.Shred.Query().Where(shred.Purpose(string(purpose)), shred.Subject(subject)).Only(ctx)
	if ent.IsNotFound(err) {
		return registry.ShredRecord{}, shredNotFound(purpose, subject)
	}
	if err != nil {
		return registry.ShredRecord{}, err
	}
	return toShred(e), nil
}

// ListShreds implements [registry.Store].
func (s *Store) ListShreds(ctx context.Context) ([]registry.ShredRecord, error) {
	es, err := s.client.Shred.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]registry.ShredRecord, len(es))
	for i, e := range es {
		out[i] = toShred(e)
	}
	// Ordered here, bytewise, so the order does not depend on the database's
	// collation.
	slices.SortFunc(out, func(a, b registry.ShredRecord) int {
		if c := strings.Compare(string(a.Purpose), string(b.Purpose)); c != 0 {
			return c
		}
		return strings.Compare(a.Subject, b.Subject)
	})
	return out, nil
}

// CompleteShred implements [registry.Store].
func (s *Store) CompleteShred(ctx context.Context, purpose keyforge.Purpose, subject string, at time.Time) (registry.ShredRecord, error) {
	var out registry.ShredRecord
	err := s.tx(ctx, func(tx *ent.Tx) error {
		e, err := tx.Shred.Query().Where(shred.Purpose(string(purpose)), shred.Subject(subject)).Only(ctx)
		if ent.IsNotFound(err) {
			return shredNotFound(purpose, subject)
		}
		if err != nil {
			return err
		}
		if e.CompletedAt != nil {
			out = toShred(e)
			return nil
		}
		pending := 0
		for _, ref := range e.Versions {
			v, err := tx.KEKVersion.Query().Where(kekversion.KekID(ref.KEKID), kekversion.Version(ref.Version)).Only(ctx)
			switch {
			case ent.IsNotFound(err):
				pending++
			case err != nil:
				return err
			case registry.VersionState(v.State) != registry.VersionDestroyed:
				pending++
			}
		}
		if pending > 0 {
			return fmt.Errorf("%w: %d of %d versions", registry.ErrShredPending, pending, len(e.Versions))
		}
		e, err = tx.Shred.UpdateOne(e).SetCompletedAt(at).Save(ctx)
		if err != nil {
			return err
		}
		out = toShred(e)
		return nil
	})
	return out, err
}
