// Package memory provides an in-memory [registry.Store] for tests, examples
// and single-process use.
//
// Nothing persists. It holds the whole registry under one mutex, so every
// operation is atomic by construction, which makes it the reference the SQL
// store is compared against by the shared conformance suite.
package memory

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/registry"
)

var _ registry.Store = (*Store)(nil)

// defect selects a deliberate fault, so the conformance suite can be shown to
// catch it. It is set only by this package's tests and is zero otherwise.
type defect int

const (
	noDefect defect = iota
	defectNoDemote
	defectAnyRollback
	defectIgnoreReferences
	defectIgnoreDelay
)

// Store is an in-memory registry. It is safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	keks     map[envelope.ID]registry.KEK
	versions map[envelope.ID]map[uint32]registry.VersionRecord
	deks     map[envelope.ID]keyforge.DEKRecord
	current  map[scope]envelope.ID
	sentinel map[envelope.ID]map[uint32]registry.Sentinel
	defect   defect
}

type scope struct {
	purpose keyforge.Purpose
	subject string
}

// NewStore returns an empty registry.
func NewStore() *Store {
	return &Store{
		keks:     map[envelope.ID]registry.KEK{},
		versions: map[envelope.ID]map[uint32]registry.VersionRecord{},
		deks:     map[envelope.ID]keyforge.DEKRecord{},
		current:  map[scope]envelope.ID{},
		sentinel: map[envelope.ID]map[uint32]registry.Sentinel{},
	}
}

func clone(r keyforge.DEKRecord) keyforge.DEKRecord {
	r.Wrapped = slices.Clone(r.Wrapped)
	return r
}

func kekNotFound(id envelope.ID) error {
	return fmt.Errorf("%w: %s", keyforge.ErrKEKNotFound, id)
}

// Bootstrap registers a KEK for a purpose with its first version active, which
// is the usual starting point for a test or an example.
func (s *Store) Bootstrap(ctx context.Context, purpose keyforge.Purpose, ref provider.KeyRef, version uint32, at time.Time) error {
	k := registry.KEK{
		ID: ref.ID, Purpose: purpose, Provider: ref.Provider, ProviderRef: ref.ProviderRef,
		State: registry.KeyActive, CreatedAt: at,
	}
	if err := s.CreateKEK(ctx, k); err != nil {
		return err
	}
	v := registry.VersionRecord{KEKID: ref.ID, Version: version, State: registry.VersionPending, CreatedAt: at}
	if err := s.AddVersion(ctx, v); err != nil {
		return err
	}
	return s.TransitionVersion(ctx, ref.ID, version, registry.VersionActive, registry.TransitionOptions{At: at})
}

// CreateKEK implements [registry.Store].
func (s *Store) CreateKEK(ctx context.Context, k registry.KEK) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := k.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keks[k.ID]; ok {
		return fmt.Errorf("%w: %s", registry.ErrKEKExists, k.ID)
	}
	if k.State == registry.KeyActive {
		for _, other := range s.keks {
			if other.State == registry.KeyActive && other.Purpose == k.Purpose {
				return fmt.Errorf("%w: %q is served by %s", registry.ErrPurposeBound, string(k.Purpose), other.ID)
			}
		}
	}
	s.keks[k.ID] = k
	s.versions[k.ID] = map[uint32]registry.VersionRecord{}
	return nil
}

// GetKEK implements [registry.Store].
func (s *Store) GetKEK(ctx context.Context, id envelope.ID) (registry.KEK, error) {
	if err := ctx.Err(); err != nil {
		return registry.KEK{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keks[id]
	if !ok {
		return registry.KEK{}, kekNotFound(id)
	}
	return k, nil
}

// KEKForPurpose implements [registry.Store].
func (s *Store) KEKForPurpose(ctx context.Context, purpose keyforge.Purpose) (registry.KEK, error) {
	if err := ctx.Err(); err != nil {
		return registry.KEK{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kekForPurposeLocked(purpose)
}

func (s *Store) kekForPurposeLocked(purpose keyforge.Purpose) (registry.KEK, error) {
	for _, k := range s.keks {
		if k.State == registry.KeyActive && k.Purpose == purpose {
			return k, nil
		}
	}
	return registry.KEK{}, fmt.Errorf("%w: no active KEK for %q", keyforge.ErrKEKNotFound, string(purpose))
}

// ListKEKs implements [registry.Store].
func (s *Store) ListKEKs(ctx context.Context) ([]registry.KEK, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]registry.KEK, 0, len(s.keks))
	for _, k := range s.keks {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b registry.KEK) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return out, nil
}

// ActiveKEK implements [keyforge.Store].
func (s *Store) ActiveKEK(ctx context.Context, purpose keyforge.Purpose) (keyforge.KEKVersion, error) {
	if err := ctx.Err(); err != nil {
		return keyforge.KEKVersion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, err := s.kekForPurposeLocked(purpose)
	if err != nil {
		return keyforge.KEKVersion{}, fmt.Errorf("%w: %q", keyforge.ErrNoActiveKEK, string(purpose))
	}
	for _, v := range s.versions[k.ID] {
		if v.State == registry.VersionActive {
			return keyforge.KEKVersion{Ref: k.Ref(), Version: v.Version}, nil
		}
	}
	return keyforge.KEKVersion{}, fmt.Errorf("%w: %q has no active version", keyforge.ErrNoActiveKEK, string(purpose))
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
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vs, ok := s.versions[id]
	if !ok {
		return false, kekNotFound(id)
	}
	v, ok := vs[version]
	return ok && v.State.CanUnwrap(), nil
}

// AddVersion implements [registry.Store].
func (s *Store) AddVersion(ctx context.Context, v registry.VersionRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.Version == 0 {
		return fmt.Errorf("%w: versions start at 1", registry.ErrInvalid)
	}
	if v.State != registry.VersionPending {
		return fmt.Errorf("%w: a new version is pending, not %s", registry.ErrInvalid, v.State)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vs, ok := s.versions[v.KEKID]
	if !ok {
		return kekNotFound(v.KEKID)
	}
	var latest uint32
	for n := range vs {
		latest = max(latest, n)
	}
	if v.Version <= latest {
		return fmt.Errorf("%w: version %d, latest is %d", registry.ErrVersionExists, v.Version, latest)
	}
	vs[v.Version] = v
	return nil
}

// GetVersion implements [registry.Store].
func (s *Store) GetVersion(ctx context.Context, kekID envelope.ID, version uint32) (registry.VersionRecord, error) {
	if err := ctx.Err(); err != nil {
		return registry.VersionRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vs, ok := s.versions[kekID]
	if !ok {
		return registry.VersionRecord{}, kekNotFound(kekID)
	}
	v, ok := vs[version]
	if !ok {
		return registry.VersionRecord{}, fmt.Errorf("%w: %s version %d", registry.ErrVersionNotFound, kekID, version)
	}
	return v, nil
}

// ListVersions implements [registry.Store].
func (s *Store) ListVersions(ctx context.Context, kekID envelope.ID) ([]registry.VersionRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	vs, ok := s.versions[kekID]
	if !ok {
		return nil, kekNotFound(kekID)
	}
	out := make([]registry.VersionRecord, 0, len(vs))
	for _, v := range vs {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b registry.VersionRecord) int { return int(a.Version) - int(b.Version) }) //nolint:gosec // G115: orders a listing; version numbers are far from the int range
	return out, nil
}

// countLocked counts data keys wrapped under a version, excluding destroyed.
func (s *Store) countLocked(kekID envelope.ID, version uint32) int {
	n := 0
	for _, d := range s.deks {
		if d.KEKID == kekID && d.KEKVersion == version && d.State != keyforge.DEKDestroyed {
			n++
		}
	}
	return n
}

// TransitionVersion implements [registry.Store].
func (s *Store) TransitionVersion(ctx context.Context, kekID envelope.ID, version uint32, to registry.VersionState, opts registry.TransitionOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.At.IsZero() {
		return fmt.Errorf("%w: a transition needs a time", registry.ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	vs, ok := s.versions[kekID]
	if !ok {
		return kekNotFound(kekID)
	}
	cur, ok := vs[version]
	if !ok {
		return fmt.Errorf("%w: %s version %d", registry.ErrVersionNotFound, kekID, version)
	}
	from := cur.State
	if err := registry.CheckTransition(from, to); err != nil {
		return err
	}

	switch {
	case from == registry.VersionActive && to == registry.VersionDecryptOnly:
		// A version stops being active by another being activated, so that
		// there is never a moment with none.
		return &registry.TransitionError{From: from, To: to}

	case to == registry.VersionActive:
		cur.ActivatedAt = opts.At
		if from == registry.VersionDecryptOnly && s.defect != defectAnyRollback {
			var latest uint32
			for n, v := range vs {
				if v.State == registry.VersionDecryptOnly {
					latest = max(latest, n)
				}
			}
			if version != latest {
				return fmt.Errorf("%w: version %d, the most recent is %d", registry.ErrNoRollbackTarget, version, latest)
			}
		}
		if s.defect != defectNoDemote {
			for n, v := range vs {
				if v.State == registry.VersionActive && n != version {
					v.State = registry.VersionDecryptOnly
					v.RotatedAt = opts.At
					vs[n] = v
				}
			}
		}

	case to == registry.VersionRetireRequested:
		if opts.RetireAfter.IsZero() || !opts.RetireAfter.After(opts.At) {
			return fmt.Errorf("%w: retirement needs a retire-after later than now", registry.ErrInvalid)
		}
		cur.RetireAfter = opts.RetireAfter

	case from == registry.VersionRetireRequested && to == registry.VersionDecryptOnly:
		cur.RetireAfter = time.Time{}

	case to == registry.VersionRetired:
		if from == registry.VersionRetireRequested && opts.At.Before(cur.RetireAfter) && s.defect != defectIgnoreDelay {
			return fmt.Errorf("%w: until %s", registry.ErrRetireDelay, cur.RetireAfter.Format(time.RFC3339))
		}
		if s.defect != defectIgnoreReferences {
			if n := s.countLocked(kekID, version); n > 0 {
				return fmt.Errorf("%w: %d data keys", registry.ErrVersionReferenced, n)
			}
		}

	case to == registry.VersionDestroyed:
		if n := s.countLocked(kekID, version); n > 0 && s.defect != defectIgnoreReferences {
			return fmt.Errorf("%w: %d data keys", registry.ErrVersionReferenced, n)
		}
	}

	cur.State = to
	vs[version] = cur
	return nil
}

// CurrentDEK implements [keyforge.Store].
func (s *Store) CurrentDEK(ctx context.Context, purpose keyforge.Purpose, subject string) (keyforge.DEKRecord, error) {
	if err := ctx.Err(); err != nil {
		return keyforge.DEKRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.current[scope{purpose, subject}]
	if !ok {
		return keyforge.DEKRecord{}, fmt.Errorf("%w: %q", keyforge.ErrDEKNotFound, string(purpose))
	}
	return clone(s.deks[id]), nil
}

// GetDEK implements [keyforge.Store].
func (s *Store) GetDEK(ctx context.Context, id envelope.ID) (keyforge.DEKRecord, error) {
	if err := ctx.Err(); err != nil {
		return keyforge.DEKRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.deks[id]
	if !ok {
		return keyforge.DEKRecord{}, fmt.Errorf("%w: %s", keyforge.ErrDEKNotFound, id)
	}
	return clone(rec), nil
}

// usableVersionLocked checks that a data key can be wrapped under a KEK
// version belonging to its purpose.
func (s *Store) usableVersionLocked(kekID envelope.ID, version uint32, purpose keyforge.Purpose) error {
	k, ok := s.keks[kekID]
	if !ok {
		return kekNotFound(kekID)
	}
	if k.Purpose != purpose {
		return fmt.Errorf("%w: KEK %s serves %q, not %q", registry.ErrInvalid, kekID, string(k.Purpose), string(purpose))
	}
	v, ok := s.versions[kekID][version]
	if !ok {
		return fmt.Errorf("%w: %s version %d", registry.ErrVersionNotFound, kekID, version)
	}
	if v.State != registry.VersionActive && v.State != registry.VersionDecryptOnly {
		return fmt.Errorf("%w: version %d is %s", registry.ErrVersionUnusable, version, v.State)
	}
	return nil
}

// AdvanceDEK implements [keyforge.Store].
func (s *Store) AdvanceDEK(ctx context.Context, purpose keyforge.Purpose, subject string, from uint32, next keyforge.DEKRecord) (keyforge.DEKRecord, error) {
	if err := ctx.Err(); err != nil {
		return keyforge.DEKRecord{}, err
	}
	switch {
	case next.ID.IsZero(), len(next.Wrapped) == 0, !next.Algorithm.Valid():
		return keyforge.DEKRecord{}, fmt.Errorf("%w: data key record is incomplete", registry.ErrInvalid)
	case next.Purpose != purpose, next.Subject != subject, next.Epoch != from+1:
		return keyforge.DEKRecord{}, fmt.Errorf("%w: record is not epoch %d of %q", registry.ErrInvalid, from+1, string(purpose))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableVersionLocked(next.KEKID, next.KEKVersion, purpose); err != nil {
		return keyforge.DEKRecord{}, err
	}

	key := scope{purpose, subject}
	if curID, ok := s.current[key]; ok {
		cur := s.deks[curID]
		if cur.Epoch != from {
			return clone(cur), nil
		}
		if cur.State == keyforge.DEKActive {
			cur.State = keyforge.DEKDecryptOnly
			s.deks[curID] = cur
		}
	} else if from != 0 {
		return keyforge.DEKRecord{}, fmt.Errorf("%w: no current data key at epoch %d for %q", registry.ErrConflict, from, string(purpose))
	}
	if _, dup := s.deks[next.ID]; dup {
		return keyforge.DEKRecord{}, fmt.Errorf("%w: data key %s exists", registry.ErrInvalid, next.ID)
	}
	next.State = keyforge.DEKActive
	next.Reserved = 0
	s.deks[next.ID] = clone(next)
	s.current[key] = next.ID
	return clone(next), nil
}

// ReserveEncryptions implements [keyforge.Store].
func (s *Store) ReserveEncryptions(ctx context.Context, id envelope.ID, n, limit uint64) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.deks[id]
	if !ok {
		return 0, fmt.Errorf("%w: %s", keyforge.ErrDEKNotFound, id)
	}
	if rec.State != keyforge.DEKActive || rec.Reserved >= limit || s.current[scope{rec.Purpose, rec.Subject}] != id {
		return 0, nil
	}
	granted := min(n, limit-rec.Reserved)
	rec.Reserved += granted
	s.deks[id] = rec
	return granted, nil
}

// ListDEKs implements [registry.Store].
func (s *Store) ListDEKs(ctx context.Context, f registry.DEKFilter) ([]keyforge.DEKRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []keyforge.DEKRecord
	for _, d := range s.deks {
		switch {
		case !f.KEKID.IsZero() && d.KEKID != f.KEKID,
			f.KEKVersion != 0 && d.KEKVersion != f.KEKVersion,
			f.Purpose != "" && d.Purpose != f.Purpose,
			bytes.Compare(d.ID[:], f.After[:]) <= 0:
			continue
		}
		out = append(out, clone(d))
	}
	slices.SortFunc(out, func(a, b keyforge.DEKRecord) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	if n := f.PageSize(); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

// CountDEKs implements [registry.Store].
func (s *Store) CountDEKs(ctx context.Context, kekID envelope.ID, version uint32) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keks[kekID]; !ok {
		return 0, kekNotFound(kekID)
	}
	return s.countLocked(kekID, version), nil
}

// RewrapDEK implements [registry.Store].
func (s *Store) RewrapDEK(ctx context.Context, r registry.Rewrap) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(r.Wrapped) == 0 {
		return fmt.Errorf("%w: rewrap has no wrapped key", registry.ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.deks[r.ID]
	if !ok {
		return fmt.Errorf("%w: %s", keyforge.ErrDEKNotFound, r.ID)
	}
	if rec.State == keyforge.DEKDestroyed {
		return fmt.Errorf("%w: data key %s is destroyed", keyforge.ErrKeyUnusable, r.ID)
	}
	v, ok := s.versions[r.ToKEKID][r.ToVersion]
	if !ok {
		if _, known := s.keks[r.ToKEKID]; !known {
			return kekNotFound(r.ToKEKID)
		}
		return fmt.Errorf("%w: %s version %d", registry.ErrVersionNotFound, r.ToKEKID, r.ToVersion)
	}
	if v.State != registry.VersionActive {
		return fmt.Errorf("%w: version %d is %s", registry.ErrVersionUnusable, r.ToVersion, v.State)
	}

	if rec.KEKID == r.ToKEKID && rec.KEKVersion == r.ToVersion {
		if bytes.Equal(rec.Wrapped, r.Wrapped) {
			return nil // already done: a resumed job repeats it
		}
		return fmt.Errorf("%w: data key %s is already wrapped under that version differently", registry.ErrConflict, r.ID)
	}
	if rec.KEKID != r.FromKEKID || rec.KEKVersion != r.FromVersion {
		return fmt.Errorf("%w: data key %s is wrapped under version %d, not %d", registry.ErrConflict, r.ID, rec.KEKVersion, r.FromVersion)
	}
	rec.KEKID, rec.KEKVersion, rec.Wrapped = r.ToKEKID, r.ToVersion, slices.Clone(r.Wrapped)
	s.deks[r.ID] = rec
	return nil
}

// MarkDEK implements [registry.Store].
func (s *Store) MarkDEK(ctx context.Context, id envelope.ID, to keyforge.DEKState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.deks[id]
	if !ok {
		return fmt.Errorf("%w: %s", keyforge.ErrDEKNotFound, id)
	}
	// Demotion is done by advancing the epoch, never directly.
	if to == keyforge.DEKDecryptOnly || to == keyforge.DEKActive {
		return &registry.DEKTransitionError{From: rec.State, To: to}
	}
	if err := registry.CheckDEKTransition(rec.State, to); err != nil {
		return err
	}
	rec.State = to
	s.deks[id] = rec
	return nil
}

// PutSentinel implements [registry.Store].
func (s *Store) PutSentinel(ctx context.Context, sn registry.Sentinel) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sn.Envelope == "" {
		return fmt.Errorf("%w: a sentinel needs an envelope", registry.ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[sn.KEKID]; !ok {
		return kekNotFound(sn.KEKID)
	}
	if _, ok := s.versions[sn.KEKID][sn.Version]; !ok {
		return fmt.Errorf("%w: %s version %d", registry.ErrVersionNotFound, sn.KEKID, sn.Version)
	}
	if have, ok := s.sentinel[sn.KEKID][sn.Version]; ok {
		if have.Envelope == sn.Envelope {
			return nil
		}
		return fmt.Errorf("%w: version %d already has a different sentinel", registry.ErrConflict, sn.Version)
	}
	if s.sentinel[sn.KEKID] == nil {
		s.sentinel[sn.KEKID] = map[uint32]registry.Sentinel{}
	}
	s.sentinel[sn.KEKID][sn.Version] = sn
	return nil
}

// GetSentinel implements [registry.Store].
func (s *Store) GetSentinel(ctx context.Context, kekID envelope.ID, version uint32) (registry.Sentinel, error) {
	if err := ctx.Err(); err != nil {
		return registry.Sentinel{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[kekID]; !ok {
		return registry.Sentinel{}, kekNotFound(kekID)
	}
	sn, ok := s.sentinel[kekID][version]
	if !ok {
		return registry.Sentinel{}, fmt.Errorf("%w: %s version %d", registry.ErrSentinelNotFound, kekID, version)
	}
	return sn, nil
}

// ListSentinels implements [registry.Store].
func (s *Store) ListSentinels(ctx context.Context, kekID envelope.ID) ([]registry.Sentinel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[kekID]; !ok {
		return nil, kekNotFound(kekID)
	}
	out := make([]registry.Sentinel, 0, len(s.sentinel[kekID]))
	for _, sn := range s.sentinel[kekID] {
		out = append(out, sn)
	}
	slices.SortFunc(out, func(a, b registry.Sentinel) int { return int(a.Version) - int(b.Version) }) //nolint:gosec // G115: orders a listing
	return out, nil
}
