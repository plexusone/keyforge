// Package memory provides an in-memory registry for tests and examples.
//
// It implements [keyforge.Store], which is everything the client needs, plus
// the administrative calls a control plane makes: registering a KEK and
// choosing its active version. Nothing persists. The full registry, with the
// key state machine and its conformance suite, builds on this contract.
package memory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
)

var _ keyforge.Store = (*Store)(nil)

// Store is an in-memory registry. It is safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	keks    map[envelope.ID]provider.KeyRef
	active  map[keyforge.Purpose]keyforge.KEKVersion
	deks    map[envelope.ID]keyforge.DEKRecord
	current map[scope]envelope.ID
}

type scope struct {
	purpose keyforge.Purpose
	subject string
}

// NewStore returns an empty registry.
func NewStore() *Store {
	return &Store{
		keks:    map[envelope.ID]provider.KeyRef{},
		active:  map[keyforge.Purpose]keyforge.KEKVersion{},
		deks:    map[envelope.ID]keyforge.DEKRecord{},
		current: map[scope]envelope.ID{},
	}
}

// PutKEK registers a KEK so data keys can be wrapped under it and its
// identifier resolved to a provider reference.
func (s *Store) PutKEK(ref provider.KeyRef) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keks[ref.ID] = ref
	return nil
}

// SetActiveKEK makes kv the version new data keys for purpose are wrapped
// under. The KEK must have been registered.
func (s *Store) SetActiveKEK(purpose keyforge.Purpose, kv keyforge.KEKVersion) error {
	if err := purpose.Validate(); err != nil {
		return err
	}
	if kv.Version == 0 {
		return errors.New("registry: KEK versions start at 1")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keks[kv.Ref.ID]; !ok {
		return fmt.Errorf("%w: %s", keyforge.ErrKEKNotFound, kv.Ref.ID)
	}
	s.active[purpose] = kv
	return nil
}

// DEKs returns a copy of every data key record, ordered by purpose, subject and
// epoch, for inspection.
func (s *Store) DEKs() []keyforge.DEKRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]keyforge.DEKRecord, 0, len(s.deks))
	for _, r := range s.deks {
		out = append(out, clone(r))
	}
	slices.SortFunc(out, func(a, b keyforge.DEKRecord) int {
		switch {
		case a.Purpose != b.Purpose:
			return cmpString(string(a.Purpose), string(b.Purpose))
		case a.Subject != b.Subject:
			return cmpString(a.Subject, b.Subject)
		default:
			return int(a.Epoch) - int(b.Epoch) //nolint:gosec // G115: epochs are small; this orders a listing
		}
	})
	return out
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func clone(r keyforge.DEKRecord) keyforge.DEKRecord {
	r.Wrapped = slices.Clone(r.Wrapped)
	return r
}

// ActiveKEK implements [keyforge.Store].
func (s *Store) ActiveKEK(ctx context.Context, purpose keyforge.Purpose) (keyforge.KEKVersion, error) {
	if err := ctx.Err(); err != nil {
		return keyforge.KEKVersion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kv, ok := s.active[purpose]
	if !ok {
		return keyforge.KEKVersion{}, fmt.Errorf("%w: %q", keyforge.ErrNoActiveKEK, string(purpose))
	}
	return kv, nil
}

// KEK implements [keyforge.Store].
func (s *Store) KEK(ctx context.Context, id envelope.ID) (provider.KeyRef, error) {
	if err := ctx.Err(); err != nil {
		return provider.KeyRef{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.keks[id]
	if !ok {
		return provider.KeyRef{}, fmt.Errorf("%w: %s", keyforge.ErrKEKNotFound, id)
	}
	return ref, nil
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

// AdvanceDEK implements [keyforge.Store].
func (s *Store) AdvanceDEK(ctx context.Context, purpose keyforge.Purpose, subject string, from uint32, next keyforge.DEKRecord) (keyforge.DEKRecord, error) {
	if err := ctx.Err(); err != nil {
		return keyforge.DEKRecord{}, err
	}
	if next.ID.IsZero() || next.Purpose != purpose || next.Subject != subject || next.Epoch != from+1 {
		return keyforge.DEKRecord{}, fmt.Errorf("registry: record does not describe epoch %d of %q", from+1, string(purpose))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keks[next.KEKID]; !ok {
		return keyforge.DEKRecord{}, fmt.Errorf("%w: %s", keyforge.ErrKEKNotFound, next.KEKID)
	}
	key := scope{purpose, subject}
	if curID, ok := s.current[key]; ok {
		cur := s.deks[curID]
		if cur.Epoch != from {
			return clone(cur), nil
		}
		cur.State = keyforge.DEKDecryptOnly
		s.deks[curID] = cur
	} else if from != 0 {
		return keyforge.DEKRecord{}, fmt.Errorf("registry: no current data key at epoch %d for %q", from, string(purpose))
	}
	if _, dup := s.deks[next.ID]; dup {
		return keyforge.DEKRecord{}, fmt.Errorf("registry: data key %s already exists", next.ID)
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
	if rec.State != keyforge.DEKActive || rec.Reserved >= limit {
		return 0, nil
	}
	granted := min(n, limit-rec.Reserved)
	rec.Reserved += granted
	s.deks[id] = rec
	return granted, nil
}
