package keyforge_test

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
)

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// detEntropy is a deterministic entropy reader: the stream is SHA-256 of a seed
// and a counter, so a test can predict nothing yet reproduce everything.
type detEntropy struct {
	mu   sync.Mutex
	seed string
	n    uint64
	buf  []byte
}

func (e *detEntropy) Read(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for len(e.buf) < len(p) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], e.n)
		e.n++
		sum := sha256.Sum256(append([]byte(e.seed), c[:]...))
		e.buf = append(e.buf, sum[:]...)
	}
	n := copy(p, e.buf)
	e.buf = e.buf[n:]
	return n, nil
}

// memProvider is a minimal provider that counts calls and can be made to fail.
type memProvider struct {
	mu       sync.Mutex
	name     string
	keys     map[envelope.ID]map[uint32]cipher.AEAD
	latest   map[envelope.ID]uint32
	calls    map[string]int
	failWith error
}

func newMemProvider(name string) *memProvider {
	return &memProvider{name: name, keys: map[envelope.ID]map[uint32]cipher.AEAD{}, latest: map[envelope.ID]uint32{}, calls: map[string]int{}}
}

func (p *memProvider) Name() string { return p.name }

func (p *memProvider) count(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[name]
}

func (p *memProvider) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failWith = err
}

func (p *memProvider) enter(ctx context.Context, op string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[op]++
	if p.failWith != nil {
		return p.failWith
	}
	return ctx.Err()
}

func (p *memProvider) newAEAD() (cipher.AEAD, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return algorithm.New(algorithm.AES256GCM, k)
}

func (p *memProvider) CreateKey(ctx context.Context, spec provider.KeySpec) (provider.KeyRef, error) {
	if err := p.enter(ctx, "CreateKey"); err != nil {
		return provider.KeyRef{}, err
	}
	var id envelope.ID
	if _, err := rand.Read(id[:]); err != nil {
		return provider.KeyRef{}, err
	}
	a, err := p.newAEAD()
	if err != nil {
		return provider.KeyRef{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[id] = map[uint32]cipher.AEAD{1: a}
	p.latest[id] = 1
	return provider.KeyRef{ID: id, Provider: p.name, ProviderRef: "mem/" + id.String()}, nil
}

func (p *memProvider) Rotate(ctx context.Context, ref provider.KeyRef) (uint32, error) {
	if err := p.enter(ctx, "Rotate"); err != nil {
		return 0, err
	}
	a, err := p.newAEAD()
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	vs, ok := p.keys[ref.ID]
	if !ok {
		return 0, provider.ErrKeyNotFound
	}
	p.latest[ref.ID]++
	vs[p.latest[ref.ID]] = a
	return p.latest[ref.ID], nil
}

func (p *memProvider) aead(ref provider.KeyRef, version uint32) (cipher.AEAD, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	vs, ok := p.keys[ref.ID]
	if !ok {
		return nil, provider.ErrKeyNotFound
	}
	a, ok := vs[version]
	if !ok || a == nil {
		return nil, provider.ErrVersionNotFound
	}
	return a, nil
}

func (p *memProvider) Wrap(ctx context.Context, ref provider.KeyRef, version uint32, dek, aad []byte) ([]byte, error) {
	if err := p.enter(ctx, "Wrap"); err != nil {
		return nil, err
	}
	a, err := p.aead(ref, version)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nil, dek, aad), nil //nolint:gosec // G407: a nil nonce is the API of the registry's random-nonce AEAD
}

func (p *memProvider) Unwrap(ctx context.Context, ref provider.KeyRef, version uint32, wrapped, aad []byte) ([]byte, error) {
	if err := p.enter(ctx, "Unwrap"); err != nil {
		return nil, err
	}
	a, err := p.aead(ref, version)
	if err != nil {
		return nil, err
	}
	dek, err := a.Open(nil, nil, wrapped, aad)
	if err != nil {
		return nil, provider.ErrUnwrapFailed
	}
	return dek, nil
}

func (p *memProvider) Destroy(ctx context.Context, ref provider.KeyRef, version uint32) error {
	if err := p.enter(ctx, "Destroy"); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if vs, ok := p.keys[ref.ID]; ok {
		vs[version] = nil
	}
	return nil
}

func (p *memProvider) Health(ctx context.Context) error { return p.enter(ctx, "Health") }

// memStore is a minimal registry that counts calls and can be made to fail.
type memStore struct {
	mu       sync.Mutex
	keks     map[envelope.ID]provider.KeyRef
	active   map[keyforge.Purpose]keyforge.KEKVersion
	deks     map[envelope.ID]keyforge.DEKRecord
	current  map[curKey]envelope.ID
	calls    map[string]int
	failWith error
}

type curKey struct {
	purpose keyforge.Purpose
	subject string
}

func newMemStore() *memStore {
	return &memStore{
		keks:    map[envelope.ID]provider.KeyRef{},
		active:  map[keyforge.Purpose]keyforge.KEKVersion{},
		deks:    map[envelope.ID]keyforge.DEKRecord{},
		current: map[curKey]envelope.ID{},
		calls:   map[string]int{},
	}
}

func (s *memStore) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[name]
}

func (s *memStore) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWith = err
}

func (s *memStore) enter(op string) error {
	s.calls[op]++
	return s.failWith
}

func (s *memStore) ActiveKEK(_ context.Context, p keyforge.Purpose) (keyforge.KEKVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("ActiveKEK"); err != nil {
		return keyforge.KEKVersion{}, err
	}
	kv, ok := s.active[p]
	if !ok {
		return keyforge.KEKVersion{}, keyforge.ErrNoActiveKEK
	}
	return kv, nil
}

func (s *memStore) KEK(_ context.Context, id envelope.ID) (provider.KeyRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("KEK"); err != nil {
		return provider.KeyRef{}, err
	}
	ref, ok := s.keks[id]
	if !ok {
		return provider.KeyRef{}, keyforge.ErrKEKNotFound
	}
	return ref, nil
}

func (s *memStore) CurrentDEK(_ context.Context, p keyforge.Purpose, subject string) (keyforge.DEKRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("CurrentDEK"); err != nil {
		return keyforge.DEKRecord{}, err
	}
	id, ok := s.current[curKey{p, subject}]
	if !ok {
		return keyforge.DEKRecord{}, keyforge.ErrDEKNotFound
	}
	return s.deks[id], nil
}

func (s *memStore) GetDEK(_ context.Context, id envelope.ID) (keyforge.DEKRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("GetDEK"); err != nil {
		return keyforge.DEKRecord{}, err
	}
	rec, ok := s.deks[id]
	if !ok {
		return keyforge.DEKRecord{}, keyforge.ErrDEKNotFound
	}
	return rec, nil
}

func (s *memStore) AdvanceDEK(_ context.Context, p keyforge.Purpose, subject string, from uint32, next keyforge.DEKRecord) (keyforge.DEKRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("AdvanceDEK"); err != nil {
		return keyforge.DEKRecord{}, err
	}
	key := curKey{p, subject}
	var epoch uint32
	if id, ok := s.current[key]; ok {
		epoch = s.deks[id].Epoch
		if epoch != from {
			return s.deks[id], nil
		}
		prev := s.deks[id]
		prev.State = keyforge.DEKDecryptOnly
		s.deks[id] = prev
	} else if from != 0 {
		return keyforge.DEKRecord{}, fmt.Errorf("no current key at epoch %d", from)
	}
	s.deks[next.ID] = next
	s.current[key] = next.ID
	return next, nil
}

func (s *memStore) ReserveEncryptions(_ context.Context, id envelope.ID, n, limit uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("ReserveEncryptions"); err != nil {
		return 0, err
	}
	rec, ok := s.deks[id]
	if !ok {
		return 0, keyforge.ErrDEKNotFound
	}
	if rec.State != keyforge.DEKActive || rec.Reserved >= limit {
		return 0, nil
	}
	granted := min(n, limit-rec.Reserved)
	rec.Reserved += granted
	s.deks[id] = rec
	return granted, nil
}

// env wires a client to fakes.
type env struct {
	t     *testing.T
	store *memStore
	prov  *memProvider
	clock *fakeClock
	kek   provider.KeyRef
	opts  keyforge.Options
}

const testPurpose keyforge.Purpose = "session-secrets"

func newEnv(t *testing.T, mutate ...func(*env)) *env {
	t.Helper()
	e := &env{t: t, store: newMemStore(), prov: newMemProvider("mem"), clock: newFakeClock()}
	kek, err := e.prov.CreateKey(context.Background(), provider.KeySpec{Purpose: string(testPurpose), Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	e.kek = kek
	e.store.keks[kek.ID] = kek
	e.store.active[testPurpose] = keyforge.KEKVersion{Ref: kek, Version: 1}
	e.opts = keyforge.Options{
		Store:     e.store,
		Providers: []provider.Provider{e.prov},
		Purposes:  map[keyforge.Purpose]keyforge.PurposeConfig{testPurpose: {}},
		Clock:     e.clock,
		Entropy:   &detEntropy{seed: t.Name()},
	}
	for _, m := range mutate {
		m(e)
	}
	return e
}

func (e *env) client() *keyforge.Client {
	e.t.Helper()
	c, err := keyforge.New(e.opts)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

var bg = context.Background()

func is(err error, target error) bool { return errors.Is(err, target) }
