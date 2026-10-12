package keyforge_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/provider"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	registrymemory "github.com/plexusone/keyforge/registry/memory"
)

var bgctx = context.Background()

const stateCachePurpose keyforge.Purpose = "orders"

type stateWorld struct {
	store *registrymemory.Store
	prov  provider.Provider
	clock *fakeClock
}

func newStateWorld(t *testing.T, prov provider.Provider) *stateWorld {
	t.Helper()
	if prov == nil {
		prov = providermemory.NewKeyring()
	}
	w := &stateWorld{store: registrymemory.NewStore(), prov: prov, clock: newFakeClock()}
	for _, p := range []keyforge.Purpose{stateCachePurpose} {
		kek, err := prov.CreateKey(bgctx, provider.KeySpec{Purpose: string(p), Algorithm: algorithm.AES256GCM})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.store.Bootstrap(bgctx, p, kek, 1, w.clock.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func (w *stateWorld) client(t *testing.T, perSubject bool) *keyforge.Client {
	t.Helper()
	c, err := keyforge.New(keyforge.Options{
		Store: w.store, Providers: []provider.Provider{w.prov}, Clock: w.clock,
		Purposes: map[keyforge.Purpose]keyforge.PurposeConfig{stateCachePurpose: {PerSubject: perSubject}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A current data key that was marked compromised and then destroyed must not
// wedge writes: the next write moves to a new epoch.
func TestDestroyedCurrentKeyMovesWritesToANewEpoch(t *testing.T) {
	w := newStateWorld(t, nil)
	c := w.client(t, false)
	first, err := c.Encrypt(bgctx, stateCachePurpose, []byte("a"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range []keyforge.DEKState{keyforge.DEKCompromised, keyforge.DEKDestroyed} {
		if err := w.store.MarkDEK(bgctx, first.DEKID, st); err != nil {
			t.Fatal(err)
		}
	}
	c.Purge() // as the documentation advises after destroying a key

	second, err := c.Encrypt(bgctx, stateCachePurpose, []byte("b"), nil)
	if err != nil {
		t.Fatalf("a write after the current key was destroyed: %v", err)
	}
	if second.DEKID == first.DEKID {
		t.Fatal("the write used the destroyed key")
	}
	if _, _, err := c.Decrypt(bgctx, stateCachePurpose, first, nil); !errors.Is(err, keyforge.ErrKeyUnusable) {
		t.Fatalf("reading under a destroyed key = %v, want ErrKeyUnusable", err)
	}
}

// A current key that is marked compromised is replaced on the next write once
// the cached view expires, and data under it is reported stale.
func TestCompromisedCurrentKeyIsReplacedAndReportedStale(t *testing.T) {
	w := newStateWorld(t, nil)
	c := w.client(t, false)
	first, err := c.Encrypt(bgctx, stateCachePurpose, []byte("a"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.store.MarkDEK(bgctx, first.DEKID, keyforge.DEKCompromised); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(keyforge.DefaultCacheTTL + time.Minute)

	_, info, err := c.Decrypt(bgctx, stateCachePurpose, first, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Stale {
		t.Error("data under a compromised current key was not reported stale")
	}
	second, err := c.Encrypt(bgctx, stateCachePurpose, []byte("b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.DEKID == first.DEKID {
		t.Fatal("a write still used the compromised key")
	}
}

// gate blocks Unwrap until released and counts the calls.
type gate struct {
	provider.Provider
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	armed   atomic.Bool
}

func (g *gate) Unwrap(ctx context.Context, ref provider.KeyRef, v uint32, wrapped, aad []byte) ([]byte, error) {
	g.calls.Add(1)
	if g.armed.Load() {
		g.once.Do(func() { close(g.entered) })
		<-g.release
	}
	return g.Provider.Unwrap(ctx, ref, v, wrapped, aad)
}

// An operation already past its cache lookup when Purge is called must not
// put the key it fetched back into the cache.
func TestPurgeIsNotUndoneByAnOperationInFlight(t *testing.T) {
	g := &gate{Provider: providermemory.NewKeyring(), entered: make(chan struct{}), release: make(chan struct{})}
	w := newStateWorld(t, g)
	e, err := w.client(t, false).Encrypt(bgctx, stateCachePurpose, []byte("a"), nil)
	if err != nil {
		t.Fatal(err)
	}

	reader := w.client(t, false) // cold: it must unwrap
	g.armed.Store(true)
	done := make(chan error, 1)
	go func() {
		_, _, err := reader.Decrypt(bgctx, stateCachePurpose, e, nil)
		done <- err
	}()
	<-g.entered
	reader.Purge()
	close(g.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	before := g.calls.Load()
	if _, _, err := reader.Decrypt(bgctx, stateCachePurpose, e, nil); err != nil {
		t.Fatal(err)
	}
	if g.calls.Load() == before {
		t.Fatal("a key fetched before Purge was cached after it")
	}
}

// Reencrypt must not create a key of the wrong kind for a purpose whose
// per-subject setting has changed since the data was written.
func TestReencryptChecksTheSubjectAgainstTheConfiguration(t *testing.T) {
	w := newStateWorld(t, nil)
	e, err := w.client(t, true).EncryptFor(bgctx, stateCachePurpose, "u1", []byte("a"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.client(t, false).Reencrypt(bgctx, stateCachePurpose, e, nil); !errors.Is(err, keyforge.ErrSubjectNotAllowed) {
		t.Fatalf("Reencrypt = %v, want ErrSubjectNotAllowed", err)
	}
	// And the other way round.
	plain, err := w.client(t, false).Encrypt(bgctx, stateCachePurpose, []byte("b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.client(t, true).Reencrypt(bgctx, stateCachePurpose, plain, nil); !errors.Is(err, keyforge.ErrSubjectRequired) {
		t.Fatalf("Reencrypt = %v, want ErrSubjectRequired", err)
	}
}
