package embedded_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/embedded"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/rotate"
)

// These tests run the whole stack: the client, the rotator, the SQL registry
// and the keyring file, each reopened from disk as a restarted process would.

const tenants keyforge.Purpose = "tenants"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

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

type written struct {
	purpose keyforge.Purpose
	subject string
	env     *envelope.Envelope
	plain   string
	ctx     string
}

func lifecycleOptions(dir string, clock keyforge.Clock) embedded.Options {
	pol := policy.Set{Default: policy.Policy{DEKMaxEncryptions: 3}}
	return embedded.Options{
		Dir:  dir,
		Root: rootKey(7),
		Purposes: map[keyforge.Purpose]embedded.PurposeOptions{
			purpose: {},
			tenants: {PerSubject: true},
		},
		Policy: pol,
		Clock:  clock,
	}
}

func (w written) check(t *testing.T, c *keyforge.Client) {
	t.Helper()
	pt, info, err := c.Decrypt(bg, w.purpose, w.env, []byte(w.ctx))
	if err != nil || string(pt) != w.plain {
		t.Fatalf("%s/%s %q: got %q, %v", w.purpose, w.subject, w.plain, pt, err)
	}
	if info.Subject != w.subject {
		t.Fatalf("%q: subject %q, want %q", w.plain, info.Subject, w.subject)
	}
}

// TestRandomLifecycleKeepsEveryEnvelopeReadable applies a random sequence of
// writes, rotations, re-wraps, the passage of time and restarts, and checks
// that every envelope ever written still decrypts to what was written. Nothing
// in the sequence retires a version, so nothing may become unreadable.
func TestRandomLifecycleKeepsEveryEnvelopeReadable(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed)) //nolint:gosec // G404: a seeded generator makes the sequence reproducible; no secret depends on it
			dir := t.TempDir()
			clock := &fakeClock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
			o := lifecycleOptions(dir, clock)

			s := open(t, o)
			var all []written
			encrypt := func() {
				p := purpose
				subject := ""
				if rng.Intn(2) == 0 {
					p, subject = tenants, fmt.Sprintf("tenant-%d", rng.Intn(4))
				}
				w := written{purpose: p, subject: subject, plain: fmt.Sprintf("m-%d", len(all)), ctx: fmt.Sprintf("c-%d", rng.Intn(5))}
				var err error
				if subject == "" {
					w.env, err = s.Client.Encrypt(bg, p, []byte(w.plain), []byte(w.ctx))
				} else {
					w.env, err = s.Client.EncryptFor(bg, p, subject, []byte(w.plain), []byte(w.ctx))
				}
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				all = append(all, w)
			}

			for step := range 120 {
				switch n := rng.Intn(12); {
				case n < 5:
					encrypt()
				case n == 5, n == 6:
					p := []keyforge.Purpose{purpose, tenants}[rng.Intn(2)]
					if _, err := s.Rotator.RotateKEK(bg, p); err != nil {
						t.Fatalf("step %d: rotate %s: %v", step, p, err)
					}
				case n == 7:
					p := []keyforge.Purpose{purpose, tenants}[rng.Intn(2)]
					kek, err := s.Registry.KEKForPurpose(bg, p)
					if err != nil {
						t.Fatal(err)
					}
					res, err := s.Rotator.RewrapAll(bg, kek.ID, rotate.RewrapOptions{BatchSize: 1 + rng.Intn(5)})
					if err != nil || !res.Done {
						t.Fatalf("step %d: rewrap %s: %+v, %v", step, p, res, err)
					}
				case n == 8:
					clock.Advance(time.Duration(1+rng.Intn(120)) * 24 * time.Hour)
				case n == 9:
					// A restart: everything is read back from disk.
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					var err error
					if s, err = embedded.Open(bg, o); err != nil {
						t.Fatalf("step %d: reopen: %v", step, err)
					}
					t.Cleanup(func() { _ = s.Close() })
				default:
					if len(all) > 0 {
						all[rng.Intn(len(all))].check(t, s.Client)
					}
				}
			}
			for _, w := range all {
				w.check(t, s.Client)
			}

			// The registry's own bookkeeping agrees with itself.
			for _, p := range []keyforge.Purpose{purpose, tenants} {
				assertConsistent(t, s, p)
			}
		})
	}
}

// assertConsistent checks invariants of the registry that no sequence of
// operations may break: one active version, no data key under a version that
// cannot unwrap, and a wrapping history that ends where the key is now.
func assertConsistent(t *testing.T, s *embedded.System, p keyforge.Purpose) {
	t.Helper()
	kek, err := s.Registry.KEKForPurpose(bg, p)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := s.Registry.ListVersions(bg, kek.ID)
	if err != nil {
		t.Fatal(err)
	}
	active := 0
	states := map[uint32]registry.VersionState{}
	for _, v := range vs {
		states[v.Version] = v.State
		if v.State == registry.VersionActive {
			active++
		}
	}
	if active != 1 {
		t.Errorf("%s: %d active versions, want 1", p, active)
	}
	var after envelope.ID
	for {
		page, err := s.Registry.ListDEKs(bg, registry.DEKFilter{Purpose: p, After: after, Limit: 200})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			return
		}
		for _, d := range page {
			after = d.ID
			if d.State == keyforge.DEKDestroyed {
				continue
			}
			if !states[d.KEKVersion].CanUnwrap() {
				t.Errorf("%s: data key %s is under version %d, which is %s", p, d.ID, d.KEKVersion, states[d.KEKVersion])
			}
			last := d.WrappedUnder[len(d.WrappedUnder)-1]
			if last.KEKID != d.KEKID || last.Version != d.KEKVersion {
				t.Errorf("%s: data key %s history ends at %+v, but it is wrapped under %d", p, d.ID, last, d.KEKVersion)
			}
		}
	}
}

// interrupting wraps a provider and fails every Wrap after the first n, as a
// process killed part-way through a re-wrap would.
type interrupting struct {
	provider.Provider
	mu    sync.Mutex
	left  int
	armed bool
}

var errInterrupted = errors.New("interrupted")

func (p *interrupting) Wrap(ctx context.Context, ref provider.KeyRef, version uint32, dek, aad []byte) ([]byte, error) {
	p.mu.Lock()
	if p.armed {
		if p.left <= 0 {
			p.mu.Unlock()
			return nil, errInterrupted
		}
		p.left--
	}
	p.mu.Unlock()
	return p.Provider.Wrap(ctx, ref, version, dek, aad)
}

// TestRewrapInterruptedAtEveryPointCompletesAfterARestart interrupts a re-wrap
// after each possible number of keys, restarts the whole system from disk, and
// runs it again. Every data key must end under the new version exactly once,
// and nothing may be unreadable at any point.
func TestRewrapInterruptedAtEveryPointCompletesAfterARestart(t *testing.T) {
	const messages = 24 // 8 data keys at a cap of 3
	for stopAfter := 0; stopAfter <= 9; stopAfter++ {
		t.Run(fmt.Sprintf("after-%d", stopAfter), func(t *testing.T) {
			dir := t.TempDir()
			clock := &fakeClock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
			o := lifecycleOptions(dir, clock)

			s, err := embedded.Open(bg, o)
			if err != nil {
				t.Fatal(err)
			}
			var all []written
			for i := range messages {
				w := written{purpose: purpose, plain: fmt.Sprintf("m-%d", i), ctx: fmt.Sprintf("c-%d", i)}
				if w.env, err = s.Client.Encrypt(bg, purpose, []byte(w.plain), []byte(w.ctx)); err != nil {
					t.Fatal(err)
				}
				all = append(all, w)
			}
			rot, err := s.Rotator.RotateKEK(bg, purpose)
			if err != nil {
				t.Fatal(err)
			}

			// A rotator over the same registry whose provider dies after
			// stopAfter wraps.
			flaky := &interrupting{Provider: s.Keyring, left: stopAfter, armed: true}
			r2, err := rotate.New(rotate.Options{
				Store: s.Registry, Providers: []provider.Provider{flaky}, Policy: o.Policy, Clock: clock,
			})
			if err != nil {
				t.Fatal(err)
			}
			res, err := r2.Rewrap(bg, rot.KEK.ID, 1, rotate.RewrapOptions{BatchSize: 3})
			if err != nil {
				t.Fatalf("an interrupted Rewrap returned an error rather than a result: %v", err)
			}
			if stopAfter < 8 && (res.Done || res.FailedCount == 0) {
				t.Fatalf("stopped after %d wraps but Rewrap = %+v", stopAfter, res)
			}

			// Nothing is unreadable halfway.
			for _, w := range all {
				w.check(t, s.Client)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			// The restarted process finishes the job.
			s = open(t, o)
			done, err := s.Rotator.Rewrap(bg, rot.KEK.ID, 1, rotate.RewrapOptions{})
			if err != nil || !done.Done || done.FailedCount != 0 {
				t.Fatalf("resumed Rewrap = %+v, %v", done, err)
			}
			if n, err := s.Registry.CountDEKs(bg, rot.KEK.ID, 1); err != nil || n != 0 {
				t.Fatalf("%d data keys remain under version 1, %v", n, err)
			}
			var after envelope.ID
			for {
				page, err := s.Registry.ListDEKs(bg, registry.DEKFilter{KEKID: rot.KEK.ID, After: after})
				if err != nil {
					t.Fatal(err)
				}
				if len(page) == 0 {
					break
				}
				for _, d := range page {
					after = d.ID
					if len(d.WrappedUnder) != 2 || d.WrappedUnder[0].Version != 1 || d.WrappedUnder[1].Version != 2 {
						t.Errorf("data key %s history = %+v, want versions 1 then 2 exactly once", d.ID, d.WrappedUnder)
					}
				}
			}
			for _, w := range all {
				w.check(t, s.Client)
			}
		})
	}
}

// TestReadsSucceedThroughoutARotation reads continuously from several
// goroutines, each with its own cold client so that it must reach the registry
// and the keyring, while a rotation and a full re-wrap run.
func TestReadsSucceedThroughoutARotation(t *testing.T) {
	o := lifecycleOptions(t.TempDir(), nil)
	s := open(t, o)

	const subjects = 300
	var all []written
	for i := range subjects {
		w := written{purpose: tenants, subject: fmt.Sprintf("t-%d", i), plain: fmt.Sprintf("m-%d", i), ctx: "c"}
		var err error
		if w.env, err = s.Client.EncryptFor(bg, tenants, w.subject, []byte(w.plain), []byte(w.ctx)); err != nil {
			t.Fatal(err)
		}
		all = append(all, w)
	}

	ctx, stop := context.WithCancel(bg)
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		fails []error
		reads int
	)
	for g := range 4 {
		reader, err := keyforge.New(keyforge.Options{
			Store: s.Registry, Providers: []provider.Provider{s.Keyring},
			Purposes: map[keyforge.Purpose]keyforge.PurposeConfig{tenants: {PerSubject: true}},
		})
		if err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			for i := g; ctx.Err() == nil; i += 4 {
				w := all[i%len(all)]
				pt, _, err := reader.Decrypt(bg, w.purpose, w.env, []byte(w.ctx))
				mu.Lock()
				reads++
				if err != nil || string(pt) != w.plain {
					fails = append(fails, fmt.Errorf("%s: %q, %v", w.plain, pt, err))
				}
				mu.Unlock()
			}
		})
	}

	rot, err := s.Rotator.RotateKEK(bg, tenants)
	if err == nil {
		var res rotate.RewrapAllResult
		if res, err = s.Rotator.RewrapAll(bg, rot.KEK.ID, rotate.RewrapOptions{BatchSize: 20}); err == nil && !res.Done {
			err = fmt.Errorf("RewrapAll = %+v", res)
		}
	}
	stop()
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if len(fails) > 0 {
		t.Fatalf("%d of %d reads failed during the rotation; first: %v", len(fails), reads, fails[0])
	}
	if reads == 0 {
		t.Fatal("no reads happened")
	}
}
