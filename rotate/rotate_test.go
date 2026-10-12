package rotate_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/provider/local"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	"github.com/plexusone/keyforge/registry"
	registrymemory "github.com/plexusone/keyforge/registry/memory"
	"github.com/plexusone/keyforge/rotate"
)

var bg = context.Background()

const purpose keyforge.Purpose = "orders"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type world struct {
	pol   policy.Set
	t     *testing.T
	store *registrymemory.Store
	prov  provider.Provider
	kek   provider.KeyRef
	clock *clock
	audit *audit.Recorder
	rot   *rotate.Rotator
}

type setup struct {
	prov    func(t *testing.T) provider.Provider
	policy  policy.Set
	backups func(p provider.Provider) map[string]rotate.Backup
}

func newWorld(t *testing.T, s setup) *world {
	t.Helper()
	w := &world{t: t, store: registrymemory.NewStore(), clock: &clock{t: time.Unix(1_700_000_000, 0)}, audit: &audit.Recorder{}}
	if s.prov == nil {
		s.prov = func(*testing.T) provider.Provider { return providermemory.NewKeyring() }
	}
	w.prov = s.prov(t)
	kek, err := w.prov.CreateKey(bg, provider.KeySpec{Purpose: string(purpose), Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	w.kek = kek
	if err := w.store.Bootstrap(bg, purpose, kek, 1, w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	w.pol = s.policy
	opts := rotate.Options{
		Store: w.store, Providers: []provider.Provider{w.prov}, Policy: s.policy,
		Clock: w.clock, Audit: w.audit,
	}
	if s.backups != nil {
		opts.Backups = s.backups(w.prov)
	}
	w.rot, err = rotate.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) client(opts ...func(*keyforge.Options)) *keyforge.Client {
	w.t.Helper()
	o := keyforge.Options{
		Store: w.store, Providers: []provider.Provider{w.prov},
		Purposes: map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {}},
		Clock:    w.clock,
	}
	for _, f := range opts {
		f(&o)
	}
	c, err := keyforge.New(o)
	if err != nil {
		w.t.Fatal(err)
	}
	return c
}

// seed writes n messages with a cap of 2, so n/2 data keys exist, all wrapped
// under whatever version is active. It returns what it wrote.
type sealed struct {
	e   *envelope.Envelope
	msg string
	ctx string
}

func (w *world) seed(c *keyforge.Client, n int) []sealed {
	w.t.Helper()
	var out []sealed
	for i := range n {
		msg, ctx := fmt.Sprintf("message %d", i), fmt.Sprintf("ctx-%d", i)
		e, err := c.Encrypt(bg, purpose, []byte(msg), []byte(ctx))
		if err != nil {
			w.t.Fatal(err)
		}
		out = append(out, sealed{e, msg, ctx})
	}
	return out
}

func (w *world) mustDecrypt(c *keyforge.Client, all []sealed) {
	w.t.Helper()
	for _, s := range all {
		pt, _, err := c.Decrypt(bg, purpose, s.e, []byte(s.ctx))
		if err != nil || string(pt) != s.msg {
			w.t.Fatalf("%s: %q, %v", s.msg, pt, err)
		}
	}
}

func small(o *keyforge.Options) { o.EncryptionCap, o.ReserveBlock = 2, 2 }

func (w *world) versions() map[uint32]registry.VersionState {
	w.t.Helper()
	vs, err := w.store.ListVersions(bg, w.kek.ID)
	if err != nil {
		w.t.Fatal(err)
	}
	out := map[uint32]registry.VersionState{}
	for _, v := range vs {
		out[v.Version] = v.State
	}
	return out
}

func styles() map[string]func(*testing.T) provider.Provider {
	return map[string]func(*testing.T) provider.Provider{
		"keyring": func(*testing.T) provider.Provider { return providermemory.NewKeyring() },
		"native":  func(*testing.T) provider.Provider { return providermemory.NewNative() },
		"local": func(t *testing.T) provider.Provider {
			root := bytes.Repeat([]byte{0x11}, local.RootKeySize)
			p, err := local.Create(bg, local.Options{Path: filepath.Join(t.TempDir(), "keyring.kf"), Root: local.StaticSource(root)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.Close() })
			return p
		},
	}
}

func TestRotateKEKActivatesAndRecordsASentinel(t *testing.T) {
	for name, mk := range styles() {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, setup{prov: mk})
			w.clock.Advance(time.Hour)

			r, err := w.rot.RotateKEK(bg, purpose)
			if err != nil {
				t.Fatal(err)
			}
			if r.From != 1 || r.To <= 1 || !r.At.Equal(w.clock.Now()) {
				t.Fatalf("Rotation = %+v", r)
			}
			vs := w.versions()
			if vs[1] != registry.VersionDecryptOnly || vs[r.To] != registry.VersionActive {
				t.Fatalf("versions = %v, want 1 decrypt-only and %d active", vs, r.To)
			}
			if kv, err := w.store.ActiveKEK(bg, purpose); err != nil || kv.Version != r.To {
				t.Fatalf("ActiveKEK = %+v, %v", kv, err)
			}

			// The sentinel is an envelope the client opens, under that version.
			sn, err := w.store.GetSentinel(bg, w.kek.ID, r.To)
			if err != nil {
				t.Fatal(err)
			}
			e, err := envelope.ParseText(sn.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			if e.KEKVersion != r.To {
				t.Fatalf("the sentinel is under version %d, want %d", e.KEKVersion, r.To)
			}
			pt, _, err := w.client().Decrypt(bg, purpose, e, []byte(rotate.SentinelContext))
			if err != nil || string(pt) != rotate.SentinelPlaintext {
				t.Fatalf("sentinel = %q, %v", pt, err)
			}

			got := w.audit.Actions()
			if len(got) != 2 || got[0] != audit.KeyRotated || got[1] != audit.KeyActivated {
				t.Fatalf("audit actions = %v", got)
			}
		})
	}
}

func TestRotateRepeatedlyNumbersVersionsAsTheProviderDoes(t *testing.T) {
	w := newWorld(t, setup{prov: styles()["native"]})
	var seen []uint32
	for range 4 {
		r, err := w.rot.RotateKEK(bg, purpose)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, r.To)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("versions %v do not increase", seen)
		}
	}
	// The native provider's numbers are not consecutive, and the registry
	// accepts them as given.
	if seen[1] == seen[0]+1 && seen[2] == seen[1]+1 {
		t.Fatalf("versions %v are consecutive; the native style should not be", seen)
	}
}

func TestRotateResumesAPendingVersion(t *testing.T) {
	w := newWorld(t, setup{})
	// An earlier rotation created the version at the provider and registered it,
	// then stopped before activating.
	v, err := w.prov.Rotate(bg, w.kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.store.AddVersion(bg, registry.VersionRecord{KEKID: w.kek.ID, Version: v, State: registry.VersionPending, CreatedAt: w.clock.Now()}); err != nil {
		t.Fatal(err)
	}

	r, err := w.rot.RotateKEK(bg, purpose)
	if err != nil {
		t.Fatal(err)
	}
	if r.To != v {
		t.Fatalf("rotated to version %d, want the pending version %d to be activated", r.To, v)
	}
	// No further version was created at the provider.
	next, err := w.prov.Rotate(bg, w.kek)
	if err != nil || next != v+1 {
		t.Fatalf("the provider's next version is %d, %v; want %d: a spare version was created", next, err, v+1)
	}
}

func TestRewrapMovesEveryDataKeyAndLeavesDataAlone(t *testing.T) {
	for name, mk := range styles() {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, setup{prov: mk})
			c := w.client(small)
			all := w.seed(c, 21) // 11 data keys, all under version 1
			var before []string
			for _, s := range all {
				before = append(before, s.e.String())
			}
			if n, _ := w.store.CountDEKs(bg, w.kek.ID, 1); n != 11 {
				t.Fatalf("setup: %d data keys under version 1, want 11", n)
			}

			r, err := w.rot.RotateKEK(bg, purpose)
			if err != nil {
				t.Fatal(err)
			}
			var batches int
			res, err := w.rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{BatchSize: 4, Progress: func(rotate.RewrapResult) { batches++ }})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Done || res.Rewrapped != 11 || res.FailedCount != 0 {
				t.Fatalf("Rewrap = %+v", res)
			}
			if batches != 3 {
				t.Errorf("progress was reported %d times, want 3 batches of up to 4", batches)
			}
			if n, _ := w.store.CountDEKs(bg, w.kek.ID, 1); n != 0 {
				t.Errorf("%d data keys are still under version 1", n)
			}
			if n, _ := w.store.CountDEKs(bg, w.kek.ID, r.To); n != 11 {
				t.Errorf("%d data keys under version %d, want 11", n, r.To)
			}

			// Stored data is untouched and still decrypts, from a cold process.
			for i, s := range all {
				if before[i] != s.e.String() {
					t.Fatal("an envelope changed")
				}
			}
			w.mustDecrypt(w.client(small), all)

			// Version 1 can now be taken away, and nothing is lost.
			if err := w.prov.Destroy(bg, w.kek, 1); err != nil {
				t.Fatal(err)
			}
			w.mustDecrypt(w.client(small), all)
		})
	}
}

func TestRewrapIsIdempotentAndResumable(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client(small)
	all := w.seed(c, 40) // 20 data keys
	if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}

	// Interrupt it partway by cancelling from the progress callback.
	ctx, cancel := context.WithCancel(bg)
	first, err := w.rot.Rewrap(ctx, w.kek.ID, 1, rotate.RewrapOptions{BatchSize: 3, Progress: func(r rotate.RewrapResult) {
		if r.Rewrapped >= 6 {
			cancel()
		}
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Rewrap = %v, want the cancellation", err)
	}
	if first.Done || first.Rewrapped < 6 || first.Rewrapped >= 20 {
		t.Fatalf("interrupted run = %+v", first)
	}
	// Reads work throughout: both versions are live.
	w.mustDecrypt(w.client(small), all)

	// Resume from the cursor, and also from the beginning.
	second, err := w.rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{After: first.Cursor})
	if err != nil || !second.Done {
		t.Fatalf("resume = %+v, %v", second, err)
	}
	if first.Rewrapped+second.Rewrapped != 20 {
		t.Fatalf("moved %d + %d, want 20 in total with none twice", first.Rewrapped, second.Rewrapped)
	}
	again, err := w.rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{})
	if err != nil || !again.Done || again.Rewrapped != 0 {
		t.Fatalf("a repeat run = %+v, %v, want nothing to do", again, err)
	}
	w.mustDecrypt(w.client(small), all)
}

func TestConcurrentRewrapRunsDoNotConflict(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client(small)
	all := w.seed(c, 60) // 30 data keys
	if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	results := make([]rotate.RewrapResult, 4)
	for i := range results {
		wg.Go(func() {
			res, err := w.rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{BatchSize: 5})
			if err != nil {
				t.Errorf("worker %d: %v", i, err)
			}
			results[i] = res
		})
	}
	wg.Wait()

	var moved int
	for _, r := range results {
		moved += r.Rewrapped
		if r.FailedCount != 0 || !r.Done {
			t.Errorf("a worker did not finish cleanly: %+v", r)
		}
	}
	if moved != 30 {
		t.Fatalf("workers moved %d data keys between them, want exactly 30", moved)
	}
	w.mustDecrypt(w.client(small), all)
}

// flakyUnwrap fails one Unwrap call, as a provider with a transient fault
// would, and passes everything else through.
type flakyUnwrap struct {
	provider.Provider
	mu     sync.Mutex
	failOn int // the 1-based call to fail; 0 never
	calls  int
}

func (f *flakyUnwrap) Unwrap(ctx context.Context, ref provider.KeyRef, v uint32, wrapped, aad []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	fail := f.calls == f.failOn
	f.mu.Unlock()
	if fail {
		return nil, errors.New("transient provider fault")
	}
	return f.Provider.Unwrap(ctx, ref, v, wrapped, aad)
}

func TestRewrapReportsFailuresAndDoesNotRetire(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client(small)
	all := w.seed(c, 10) // 5 data keys
	if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}

	flaky := &flakyUnwrap{Provider: w.prov, failOn: 3}
	rot, err := rotate.New(rotate.Options{
		Store: w.store, Providers: []provider.Provider{flaky}, Clock: w.clock, Audit: w.audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Done || res.FailedCount != 1 || res.Rewrapped != 4 || len(res.Failed) != 1 {
		t.Fatalf("Rewrap = %+v, want 4 moved, 1 failed, not done", res)
	}
	// The failure is named and carries no key material.
	if res.Failed[0].DEKID.IsZero() || res.Failed[0].Err == nil {
		t.Fatalf("the failure is not described: %+v", res.Failed[0])
	}

	// A version that is still referenced is not eligible for retirement.
	if e, err := w.rot.Eligibility(bg, w.kek.ID, 1); err != nil || e.References != 1 || e.Eligible {
		t.Fatalf("Eligibility = %+v, %v, want one reference remaining", e, err)
	}
	var sawFailure bool
	for _, a := range w.audit.Actions() {
		sawFailure = sawFailure || a == audit.WrapFailed
	}
	if !sawFailure {
		t.Error("the failure was not audited")
	}

	// Everything still decrypts, and a healthy retry finishes the job.
	w.mustDecrypt(w.client(small), all)
	retry, err := w.rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{})
	if err != nil || !retry.Done || retry.Rewrapped != 1 {
		t.Fatalf("retry = %+v, %v, want the one remaining key moved", retry, err)
	}
}

func TestRewrapRefusals(t *testing.T) {
	w := newWorld(t, setup{})
	if _, err := w.rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{}); !errors.Is(err, rotate.ErrNothingToRewrap) {
		t.Errorf("rewrapping from the active version = %v, want ErrNothingToRewrap", err)
	}
	if _, err := w.rot.Rewrap(bg, w.kek.ID, 9, rotate.RewrapOptions{}); !errors.Is(err, registry.ErrVersionNotFound) {
		t.Errorf("rewrapping from a version that does not exist = %v", err)
	}
	if _, err := w.rot.Rewrap(bg, [16]byte{1}, 1, rotate.RewrapOptions{}); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("rewrapping an unknown KEK = %v", err)
	}
}

func TestEligibility(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client(small)
	w.seed(c, 4) // two data keys under version 1

	get := func(v uint32) rotate.Eligibility {
		t.Helper()
		e, err := w.rot.Eligibility(bg, w.kek.ID, v)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}

	if e := get(1); e.Eligible || e.State != registry.VersionActive {
		t.Fatalf("the active version is eligible: %+v", e)
	}

	r1, err := w.rot.RotateKEK(bg, purpose) // 1 decrypt-only, 2 active
	if err != nil {
		t.Fatal(err)
	}
	// Referenced and inside the floor: two reasons.
	e := get(1)
	if e.Eligible || e.References != 2 || len(e.Reasons) != 2 {
		t.Fatalf("version 1 = %+v, want referenced and within the floor", e)
	}

	if _, err := w.rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{}); err != nil {
		t.Fatal(err)
	}
	// Drained, but it is still the rollback margin.
	e = get(1)
	if e.Eligible || e.References != 0 || len(e.Reasons) != 1 {
		t.Fatalf("version 1 after the re-wrap = %+v, want only the floor", e)
	}

	r2, err := w.rot.RotateKEK(bg, purpose) // 2 decrypt-only, 3 active
	if err != nil {
		t.Fatal(err)
	}
	if e = get(1); !e.Eligible {
		t.Fatalf("version 1 beyond the floor and unreferenced = %+v, want eligible", e)
	}
	if e = get(r1.To); e.Eligible {
		t.Fatalf("version %d is the most recent decrypt-only and must be kept: %+v", r1.To, e)
	}
	if e = get(r2.To); e.Eligible {
		t.Fatalf("the active version is eligible: %+v", e)
	}
	if _, err := w.rot.Eligibility(bg, w.kek.ID, 99); !errors.Is(err, registry.ErrVersionNotFound) {
		t.Fatalf("Eligibility of a missing version = %v", err)
	}
}

func TestRetainVersionsRaisesTheFloor(t *testing.T) {
	w := newWorld(t, setup{policy: policy.Set{Default: policy.Policy{RetainVersions: 3}}})
	for range 3 {
		if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
			t.Fatal(err)
		}
	}
	// Versions 1, 2, 3 decrypt-only and 4 active; the floor of 3 keeps 4, 3, 2.
	if e, _ := w.rot.Eligibility(bg, w.kek.ID, 2); e.Eligible {
		t.Fatalf("version 2 is inside a floor of 3: %+v", e)
	}
	if e, err := w.rot.Eligibility(bg, w.kek.ID, 1); err != nil || !e.Eligible {
		t.Fatalf("version 1 = %+v, %v, want eligible", e, err)
	}
}

func TestCompromisedVersionIsNotHeldByTheFloor(t *testing.T) {
	w := newWorld(t, setup{})
	if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}
	if err := w.store.TransitionVersion(bg, w.kek.ID, 1, registry.VersionCompromised, registry.TransitionOptions{At: w.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	e, err := w.rot.Eligibility(bg, w.kek.ID, 1)
	if err != nil || !e.Eligible {
		t.Fatalf("a compromised, unreferenced version = %+v, %v, want eligible whatever the floor", e, err)
	}
}

func TestRollback(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client(small)
	if _, err := w.rot.Rollback(bg, purpose); !errors.Is(err, registry.ErrNoRollbackTarget) {
		t.Fatalf("Rollback with nothing to return to = %v, want ErrNoRollbackTarget", err)
	}

	r, err := w.rot.RotateKEK(bg, purpose)
	if err != nil {
		t.Fatal(err)
	}
	// A data key is created under the new version, which then proves bad.
	w.clock.Advance(10 * time.Minute) // let the client's cached active version expire
	fresh := w.client(small)
	all := w.seed(fresh, 4)
	if n, _ := w.store.CountDEKs(bg, w.kek.ID, r.To); n == 0 {
		t.Fatal("setup: no data key was wrapped under the new version")
	}

	back, err := w.rot.Rollback(bg, purpose)
	if err != nil {
		t.Fatal(err)
	}
	if back.To != 1 || back.From != r.To {
		t.Fatalf("Rollback = %+v", back)
	}
	vs := w.versions()
	if vs[1] != registry.VersionActive || vs[r.To] != registry.VersionDecryptOnly {
		t.Fatalf("versions = %v", vs)
	}
	// What was wrapped under the demoted version still opens.
	w.mustDecrypt(w.client(small), all)
	_ = c

	last := w.audit.Actions()
	if last[len(last)-1] != audit.KeyRolledBack {
		t.Fatalf("audit actions = %v, want the rollback recorded", last)
	}
}

func TestDue(t *testing.T) {
	w := newWorld(t, setup{policy: policy.Set{Default: policy.Policy{KEKInterval: 30 * 24 * time.Hour}}})
	d, err := w.rot.Due(bg, purpose)
	if err != nil {
		t.Fatal(err)
	}
	if d.Overdue || d.Version != 1 || !d.DueAt.Equal(d.ActivatedAt.Add(30*24*time.Hour)) {
		t.Fatalf("Due = %+v", d)
	}
	w.clock.Advance(31 * 24 * time.Hour)
	if d, _ = w.rot.Due(bg, purpose); !d.Overdue {
		t.Fatalf("Due after the interval = %+v, want overdue", d)
	}
	// Rotating resets the clock from the new activation.
	if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}
	if d, _ = w.rot.Due(bg, purpose); d.Overdue || d.Version != 2 {
		t.Fatalf("Due after rotating = %+v", d)
	}
	if _, err := w.rot.Due(bg, "unknown"); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Fatalf("Due for an unknown purpose = %v", err)
	}
}

func TestBackupRequirement(t *testing.T) {
	require := policy.Set{Default: policy.Policy{RequireBackup: true}}

	t.Run("provider cannot say", func(t *testing.T) {
		w := newWorld(t, setup{policy: require})
		if _, err := w.rot.RotateKEK(bg, purpose); !errors.Is(err, rotate.ErrBackupUnknown) {
			t.Fatalf("RotateKEK = %v, want ErrBackupUnknown: fail closed", err)
		}
		if w.versions()[2] != 0 {
			t.Fatal("a version was created although the backup state is unknown")
		}
	})

	t.Run("local keyring waits for an acknowledgement", func(t *testing.T) {
		var lp *local.Provider
		w := newWorld(t, setup{
			policy: require,
			prov: func(t *testing.T) provider.Provider {
				p := styles()["local"](t).(*local.Provider)
				lp = p
				return p
			},
			backups: func(p provider.Provider) map[string]rotate.Backup {
				return map[string]rotate.Backup{p.Name(): p.(*local.Provider)}
			},
		})
		if _, err := w.rot.RotateKEK(bg, purpose); !errors.Is(err, rotate.ErrBackupStale) {
			t.Fatalf("RotateKEK before any acknowledgement = %v, want ErrBackupStale", err)
		}
		acts := w.audit.Actions()
		if len(acts) != 1 || acts[0] != audit.BackupStale {
			t.Fatalf("audit actions = %v, want the refusal recorded", acts)
		}

		st, err := lp.BackupStatus(bg)
		if err != nil {
			t.Fatal(err)
		}
		if err := lp.AckBackup(bg, st.Generation, w.clock.Now(), "offsite"); err != nil {
			t.Fatal(err)
		}
		if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
			t.Fatalf("RotateKEK after the acknowledgement: %v", err)
		}
		// The rotation itself advanced the keyring, so the next one waits again.
		if _, err := w.rot.RotateKEK(bg, purpose); !errors.Is(err, rotate.ErrBackupStale) {
			t.Fatalf("a second RotateKEK = %v, want to wait for the new copy", err)
		}
	})
}

func TestAuditFailureIsReportedAfterTheChange(t *testing.T) {
	w := newWorld(t, setup{})
	w.audit.Err = errors.New("sink down")
	r, err := w.rot.RotateKEK(bg, purpose)
	if !errors.Is(err, audit.ErrNotRecorded) {
		t.Fatalf("RotateKEK = %v, want ErrNotRecorded", err)
	}
	if r.To != 2 || w.versions()[2] != registry.VersionActive {
		t.Fatalf("the rotation did not stand: %+v %v", r, w.versions())
	}
}

func TestActorIsAttributed(t *testing.T) {
	w := newWorld(t, setup{})
	if _, err := w.rot.RotateKEK(audit.WithActor(bg, "alice"), purpose); err != nil {
		t.Fatal(err)
	}
	for _, e := range w.audit.Events() {
		if e.Actor != "alice" || e.ID == "" || e.Time.IsZero() || e.Outcome != audit.Success {
			t.Errorf("event %+v is not fully attributed", e)
		}
	}
}

func TestNewValidates(t *testing.T) {
	store := registrymemory.NewStore()
	prov := providermemory.NewKeyring()
	for name, o := range map[string]rotate.Options{
		"no store":     {Providers: []provider.Provider{prov}},
		"no providers": {Store: store},
		"duplicate":    {Store: store, Providers: []provider.Provider{prov, prov}},
		"bad policy":   {Store: store, Providers: []provider.Provider{prov}, Policy: policy.Set{Default: policy.Policy{DEKMaxEncryptions: keyforge.MaxEncryptionCap + 1}}},
	} {
		if _, err := rotate.New(o); err == nil {
			t.Errorf("%s: New accepted the options", name)
		}
	}
}

// ---- retirement and destruction ----

// guardLog is a guard that answers from a script and records what it was asked.
type guardLog struct {
	mu      sync.Mutex
	answers []guardAnswer
	asked   []guardAsked
}

type guardAnswer struct {
	d   guard.Decision
	err error
}

type guardAsked struct{ action, refs, emergency string }

func (g *guardLog) Check(_ context.Context, req guard.Request) (guard.Decision, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asked = append(g.asked, guardAsked{string(req.Action), fmt.Sprint(req.References), fmt.Sprint(req.Emergency)})
	if len(g.answers) == 0 {
		return guard.Allow(), nil
	}
	a := g.answers[0]
	if len(g.answers) > 1 {
		g.answers = g.answers[1:]
	}
	return a.d, a.err
}

func (g *guardLog) calls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.asked)
}

// retireWorld has KEK version 1 drained and outside the floor, ready to retire.
// It also returns an inline envelope made under version 1, which no registry
// record points at.
func retireWorld(t *testing.T, g guard.Guard, mk func(*testing.T) provider.Provider) (*world, *rotate.Rotator, *envelope.Envelope) {
	t.Helper()
	w := newWorld(t, setup{prov: mk})
	c := w.client(small)
	w.seed(c, 4)
	inline, err := c.EncryptInline(bg, purpose, []byte("an export"), []byte("exp"))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
			t.Fatal(err)
		}
		w.clock.Advance(time.Minute)
	}
	// Move what the first version wraps, so nothing references it.
	if _, err := w.rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{}); err != nil {
		t.Fatal(err)
	}
	rot, err := rotate.New(rotate.Options{
		Store: w.store, Providers: []provider.Provider{w.prov}, Clock: w.clock, Audit: w.audit, Guard: g,
	})
	if err != nil {
		t.Fatal(err)
	}
	return w, rot, inline
}

func TestRequestRetirementStartsTheDelay(t *testing.T) {
	w, _, _ := retireWorld(t, guard.AllowAll(), nil)
	w.audit = &audit.Recorder{} // only what follows
	rot2, err := rotate.New(rotate.Options{Store: w.store, Providers: []provider.Provider{w.prov}, Clock: w.clock, Audit: w.audit, Guard: guard.AllowAll()})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rot2.RequestRetirement(bg, w.kek.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != registry.VersionRetireRequested {
		t.Fatalf("RequestRetirement = %+v", res)
	}
	rec, err := w.store.GetVersion(bg, w.kek.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := w.clock.Now().Add(policy.DefaultRetirementDelay)
	if !rec.RetireAfter.Equal(want) {
		t.Fatalf("RetireAfter = %v, want now plus the policy delay %v", rec.RetireAfter, want)
	}
	if a := w.audit.Actions(); len(a) != 1 || a[0] != audit.KeyRetireRequested {
		t.Fatalf("audit actions = %v", a)
	}
}

func TestRequestRetirementRefusals(t *testing.T) {
	w := newWorld(t, setup{})
	rot, err := rotate.New(rotate.Options{Store: w.store, Providers: []provider.Provider{w.prov}, Clock: w.clock, Guard: guard.AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	// The active version.
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); !errors.Is(err, rotate.ErrWrongState) {
		t.Errorf("retiring the active version = %v, want ErrWrongState", err)
	}
	if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}
	// Decrypt-only, but it is the rollback margin.
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); !errors.Is(err, rotate.ErrNotEligible) {
		t.Errorf("retiring a version inside the floor = %v, want ErrNotEligible", err)
	}
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 99); !errors.Is(err, registry.ErrVersionNotFound) {
		t.Errorf("retiring a missing version = %v", err)
	}
}

func TestCompleteRetirementWaitsForTheDelayAndReferences(t *testing.T) {
	g := &guardLog{}
	w, rot, _ := retireWorld(t, g, nil)
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}

	// Before the delay the guard is not even asked.
	if _, err := rot.CompleteRetirement(bg, w.kek.ID, 1); !errors.Is(err, registry.ErrRetireDelay) {
		t.Fatalf("CompleteRetirement inside the delay = %v, want ErrRetireDelay", err)
	}
	if g.calls() != 0 {
		t.Fatalf("the guard was asked %d times before the delay had run", g.calls())
	}

	w.clock.Advance(policy.DefaultRetirementDelay)
	res, err := rot.CompleteRetirement(bg, w.kek.ID, 1)
	if err != nil || res.Outcome != guard.Allowed || res.State != registry.VersionRetired {
		t.Fatalf("CompleteRetirement = %+v, %v", res, err)
	}
	if g.asked[0].action != "retire" || g.asked[0].refs != "0" || g.asked[0].emergency != "false" {
		t.Fatalf("the guard was asked %+v", g.asked)
	}
	// Retired is not usable, though the provider still holds the material.
	if ok, err := w.store.KEKVersionUsable(bg, w.kek.ID, 1); err != nil || ok {
		t.Fatalf("a retired version is usable: %v, %v", ok, err)
	}
}

func TestCompleteRetirementRefusesWhileReferenced(t *testing.T) {
	g := &guardLog{}
	w := newWorld(t, setup{})
	c := w.client(small)
	w.seed(c, 4)
	for range 2 {
		if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
			t.Fatal(err)
		}
	}
	// Version 1 still wraps two data keys: it was never re-wrapped.
	rot, err := rotate.New(rotate.Options{Store: w.store, Providers: []provider.Provider{w.prov}, Clock: w.clock, Guard: g})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(policy.DefaultRetirementDelay)
	if _, err := rot.CompleteRetirement(bg, w.kek.ID, 1); !errors.Is(err, registry.ErrVersionReferenced) {
		t.Fatalf("CompleteRetirement = %v, want ErrVersionReferenced", err)
	}
	if g.calls() != 0 {
		t.Fatal("the guard was asked about a version that is still referenced")
	}
	if w.versions()[1] != registry.VersionRetireRequested {
		t.Fatalf("state = %v", w.versions()[1])
	}
}

func TestGuardDenialReturnsTheKeyToService(t *testing.T) {
	g := &guardLog{answers: []guardAnswer{{d: guard.Deny("legal hold on orders")}}}
	w, _, _ := retireWorld(t, g, nil)
	w.audit = &audit.Recorder{}
	rot, err := rotate.New(rotate.Options{Store: w.store, Providers: []provider.Provider{w.prov}, Clock: w.clock, Audit: w.audit, Guard: g})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(policy.DefaultRetirementDelay)

	res, err := rot.CompleteRetirement(bg, w.kek.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != guard.Denied || res.Reason != "legal hold on orders" || res.State != registry.VersionDecryptOnly {
		t.Fatalf("CompleteRetirement = %+v", res)
	}
	rec, _ := w.store.GetVersion(bg, w.kek.ID, 1)
	if rec.State != registry.VersionDecryptOnly || !rec.RetireAfter.IsZero() {
		t.Fatalf("version = %+v, want decrypt-only with no delay running", rec)
	}
	want := []audit.Action{audit.KeyRetireRequested, audit.GuardDenied, audit.KeyRetireCancelled}
	got := w.audit.Actions()
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("audit actions = %v, want %v", got, want)
	}
	if ev := w.audit.Events()[1]; ev.Reason != "legal hold on orders" || ev.Outcome != audit.Denied {
		t.Fatalf("the denial event = %+v", ev)
	}
}

func TestGuardPendingLeavesItWaiting(t *testing.T) {
	g := &guardLog{answers: []guardAnswer{{d: guard.AwaitApproval("approval 41 outstanding")}, {d: guard.Allow()}}}
	w, rot, _ := retireWorld(t, g, nil)
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(policy.DefaultRetirementDelay)

	res, err := rot.CompleteRetirement(bg, w.kek.ID, 1)
	if err != nil || res.Outcome != guard.Pending || res.State != registry.VersionRetireRequested {
		t.Fatalf("first CompleteRetirement = %+v, %v", res, err)
	}
	if ok, _ := w.store.KEKVersionUsable(bg, w.kek.ID, 1); !ok {
		t.Fatal("a pending answer made the version unusable")
	}
	// Asked again on the next pass, and this time allowed.
	res, err = rot.CompleteRetirement(bg, w.kek.ID, 1)
	if err != nil || res.State != registry.VersionRetired {
		t.Fatalf("second CompleteRetirement = %+v, %v", res, err)
	}
}

func TestGuardErrorOrAbsenceAdvancesNothing(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		g := &guardLog{answers: []guardAnswer{{err: errors.New("approval service unreachable")}}}
		w, rot, _ := retireWorld(t, g, nil)
		if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
			t.Fatal(err)
		}
		w.clock.Advance(policy.DefaultRetirementDelay)
		if _, err := rot.CompleteRetirement(bg, w.kek.ID, 1); err == nil {
			t.Fatal("a guard error was treated as consent")
		}
		if w.versions()[1] != registry.VersionRetireRequested {
			t.Fatalf("state = %v", w.versions()[1])
		}
	})
	t.Run("no guard", func(t *testing.T) {
		w, rot, _ := retireWorld(t, nil, nil)
		if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
			t.Fatal(err)
		}
		w.clock.Advance(policy.DefaultRetirementDelay)
		res, err := rot.CompleteRetirement(bg, w.kek.ID, 1)
		if err != nil || res.Outcome != guard.Denied || res.Reason != guard.ErrNoGuard {
			t.Fatalf("CompleteRetirement with no guard = %+v, %v, want a denial", res, err)
		}
	})
	t.Run("invalid outcome", func(t *testing.T) {
		g := &guardLog{answers: []guardAnswer{{d: guard.Decision{}}}}
		w, rot, _ := retireWorld(t, g, nil)
		if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
			t.Fatal(err)
		}
		w.clock.Advance(policy.DefaultRetirementDelay)
		if _, err := rot.CompleteRetirement(bg, w.kek.ID, 1); err == nil {
			t.Fatal("a zero decision was treated as an allow")
		}
	})
}

func TestCancelRetirement(t *testing.T) {
	w, rot, _ := retireWorld(t, guard.AllowAll(), nil)
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}
	res, err := rot.CancelRetirement(bg, w.kek.ID, 1)
	if err != nil || res.State != registry.VersionDecryptOnly {
		t.Fatalf("CancelRetirement = %+v, %v", res, err)
	}
	if _, err := rot.CancelRetirement(bg, w.kek.ID, 1); err == nil {
		t.Fatal("cancelling a version that is not retire-requested succeeded")
	}
}

func TestDestroyOrderAndGuard(t *testing.T) {
	for name, mk := range styles() {
		t.Run(name, func(t *testing.T) {
			g := &guardLog{}
			w, rot, _ := retireWorld(t, g, mk)
			if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
				t.Fatal(err)
			}
			w.clock.Advance(policy.DefaultRetirementDelay)
			if _, err := rot.CompleteRetirement(bg, w.kek.ID, 1); err != nil {
				t.Fatal(err)
			}

			// A version that is only retired still has its material at the provider.
			if _, err := w.prov.Wrap(bg, w.kek, 1, bytes.Repeat([]byte{1}, 32), nil); err != nil {
				t.Fatalf("the provider no longer has a retired version: %v", err)
			}

			res, err := rot.Destroy(bg, w.kek.ID, 1)
			if err != nil || res.State != registry.VersionDestroyed {
				t.Fatalf("Destroy = %+v, %v", res, err)
			}
			if g.asked[len(g.asked)-1].action != "destroy" {
				t.Fatalf("the guard was asked %+v", g.asked)
			}
			if _, err := w.prov.Wrap(bg, w.kek, 1, bytes.Repeat([]byte{1}, 32), nil); !errors.Is(err, provider.ErrVersionDestroyed) {
				t.Fatalf("the provider still wraps under a destroyed version: %v", err)
			}
			// Repeating is harmless.
			if _, err := rot.Destroy(bg, w.kek.ID, 1); !errors.Is(err, rotate.ErrWrongState) {
				t.Fatalf("destroying a destroyed version = %v, want ErrWrongState", err)
			}
		})
	}
}

func TestDestroyDeniedLeavesTheMaterial(t *testing.T) {
	g := &guardLog{answers: []guardAnswer{{d: guard.Allow()}, {d: guard.Deny("export from last quarter still needs it")}}}
	w, rot, _ := retireWorld(t, g, nil)
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(policy.DefaultRetirementDelay)
	if _, err := rot.CompleteRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}

	res, err := rot.Destroy(bg, w.kek.ID, 1)
	if err != nil || res.Outcome != guard.Denied || res.State != registry.VersionRetired {
		t.Fatalf("Destroy = %+v, %v, want a denial leaving it retired", res, err)
	}
	if _, err := w.prov.Wrap(bg, w.kek, 1, bytes.Repeat([]byte{1}, 32), nil); err != nil {
		t.Fatalf("a denied destruction touched the provider: %v", err)
	}
	if !contains(w.audit.Actions(), audit.GuardDenied) {
		t.Fatalf("audit actions = %v, want the denial recorded", w.audit.Actions())
	}
}

// failingDestroy fails the provider's Destroy, as a provider outage would.
type failingDestroy struct {
	provider.Provider
	fail bool
}

func (f *failingDestroy) Destroy(ctx context.Context, ref provider.KeyRef, v uint32) error {
	if f.fail {
		return errors.New("provider unavailable")
	}
	return f.Provider.Destroy(ctx, ref, v)
}

func TestDestroyIsRetryable(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client(small)
	w.seed(c, 4)
	for range 2 {
		if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{}); err != nil {
		t.Fatal(err)
	}
	fd := &failingDestroy{Provider: w.prov, fail: true}
	rot, err := rotate.New(rotate.Options{Store: w.store, Providers: []provider.Provider{fd}, Clock: w.clock, Guard: guard.AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(policy.DefaultRetirementDelay)
	if _, err := rot.CompleteRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}

	// The provider fails: the registry does not claim a destruction that did not happen.
	if _, err := rot.Destroy(bg, w.kek.ID, 1); err == nil {
		t.Fatal("Destroy succeeded although the provider failed")
	}
	if w.versions()[1] != registry.VersionRetired {
		t.Fatalf("state = %v after a provider failure, want retired", w.versions()[1])
	}

	fd.fail = false
	if res, err := rot.Destroy(bg, w.kek.ID, 1); err != nil || res.State != registry.VersionDestroyed {
		t.Fatalf("retry = %+v, %v", res, err)
	}
}

func TestClientRefusesARetiredVersionEvenWhileTheProviderHoldsIt(t *testing.T) {
	w, rot, inline := retireWorld(t, guard.AllowAll(), nil)

	// Before retirement the inline object, made under version 1, still opens:
	// it is decrypt-only, and the registry does not count inline data.
	if pt, _, err := w.client(small).Decrypt(bg, purpose, inline, []byte("exp")); err != nil || string(pt) != "an export" {
		t.Fatalf("Decrypt before retirement = %q, %v", pt, err)
	}

	if _, err := rot.RequestRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(policy.DefaultRetirementDelay)
	if _, err := rot.CompleteRetirement(bg, w.kek.ID, 1); err != nil {
		t.Fatal(err)
	}
	// The provider still holds the material, since retiring does not destroy it.
	if _, err := w.prov.Wrap(bg, w.kek, 1, bytes.Repeat([]byte{1}, 32), nil); err != nil {
		t.Fatalf("setup: the provider no longer holds version 1: %v", err)
	}

	// A fresh client, with nothing cached, is refused: retired means unusable.
	_, _, err := w.client(small).Decrypt(bg, purpose, inline, []byte("exp"))
	if !errors.Is(err, keyforge.ErrKeyUnusable) {
		t.Fatalf("Decrypt under a retired version = %v, want ErrKeyUnusable", err)
	}
}

func contains(as []audit.Action, a audit.Action) bool {
	for _, x := range as {
		if x == a {
			return true
		}
	}
	return false
}

func TestRewrapAllDrainsEveryNonActiveVersion(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client(small)
	all := w.seed(c, 6) // three data keys under version 1
	if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(10 * time.Minute)
	c2 := w.client(small)
	all = append(all, w.seed(c2, 4)...) // two more, under version 2
	if _, err := w.rot.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}

	res, err := w.rot.RewrapAll(bg, w.kek.ID, rotate.RewrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Done || len(res.Versions) != 2 || res.Versions[1].Rewrapped != 3 || res.Versions[2].Rewrapped != 2 {
		t.Fatalf("RewrapAll = %+v", res)
	}
	for v := uint32(1); v <= 2; v++ {
		if n, _ := w.store.CountDEKs(bg, w.kek.ID, v); n != 0 {
			t.Errorf("%d data keys still under version %d", n, v)
		}
	}
	w.mustDecrypt(w.client(small), all)

	// Nothing left: a second run does nothing and is done.
	again, err := w.rot.RewrapAll(bg, w.kek.ID, rotate.RewrapOptions{})
	if err != nil || !again.Done || len(again.Versions) != 0 {
		t.Fatalf("a repeat RewrapAll = %+v, %v", again, err)
	}
}

func TestRewrapAllNeedsAnActiveVersion(t *testing.T) {
	w := newWorld(t, setup{})
	if err := w.store.TransitionVersion(bg, w.kek.ID, 1, registry.VersionCompromised, registry.TransitionOptions{At: w.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.rot.RewrapAll(bg, w.kek.ID, rotate.RewrapOptions{}); !errors.Is(err, keyforge.ErrNoActiveKEK) {
		t.Fatalf("RewrapAll with no active version = %v, want ErrNoActiveKEK", err)
	}
}
