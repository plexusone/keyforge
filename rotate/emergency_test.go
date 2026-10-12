package rotate_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/rotate"
)

func (w *world) rotator(t *testing.T, mutate func(*rotate.Options)) *rotate.Rotator {
	t.Helper()
	o := rotate.Options{Store: w.store, Providers: []provider.Provider{w.prov}, Clock: w.clock, Audit: w.audit}
	if mutate != nil {
		mutate(&o)
	}
	r, err := rotate.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCompromisedActiveKEKIsReplacedRewrappedAndDestroyed(t *testing.T) {
	for name, mk := range styles() {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, setup{prov: mk})
			c := w.client(small)
			all := w.seed(c, 10) // five data keys under version 1
			w.audit = &audit.Recorder{}
			rot := w.rotator(t, func(o *rotate.Options) { o.Audit = w.audit })

			res, err := rot.CompromiseKEK(bg, w.kek.ID, 1, rotate.EmergencyKEKOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if res.Replacement.From != 1 || res.Replacement.To <= 1 {
				t.Fatalf("Replacement = %+v", res.Replacement)
			}
			if res.Rewrap.Rewrapped != 5 || !res.Rewrap.Done || res.Remaining != 0 {
				t.Fatalf("Rewrap = %+v, remaining %d", res.Rewrap, res.Remaining)
			}
			if !res.Retired || !res.Destroyed {
				t.Fatalf("Retired=%v Destroyed=%v", res.Retired, res.Destroyed)
			}
			if got := w.versions()[1]; got != registry.VersionDestroyed {
				t.Fatalf("version 1 is %s, want destroyed", got)
			}
			if _, err := w.prov.Wrap(bg, w.kek, 1, bytes.Repeat([]byte{1}, 32), nil); !errors.Is(err, provider.ErrVersionDestroyed) {
				t.Fatalf("the provider still holds the compromised version: %v", err)
			}

			// Nothing was lost: the data keys were moved before it went.
			w.mustDecrypt(w.client(small), all)
			if kv, err := w.store.ActiveKEK(bg, purpose); err != nil || kv.Version != res.Replacement.To {
				t.Fatalf("ActiveKEK = %+v, %v", kv, err)
			}

			// The trail tells the story in order.
			want := []audit.Action{
				audit.KeyRotated, audit.KeyActivated, audit.KeyCompromised, audit.KeyRotated,
				audit.GuardDenied, audit.KeyRetired, audit.KeyDestroyed,
			}
			got := w.audit.Actions()
			if len(got) != len(want) {
				t.Fatalf("audit actions = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("audit actions = %v, want %v", got, want)
				}
			}
		})
	}
}

// TestEmergencyGuardIsRecordedAndNotObeyed checks the one place the guard does
// not decide: it is asked, its answer is on the trail, and the procedure
// continues whatever it said.
func TestEmergencyGuardIsRecordedAndNotObeyed(t *testing.T) {
	cases := map[string]guard.Guard{
		"denies": guard.DenyAll("legal hold on orders"),
		"pending": guard.Func(func(context.Context, guard.Request) (guard.Decision, error) {
			return guard.AwaitApproval("ticket 9"), nil
		}),
		"fails": guard.Func(func(context.Context, guard.Request) (guard.Decision, error) {
			return guard.Decision{}, errors.New("approval service down")
		}),
		"allows": guard.AllowAll(),
		"absent": nil,
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, setup{})
			w.seed(w.client(small), 4)
			asked := &guardLog{}
			var gg guard.Guard = g
			if g != nil {
				gg = guard.Func(func(ctx context.Context, req guard.Request) (guard.Decision, error) {
					_, _ = asked.Check(ctx, req)
					return g.Check(ctx, req)
				})
			}
			rot := w.rotator(t, func(o *rotate.Options) { o.Guard = gg })

			res, err := rot.CompromiseKEK(bg, w.kek.ID, 1, rotate.EmergencyKEKOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Destroyed {
				t.Fatalf("the guard blocked an emergency rotation: %+v", res)
			}
			if g != nil && asked.calls() != 1 {
				t.Fatalf("the guard was asked %d times, want once", asked.calls())
			}
			if g != nil && asked.asked[0].emergency != "true" {
				t.Fatalf("the guard was not told it was an emergency: %+v", asked.asked)
			}
			if name == "denies" {
				var found bool
				for _, e := range w.audit.Events() {
					if e.Action == audit.GuardDenied && e.Reason != "" {
						found = true
					}
				}
				if !found {
					t.Fatalf("the denial was not recorded: %v", w.audit.Actions())
				}
			}
		})
	}
}

func TestEmergencyDoesNotWaitForABackup(t *testing.T) {
	w := newWorld(t, setup{policy: policy.Set{Default: policy.Policy{RequireBackup: true}}})
	w.seed(w.client(small), 4)
	// A scheduled rotation waits, here because the provider cannot say whether
	// there is a backup.
	if _, err := w.rot.RotateKEK(bg, purpose); !errors.Is(err, rotate.ErrBackupUnknown) {
		t.Fatalf("setup: scheduled rotation = %v, want it to wait", err)
	}
	// An emergency does not.
	res, err := w.rot.CompromiseKEK(bg, w.kek.ID, 1, rotate.EmergencyKEKOptions{})
	if err != nil {
		t.Fatalf("CompromiseKEK = %v, want it not to wait for a backup", err)
	}
	if res.Replacement.To == 0 {
		t.Fatalf("no replacement was activated: %+v", res)
	}
}

func TestCompromisedOlderVersionIsMovedWithoutAnotherRotation(t *testing.T) {
	w := newWorld(t, setup{})
	w.seed(w.client(small), 6) // three data keys under version 1
	first, err := w.rot.RotateKEK(bg, purpose)
	if err != nil {
		t.Fatal(err)
	}
	// Version 1 is decrypt-only. Compromising it needs no new rotation.
	res, err := w.rot.CompromiseKEK(bg, w.kek.ID, 1, rotate.EmergencyKEKOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Replacement.To != 0 {
		t.Fatalf("a replacement was created for a version that was not active: %+v", res.Replacement)
	}
	if res.Rewrap.Rewrapped != 3 || !res.Destroyed {
		t.Fatalf("result = %+v", res)
	}
	if kv, _ := w.store.ActiveKEK(bg, purpose); kv.Version != first.To {
		t.Fatalf("the active version changed to %d, want %d", kv.Version, first.To)
	}
}

func TestEmergencyResumesAfterAFailedRewrap(t *testing.T) {
	w := newWorld(t, setup{})
	all := w.seed(w.client(small), 10)
	flaky := &flakyUnwrap{Provider: w.prov, failOn: 2}
	rot := w.rotator(t, func(o *rotate.Options) { o.Providers = []provider.Provider{flaky} })

	res, err := rot.CompromiseKEK(bg, w.kek.ID, 1, rotate.EmergencyKEKOptions{})
	if !errors.Is(err, rotate.ErrEmergencyIncomplete) {
		t.Fatalf("CompromiseKEK = %v, want ErrEmergencyIncomplete", err)
	}
	if res.Remaining != 1 || res.Retired || res.Destroyed {
		t.Fatalf("result = %+v, want one key left and nothing retired or destroyed", res)
	}
	if w.versions()[1] != registry.VersionCompromised {
		t.Fatalf("version 1 is %s, want compromised", w.versions()[1])
	}
	// The data is all still readable while it waits.
	w.mustDecrypt(w.client(small), all)

	// Calling again, with the fault gone, finishes. Marking and replacing are not repeated.
	flaky.mu.Lock()
	flaky.failOn = 0
	flaky.mu.Unlock()
	res, err = rot.CompromiseKEK(bg, w.kek.ID, 1, rotate.EmergencyKEKOptions{})
	if err != nil || !res.Destroyed || res.Replacement.To != 0 {
		t.Fatalf("resumed CompromiseKEK = %+v, %v", res, err)
	}
	w.mustDecrypt(w.client(small), all)
}

func TestKeepMaterialStopsAtRetired(t *testing.T) {
	w := newWorld(t, setup{})
	w.seed(w.client(small), 4)
	res, err := w.rot.CompromiseKEK(bg, w.kek.ID, 1, rotate.EmergencyKEKOptions{KeepMaterial: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Retired || res.Destroyed {
		t.Fatalf("result = %+v, want retired and not destroyed", res)
	}
	// The host recovers what it needs, then destroys through the usual guard.
	if _, err := w.prov.Wrap(bg, w.kek, 1, bytes.Repeat([]byte{1}, 32), nil); err != nil {
		t.Fatalf("the provider no longer holds the version: %v", err)
	}
	rot := w.rotator(t, func(o *rotate.Options) { o.Guard = guard.AllowAll() })
	if out, err := rot.Destroy(bg, w.kek.ID, 1); err != nil || out.State != registry.VersionDestroyed {
		t.Fatalf("Destroy = %+v, %v", out, err)
	}
}

func TestEmergencyRefusals(t *testing.T) {
	w := newWorld(t, setup{})
	if _, err := w.rot.CompromiseKEK(bg, w.kek.ID, 9, rotate.EmergencyKEKOptions{}); !errors.Is(err, registry.ErrVersionNotFound) {
		t.Errorf("a missing version = %v", err)
	}
	if _, err := w.rot.CompromiseKEK(bg, w.kek.ID, 1, rotate.EmergencyKEKOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.rot.CompromiseKEK(bg, w.kek.ID, 1, rotate.EmergencyKEKOptions{}); !errors.Is(err, rotate.ErrWrongState) {
		t.Errorf("a version that is already destroyed = %v, want ErrWrongState", err)
	}
}

func TestCompromisedCurrentDEKIsReplacedAndStaysReadable(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client()
	rot := w.rotator(t, func(o *rotate.Options) { o.Epochs = c; o.Guard = guard.AllowAll() })

	old, err := c.Encrypt(bg, purpose, []byte("exposed"), []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if _, err := c.Encrypt(bg, purpose, []byte("more"), nil); err != nil {
			t.Fatal(err)
		}
	}

	out, err := rot.CompromiseDEK(audit.WithActor(bg, "alice"), old.DEKID)
	if err != nil {
		t.Fatal(err)
	}
	if out.Replacement.ID == old.DEKID || out.Replacement.State != keyforge.DEKActive || out.Replacement.Epoch != 2 {
		t.Fatalf("Replacement = %+v", out.Replacement)
	}
	if out.Exposed.State != keyforge.DEKCompromised {
		t.Fatalf("Exposed = %+v", out.Exposed)
	}
	if out.EncryptionsUpperBound < 7 {
		t.Fatalf("EncryptionsUpperBound = %d, want at least the 7 encryptions made", out.EncryptionsUpperBound)
	}

	// Writes moved at once. The exposed key still reads, reports itself stale,
	// and the host re-encrypts through the client.
	next, err := c.Encrypt(bg, purpose, []byte("after"), nil)
	if err != nil || next.DEKID != out.Replacement.ID {
		t.Fatalf("a write after the exposure used %v, %v", next.DEKID, err)
	}
	pt, info, err := c.Decrypt(bg, purpose, old, []byte("ctx"))
	if err != nil || string(pt) != "exposed" || !info.Stale {
		t.Fatalf("Decrypt under the exposed key = %q, %+v, %v", pt, info, err)
	}
	renewed, err := c.Reencrypt(bg, purpose, old, []byte("ctx"))
	if err != nil || renewed.DEKID != out.Replacement.ID {
		t.Fatalf("Reencrypt = %v, %v", renewed.DEKID, err)
	}

	// Once the host is done, the exposed key goes, and the record stays.
	res, err := rot.DestroyDEK(bg, old.DEKID)
	if err != nil || res.Outcome != guard.Allowed {
		t.Fatalf("DestroyDEK = %+v, %v", res, err)
	}
	rec, err := w.store.GetDEK(bg, old.DEKID)
	if err != nil || rec.State != keyforge.DEKDestroyed || len(rec.Wrapped) != 0 {
		t.Fatalf("destroyed record = %+v, %v", rec, err)
	}
	if _, _, err := w.client().Decrypt(bg, purpose, old, []byte("ctx")); !errors.Is(err, keyforge.ErrKeyUnusable) {
		t.Fatalf("Decrypt under a destroyed key = %v, want ErrKeyUnusable", err)
	}
	if !contains(w.audit.Actions(), audit.DataKeyCompromised) || !contains(w.audit.Actions(), audit.DataKeyDestroyed) {
		t.Fatalf("audit actions = %v", w.audit.Actions())
	}
	for _, e := range w.audit.Events() {
		if e.Action == audit.DataKeyCompromised && e.Actor != "alice" {
			t.Errorf("the event is attributed to %q", e.Actor)
		}
	}
}

func TestCompromisedNonCurrentDEKNeedsNoNewEpoch(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client(small)
	all := w.seed(c, 6)
	rot := w.rotator(t, nil) // no epoch advancer: not needed here
	first := all[0].e.DEKID

	out, err := rot.CompromiseDEK(bg, first)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Replacement.ID.IsZero() {
		t.Fatalf("a replacement was created for a key that was not current: %+v", out.Replacement)
	}
	if out.Exposed.State != keyforge.DEKCompromised {
		t.Fatalf("Exposed = %+v", out.Exposed)
	}
	// Repeating is harmless.
	if _, err := rot.CompromiseDEK(bg, first); err != nil {
		t.Fatalf("repeating CompromiseDEK = %v", err)
	}
}

func TestCompromisingTheCurrentDEKNeedsAnAdvancer(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client()
	e, err := c.Encrypt(bg, purpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	rot := w.rotator(t, nil)
	if _, err := rot.CompromiseDEK(bg, e.DEKID); !errors.Is(err, rotate.ErrNoEpochAdvancer) {
		t.Fatalf("CompromiseDEK = %v, want ErrNoEpochAdvancer", err)
	}
	// And nothing was marked.
	rec, _ := w.store.GetDEK(bg, e.DEKID)
	if rec.State != keyforge.DEKActive {
		t.Fatalf("the key is %s after a refused call", rec.State)
	}
}

func TestDestroyDEKRespectsTheGuard(t *testing.T) {
	w := newWorld(t, setup{})
	c := w.client(small)
	all := w.seed(c, 4)
	id := all[0].e.DEKID

	for name, g := range map[string]guard.Guard{
		"absent": nil,
		"denies": guard.DenyAll("still referenced by an export"),
		"pending": guard.Func(func(context.Context, guard.Request) (guard.Decision, error) {
			return guard.AwaitApproval("ticket"), nil
		}),
	} {
		t.Run(name, func(t *testing.T) {
			rot := w.rotator(t, func(o *rotate.Options) { o.Guard = g })
			// The key must be compromised or superseded for destruction to be legal.
			if _, err := rot.CompromiseDEK(bg, id); err != nil && !errors.Is(err, rotate.ErrNoEpochAdvancer) {
				t.Fatal(err)
			}
			res, err := rot.DestroyDEK(bg, id)
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome == guard.Allowed {
				t.Fatalf("DestroyDEK was allowed: %+v", res)
			}
			rec, _ := w.store.GetDEK(bg, id)
			if rec.State == keyforge.DEKDestroyed || len(rec.Wrapped) == 0 {
				t.Fatalf("the key was destroyed despite the guard: %+v", rec)
			}
		})
	}
}
