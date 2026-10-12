package rotate_test

import (
	"errors"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/rotate"
)

func perSubject(o *keyforge.Options) {
	o.Purposes[purpose] = keyforge.PurposeConfig{PerSubject: true}
	o.EncryptionCap, o.ReserveBlock = 2, 2
}

const day = 24 * time.Hour

// TestShredIsCompleteOnlyWhenEveryWrappingVersionIsGone follows an erasure from
// the request to completion through real rotations, retirements and
// destructions, with a clock that jumps by the policy's intervals.
func TestShredIsCompleteOnlyWhenEveryWrappingVersionIsGone(t *testing.T) {
	w := newWorld(t, setup{policy: policy.Set{Default: policy.Policy{
		KEKInterval: 30 * day, RetirementDelay: 7 * day, RetainVersions: 2,
	}}})
	c := w.client(perSubject)
	w.audit = &audit.Recorder{}
	rot := w.rotator(t, func(o *rotate.Options) { o.Guard = guard.AllowAll(); o.Epochs = c; o.Audit = w.audit })

	// Alice and Bob both have keys under version 1; Alice's are moved to
	// version 2 before she is erased, so she has been under two versions.
	var aliceData, bobData []sealed
	for i := range 4 {
		a, err := c.EncryptFor(bg, purpose, "alice", []byte("a"), []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		aliceData = append(aliceData, sealed{e: a, msg: "a", ctx: string([]byte{byte(i)})})
		b, err := c.EncryptFor(bg, purpose, "bob", []byte("b"), []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		bobData = append(bobData, sealed{e: b, msg: "b", ctx: string([]byte{byte(i)})})
	}
	if _, err := rot.RotateKEK(bg, purpose); err != nil { // version 2
		t.Fatal(err)
	}
	if res, err := rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{}); err != nil || !res.Done {
		t.Fatalf("Rewrap = %+v, %v", res, err)
	}

	// Erase Alice.
	rec, err := rot.RequestShred(bg, purpose, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if rec.DEKs != 2 || len(rec.Versions) != 2 || rec.Complete() {
		t.Fatalf("ShredRecord = %+v, want 2 keys and both versions pending", rec)
	}
	c.Purge()

	// Her data is gone from the live registry at once; Bob's is untouched.
	fresh := w.client(perSubject)
	for _, s := range aliceData {
		if _, _, err := fresh.Decrypt(bg, purpose, s.e, []byte(s.ctx)); !errors.Is(err, keyforge.ErrKeyUnusable) {
			t.Fatalf("Alice's data after the shred = %v, want ErrKeyUnusable", err)
		}
	}
	for _, s := range bobData {
		if pt, _, err := fresh.Decrypt(bg, purpose, s.e, []byte(s.ctx)); err != nil || string(pt) != "b" {
			t.Fatalf("Bob's data: %q, %v", pt, err)
		}
	}
	if _, err := fresh.EncryptFor(bg, purpose, "alice", []byte("again"), nil); !errors.Is(err, keyforge.ErrSubjectShredded) {
		t.Fatalf("writing a shredded subject = %v, want ErrSubjectShredded", err)
	}

	// But it is not complete: an old registry backup holds her key under
	// version 1 and version 2, and either still exists.
	st, err := rot.ShredStatus(bg, purpose, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if st.Complete || len(st.Pending) != 2 || st.ExpectedBy.IsZero() {
		t.Fatalf("ShredStatus = %+v, want two pending versions and an expected date", st)
	}
	if done, err := rot.CompleteShreds(bg); err != nil || len(done) != 0 {
		t.Fatalf("CompleteShreds = %v, %v, want nothing complete yet", done, err)
	}

	// Drive the lifecycle. Each rotation moves Bob's keys off the old version
	// so nothing references it, and the floor of two lets go of version 1 and
	// then version 2 as newer versions arrive.
	rotateAndDrain := func() {
		t.Helper()
		w.clock.Advance(31 * day)
		r, err := rot.RotateKEK(bg, purpose)
		if err != nil {
			t.Fatal(err)
		}
		for v := uint32(1); v < r.To; v++ {
			if st := w.versions()[v]; st == registry.VersionDecryptOnly || st == registry.VersionRetireRequested {
				if res, err := rot.Rewrap(bg, w.kek.ID, v, rotate.RewrapOptions{}); err != nil || !res.Done {
					t.Fatalf("Rewrap from %d = %+v, %v", v, res, err)
				}
			}
		}
	}
	retire := func(v uint32) {
		t.Helper()
		if _, err := rot.RequestRetirement(bg, w.kek.ID, v); err != nil {
			t.Fatalf("RequestRetirement(%d): %v", v, err)
		}
		w.clock.Advance(8 * day)
		if res, err := rot.CompleteRetirement(bg, w.kek.ID, v); err != nil || res.State != registry.VersionRetired {
			t.Fatalf("CompleteRetirement(%d) = %+v, %v", v, res, err)
		}
		if res, err := rot.Destroy(bg, w.kek.ID, v); err != nil || res.State != registry.VersionDestroyed {
			t.Fatalf("Destroy(%d) = %+v, %v", v, res, err)
		}
	}

	rotateAndDrain() // version 3: version 1 is now outside a floor of two
	retire(1)
	if done, _ := rot.CompleteShreds(bg); len(done) != 0 {
		t.Fatal("the shred completed with version 2 still alive")
	}
	st, _ = rot.ShredStatus(bg, purpose, "alice")
	if st.Complete || len(st.Pending) != 1 || st.Pending[0].Version.Version != 2 {
		t.Fatalf("after destroying version 1: %+v, want only version 2 pending", st)
	}

	rotateAndDrain() // version 4: version 2 is outside the floor
	retire(2)
	done, err := rot.CompleteShreds(bg)
	if err != nil || len(done) != 1 || done[0].Subject != "alice" || !done[0].Complete() {
		t.Fatalf("CompleteShreds = %+v, %v, want Alice's shred complete", done, err)
	}
	st, _ = rot.ShredStatus(bg, purpose, "alice")
	if !st.Complete || len(st.Pending) != 0 || !st.ExpectedBy.IsZero() {
		t.Fatalf("ShredStatus after completion = %+v", st)
	}

	// Bob never noticed.
	w.client(perSubject).Purge()
	for _, s := range bobData {
		if pt, _, err := w.client(perSubject).Decrypt(bg, purpose, s.e, []byte(s.ctx)); err != nil || string(pt) != "b" {
			t.Fatalf("Bob's data at the end: %q, %v", pt, err)
		}
	}

	// The trail records the request and the completion, once each.
	var requested, completed int
	for _, a := range w.audit.Actions() {
		switch a {
		case audit.SubjectShredRequest:
			requested++
		case audit.SubjectShredComplete:
			completed++
		}
	}
	if requested != 1 || completed != 1 {
		t.Fatalf("shred events: %d requested, %d completed, want one each (%v)", requested, completed, w.audit.Actions())
	}
}

func TestShredEstimateFollowsPolicy(t *testing.T) {
	pol := policy.Set{Default: policy.Policy{KEKInterval: 100 * day, RetirementDelay: 20 * day, RetainVersions: 2}}
	w := newWorld(t, setup{policy: pol})
	c := w.client(perSubject)
	if _, err := c.EncryptFor(bg, purpose, "alice", []byte("a"), nil); err != nil {
		t.Fatal(err)
	}
	rot := w.rotator(t, func(o *rotate.Options) { o.Policy = pol })
	if _, err := rot.RequestShred(bg, purpose, "alice"); err != nil {
		t.Fatal(err)
	}
	active, err := w.store.GetVersion(bg, w.kek.ID, 1)
	if err != nil {
		t.Fatal(err)
	}

	st, err := rot.ShredStatus(bg, purpose, "alice")
	if err != nil || len(st.Pending) != 1 {
		t.Fatalf("ShredStatus = %+v, %v", st, err)
	}
	// Version 1 is active: it needs two rotations to leave a floor of two, each
	// a KEK interval after the last, then the retirement delay.
	want := active.ActivatedAt.Add(2*100*day + 20*day)
	if !st.ExpectedBy.Equal(want) {
		t.Fatalf("ExpectedBy = %v, want %v: interval x retained versions plus the delay", st.ExpectedBy, want)
	}
}

func TestShredOfASubjectWithNoKeysCompletesAtOnce(t *testing.T) {
	w := newWorld(t, setup{})
	rec, err := w.rot.RequestShred(bg, purpose, "never-enrolled")
	if err != nil || !rec.Complete() {
		t.Fatalf("RequestShred = %+v, %v", rec, err)
	}
	var sawComplete bool
	for _, a := range w.audit.Actions() {
		sawComplete = sawComplete || a == audit.SubjectShredComplete
	}
	if !sawComplete {
		t.Fatalf("audit actions = %v, want the completion recorded", w.audit.Actions())
	}
}

func TestRequestShredValidatesAndIsIdempotent(t *testing.T) {
	w := newWorld(t, setup{})
	if _, err := w.rot.RequestShred(bg, purpose, ""); !errors.Is(err, keyforge.ErrInvalidSubject) {
		t.Errorf("an empty subject = %v, want ErrInvalidSubject", err)
	}
	c := w.client(perSubject)
	if _, err := c.EncryptFor(bg, purpose, "alice", []byte("a"), nil); err != nil {
		t.Fatal(err)
	}
	first, err := w.rot.RequestShred(bg, purpose, "alice")
	if err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(time.Hour)
	second, err := w.rot.RequestShred(bg, purpose, "alice")
	if err != nil || !second.RequestedAt.Equal(first.RequestedAt) {
		t.Fatalf("a repeated RequestShred = %+v, %v, want the original request", second, err)
	}
	if _, err := w.rot.ShredStatus(bg, purpose, "nobody"); !errors.Is(err, registry.ErrShredNotFound) {
		t.Errorf("ShredStatus of an unknown subject = %v", err)
	}
}

func TestRequestShredRefusesAPurposeWithNoKey(t *testing.T) {
	w := newWorld(t, setup{})
	_, err := w.rot.RequestShred(bg, "ordres", "alice")
	if !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Fatalf("RequestShred under a mistyped purpose = %v, want ErrKEKNotFound", err)
	}
	if shreds, err := w.store.ListShreds(bg); err != nil || len(shreds) != 0 {
		t.Fatalf("a tombstone was written for a purpose with no key: %v, %v", shreds, err)
	}
}
