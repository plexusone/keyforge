// Package storetest is the conformance suite every [registry.Store] must pass.
// A store's own tests call [Run] with a constructor:
//
//	func TestConformance(t *testing.T) {
//		storetest.Run(t, func() registry.Store { return newStore() })
//	}
//
// It checks the transition table, that exactly one version is active, that a
// referenced version is not retired, the compare-and-set behaviour of
// advancing and re-wrapping data keys, that the cap is never over-granted under
// concurrency, paging, and that returned records are copies.
package storetest

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/registry"
)

// TB is the part of [testing.TB] the suite uses, so the suite can also run
// against a recorder to show that it rejects a broken store.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
}

// Case is one conformance check. It runs against a fresh store.
type Case struct {
	Name string
	Run  func(t TB, s registry.Store)
}

// Run runs every case as a subtest, each against a store from newStore.
func Run(t *testing.T, newStore func() registry.Store) {
	t.Helper()
	for _, c := range Cases() {
		t.Run(c.Name, func(t *testing.T) {
			t.Helper()
			c.Run(t, newStore())
		})
	}
}

// Cases returns the conformance cases.
func Cases() []Case {
	return []Case{
		{"CreateKEK", caseCreateKEK},
		{"CreateKEKRejects", caseCreateKEKRejects},
		{"UnknownKEK", caseUnknownKEK},
		{"AddVersion", caseAddVersion},
		{"ActivateFirstVersion", caseActivateFirst},
		{"ActivationDemotesPrevious", caseActivationDemotes},
		{"RollbackOnlyToMostRecentDecryptOnly", caseRollback},
		{"ActiveIsNotDemotedDirectly", caseNoDirectDemotion},
		{"TransitionMatrix", caseTransitionMatrix},
		{"RetirementNeedsDelayAndNoReferences", caseRetirement},
		{"CancelRetirement", caseCancelRetirement},
		{"CompromisedActiveLeavesNoneActive", caseCompromisedActive},
		{"AdvanceDEK", caseAdvanceDEK},
		{"AdvanceDEKNeedsAUsableVersion", caseAdvanceNeedsVersion},
		{"AdvanceDEKKeepsCompromised", caseAdvanceKeepsCompromised},
		{"AdvanceDEKConcurrent", caseAdvanceConcurrent},
		{"ReserveEncryptions", caseReserve},
		{"ReserveEncryptionsConcurrent", caseReserveConcurrent},
		{"ListDEKsPagesInOrder", caseListDEKs},
		{"CountDEKs", caseCountDEKs},
		{"RewrapDEK", caseRewrap},
		{"MarkDEK", caseMarkDEK},
		{"ActivationConcurrent", caseActivationConcurrent},
		{"RecordsAreCopies", caseCopies},
		{"KEKVersionUsableFollowsState", caseUsable},
		{"ActivationTimeIsRecorded", caseActivationTime},
		{"Sentinels", caseSentinels},
		{"CancelledContextChangesNothing", caseCancelled},
	}
}

var (
	bg      = context.Background()
	counter atomic.Uint64
	epoch   = time.Unix(1_700_000_000, 0).UTC()
)

// nextID returns a fresh, non-zero identifier. Identifiers increase with the
// counter, which the paging test relies on only to know they are distinct.
func nextID() envelope.ID {
	var id envelope.ID
	binary.BigEndian.PutUint64(id[:8], counter.Add(1))
	copy(id[8:], "keyforge-suite!!")
	return id
}

func at(minutes int) time.Time { return epoch.Add(time.Duration(minutes) * time.Minute) }

func newKEK(t TB, s registry.Store, purpose keyforge.Purpose) registry.KEK {
	t.Helper()
	id := nextID()
	k := registry.KEK{
		ID: id, Purpose: purpose, Provider: "conformance", ProviderRef: "kek/" + id.String(),
		State: registry.KeyActive, CreatedAt: at(0),
	}
	if err := s.CreateKEK(bg, k); err != nil {
		t.Fatalf("CreateKEK: %v", err)
	}
	return k
}

func addVersion(t TB, s registry.Store, k registry.KEK, v uint32) {
	t.Helper()
	rec := registry.VersionRecord{KEKID: k.ID, Version: v, State: registry.VersionPending, ProviderRef: fmt.Sprintf("v%d", v), CreatedAt: at(0)}
	if err := s.AddVersion(bg, rec); err != nil {
		t.Fatalf("AddVersion(%d): %v", v, err)
	}
}

func transition(t TB, s registry.Store, k registry.KEK, v uint32, to registry.VersionState, opts registry.TransitionOptions) {
	t.Helper()
	if err := s.TransitionVersion(bg, k.ID, v, to, opts); err != nil {
		t.Fatalf("TransitionVersion(%d to %s): %v", v, to, err)
	}
}

func activate(t TB, s registry.Store, k registry.KEK, v uint32, minute int) {
	t.Helper()
	transition(t, s, k, v, registry.VersionActive, registry.TransitionOptions{At: at(minute)})
}

func stateOf(t TB, s registry.Store, k registry.KEK, v uint32) registry.VersionState {
	t.Helper()
	rec, err := s.GetVersion(bg, k.ID, v)
	if err != nil {
		t.Fatalf("GetVersion(%d): %v", v, err)
	}
	return rec.State
}

// kekWithActive makes a KEK whose version 1 is active.
func kekWithActive(t TB, s registry.Store, purpose keyforge.Purpose) registry.KEK {
	t.Helper()
	k := newKEK(t, s, purpose)
	addVersion(t, s, k, 1)
	activate(t, s, k, 1, 1)
	return k
}

func dekRecord(k registry.KEK, version uint32, purpose keyforge.Purpose, subject string, epochN uint32) keyforge.DEKRecord {
	return keyforge.DEKRecord{
		ID: nextID(), Purpose: purpose, Subject: subject, Epoch: epochN, Algorithm: algorithm.AES256GCM,
		KEKID: k.ID, KEKVersion: version, Wrapped: binary.BigEndian.AppendUint32([]byte{0xDE, 0xAD}, epochN), State: keyforge.DEKActive, CreatedAt: at(2),
	}
}

func advance(t TB, s registry.Store, rec keyforge.DEKRecord, from uint32) keyforge.DEKRecord {
	t.Helper()
	got, err := s.AdvanceDEK(bg, rec.Purpose, rec.Subject, from, rec)
	if err != nil {
		t.Fatalf("AdvanceDEK: %v", err)
	}
	return got
}

func caseCreateKEK(t TB, s registry.Store) {
	t.Helper()
	k := newKEK(t, s, "orders")

	got, err := s.GetKEK(bg, k.ID)
	if err != nil || got.ID != k.ID || got.Purpose != "orders" || got.State != registry.KeyActive || got.Ref() != k.Ref() {
		t.Fatalf("GetKEK = %+v, %v", got, err)
	}
	byPurpose, err := s.KEKForPurpose(bg, "orders")
	if err != nil || byPurpose.ID != k.ID {
		t.Fatalf("KEKForPurpose = %+v, %v", byPurpose, err)
	}
	if ref, err := s.KEK(bg, k.ID); err != nil || ref != k.Ref() {
		t.Fatalf("KEK = %+v, %v", ref, err)
	}
	list, err := s.ListKEKs(bg)
	if err != nil || len(list) != 1 || list[0].ID != k.ID {
		t.Fatalf("ListKEKs = %+v, %v", list, err)
	}
	// With no version active yet there is nothing to wrap with.
	if _, err := s.ActiveKEK(bg, "orders"); !errors.Is(err, keyforge.ErrNoActiveKEK) {
		t.Errorf("ActiveKEK before any activation = %v, want ErrNoActiveKEK", err)
	}
}

func caseCreateKEKRejects(t TB, s registry.Store) {
	t.Helper()
	k := newKEK(t, s, "orders")

	dup := k
	dup.Purpose = "other"
	if err := s.CreateKEK(bg, dup); !errors.Is(err, registry.ErrKEKExists) {
		t.Errorf("duplicate ID: %v, want ErrKEKExists", err)
	}

	second := registry.KEK{ID: nextID(), Purpose: "orders", Provider: "p", ProviderRef: "r", State: registry.KeyActive, CreatedAt: at(0)}
	if err := s.CreateKEK(bg, second); !errors.Is(err, registry.ErrPurposeBound) {
		t.Errorf("second active KEK for a purpose: %v, want ErrPurposeBound", err)
	}
	// A retired KEK may share a purpose, which is how a purpose moves provider.
	second.State = registry.KeyRetired
	if err := s.CreateKEK(bg, second); err != nil {
		t.Errorf("retired KEK for a bound purpose: %v", err)
	}

	for name, bad := range map[string]registry.KEK{
		"zero id":     {Purpose: "p", Provider: "p", ProviderRef: "r", State: registry.KeyActive},
		"no provider": {ID: nextID(), Purpose: "p", ProviderRef: "r", State: registry.KeyActive},
		"no ref":      {ID: nextID(), Purpose: "p", Provider: "p", State: registry.KeyActive},
		"bad purpose": {ID: nextID(), Purpose: "Bad Purpose", Provider: "p", ProviderRef: "r", State: registry.KeyActive},
		"no state":    {ID: nextID(), Purpose: "p", Provider: "p", ProviderRef: "r"},
	} {
		if err := s.CreateKEK(bg, bad); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("%s: CreateKEK = %v, want ErrInvalid", name, err)
		}
	}
}

func caseUnknownKEK(t TB, s registry.Store) {
	t.Helper()
	unknown := nextID()
	if _, err := s.GetKEK(bg, unknown); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("GetKEK = %v, want ErrKEKNotFound", err)
	}
	if _, err := s.KEK(bg, unknown); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("KEK = %v, want ErrKEKNotFound", err)
	}
	if _, err := s.KEKForPurpose(bg, "nothing"); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("KEKForPurpose = %v, want ErrKEKNotFound", err)
	}
	if _, err := s.ListVersions(bg, unknown); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("ListVersions = %v, want ErrKEKNotFound", err)
	}
	err := s.AddVersion(bg, registry.VersionRecord{KEKID: unknown, Version: 1, State: registry.VersionPending})
	if !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("AddVersion = %v, want ErrKEKNotFound", err)
	}
	if err := s.TransitionVersion(bg, unknown, 1, registry.VersionActive, registry.TransitionOptions{At: at(1)}); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("TransitionVersion = %v, want ErrKEKNotFound", err)
	}
}

func caseAddVersion(t TB, s registry.Store) {
	t.Helper()
	k := newKEK(t, s, "orders")

	// Version numbers need not be consecutive: a managed provider assigns them.
	for _, v := range []uint32{1, 2, 4, 8} {
		addVersion(t, s, k, v)
	}
	list, err := s.ListVersions(bg, k.ID)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	var got []uint32
	for _, r := range list {
		got = append(got, r.Version)
		if r.State != registry.VersionPending {
			t.Errorf("version %d is %s, want pending", r.Version, r.State)
		}
	}
	if !slices.Equal(got, []uint32{1, 2, 4, 8}) {
		t.Fatalf("ListVersions = %v, want ascending 1 2 4 8", got)
	}

	rec, err := s.GetVersion(bg, k.ID, 4)
	if err != nil || rec.ProviderRef != "v4" || rec.KEKID != k.ID {
		t.Errorf("GetVersion = %+v, %v", rec, err)
	}
	if _, err := s.GetVersion(bg, k.ID, 3); !errors.Is(err, registry.ErrVersionNotFound) {
		t.Errorf("GetVersion of a missing version = %v, want ErrVersionNotFound", err)
	}

	for _, v := range []uint32{8, 5, 1} {
		err := s.AddVersion(bg, registry.VersionRecord{KEKID: k.ID, Version: v, State: registry.VersionPending})
		if !errors.Is(err, registry.ErrVersionExists) {
			t.Errorf("AddVersion(%d) = %v, want ErrVersionExists", v, err)
		}
	}
	for name, bad := range map[string]registry.VersionRecord{
		"version zero": {KEKID: k.ID, Version: 0, State: registry.VersionPending},
		"not pending":  {KEKID: k.ID, Version: 9, State: registry.VersionActive},
	} {
		if err := s.AddVersion(bg, bad); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("%s: AddVersion = %v, want ErrInvalid", name, err)
		}
	}
}

func caseActivateFirst(t TB, s registry.Store) {
	t.Helper()
	k := newKEK(t, s, "orders")
	addVersion(t, s, k, 1)
	activate(t, s, k, 1, 5)

	kv, err := s.ActiveKEK(bg, "orders")
	if err != nil || kv.Version != 1 || kv.Ref != k.Ref() {
		t.Fatalf("ActiveKEK = %+v, %v", kv, err)
	}
	if stateOf(t, s, k, 1) != registry.VersionActive {
		t.Errorf("version 1 is not active")
	}
}

func caseActivationDemotes(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	addVersion(t, s, k, 2)
	activate(t, s, k, 2, 10)

	v1, err := s.GetVersion(bg, k.ID, 1)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if v1.State != registry.VersionDecryptOnly || !v1.RotatedAt.Equal(at(10)) {
		t.Errorf("version 1 = %s rotated %v, want decrypt-only rotated at the activation", v1.State, v1.RotatedAt)
	}
	if stateOf(t, s, k, 2) != registry.VersionActive {
		t.Errorf("version 2 is not active")
	}
	kv, err := s.ActiveKEK(bg, "orders")
	if err != nil || kv.Version != 2 {
		t.Errorf("ActiveKEK = %+v, %v, want version 2", kv, err)
	}
	assertOneActive(t, s, k)
}

func assertOneActive(t TB, s registry.Store, k registry.KEK) {
	t.Helper()
	list, err := s.ListVersions(bg, k.ID)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	n := 0
	for _, r := range list {
		if r.State == registry.VersionActive {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d versions are active, want exactly one: %+v", n, list)
	}
}

func caseRollback(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	for v := uint32(2); v <= 3; v++ {
		addVersion(t, s, k, v)
		activate(t, s, k, v, int(v)*10)
	}
	// 1 and 2 are decrypt-only, 3 is active. Only 2 is the most recent.
	err := s.TransitionVersion(bg, k.ID, 1, registry.VersionActive, registry.TransitionOptions{At: at(50)})
	if !errors.Is(err, registry.ErrNoRollbackTarget) {
		t.Errorf("rollback to version 1 = %v, want ErrNoRollbackTarget", err)
	}
	if stateOf(t, s, k, 3) != registry.VersionActive {
		t.Errorf("a refused rollback changed the active version")
	}

	transition(t, s, k, 2, registry.VersionActive, registry.TransitionOptions{At: at(60)})
	if stateOf(t, s, k, 2) != registry.VersionActive || stateOf(t, s, k, 3) != registry.VersionDecryptOnly {
		t.Errorf("after rollback version 2 is %s and version 3 is %s", stateOf(t, s, k, 2), stateOf(t, s, k, 3))
	}
	assertOneActive(t, s, k)
	if kv, err := s.ActiveKEK(bg, "orders"); err != nil || kv.Version != 2 {
		t.Errorf("ActiveKEK after rollback = %+v, %v", kv, err)
	}
}

func caseNoDirectDemotion(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	err := s.TransitionVersion(bg, k.ID, 1, registry.VersionDecryptOnly, registry.TransitionOptions{At: at(5)})
	if !errors.Is(err, registry.ErrInvalidTransition) {
		t.Errorf("demoting the active version directly = %v, want ErrInvalidTransition", err)
	}
	if stateOf(t, s, k, 1) != registry.VersionActive {
		t.Errorf("the active version was demoted")
	}
}

// reach builds a KEK whose version 1 is in the wanted state; for decrypt-only
// and later states a second version is active.
func reach(t TB, s registry.Store, want registry.VersionState) registry.KEK {
	t.Helper()
	k := newKEK(t, s, keyforge.Purpose(fmt.Sprintf("m-%s-%d", want, counter.Add(1))))
	addVersion(t, s, k, 1)
	if want == registry.VersionPending {
		return k
	}
	activate(t, s, k, 1, 1)
	if want == registry.VersionActive {
		return k
	}
	if want == registry.VersionCompromised {
		transition(t, s, k, 1, registry.VersionCompromised, registry.TransitionOptions{At: at(2)})
		return k
	}
	addVersion(t, s, k, 2)
	activate(t, s, k, 2, 2)
	if want == registry.VersionDecryptOnly {
		return k
	}
	transition(t, s, k, 1, registry.VersionRetireRequested, registry.TransitionOptions{At: at(3), RetireAfter: at(10)})
	if want == registry.VersionRetireRequested {
		return k
	}
	transition(t, s, k, 1, registry.VersionRetired, registry.TransitionOptions{At: at(11)})
	if want == registry.VersionRetired {
		return k
	}
	transition(t, s, k, 1, registry.VersionDestroyed, registry.TransitionOptions{At: at(12)})
	return k
}

// caseTransitionMatrix tries every forbidden target from every state and
// requires a typed refusal that leaves the record alone.
func caseTransitionMatrix(t TB, s registry.Store) {
	t.Helper()
	for _, from := range registry.VersionStates {
		for _, to := range registry.VersionStates {
			if registry.CanTransition(from, to) {
				continue
			}
			k := reach(t, s, from)
			const v = 1
			err := s.TransitionVersion(bg, k.ID, v, to, registry.TransitionOptions{At: at(30), RetireAfter: at(40)})
			if !errors.Is(err, registry.ErrInvalidTransition) {
				t.Errorf("%s to %s = %v, want ErrInvalidTransition", from, to, err)
				continue
			}
			if got := stateOf(t, s, k, v); got != from {
				t.Errorf("%s to %s was refused but the state became %s", from, to, got)
			}
		}
	}
}

func caseRetirement(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	addVersion(t, s, k, 2)
	activate(t, s, k, 2, 2)

	// A data key is wrapped under version 1.
	rec := advance(t, s, dekRecord(k, 1, "orders", "", 1), 0)

	badOpts := registry.TransitionOptions{At: at(3), RetireAfter: at(3)}
	if err := s.TransitionVersion(bg, k.ID, 1, registry.VersionRetireRequested, badOpts); !errors.Is(err, registry.ErrInvalid) {
		t.Errorf("a retire-after that is not later than now: %v, want ErrInvalid", err)
	}
	if err := s.TransitionVersion(bg, k.ID, 1, registry.VersionRetireRequested, registry.TransitionOptions{At: at(3)}); !errors.Is(err, registry.ErrInvalid) {
		t.Errorf("no retire-after: %v, want ErrInvalid", err)
	}
	transition(t, s, k, 1, registry.VersionRetireRequested, registry.TransitionOptions{At: at(3), RetireAfter: at(60)})

	if err := s.TransitionVersion(bg, k.ID, 1, registry.VersionRetired, registry.TransitionOptions{At: at(59)}); !errors.Is(err, registry.ErrRetireDelay) {
		t.Errorf("retiring before the delay: %v, want ErrRetireDelay", err)
	}
	if err := s.TransitionVersion(bg, k.ID, 1, registry.VersionRetired, registry.TransitionOptions{At: at(60)}); !errors.Is(err, registry.ErrVersionReferenced) {
		t.Errorf("retiring while referenced: %v, want ErrVersionReferenced", err)
	}
	if stateOf(t, s, k, 1) != registry.VersionRetireRequested {
		t.Errorf("a refused retirement changed the state")
	}

	// Re-wrapping the key to the active version drops the reference.
	err := s.RewrapDEK(bg, registry.Rewrap{ID: rec.ID, FromKEKID: k.ID, FromVersion: 1, ToKEKID: k.ID, ToVersion: 2, Wrapped: []byte{9}})
	if err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}
	transition(t, s, k, 1, registry.VersionRetired, registry.TransitionOptions{At: at(60)})
	transition(t, s, k, 1, registry.VersionDestroyed, registry.TransitionOptions{At: at(61)})
	if stateOf(t, s, k, 1) != registry.VersionDestroyed {
		t.Errorf("version 1 is %s, want destroyed", stateOf(t, s, k, 1))
	}
}

func caseCancelRetirement(t TB, s registry.Store) {
	t.Helper()
	k := reach(t, s, registry.VersionRetireRequested)
	const v = 1
	transition(t, s, k, v, registry.VersionDecryptOnly, registry.TransitionOptions{At: at(4)})

	rec, err := s.GetVersion(bg, k.ID, v)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if rec.State != registry.VersionDecryptOnly || !rec.RetireAfter.IsZero() {
		t.Errorf("after cancelling: %s with retire-after %v, want decrypt-only and none", rec.State, rec.RetireAfter)
	}
	// It can be requested again, with a fresh delay.
	transition(t, s, k, v, registry.VersionRetireRequested, registry.TransitionOptions{At: at(5), RetireAfter: at(90)})
	rec, err = s.GetVersion(bg, k.ID, v)
	if err != nil || !rec.RetireAfter.Equal(at(90)) {
		t.Errorf("retire-after = %v, %v, want the new delay", rec.RetireAfter, err)
	}
}

func caseCompromisedActive(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	rec := advance(t, s, dekRecord(k, 1, "orders", "", 1), 0)
	transition(t, s, k, 1, registry.VersionCompromised, registry.TransitionOptions{At: at(5)})

	if _, err := s.ActiveKEK(bg, "orders"); !errors.Is(err, keyforge.ErrNoActiveKEK) {
		t.Errorf("ActiveKEK with the only version compromised = %v, want ErrNoActiveKEK", err)
	}
	addVersion(t, s, k, 2)
	activate(t, s, k, 2, 6)
	if kv, err := s.ActiveKEK(bg, "orders"); err != nil || kv.Version != 2 {
		t.Errorf("ActiveKEK after replacing it = %+v, %v", kv, err)
	}

	// Emergency retirement needs no delay, but still needs nothing referencing it.
	if err := s.TransitionVersion(bg, k.ID, 1, registry.VersionRetired, registry.TransitionOptions{At: at(7)}); !errors.Is(err, registry.ErrVersionReferenced) {
		t.Errorf("retiring a compromised version that is referenced = %v, want ErrVersionReferenced", err)
	}
	err := s.RewrapDEK(bg, registry.Rewrap{ID: rec.ID, FromKEKID: k.ID, FromVersion: 1, ToKEKID: k.ID, ToVersion: 2, Wrapped: []byte{7}})
	if err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}
	transition(t, s, k, 1, registry.VersionRetired, registry.TransitionOptions{At: at(8)})
}

func caseAdvanceDEK(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")

	first := dekRecord(k, 1, "orders", "", 1)
	first.Reserved = 99 // not the caller's to set
	got := advance(t, s, first, 0)
	if got.ID != first.ID || got.State != keyforge.DEKActive || got.Reserved != 0 {
		t.Fatalf("first AdvanceDEK = %+v, want the record, active, with nothing reserved", got)
	}
	if cur, err := s.CurrentDEK(bg, "orders", ""); err != nil || cur.ID != first.ID {
		t.Fatalf("CurrentDEK = %+v, %v", cur, err)
	}

	// A writer that also saw "no key" loses and is handed the winner.
	loser := dekRecord(k, 1, "orders", "", 1)
	if got := advance(t, s, loser, 0); got.ID != first.ID {
		t.Errorf("a losing AdvanceDEK returned %s, want the winner %s", got.ID, first.ID)
	}
	if _, err := s.GetDEK(bg, loser.ID); !errors.Is(err, keyforge.ErrDEKNotFound) {
		t.Errorf("the losing record was stored: %v", err)
	}

	second := advance(t, s, dekRecord(k, 1, "orders", "", 2), 1)
	if prev, err := s.GetDEK(bg, first.ID); err != nil || prev.State != keyforge.DEKDecryptOnly {
		t.Errorf("the previous key = %+v, %v, want decrypt-only", prev, err)
	}
	stale := dekRecord(k, 1, "orders", "", 2)
	if got := advance(t, s, stale, 1); got.ID != second.ID {
		t.Errorf("advancing from a stale epoch returned %s, want %s", got.ID, second.ID)
	}

	// Subjects have epochs of their own.
	subj := advance(t, s, dekRecord(k, 1, "orders", "alice", 1), 0)
	if cur, err := s.CurrentDEK(bg, "orders", "alice"); err != nil || cur.ID != subj.ID || cur.Epoch != 1 {
		t.Errorf("subject CurrentDEK = %+v, %v", cur, err)
	}
	if cur, _ := s.CurrentDEK(bg, "orders", ""); cur.ID != second.ID {
		t.Errorf("a subject's key replaced the purpose's current key")
	}

	for name, bad := range map[string]keyforge.DEKRecord{
		"epoch not from+1":  dekRecord(k, 1, "orders", "", 9),
		"wrong subject":     dekRecord(k, 1, "orders", "bob", 3),
		"purpose not KEK's": dekRecord(k, 1, "payments", "", 3),
	} {
		if _, err := s.AdvanceDEK(bg, "orders", "", 2, bad); err == nil {
			t.Errorf("%s: AdvanceDEK accepted the record", name)
		}
	}
	// A data key's purpose is its KEK's purpose, whatever scope it is filed under.
	if _, err := s.AdvanceDEK(bg, "payments", "", 0, dekRecord(k, 1, "payments", "", 1)); !errors.Is(err, registry.ErrInvalid) {
		t.Errorf("a data key under another purpose's KEK = %v, want ErrInvalid", err)
	}
	if _, err := s.AdvanceDEK(bg, "orders", "carol", 4, dekRecord(k, 1, "orders", "carol", 5)); err == nil {
		t.Errorf("advancing from an epoch that does not exist was accepted")
	}
	if _, err := s.CurrentDEK(bg, "orders", "nobody"); !errors.Is(err, keyforge.ErrDEKNotFound) {
		t.Errorf("CurrentDEK for an unknown subject = %v, want ErrDEKNotFound", err)
	}
}

func caseAdvanceNeedsVersion(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	addVersion(t, s, k, 2) // pending

	rec := dekRecord(k, 2, "orders", "", 1)
	if _, err := s.AdvanceDEK(bg, "orders", "", 0, rec); !errors.Is(err, registry.ErrVersionUnusable) {
		t.Errorf("wrapping under a pending version = %v, want ErrVersionUnusable", err)
	}
	rec = dekRecord(k, 9, "orders", "", 1)
	if _, err := s.AdvanceDEK(bg, "orders", "", 0, rec); !errors.Is(err, registry.ErrVersionNotFound) && !errors.Is(err, registry.ErrVersionUnusable) {
		t.Errorf("wrapping under an unknown version = %v", err)
	}
	other := dekRecord(k, 1, "orders", "", 1)
	other.KEKID = nextID()
	if _, err := s.AdvanceDEK(bg, "orders", "", 0, other); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("wrapping under an unknown KEK = %v, want ErrKEKNotFound", err)
	}

	// A client with a cached view may still wrap under a version that has just
	// been rotated out; the re-wrap job moves it later.
	activate(t, s, k, 2, 5)
	if _, err := s.AdvanceDEK(bg, "orders", "", 0, dekRecord(k, 1, "orders", "", 1)); err != nil {
		t.Errorf("wrapping under a decrypt-only version = %v, want it accepted", err)
	}

	transition(t, s, k, 1, registry.VersionRetireRequested, registry.TransitionOptions{At: at(6), RetireAfter: at(7)})
	if _, err := s.AdvanceDEK(bg, "orders", "other", 0, dekRecord(k, 1, "orders", "other", 1)); !errors.Is(err, registry.ErrVersionUnusable) {
		t.Errorf("wrapping under a retire-requested version = %v, want ErrVersionUnusable", err)
	}
}

func caseAdvanceKeepsCompromised(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	first := advance(t, s, dekRecord(k, 1, "orders", "", 1), 0)
	if err := s.MarkDEK(bg, first.ID, keyforge.DEKCompromised); err != nil {
		t.Fatalf("MarkDEK: %v", err)
	}
	second := advance(t, s, dekRecord(k, 1, "orders", "", 2), 1)

	if prev, err := s.GetDEK(bg, first.ID); err != nil || prev.State != keyforge.DEKCompromised {
		t.Errorf("the compromised key = %+v, %v, want it to stay compromised", prev, err)
	}
	if second.State != keyforge.DEKActive {
		t.Errorf("the new key is %s", second.State)
	}
}

func caseAdvanceConcurrent(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")

	const writers = 16
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ids  = map[envelope.ID]int{}
		errs []error
	)
	for range writers {
		rec := dekRecord(k, 1, "orders", "", 1)
		wg.Go(func() {
			got, err := s.AdvanceDEK(bg, "orders", "", 0, rec)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			ids[got.ID]++
		})
	}
	wg.Wait()
	for _, err := range errs {
		t.Errorf("AdvanceDEK: %v", err)
	}
	if len(ids) != 1 {
		t.Errorf("%d different records were returned as the winner, want one: %v", len(ids), ids)
	}
	list, err := s.ListDEKs(bg, registry.DEKFilter{Purpose: "orders"})
	if err != nil || len(list) != 1 {
		t.Errorf("%d records stored, %v, want exactly one", len(list), err)
	}
}

func caseReserve(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	rec := advance(t, s, dekRecord(k, 1, "orders", "", 1), 0)

	steps := []struct{ n, limit, want uint64 }{
		{4, 10, 4}, {4, 10, 4},
		{4, 10, 2}, // the last block is partial: never past the limit
		{4, 10, 0}, {4, 10, 0},
	}
	for i, st := range steps {
		got, err := s.ReserveEncryptions(bg, rec.ID, st.n, st.limit)
		if err != nil || got != st.want {
			t.Fatalf("step %d: granted %d, %v, want %d", i, got, err, st.want)
		}
	}
	if r, err := s.GetDEK(bg, rec.ID); err != nil || r.Reserved != 10 {
		t.Errorf("Reserved = %d, %v, want 10", r.Reserved, err)
	}

	// A key that is no longer current is granted nothing, which tells the
	// caller to advance.
	advance(t, s, dekRecord(k, 1, "orders", "", 2), 1)
	if got, err := s.ReserveEncryptions(bg, rec.ID, 4, 100); err != nil || got != 0 {
		t.Errorf("a replaced key was granted %d, %v", got, err)
	}
	if _, err := s.ReserveEncryptions(bg, nextID(), 1, 10); !errors.Is(err, keyforge.ErrDEKNotFound) {
		t.Errorf("reserving on an unknown key = %v, want ErrDEKNotFound", err)
	}
}

func caseReserveConcurrent(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	rec := advance(t, s, dekRecord(k, 1, "orders", "", 1), 0)

	const limit = 1000
	var (
		wg    sync.WaitGroup
		total atomic.Uint64
	)
	for range 16 {
		wg.Go(func() {
			for {
				n, err := s.ReserveEncryptions(bg, rec.ID, 7, limit)
				if err != nil || n == 0 {
					return
				}
				total.Add(n)
			}
		})
	}
	wg.Wait()
	if got := total.Load(); got != limit {
		t.Errorf("granted %d in total, want exactly %d: the cap does not hold across callers", got, limit)
	}
}

func caseListDEKs(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	var all []envelope.ID
	for i := range 12 {
		rec := advance(t, s, dekRecord(k, 1, "orders", fmt.Sprintf("s%02d", i), 1), 0)
		all = append(all, rec.ID)
	}
	addVersion(t, s, k, 2)
	activate(t, s, k, 2, 5)
	var v2 []envelope.ID
	for i := range 8 {
		rec := advance(t, s, dekRecord(k, 2, "orders", fmt.Sprintf("t%02d", i), 1), 0)
		all = append(all, rec.ID)
		v2 = append(v2, rec.ID)
	}
	pay := kekWithActive(t, s, "payments")
	for i := range 5 {
		all = append(all, advance(t, s, dekRecord(pay, 1, "payments", fmt.Sprintf("p%02d", i), 1), 0).ID)
	}
	byID := func(a, b envelope.ID) int { return bytes.Compare(a[:], b[:]) }
	slices.SortFunc(all, byID)
	slices.SortFunc(v2, byID)

	page := func(f registry.DEKFilter) []envelope.ID {
		var out []envelope.ID
		for range 100 {
			recs, err := s.ListDEKs(bg, f)
			if err != nil {
				t.Fatalf("ListDEKs: %v", err)
			}
			if len(recs) > f.PageSize() {
				t.Fatalf("a page of %d exceeds the limit %d", len(recs), f.PageSize())
			}
			if len(recs) == 0 {
				return out
			}
			for _, r := range recs {
				out = append(out, r.ID)
			}
			f.After = recs[len(recs)-1].ID
		}
		t.Fatalf("paging did not finish")
		return nil
	}

	if got := page(registry.DEKFilter{Limit: 7}); !slices.Equal(got, all) {
		t.Errorf("paging with a limit of 7 gave %d records, want all %d once each in identifier order", len(got), len(all))
	}
	if got := page(registry.DEKFilter{KEKID: k.ID, KEKVersion: 2, Limit: 3}); !slices.Equal(got, v2) {
		t.Errorf("filter by KEK version 2 gave %d records, want %d", len(got), len(v2))
	}
	if got := page(registry.DEKFilter{KEKID: k.ID}); len(got) != 20 {
		t.Errorf("filter by KEK gave %d records, want 20", len(got))
	}
	if got := page(registry.DEKFilter{Purpose: "payments"}); len(got) != 5 {
		t.Errorf("filter by purpose gave %d records, want 5", len(got))
	}
	if got := page(registry.DEKFilter{KEKID: nextID()}); len(got) != 0 {
		t.Errorf("filter by an unknown KEK gave %d records", len(got))
	}
}

func caseCountDEKs(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	first := advance(t, s, dekRecord(k, 1, "orders", "", 1), 0)
	advance(t, s, dekRecord(k, 1, "orders", "x", 1), 0)
	advance(t, s, dekRecord(k, 1, "orders", "", 2), 1) // demotes first

	count := func(v uint32) int {
		n, err := s.CountDEKs(bg, k.ID, v)
		if err != nil {
			t.Fatalf("CountDEKs: %v", err)
		}
		return n
	}
	if got := count(1); got != 3 {
		t.Errorf("CountDEKs = %d, want 3", got)
	}
	if got := count(2); got != 0 {
		t.Errorf("CountDEKs for an unused version = %d, want 0", got)
	}
	// A destroyed data key no longer references the version.
	if err := s.MarkDEK(bg, first.ID, keyforge.DEKDestroyed); err != nil {
		t.Fatalf("MarkDEK: %v", err)
	}
	if got := count(1); got != 2 {
		t.Errorf("CountDEKs after destroying one = %d, want 2", got)
	}
}

func caseRewrap(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	addVersion(t, s, k, 2)
	rec := advance(t, s, dekRecord(k, 1, "orders", "", 1), 0)

	move := registry.Rewrap{ID: rec.ID, FromKEKID: k.ID, FromVersion: 1, ToKEKID: k.ID, ToVersion: 2, Wrapped: []byte{0xAA, 0xBB}}
	// Version 2 is pending, so nothing may be wrapped under it yet.
	if err := s.RewrapDEK(bg, move); !errors.Is(err, registry.ErrVersionUnusable) {
		t.Errorf("rewrapping to a pending version = %v, want ErrVersionUnusable", err)
	}
	activate(t, s, k, 2, 5)

	wrongFrom := move
	wrongFrom.FromVersion = 7
	if err := s.RewrapDEK(bg, wrongFrom); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("rewrapping from the wrong version = %v, want ErrConflict", err)
	}
	if err := s.RewrapDEK(bg, move); err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}
	got, err := s.GetDEK(bg, rec.ID)
	if err != nil || got.KEKVersion != 2 || !bytes.Equal(got.Wrapped, []byte{0xAA, 0xBB}) || got.KEKID != k.ID {
		t.Fatalf("after rewrap = %+v, %v", got, err)
	}
	if got.State != rec.State || got.Epoch != rec.Epoch || got.Reserved != rec.Reserved {
		t.Errorf("a rewrap changed more than the wrapping: %+v", got)
	}
	// Repeating a completed rewrap is safe, so a resumed job can retry.
	if err := s.RewrapDEK(bg, move); err != nil {
		t.Errorf("repeating a completed rewrap = %v, want success", err)
	}
	// A different outcome for the same record is a conflict, not a success.
	other := move
	other.Wrapped = []byte{1}
	if err := s.RewrapDEK(bg, other); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("a conflicting rewrap = %v, want ErrConflict", err)
	}
	unknown := move
	unknown.ID = nextID()
	if err := s.RewrapDEK(bg, unknown); !errors.Is(err, keyforge.ErrDEKNotFound) {
		t.Errorf("rewrapping an unknown key = %v, want ErrDEKNotFound", err)
	}
	if n, _ := s.CountDEKs(bg, k.ID, 1); n != 0 {
		t.Errorf("%d keys still reference version 1", n)
	}
}

func caseMarkDEK(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	cur := advance(t, s, dekRecord(k, 1, "orders", "", 1), 0)

	// A current key is demoted by advancing, never directly.
	for _, to := range []keyforge.DEKState{keyforge.DEKDecryptOnly, keyforge.DEKDestroyed, keyforge.DEKActive} {
		if err := s.MarkDEK(bg, cur.ID, to); !errors.Is(err, registry.ErrInvalidTransition) {
			t.Errorf("active to %s = %v, want ErrInvalidTransition", to, err)
		}
	}
	if err := s.MarkDEK(bg, cur.ID, keyforge.DEKCompromised); err != nil {
		t.Errorf("active to compromised = %v", err)
	}
	if err := s.MarkDEK(bg, cur.ID, keyforge.DEKDestroyed); err != nil {
		t.Errorf("compromised to destroyed = %v", err)
	}
	if err := s.MarkDEK(bg, cur.ID, keyforge.DEKCompromised); !errors.Is(err, registry.ErrInvalidTransition) {
		t.Errorf("destroyed to compromised = %v, want ErrInvalidTransition", err)
	}
	if err := s.MarkDEK(bg, nextID(), keyforge.DEKCompromised); !errors.Is(err, keyforge.ErrDEKNotFound) {
		t.Errorf("MarkDEK on an unknown key = %v, want ErrDEKNotFound", err)
	}
}

func caseActivationConcurrent(t TB, s registry.Store) {
	t.Helper()
	k := newKEK(t, s, "orders")
	const n = 8
	for v := uint32(1); v <= n; v++ {
		addVersion(t, s, k, v)
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for v := uint32(1); v <= n; v++ {
		wg.Go(func() {
			err := s.TransitionVersion(bg, k.ID, v, registry.VersionActive, registry.TransitionOptions{At: at(int(v))})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		t.Errorf("activation: %v", err)
	}
	assertOneActive(t, s, k)
	list, err := s.ListVersions(bg, k.ID)
	if err != nil {
		t.Fatalf("%v", err)
	}
	decryptOnly := 0
	for _, r := range list {
		if r.State == registry.VersionDecryptOnly {
			decryptOnly++
		}
	}
	if decryptOnly != n-1 {
		t.Errorf("%d versions are decrypt-only, want %d", decryptOnly, n-1)
	}
}

func caseCopies(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	rec := advance(t, s, dekRecord(k, 1, "orders", "", 1), 0)
	want := bytes.Clone(rec.Wrapped)

	got, err := s.GetDEK(bg, rec.ID)
	if err != nil {
		t.Fatalf("%v", err)
	}
	got.Wrapped[0] ^= 0xFF
	cur, err := s.CurrentDEK(bg, "orders", "")
	if err != nil {
		t.Fatalf("%v", err)
	}
	cur.Wrapped[0] ^= 0xFF
	list, err := s.ListDEKs(bg, registry.DEKFilter{})
	if err != nil || len(list) != 1 {
		t.Fatalf("ListDEKs = %v, %v", list, err)
	}
	list[0].Wrapped[0] ^= 0xFF

	again, err := s.GetDEK(bg, rec.ID)
	if err != nil || !bytes.Equal(again.Wrapped, want) {
		t.Errorf("a returned record shares its wrapped key with the store")
	}

	versions, err := s.ListVersions(bg, k.ID)
	if err != nil {
		t.Fatalf("%v", err)
	}
	versions[0].State = registry.VersionDestroyed
	if stateOf(t, s, k, 1) != registry.VersionActive {
		t.Errorf("a returned version record is shared with the store")
	}
}

func caseCancelled(t TB, s registry.Store) {
	t.Helper()
	ctx, cancel := context.WithCancel(bg)
	cancel()

	k := registry.KEK{ID: nextID(), Purpose: "orders", Provider: "p", ProviderRef: "r", State: registry.KeyActive, CreatedAt: at(0)}
	if err := s.CreateKEK(ctx, k); !errors.Is(err, context.Canceled) {
		t.Errorf("CreateKEK = %v, want context.Canceled", err)
	}
	if _, err := s.GetKEK(bg, k.ID); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("a cancelled CreateKEK created the key: %v", err)
	}

	live := kekWithActive(t, s, "payments")
	if err := s.AddVersion(ctx, registry.VersionRecord{KEKID: live.ID, Version: 2, State: registry.VersionPending}); !errors.Is(err, context.Canceled) {
		t.Errorf("AddVersion = %v, want context.Canceled", err)
	}
	if _, err := s.GetVersion(bg, live.ID, 2); !errors.Is(err, registry.ErrVersionNotFound) {
		t.Errorf("a cancelled AddVersion added the version: %v", err)
	}
	if err := s.TransitionVersion(ctx, live.ID, 1, registry.VersionCompromised, registry.TransitionOptions{At: at(9)}); !errors.Is(err, context.Canceled) {
		t.Errorf("TransitionVersion = %v, want context.Canceled", err)
	}
	if stateOf(t, s, live, 1) != registry.VersionActive {
		t.Errorf("a cancelled transition changed the state")
	}
	rec := dekRecord(live, 1, "payments", "", 1)
	if _, err := s.AdvanceDEK(ctx, "payments", "", 0, rec); !errors.Is(err, context.Canceled) {
		t.Errorf("AdvanceDEK = %v, want context.Canceled", err)
	}
	if _, err := s.CurrentDEK(bg, "payments", ""); !errors.Is(err, keyforge.ErrDEKNotFound) {
		t.Errorf("a cancelled AdvanceDEK stored a key: %v", err)
	}
}

func caseActivationTime(t TB, s registry.Store) {
	t.Helper()
	k := newKEK(t, s, "orders")
	addVersion(t, s, k, 1)
	addVersion(t, s, k, 2)

	v, err := s.GetVersion(bg, k.ID, 1)
	if err != nil || !v.ActivatedAt.IsZero() {
		t.Fatalf("a pending version has ActivatedAt %v, %v", v.ActivatedAt, err)
	}
	activate(t, s, k, 1, 10)
	activate(t, s, k, 2, 20)
	v1, _ := s.GetVersion(bg, k.ID, 1)
	v2, _ := s.GetVersion(bg, k.ID, 2)
	if !v1.ActivatedAt.Equal(at(10)) || !v2.ActivatedAt.Equal(at(20)) {
		t.Errorf("ActivatedAt = %v and %v, want the activation times", v1.ActivatedAt, v2.ActivatedAt)
	}
	if !v1.RotatedAt.Equal(at(20)) {
		t.Errorf("version 1 RotatedAt = %v, want when version 2 took over", v1.RotatedAt)
	}
	// A rollback is an activation: the interval is measured from it.
	transition(t, s, k, 1, registry.VersionActive, registry.TransitionOptions{At: at(30)})
	v1, _ = s.GetVersion(bg, k.ID, 1)
	if !v1.ActivatedAt.Equal(at(30)) {
		t.Errorf("after a rollback ActivatedAt = %v, want %v", v1.ActivatedAt, at(30))
	}
}

func caseSentinels(t TB, s registry.Store) {
	t.Helper()
	k := kekWithActive(t, s, "orders")
	addVersion(t, s, k, 2)

	if _, err := s.GetSentinel(bg, k.ID, 1); !errors.Is(err, registry.ErrSentinelNotFound) {
		t.Errorf("GetSentinel before one is stored = %v, want ErrSentinelNotFound", err)
	}
	one := registry.Sentinel{KEKID: k.ID, Version: 1, Envelope: "kf1.AAAA", CreatedAt: at(1)}
	if err := s.PutSentinel(bg, one); err != nil {
		t.Fatalf("PutSentinel: %v", err)
	}
	if err := s.PutSentinel(bg, one); err != nil {
		t.Errorf("storing the same sentinel again = %v, want success", err)
	}
	other := one
	other.Envelope = "kf1.BBBB"
	if err := s.PutSentinel(bg, other); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("storing a different sentinel = %v, want ErrConflict", err)
	}
	if err := s.PutSentinel(bg, registry.Sentinel{KEKID: k.ID, Version: 9, Envelope: "kf1.CCCC"}); !errors.Is(err, registry.ErrVersionNotFound) {
		t.Errorf("a sentinel for a missing version = %v, want ErrVersionNotFound", err)
	}
	if err := s.PutSentinel(bg, registry.Sentinel{KEKID: nextID(), Version: 1, Envelope: "kf1.CCCC"}); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("a sentinel for a missing KEK = %v, want ErrKEKNotFound", err)
	}
	if err := s.PutSentinel(bg, registry.Sentinel{KEKID: k.ID, Version: 2}); !errors.Is(err, registry.ErrInvalid) {
		t.Errorf("a sentinel with no envelope = %v, want ErrInvalid", err)
	}

	if err := s.PutSentinel(bg, registry.Sentinel{KEKID: k.ID, Version: 2, Envelope: "kf1.DDDD", CreatedAt: at(2)}); err != nil {
		t.Fatalf("%v", err)
	}
	got, err := s.GetSentinel(bg, k.ID, 1)
	if err != nil || got != one {
		t.Errorf("GetSentinel = %+v, %v, want %+v", got, err, one)
	}
	list, err := s.ListSentinels(bg, k.ID)
	if err != nil || len(list) != 2 || list[0].Version != 1 || list[1].Version != 2 {
		t.Errorf("ListSentinels = %+v, %v, want versions 1 then 2", list, err)
	}
	if _, err := s.ListSentinels(bg, nextID()); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("ListSentinels for an unknown KEK = %v", err)
	}
}

// caseUsable checks the client's view of a version: usable exactly in the
// states the specification allows to unwrap, whatever the provider holds.
func caseUsable(t TB, s registry.Store) {
	t.Helper()
	k := newKEK(t, s, "orders")
	usable := func(v uint32) bool {
		t.Helper()
		ok, err := s.KEKVersionUsable(bg, k.ID, v)
		if err != nil {
			t.Fatalf("KEKVersionUsable(%d): %v", v, err)
		}
		return ok
	}
	addVersion(t, s, k, 1)
	if usable(1) {
		t.Errorf("a pending version is usable")
	}
	activate(t, s, k, 1, 1)
	if !usable(1) {
		t.Errorf("an active version is not usable")
	}
	addVersion(t, s, k, 2)
	activate(t, s, k, 2, 2)
	if !usable(1) {
		t.Errorf("a decrypt-only version is not usable")
	}
	transition(t, s, k, 1, registry.VersionRetireRequested, registry.TransitionOptions{At: at(3), RetireAfter: at(4)})
	if !usable(1) {
		t.Errorf("a retire-requested version is not usable")
	}
	transition(t, s, k, 1, registry.VersionRetired, registry.TransitionOptions{At: at(5)})
	if usable(1) {
		t.Errorf("a retired version is usable")
	}
	transition(t, s, k, 1, registry.VersionDestroyed, registry.TransitionOptions{At: at(6)})
	if usable(1) {
		t.Errorf("a destroyed version is usable")
	}
	if usable(99) {
		t.Errorf("a version that does not exist is usable")
	}
	if _, err := s.KEKVersionUsable(bg, nextID(), 1); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Errorf("KEKVersionUsable for an unknown KEK = %v, want ErrKEKNotFound", err)
	}
}
