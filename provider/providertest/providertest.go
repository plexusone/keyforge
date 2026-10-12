// Package providertest is the conformance suite every [provider.Provider]
// must pass. A provider's own tests call [Run] with a constructor.
//
//	func TestConformance(t *testing.T) {
//		providertest.Run(t, func() provider.Provider { return newTestProvider() })
//	}
//
// The suite checks the contract on the Provider interface: version handling,
// binding of the additional data, typed errors, context cancellation, that
// inputs are not retained, that errors carry no key material, and concurrent
// use. It uses only the interface, so it applies to a local keyring and to a
// managed service alike.
package providertest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
)

// TB is the part of [testing.TB] the suite uses, so the suite can also run
// against a recorder to show that it rejects a broken provider.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
}

// Case is one conformance check. It runs against a fresh provider.
type Case struct {
	Name string
	Run  func(t TB, p provider.Provider)
}

// Run runs every case as a subtest, each against a provider from newProvider.
func Run(t *testing.T, newProvider func() provider.Provider) {
	t.Helper()
	for _, c := range Cases() {
		t.Run(c.Name, func(t *testing.T) {
			t.Helper()
			c.Run(t, newProvider())
		})
	}
}

// Cases returns the conformance cases.
func Cases() []Case {
	return []Case{
		{"Name", caseName},
		{"Health", caseHealth},
		{"CreateKey", caseCreateKey},
		{"CreateKeyHonorsSpecID", caseCreateKeyHonorsID},
		{"CreateKeyRejectsInvalidSpec", caseCreateKeyRejectsInvalid},
		{"WrapUnwrapRoundTrip", caseRoundTrip},
		{"WrapHidesTheDataKey", caseWrapHides},
		{"UnwrapBindsAAD", caseBindsAAD},
		{"UnwrapRejectsModifiedWrappedKey", caseRejectsModified},
		{"UnwrapRejectsAnotherKey", caseRejectsAnotherKey},
		{"RotateKeepsEarlierVersions", caseRotateKeeps},
		{"RotateIsMonotonic", caseRotateMonotonic},
		{"VersionsDoNotInterchange", caseVersionsDoNotInterchange},
		{"UnknownKeyAndVersion", caseUnknown},
		{"DestroyRemovesOneVersion", caseDestroy},
		{"DestroyIsIdempotent", caseDestroyIdempotent},
		{"ContextCancellation", caseContext},
		{"ErrorsCarryNoKeyMaterial", caseErrorsNoKeyMaterial},
		{"InputsAndOutputsAreNotShared", caseNotShared},
		{"ConcurrentUse", caseConcurrent},
	}
}

var bg = context.Background()

func newKey(t TB, p provider.Provider) provider.KeyRef {
	t.Helper()
	ref, err := p.CreateKey(bg, provider.KeySpec{Purpose: "conformance", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return ref
}

func testDEK(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

func testAAD(ref provider.KeyRef) []byte {
	return []byte("purpose=conformance;key=" + ref.ID.String())
}

func mustWrap(t TB, p provider.Provider, ref provider.KeyRef, version uint32, dek, aad []byte) []byte {
	t.Helper()
	w, err := p.Wrap(bg, ref, version, dek, aad)
	if err != nil {
		t.Fatalf("Wrap(version %d): %v", version, err)
	}
	return w
}

func mustRotate(t TB, p provider.Provider, ref provider.KeyRef) uint32 {
	t.Helper()
	v, err := p.Rotate(bg, ref)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	return v
}

func isAny(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func caseName(t TB, p provider.Provider) {
	t.Helper()
	n := p.Name()
	if n == "" {
		t.Fatalf("Name is empty")
	}
	if strings.TrimSpace(n) != n {
		t.Errorf("Name %q has surrounding whitespace", n)
	}
	if p.Name() != n {
		t.Errorf("Name is not stable")
	}
}

func caseHealth(t TB, p provider.Provider) {
	t.Helper()
	if err := p.Health(bg); err != nil {
		t.Fatalf("Health on a fresh provider: %v", err)
	}
}

func caseCreateKey(t TB, p provider.Provider) {
	t.Helper()
	a, b := newKey(t, p), newKey(t, p)
	for _, ref := range []provider.KeyRef{a, b} {
		if err := ref.Validate(); err != nil {
			t.Errorf("CreateKey returned an invalid reference: %v", err)
		}
		if ref.Provider != p.Name() {
			t.Errorf("KeyRef.Provider = %q, want the provider's Name %q", ref.Provider, p.Name())
		}
	}
	if a.ID == b.ID {
		t.Errorf("two keys share the ID %s", a.ID)
	}
	if a.ProviderRef == b.ProviderRef {
		t.Errorf("two keys share the provider reference %q", a.ProviderRef)
	}
	// A new key is usable at version 1.
	dek := testDEK(1)
	w := mustWrap(t, p, a, 1, dek, testAAD(a))
	got, err := p.Unwrap(bg, a, 1, w, testAAD(a))
	if err != nil || !bytes.Equal(got, dek) {
		t.Errorf("version 1 of a new key does not round-trip: %v", err)
	}
}

func caseCreateKeyHonorsID(t TB, p provider.Provider) {
	t.Helper()
	var id envelope.ID
	for i := range id {
		id[i] = 0xE0 + byte(i)
	}
	ref, err := p.CreateKey(bg, provider.KeySpec{Purpose: "conformance", Algorithm: algorithm.AES256GCM, ID: id})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if ref.ID != id {
		t.Errorf("ID = %s, want the requested %s", ref.ID, id)
	}
}

func caseCreateKeyRejectsInvalid(t TB, p provider.Provider) {
	t.Helper()
	for _, purpose := range []string{"", "Upper", "has space", strings.Repeat("a", 256)} {
		_, err := p.CreateKey(bg, provider.KeySpec{Purpose: purpose, Algorithm: algorithm.AES256GCM})
		if !errors.Is(err, provider.ErrInvalidArgument) {
			t.Errorf("purpose %q: CreateKey = %v, want ErrInvalidArgument", purpose, err)
		}
	}
	_, err := p.CreateKey(bg, provider.KeySpec{Purpose: "conformance", Algorithm: 99})
	if !errors.Is(err, provider.ErrUnsupportedAlgorithm) {
		t.Errorf("unknown algorithm: CreateKey = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func caseRoundTrip(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	for _, n := range []int{16, 32, 64} {
		dek := bytes.Repeat([]byte{0x42}, n)
		w := mustWrap(t, p, ref, 1, dek, testAAD(ref))
		got, err := p.Unwrap(bg, ref, 1, w, testAAD(ref))
		if err != nil {
			t.Fatalf("Unwrap of a %d-byte key: %v", n, err)
		}
		if !bytes.Equal(got, dek) {
			t.Errorf("a %d-byte key came back as %x", n, got)
		}
	}
	// Absent and empty additional data are the same.
	dek := testDEK(9)
	w := mustWrap(t, p, ref, 1, dek, nil)
	if got, err := p.Unwrap(bg, ref, 1, w, []byte{}); err != nil || !bytes.Equal(got, dek) {
		t.Errorf("nil and empty aad are not equivalent: %v", err)
	}
	if _, err := p.Wrap(bg, ref, 1, nil, nil); !errors.Is(err, provider.ErrInvalidArgument) {
		t.Errorf("Wrap of an empty key = %v, want ErrInvalidArgument", err)
	}
}

func caseWrapHides(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	dek := testDEK(0x80)
	w := mustWrap(t, p, ref, 1, dek, testAAD(ref))
	if bytes.Contains(w, dek) {
		t.Errorf("the wrapped key contains the data key in the clear")
	}
	if len(w) <= len(dek) {
		t.Errorf("the wrapped key (%d bytes) is no longer than the data key (%d): no authentication data", len(w), len(dek))
	}
}

func caseBindsAAD(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	dek := testDEK(3)
	w := mustWrap(t, p, ref, 1, dek, []byte("purpose=a"))
	for _, aad := range [][]byte{[]byte("purpose=b"), []byte("purpose=a "), []byte("purpose="), nil} {
		if _, err := p.Unwrap(bg, ref, 1, w, aad); !errors.Is(err, provider.ErrUnwrapFailed) {
			t.Errorf("Unwrap with aad %q = %v, want ErrUnwrapFailed", aad, err)
		}
	}
	if got, err := p.Unwrap(bg, ref, 1, w, []byte("purpose=a")); err != nil || !bytes.Equal(got, dek) {
		t.Errorf("Unwrap with the right aad: %v", err)
	}
}

func caseRejectsModified(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	aad := testAAD(ref)
	w := mustWrap(t, p, ref, 1, testDEK(5), aad)

	for i := range w {
		bad := bytes.Clone(w)
		bad[i] ^= 0x01
		if _, err := p.Unwrap(bg, ref, 1, bad, aad); !errors.Is(err, provider.ErrUnwrapFailed) {
			t.Errorf("flipping byte %d of %d: Unwrap = %v, want ErrUnwrapFailed", i, len(w), err)
			return
		}
	}
	for n := range w {
		if _, err := p.Unwrap(bg, ref, 1, w[:n], aad); !isAny(err, provider.ErrUnwrapFailed, provider.ErrInvalidArgument) {
			t.Errorf("truncating to %d of %d bytes: Unwrap = %v, want ErrUnwrapFailed", n, len(w), err)
			return
		}
	}
	if _, err := p.Unwrap(bg, ref, 1, append(bytes.Clone(w), 0), aad); !errors.Is(err, provider.ErrUnwrapFailed) {
		t.Errorf("an appended byte: Unwrap = %v, want ErrUnwrapFailed", err)
	}
}

func caseRejectsAnotherKey(t TB, p provider.Provider) {
	t.Helper()
	a, b := newKey(t, p), newKey(t, p)
	aad := []byte("shared aad")
	w := mustWrap(t, p, a, 1, testDEK(7), aad)
	if _, err := p.Unwrap(bg, b, 1, w, aad); !errors.Is(err, provider.ErrUnwrapFailed) {
		t.Errorf("unwrapping under another key = %v, want ErrUnwrapFailed", err)
	}
}

func caseRotateKeeps(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	aad := testAAD(ref)
	oldDEK, newDEK := testDEK(0x10), testDEK(0x20)
	old := mustWrap(t, p, ref, 1, oldDEK, aad)

	v := mustRotate(t, p, ref)
	if v <= 1 {
		t.Fatalf("Rotate returned version %d, want one greater than 1", v)
	}
	if got, err := p.Unwrap(bg, ref, 1, old, aad); err != nil || !bytes.Equal(got, oldDEK) {
		t.Errorf("a key wrapped before Rotate no longer unwraps: %v", err)
	}
	w := mustWrap(t, p, ref, v, newDEK, aad)
	if got, err := p.Unwrap(bg, ref, v, w, aad); err != nil || !bytes.Equal(got, newDEK) {
		t.Errorf("the new version does not round-trip: %v", err)
	}
}

func caseRotateMonotonic(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	prev := uint32(1)
	for range 5 {
		v := mustRotate(t, p, ref)
		if v <= prev {
			t.Fatalf("Rotate returned %d after %d: versions must increase", v, prev)
		}
		prev = v
	}
}

func caseVersionsDoNotInterchange(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	aad := testAAD(ref)
	v1 := mustWrap(t, p, ref, 1, testDEK(1), aad)
	v := mustRotate(t, p, ref)
	if _, err := p.Unwrap(bg, ref, v, v1, aad); !errors.Is(err, provider.ErrUnwrapFailed) {
		t.Errorf("a version 1 wrapped key unwrapped under version %d: %v", v, err)
	}
}

func caseUnknown(t TB, p provider.Provider) {
	t.Helper()
	missing := provider.KeyRef{ID: envelope.ID{0xFE, 1}, Provider: p.Name(), ProviderRef: "does-not-exist"}
	dek, aad := testDEK(1), []byte("a")
	if _, err := p.Wrap(bg, missing, 1, dek, aad); !errors.Is(err, provider.ErrKeyNotFound) {
		t.Errorf("Wrap on an unknown key = %v, want ErrKeyNotFound", err)
	}
	if _, err := p.Unwrap(bg, missing, 1, make([]byte, 60), aad); !errors.Is(err, provider.ErrKeyNotFound) {
		t.Errorf("Unwrap on an unknown key = %v, want ErrKeyNotFound", err)
	}
	if _, err := p.Rotate(bg, missing); !errors.Is(err, provider.ErrKeyNotFound) {
		t.Errorf("Rotate on an unknown key = %v, want ErrKeyNotFound", err)
	}
	if err := p.Destroy(bg, missing, 1); !errors.Is(err, provider.ErrKeyNotFound) {
		t.Errorf("Destroy on an unknown key = %v, want ErrKeyNotFound", err)
	}

	ref := newKey(t, p)
	for _, v := range []uint32{0, 2, 99} {
		if _, err := p.Wrap(bg, ref, v, dek, aad); !errors.Is(err, provider.ErrVersionNotFound) {
			t.Errorf("Wrap at version %d = %v, want ErrVersionNotFound", v, err)
		}
		if _, err := p.Unwrap(bg, ref, v, make([]byte, 60), aad); !errors.Is(err, provider.ErrVersionNotFound) {
			t.Errorf("Unwrap at version %d = %v, want ErrVersionNotFound", v, err)
		}
		if err := p.Destroy(bg, ref, v); !errors.Is(err, provider.ErrVersionNotFound) {
			t.Errorf("Destroy at version %d = %v, want ErrVersionNotFound", v, err)
		}
	}
}

func caseDestroy(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	aad := testAAD(ref)
	dek := testDEK(0x31)
	w1 := mustWrap(t, p, ref, 1, dek, aad)
	v2 := mustRotate(t, p, ref)
	w2 := mustWrap(t, p, ref, v2, dek, aad)

	if err := p.Destroy(bg, ref, 1); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := p.Unwrap(bg, ref, 1, w1, aad); !errors.Is(err, provider.ErrVersionDestroyed) {
		t.Errorf("Unwrap after Destroy = %v, want ErrVersionDestroyed", err)
	}
	if _, err := p.Wrap(bg, ref, 1, dek, aad); !errors.Is(err, provider.ErrVersionDestroyed) {
		t.Errorf("Wrap after Destroy = %v, want ErrVersionDestroyed", err)
	}
	if got, err := p.Unwrap(bg, ref, v2, w2, aad); err != nil || !bytes.Equal(got, dek) {
		t.Errorf("destroying version 1 affected version %d: %v", v2, err)
	}
}

func caseDestroyIdempotent(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	_ = mustRotate(t, p, ref)
	for i := range 3 {
		if err := p.Destroy(bg, ref, 1); err != nil {
			t.Fatalf("Destroy attempt %d: %v", i+1, err)
		}
	}
}

func caseContext(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	aad := testAAD(ref)
	dek := testDEK(0x44)
	w := mustWrap(t, p, ref, 1, dek, aad)

	ctx, cancel := context.WithCancel(bg)
	cancel()

	checks := map[string]error{}
	_, err := p.CreateKey(ctx, provider.KeySpec{Purpose: "conformance", Algorithm: algorithm.AES256GCM})
	checks["CreateKey"] = err
	_, err = p.Rotate(ctx, ref)
	checks["Rotate"] = err
	_, err = p.Wrap(ctx, ref, 1, dek, aad)
	checks["Wrap"] = err
	_, err = p.Unwrap(ctx, ref, 1, w, aad)
	checks["Unwrap"] = err
	checks["Destroy"] = p.Destroy(ctx, ref, 1)
	checks["Health"] = p.Health(ctx)
	for name, err := range checks {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s with a cancelled context = %v, want an error wrapping context.Canceled", name, err)
		}
	}

	// A cancelled Destroy changed nothing.
	if got, err := p.Unwrap(bg, ref, 1, w, aad); err != nil || !bytes.Equal(got, dek) {
		t.Errorf("a cancelled Destroy destroyed the version: %v", err)
	}
}

func caseErrorsNoKeyMaterial(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	dek := bytes.Repeat([]byte{0xC3}, 32)
	aad := []byte("aad-marker-value")
	w := mustWrap(t, p, ref, 1, dek, aad)

	var errs []error
	_, err := p.Unwrap(bg, ref, 1, w, []byte("another aad"))
	errs = append(errs, err)
	tampered := bytes.Clone(w)
	tampered[len(tampered)-1] ^= 1
	_, err = p.Unwrap(bg, ref, 1, tampered, aad)
	errs = append(errs, err)
	_, err = p.Unwrap(bg, ref, 9, w, aad)
	errs = append(errs, err)

	leaks := []string{string(dek), hex.EncodeToString(dek), string(w), hex.EncodeToString(w), "aad-marker-value", hex.EncodeToString([]byte("aad-marker-value"))}
	for _, err := range errs {
		if err == nil {
			t.Errorf("a failing call returned no error")
			continue
		}
		for _, leak := range leaks {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("error %q contains key material, a wrapped key or aad", err)
			}
		}
	}
}

func caseNotShared(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	dek := testDEK(0x55)
	aad := []byte("original aad")
	dekIn, aadIn := bytes.Clone(dek), bytes.Clone(aad)

	w := mustWrap(t, p, ref, 1, dekIn, aadIn)
	// Mutating the inputs after the call must not change what was wrapped.
	for i := range dekIn {
		dekIn[i] = 0
	}
	for i := range aadIn {
		aadIn[i] = 0
	}
	got, err := p.Unwrap(bg, ref, 1, w, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("the provider retained or modified its inputs: %v", err)
	}

	// Mutating an output must not change what the provider returns next time.
	for i := range got {
		got[i] = 0xFF
	}
	wrappedCopy := bytes.Clone(w)
	for i := range w {
		w[i] = 0
	}
	again, err := p.Unwrap(bg, ref, 1, wrappedCopy, aad)
	if err != nil || !bytes.Equal(again, dek) {
		t.Errorf("a returned slice is shared with provider state: %v", err)
	}
}

func caseConcurrent(t TB, p provider.Provider) {
	t.Helper()
	ref := newKey(t, p)
	aad := testAAD(ref)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []string
	)
	fail := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if len(errs) < 5 {
			errs = append(errs, fmt.Sprintf(format, args...))
		}
	}
	for g := range uint8(8) {
		wg.Go(func() {
			dek := testDEK(g)
			for range 25 {
				w, err := p.Wrap(bg, ref, 1, dek, aad)
				if err != nil {
					fail("Wrap: %v", err)
					return
				}
				got, err := p.Unwrap(bg, ref, 1, w, aad)
				if err != nil || !bytes.Equal(got, dek) {
					fail("Unwrap: %v", err)
					return
				}
			}
		})
	}
	wg.Go(func() {
		prev := uint32(1)
		for range 10 {
			v, err := p.Rotate(bg, ref)
			if err != nil {
				fail("Rotate: %v", err)
				return
			}
			if v <= prev {
				fail("Rotate returned %d after %d", v, prev)
				return
			}
			prev = v
		}
	})
	wg.Wait()
	for _, e := range errs {
		t.Errorf("%s", e)
	}
}
