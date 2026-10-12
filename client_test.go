package keyforge_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := newEnv(t).client()
	ctx := bg

	e, err := c.Encrypt(ctx, testPurpose, []byte("hello"), []byte("record:1"))
	if err != nil {
		t.Fatal(err)
	}
	if e.Mode != envelope.ModeReference || e.Purpose != string(testPurpose) {
		t.Fatalf("envelope = %v %q", e.Mode, e.Purpose)
	}
	pt, info, err := c.Decrypt(ctx, testPurpose, e, []byte("record:1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Fatalf("plaintext = %q", pt)
	}
	if info.Stale || info.Epoch != 1 || info.Mode != envelope.ModeReference {
		t.Fatalf("info = %+v", info)
	}

	// Through the text form, as an application would store it.
	parsed, err := envelope.ParseText(e.String())
	if err != nil {
		t.Fatal(err)
	}
	if pt, _, err := c.Decrypt(ctx, testPurpose, parsed, []byte("record:1")); err != nil || string(pt) != "hello" {
		t.Fatalf("Decrypt of the parsed text form = %q, %v", pt, err)
	}
}

func TestContextAndPurposeBinding(t *testing.T) {
	en := newEnv(t, func(e *env) {
		e.opts.Purposes["backup-keys"] = keyforge.PurposeConfig{}
		e.store.active["backup-keys"] = e.store.active[testPurpose]
	})
	c := en.client()

	e, err := c.Encrypt(bg, testPurpose, []byte("secret"), []byte("record:1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Decrypt(bg, testPurpose, e, []byte("record:2")); !is(err, envelope.ErrAuthentication) {
		t.Fatalf("another context: %v, want ErrAuthentication", err)
	}
	if _, _, err := c.Decrypt(bg, testPurpose, e, nil); !is(err, envelope.ErrAuthentication) {
		t.Fatalf("no context: %v, want ErrAuthentication", err)
	}
	if _, _, err := c.Decrypt(bg, "backup-keys", e, []byte("record:1")); !is(err, keyforge.ErrPurposeMismatch) {
		t.Fatalf("another purpose: %v, want ErrPurposeMismatch", err)
	}

	// Relabelling the envelope for another purpose does not help either: the
	// purpose is authenticated and names a different data key.
	moved := *e
	moved.Purpose = "backup-keys"
	if _, _, err := c.Decrypt(bg, "backup-keys", &moved, []byte("record:1")); err == nil {
		t.Fatal("an envelope relabelled for another purpose decrypted")
	}
}

func TestUnknownPurposeFailsClosed(t *testing.T) {
	c := newEnv(t).client()
	if _, err := c.Encrypt(bg, "not-configured", []byte("x"), nil); !is(err, keyforge.ErrUnknownPurpose) {
		t.Fatalf("Encrypt = %v, want ErrUnknownPurpose", err)
	}
	if _, err := c.EncryptInline(bg, "not-configured", []byte("x"), nil); !is(err, keyforge.ErrUnknownPurpose) {
		t.Fatalf("EncryptInline = %v, want ErrUnknownPurpose", err)
	}
	e, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	moved := *e
	moved.Purpose = "not-configured"
	if _, _, err := c.Decrypt(bg, "not-configured", &moved, nil); !is(err, keyforge.ErrUnknownPurpose) {
		t.Fatalf("Decrypt = %v, want ErrUnknownPurpose", err)
	}
}

// TestNoRegistryOrProviderCallPerOperation is the NFR1 check: once a data key
// is unwrapped and a block reserved, encrypting and decrypting touch neither
// the registry nor the provider.
func TestNoRegistryOrProviderCallPerOperation(t *testing.T) {
	en := newEnv(t)
	c := en.client()

	first, err := c.Encrypt(bg, testPurpose, []byte("warm"), nil)
	if err != nil {
		t.Fatal(err)
	}
	storeCalls := map[string]int{}
	for _, op := range []string{"ActiveKEK", "KEK", "CurrentDEK", "GetDEK", "AdvanceDEK", "ReserveEncryptions"} {
		storeCalls[op] = en.store.count(op)
	}
	wraps, unwraps := en.prov.count("Wrap"), en.prov.count("Unwrap")

	for i := range 1000 {
		e, err := c.Encrypt(bg, testPurpose, []byte("payload"), []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Decrypt(bg, testPurpose, e, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := c.Decrypt(bg, testPurpose, first, nil); err != nil {
		t.Fatal(err)
	}

	for op, before := range storeCalls {
		if got := en.store.count(op); got != before {
			t.Errorf("registry %s was called %d more times on the data path", op, got-before)
		}
	}
	if en.prov.count("Wrap") != wraps || en.prov.count("Unwrap") != unwraps {
		t.Errorf("provider was called on the data path: wraps %d->%d unwraps %d->%d", wraps, en.prov.count("Wrap"), unwraps, en.prov.count("Unwrap"))
	}
}

// TestCachedKeysSurviveAnOutage checks that reads and writes for a cached key
// continue when the registry and provider are down, and that a key that is not
// cached fails closed.
func TestCachedKeysSurviveAnOutage(t *testing.T) {
	en := newEnv(t)
	c := en.client()
	e, err := c.Encrypt(bg, testPurpose, []byte("cached"), nil)
	if err != nil {
		t.Fatal(err)
	}

	en.store.fail(errors.New("registry down"))
	en.prov.fail(errors.New("provider down"))

	if pt, _, err := c.Decrypt(bg, testPurpose, e, nil); err != nil || string(pt) != "cached" {
		t.Fatalf("Decrypt during an outage = %q, %v", pt, err)
	}
	if _, err := c.Encrypt(bg, testPurpose, []byte("more"), nil); err != nil {
		t.Fatalf("Encrypt within the reserved block during an outage: %v", err)
	}

	// A fresh client has nothing cached, so it cannot read, and says why.
	fresh := en.client()
	_, _, err = fresh.Decrypt(bg, testPurpose, e, nil)
	if !is(err, keyforge.ErrKeyUnavailable) {
		t.Fatalf("Decrypt with nothing cached = %v, want ErrKeyUnavailable", err)
	}
	if _, err := fresh.Encrypt(bg, testPurpose, []byte("x"), nil); !is(err, keyforge.ErrKeyUnavailable) {
		t.Fatalf("Encrypt with nothing cached = %v, want ErrKeyUnavailable", err)
	}
}

func TestWritesFailClosedWhenTheBlockIsSpentAndTheRegistryIsDown(t *testing.T) {
	en := newEnv(t, func(e *env) { e.opts.ReserveBlock = 3 })
	c := en.client()
	for i := range 3 {
		if _, err := c.Encrypt(bg, testPurpose, []byte("x"), nil); err != nil {
			t.Fatalf("encryption %d inside the block: %v", i, err)
		}
	}
	en.store.fail(errors.New("registry down"))
	if _, err := c.Encrypt(bg, testPurpose, []byte("x"), nil); !is(err, keyforge.ErrKeyUnavailable) {
		t.Fatalf("Encrypt past the block = %v, want ErrKeyUnavailable", err)
	}
}

// TestCapRollsTheEpoch drives a small cap and checks the invariants the block
// counter must keep: no data key is used beyond the cap, epochs advance, and
// everything written under any of them still decrypts.
func TestCapRollsTheEpoch(t *testing.T) {
	const (
		capN  = 10
		block = 4
		n     = 45
	)
	en := newEnv(t, func(e *env) {
		e.opts.EncryptionCap = capN
		e.opts.ReserveBlock = block
	})
	c := en.client()

	var all []*envelope.Envelope
	for i := range n {
		e, err := c.Encrypt(bg, testPurpose, fmt.Appendf(nil, "message %d", i), nil)
		if err != nil {
			t.Fatalf("encryption %d: %v", i, err)
		}
		all = append(all, e)
	}

	perKey := map[envelope.ID]int{}
	for _, e := range all {
		perKey[e.DEKID]++
	}
	for id, used := range perKey {
		if used > capN {
			t.Errorf("data key %s was used %d times, cap is %d", id, used, capN)
		}
		if rec := en.store.deks[id]; rec.Reserved > capN {
			t.Errorf("data key %s reserved %d, cap is %d", id, rec.Reserved, capN)
		}
	}
	if len(perKey) < n/capN {
		t.Errorf("only %d data keys for %d encryptions at cap %d", len(perKey), n, capN)
	}

	for i, e := range all {
		pt, info, err := c.Decrypt(bg, testPurpose, e, nil)
		if err != nil || string(pt) != fmt.Sprintf("message %d", i) {
			t.Fatalf("message %d: %q, %v", i, pt, err)
		}
		if info.Stale != (en.store.deks[e.DEKID].State != keyforge.DEKActive) {
			t.Errorf("message %d: Stale = %v for a key in state %v", i, info.Stale, en.store.deks[e.DEKID].State)
		}
	}
	if !all[0].Header.DEKID.IsZero() && all[0].DEKID == all[len(all)-1].DEKID {
		t.Error("the first and last envelope share a data key; the epoch never advanced")
	}
}

func TestStaleAndReencrypt(t *testing.T) {
	en := newEnv(t, func(e *env) {
		e.opts.EncryptionCap = 2
		e.opts.ReserveBlock = 2
	})
	c := en.client()

	old, err := c.Encrypt(bg, testPurpose, []byte("old data"), []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	// Spend the cap so the epoch moves on.
	for range 4 {
		if _, err := c.Encrypt(bg, testPurpose, []byte("filler"), nil); err != nil {
			t.Fatal(err)
		}
	}

	_, info, err := c.Decrypt(bg, testPurpose, old, []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Stale || info.Epoch != 1 {
		t.Fatalf("info = %+v, want a stale envelope from epoch 1", info)
	}

	renewed, err := c.Reencrypt(bg, testPurpose, old, []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if renewed.DEKID == old.DEKID {
		t.Fatal("Reencrypt kept the old data key")
	}
	pt, info, err := c.Decrypt(bg, testPurpose, renewed, []byte("ctx"))
	if err != nil || string(pt) != "old data" {
		t.Fatalf("Decrypt of the re-encrypted envelope = %q, %v", pt, err)
	}
	if info.Stale {
		t.Fatalf("a re-encrypted envelope is stale: %+v", info)
	}
}

func TestCacheTTL(t *testing.T) {
	en := newEnv(t, func(e *env) { e.opts.CacheTTL = time.Minute })
	c := en.client()
	e, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Decrypt(bg, testPurpose, e, nil); err != nil {
		t.Fatal(err)
	}
	unwraps := en.prov.count("Unwrap")

	en.clock.Advance(59 * time.Second)
	if _, _, err := c.Decrypt(bg, testPurpose, e, nil); err != nil {
		t.Fatal(err)
	}
	if got := en.prov.count("Unwrap"); got != unwraps {
		t.Fatalf("the key was unwrapped again inside the TTL (%d -> %d)", unwraps, got)
	}

	en.clock.Advance(2 * time.Second)
	if _, _, err := c.Decrypt(bg, testPurpose, e, nil); err != nil {
		t.Fatal(err)
	}
	if got := en.prov.count("Unwrap"); got != unwraps+1 {
		t.Fatalf("unwraps = %d, want the key unwrapped once more after the TTL (%d)", got, unwraps+1)
	}
}

func TestCacheSizeBound(t *testing.T) {
	en := newEnv(t, func(e *env) {
		e.opts.CacheSize = 2
		e.opts.EncryptionCap = 1
		e.opts.ReserveBlock = 1
	})
	c := en.client()

	// With a cap of one every message gets its own data key.
	var envs []*envelope.Envelope
	for range 5 {
		e, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
		if err != nil {
			t.Fatal(err)
		}
		envs = append(envs, e)
	}
	before := en.prov.count("Unwrap")
	for _, e := range envs { // the oldest are no longer cached and must be unwrapped
		if _, _, err := c.Decrypt(bg, testPurpose, e, nil); err != nil {
			t.Fatal(err)
		}
	}
	if en.prov.count("Unwrap") == before {
		t.Fatal("no key was unwrapped, so the cache is not bounded")
	}
}

func TestInlineRoundTrip(t *testing.T) {
	en := newEnv(t)
	c := en.client()

	e, err := c.EncryptInline(bg, testPurpose, []byte("exported object"), []byte("object:9"))
	if err != nil {
		t.Fatal(err)
	}
	if e.Mode != envelope.ModeInline || e.KEKID != en.kek.ID || e.KEKVersion != 1 || len(e.Wrapped) == 0 {
		t.Fatalf("inline header = %+v", e.Header)
	}

	// A fresh client has no cache and unwraps through the provider.
	fresh := en.client()
	pt, info, err := fresh.Decrypt(bg, testPurpose, e, []byte("object:9"))
	if err != nil || string(pt) != "exported object" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}
	if info.Mode != envelope.ModeInline || info.KEKVersion != 1 || info.Stale {
		t.Fatalf("info = %+v", info)
	}
	if _, _, err := fresh.Decrypt(bg, testPurpose, e, []byte("object:8")); !is(err, envelope.ErrAuthentication) {
		t.Fatalf("another context: %v, want ErrAuthentication", err)
	}

	// Each object gets its own key.
	e2, err := c.EncryptInline(bg, testPurpose, []byte("exported object"), []byte("object:9"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(e.Wrapped, e2.Wrapped) {
		t.Fatal("two inline objects share a wrapped key")
	}
}

func TestInlineStaleAfterKEKRotation(t *testing.T) {
	en := newEnv(t, func(e *env) { e.opts.CacheTTL = time.Minute })
	c := en.client()

	e, err := c.EncryptInline(bg, testPurpose, []byte("object"), nil)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := en.prov.Rotate(bg, en.kek)
	if err != nil {
		t.Fatal(err)
	}
	en.store.mu.Lock()
	en.store.active[testPurpose] = keyforge.KEKVersion{Ref: en.kek, Version: v2}
	en.store.mu.Unlock()
	en.clock.Advance(2 * time.Minute) // let the cached active version expire

	pt, info, err := c.Decrypt(bg, testPurpose, e, nil)
	if err != nil || string(pt) != "object" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}
	if !info.Stale {
		t.Fatalf("info = %+v, want Stale after the KEK rotated", info)
	}

	renewed, err := c.Reencrypt(bg, testPurpose, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.KEKVersion != v2 {
		t.Fatalf("re-encrypted under KEK version %d, want %d", renewed.KEKVersion, v2)
	}
}

func TestKeyStatesGateOperations(t *testing.T) {
	en := newEnv(t)
	c := en.client()
	e, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}

	set := func(s keyforge.DEKState) {
		en.store.mu.Lock()
		defer en.store.mu.Unlock()
		rec := en.store.deks[e.DEKID]
		rec.State = s
		en.store.deks[e.DEKID] = rec
	}

	// Decrypt-only and compromised keys are still readable, so data can be
	// re-encrypted away from them.
	for _, s := range []keyforge.DEKState{keyforge.DEKDecryptOnly, keyforge.DEKCompromised} {
		set(s)
		c.Purge()
		if _, _, err := c.Decrypt(bg, testPurpose, e, nil); err != nil {
			t.Errorf("Decrypt under a %s key: %v", s, err)
		}
	}

	set(keyforge.DEKDestroyed)
	c.Purge()
	if _, _, err := c.Decrypt(bg, testPurpose, e, nil); !is(err, keyforge.ErrKeyUnusable) {
		t.Fatalf("Decrypt under a destroyed key = %v, want ErrKeyUnusable", err)
	}
}

func TestPurgeDropsCachedKeys(t *testing.T) {
	en := newEnv(t)
	c := en.client()
	e, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	before := en.prov.count("Unwrap")
	c.Purge()
	if _, _, err := c.Decrypt(bg, testPurpose, e, nil); err != nil {
		t.Fatal(err)
	}
	if en.prov.count("Unwrap") != before+1 {
		t.Fatal("Purge did not drop the cached key")
	}
}

func TestWrappedKeyIsBoundToItsRecord(t *testing.T) {
	en := newEnv(t)
	c := en.client()
	e, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Someone with write access to the registry relabels the record's
	// purpose. The wrapped key was bound to the original, so it must not
	// unwrap.
	en.store.mu.Lock()
	rec := en.store.deks[e.DEKID]
	rec.Subject = "someone-else"
	en.store.deks[e.DEKID] = rec
	en.store.mu.Unlock()

	fresh := en.client()
	if _, _, err := fresh.Decrypt(bg, testPurpose, e, nil); !is(err, keyforge.ErrKeyUnavailable) {
		t.Fatalf("Decrypt = %v, want the wrapped key refused", err)
	}
}

func TestRecordInconsistentWithEnvelope(t *testing.T) {
	en := newEnv(t, func(e *env) {
		e.opts.Purposes["other-purpose"] = keyforge.PurposeConfig{}
		e.store.active["other-purpose"] = e.store.active[testPurpose]
	})
	c := en.client()
	e, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// An envelope for another purpose that names this purpose's data key.
	forged := *e
	forged.Purpose = "other-purpose"
	if _, _, err := c.Decrypt(bg, "other-purpose", &forged, nil); !is(err, keyforge.ErrInvalidEnvelope) {
		t.Fatalf("Decrypt = %v, want ErrInvalidEnvelope", err)
	}
}

// TestProfileMustLeaveAnAlgorithm checks that a configuration which leaves a
// purpose with nothing to write with fails when the client is built, not on
// the first write.
func TestProfileMustLeaveAnAlgorithm(t *testing.T) {
	deny, err := algorithm.NewSelector(algorithm.Config{Profile: algorithm.ProfileStandard, Deny: []algorithm.ID{algorithm.AES256GCM}})
	if err != nil {
		t.Fatal(err)
	}
	en := newEnv(t)
	en.opts.Selector = deny
	if _, err := keyforge.New(en.opts); !is(err, algorithm.ErrInvalidSelection) {
		t.Fatalf("New = %v, want ErrInvalidSelection", err)
	}
}

func TestNewValidates(t *testing.T) {
	en := newEnv(t)
	good := en.opts

	tests := []struct {
		name   string
		mutate func(o *keyforge.Options)
	}{
		{"no store", func(o *keyforge.Options) { o.Store = nil }},
		{"no provider", func(o *keyforge.Options) { o.Providers = nil }},
		{"duplicate provider", func(o *keyforge.Options) { o.Providers = []provider.Provider{en.prov, en.prov} }},
		{"bad purpose", func(o *keyforge.Options) {
			o.Purposes = map[keyforge.Purpose]keyforge.PurposeConfig{"Bad Purpose": {}}
		}},
		{"cap above the maximum", func(o *keyforge.Options) { o.EncryptionCap = keyforge.MaxEncryptionCap + 1 }},
		{"purpose cap above the maximum", func(o *keyforge.Options) {
			o.Purposes = map[keyforge.Purpose]keyforge.PurposeConfig{testPurpose: {EncryptionCap: keyforge.MaxEncryptionCap + 1}}
		}},
		{"purpose list outside the profile", func(o *keyforge.Options) {
			o.Purposes = map[keyforge.Purpose]keyforge.PurposeConfig{testPurpose: {Algorithms: algorithm.Selection{Allowed: []algorithm.ID{7}}}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := good
			tt.mutate(&o)
			if _, err := keyforge.New(o); err == nil {
				t.Fatal("New accepted the configuration")
			}
		})
	}
}

func TestDeterministicEntropy(t *testing.T) {
	ids := func() [2]envelope.ID {
		en := newEnv(t, func(e *env) { e.opts.Entropy = &detEntropy{seed: "fixed"} })
		c := en.client()
		a, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
		if err != nil {
			t.Fatal(err)
		}
		return [2]envelope.ID{a.DEKID, en.store.deks[a.DEKID].KEKID}
	}
	if a, b := ids(), ids(); a[0] != b[0] {
		t.Fatalf("data key identifiers differ under the same entropy: %s vs %s", a[0], b[0])
	}
}

func TestEntropyFailureFailsClosed(t *testing.T) {
	en := newEnv(t, func(e *env) { e.opts.Entropy = errReader{} })
	c := en.client()
	if _, err := c.Encrypt(bg, testPurpose, []byte("x"), nil); !is(err, keyforge.ErrKeyUnavailable) {
		t.Fatalf("Encrypt = %v, want ErrKeyUnavailable", err)
	}
	if _, err := c.EncryptInline(bg, testPurpose, []byte("x"), nil); !is(err, keyforge.ErrKeyUnavailable) {
		t.Fatalf("EncryptInline = %v, want ErrKeyUnavailable", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestErrorsCarryNoPlaintextOrKeyMaterial(t *testing.T) {
	en := newEnv(t)
	c := en.client()
	e, err := c.Encrypt(bg, testPurpose, []byte("plaintext-marker"), []byte("context-marker"))
	if err != nil {
		t.Fatal(err)
	}
	var errs []error
	_, _, err = c.Decrypt(bg, testPurpose, e, []byte("wrong"))
	errs = append(errs, err)
	en.prov.fail(errors.New("down"))
	_, _, err = en.client().Decrypt(bg, testPurpose, e, []byte("context-marker"))
	errs = append(errs, err)

	rec := en.store.deks[e.DEKID]
	for _, err := range errs {
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, leak := range []string{"plaintext-marker", "context-marker", string(rec.Wrapped)} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("error %q leaks %q", err, leak)
			}
		}
	}
}

// TestConcurrentUse runs many goroutines against a small cap, so epoch changes
// race with reservations and with reads. Run with -race.
func TestConcurrentUse(t *testing.T) {
	const (
		workers = 8
		each    = 60
		capN    = 100
	)
	en := newEnv(t, func(e *env) {
		e.opts.EncryptionCap = capN
		e.opts.ReserveBlock = 4
		e.opts.CacheSize = 4
	})
	c := en.client()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		fail []string
		seen = map[envelope.ID]int{}
	)
	for w := range workers {
		wg.Go(func() {
			for i := range each {
				msg := fmt.Appendf(nil, "worker %d message %d", w, i)
				ctx := fmt.Appendf(nil, "ctx-%d-%d", w, i)
				e, err := c.Encrypt(bg, testPurpose, msg, ctx)
				if err != nil {
					mu.Lock()
					fail = append(fail, "Encrypt: "+err.Error())
					mu.Unlock()
					return
				}
				pt, _, err := c.Decrypt(bg, testPurpose, e, ctx)
				if err != nil || !bytes.Equal(pt, msg) {
					mu.Lock()
					fail = append(fail, fmt.Sprintf("Decrypt: %q %v", pt, err))
					mu.Unlock()
					return
				}
				mu.Lock()
				seen[e.DEKID]++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	for _, f := range fail[:min(len(fail), 5)] {
		t.Error(f)
	}
	for id, used := range seen {
		if rec := en.store.deks[id]; used > capN || rec.Reserved > capN {
			t.Errorf("data key %s used %d times, reserved %d, cap is %d", id, used, rec.Reserved, capN)
		}
	}
	if len(seen) < workers*each/capN {
		t.Errorf("only %d data keys for %d encryptions at cap %d", len(seen), workers*each, capN)
	}
}

// TestDEKWrapAADLayoutIsFrozen pins the bytes a data key is wrapped with. They
// are stored format: a change makes every existing wrapped key unreadable, so
// it must be a deliberate, versioned decision and not a refactor.
func TestDEKWrapAADLayoutIsFrozen(t *testing.T) {
	var dek, kek envelope.ID
	for i := range dek {
		dek[i] = 0x10 + byte(i)
		kek[i] = 0x20 + byte(i)
	}
	got := keyforge.DEKWrapAAD("orders", "alice", dek, kek)
	want := []byte("keyforge/dek/v1\x00" +
		"\x00\x00\x00\x06orders" +
		"\x00\x00\x00\x05alice" +
		string(dek[:]) + string(kek[:]))
	if !bytes.Equal(got, want) {
		t.Fatalf("DEKWrapAAD = %q\nwant         %q", got, want)
	}
	// Each field is length-prefixed, so shifting a byte between purpose and
	// subject cannot produce the same data.
	a := keyforge.DEKWrapAAD("ab", "c", dek, kek)
	b := keyforge.DEKWrapAAD("a", "bc", dek, kek)
	if bytes.Equal(a, b) {
		t.Fatal("different purpose and subject splits produce the same additional data")
	}
}

func TestInlineWrapAADLayoutIsFrozen(t *testing.T) {
	var kek envelope.ID
	for i := range kek {
		kek[i] = 0x30 + byte(i)
	}
	got := keyforge.InlineWrapAAD("exports", kek)
	want := []byte("keyforge/inline/v1\x00" + "\x00\x00\x00\x07exports" + string(kek[:]))
	if !bytes.Equal(got, want) {
		t.Fatalf("InlineWrapAAD = %q\nwant           %q", got, want)
	}
}

// TestEpochRollsByAge checks the second trigger for a new epoch: a data key has
// a lifetime as well as a volume, so an epoch that has reached its age is
// replaced even though it has capacity left.
func TestEpochRollsByAge(t *testing.T) {
	en := newEnv(t, func(e *env) { e.opts.MaxAge = 24 * time.Hour })
	c := en.client()

	first, err := c.Encrypt(bg, testPurpose, []byte("one"), nil)
	if err != nil {
		t.Fatal(err)
	}
	en.clock.Advance(24*time.Hour - time.Second)
	same, err := c.Encrypt(bg, testPurpose, []byte("two"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if same.DEKID != first.DEKID {
		t.Fatal("the epoch rolled before it reached its age")
	}

	en.clock.Advance(time.Second) // exactly the age: a data key is used for less than its lifetime
	next, err := c.Encrypt(bg, testPurpose, []byte("three"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if next.DEKID == first.DEKID {
		t.Fatal("the epoch did not roll at its age")
	}
	if got := en.store.deks[next.DEKID].Epoch; got != 2 {
		t.Fatalf("new epoch = %d, want 2", got)
	}

	// The old key still reads, and reports itself stale so data can be rewritten.
	pt, info, err := c.Decrypt(bg, testPurpose, first, nil)
	if err != nil || string(pt) != "one" || !info.Stale {
		t.Fatalf("Decrypt of the old epoch = %q, %+v, %v", pt, info, err)
	}
	// And the new key serves the next writes, with no further roll.
	again, err := c.Encrypt(bg, testPurpose, []byte("four"), nil)
	if err != nil || again.DEKID != next.DEKID {
		t.Fatalf("a write after the roll used %v, %v", again.DEKID, err)
	}
}

func TestPurposeOverridesTheMaximumAge(t *testing.T) {
	en := newEnv(t, func(e *env) {
		e.opts.MaxAge = 24 * time.Hour
		e.opts.Purposes[testPurpose] = keyforge.PurposeConfig{MaxAge: time.Hour}
	})
	c := en.client()
	a, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	en.clock.Advance(2 * time.Hour)
	b, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
	if err != nil || b.DEKID == a.DEKID {
		t.Fatalf("the purpose's one-hour age was not honored: %v", err)
	}
}

func TestNegativeAgeIsRefused(t *testing.T) {
	en := newEnv(t, func(e *env) { e.opts.MaxAge = -time.Hour })
	if _, err := keyforge.New(en.opts); err == nil {
		t.Fatal("a negative maximum age was accepted")
	}
	en = newEnv(t, func(e *env) { e.opts.Purposes[testPurpose] = keyforge.PurposeConfig{MaxAge: -1} })
	if _, err := keyforge.New(en.opts); err == nil {
		t.Fatal("a negative purpose maximum age was accepted")
	}
}

func TestDefaultMaximumAgeIsNinetyDays(t *testing.T) {
	en := newEnv(t)
	c := en.client()
	a, err := c.Encrypt(bg, testPurpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	en.clock.Advance(89 * 24 * time.Hour)
	if b, err := c.Encrypt(bg, testPurpose, []byte("x"), nil); err != nil || b.DEKID != a.DEKID {
		t.Fatalf("rolled before 90 days: %v", err)
	}
	en.clock.Advance(24 * time.Hour)
	if b, err := c.Encrypt(bg, testPurpose, []byte("x"), nil); err != nil || b.DEKID == a.DEKID {
		t.Fatalf("did not roll at 90 days: %v", err)
	}
}

// ---- per-subject keys ----

func perSubject(e *env) {
	e.opts.Purposes[testPurpose] = keyforge.PurposeConfig{PerSubject: true}
}

func TestPerSubjectKeysAreIsolated(t *testing.T) {
	en := newEnv(t, perSubject, func(e *env) { e.opts.EncryptionCap, e.opts.ReserveBlock = 2, 2 })
	c := en.client()

	a1, err := c.EncryptFor(bg, testPurpose, "alice", []byte("a-one"), []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	b1, err := c.EncryptFor(bg, testPurpose, "bob", []byte("b-one"), []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	if a1.DEKID == b1.DEKID {
		t.Fatal("two subjects share a data key")
	}
	// Alice's key rolls on its own cap without touching Bob's.
	for range 4 {
		if _, err := c.EncryptFor(bg, testPurpose, "alice", []byte("more"), nil); err != nil {
			t.Fatal(err)
		}
	}
	b2, err := c.EncryptFor(bg, testPurpose, "bob", []byte("b-two"), []byte("c"))
	if err != nil || b2.DEKID != b1.DEKID {
		t.Fatalf("Bob's key changed because of Alice's volume: %v", err)
	}
	if got := en.store.deks[a1.DEKID].Subject; got != "alice" {
		t.Fatalf("subject on the record = %q", got)
	}

	// Decrypt reports whose key it was, and Reencrypt keeps the subject.
	pt, info, err := c.Decrypt(bg, testPurpose, a1, []byte("c"))
	if err != nil || string(pt) != "a-one" || info.Subject != "alice" || !info.Stale {
		t.Fatalf("Decrypt = %q, %+v, %v", pt, info, err)
	}
	renewed, err := c.Reencrypt(bg, testPurpose, a1, []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	if got := en.store.deks[renewed.DEKID].Subject; got != "alice" {
		t.Fatalf("Reencrypt moved the data to subject %q", got)
	}
}

func TestSubjectRules(t *testing.T) {
	en := newEnv(t, perSubject)
	c := en.client()
	if _, err := c.Encrypt(bg, testPurpose, []byte("x"), nil); !is(err, keyforge.ErrSubjectRequired) {
		t.Errorf("Encrypt on a per-subject purpose = %v, want ErrSubjectRequired", err)
	}

	plain := newEnv(t)
	pc := plain.client()
	if _, err := pc.EncryptFor(bg, testPurpose, "alice", []byte("x"), nil); !is(err, keyforge.ErrSubjectNotAllowed) {
		t.Errorf("EncryptFor on a purpose that is not per-subject = %v, want ErrSubjectNotAllowed", err)
	}

	for name, subject := range map[string]string{
		"empty":           "",
		"too long":        strings.Repeat("a", keyforge.MaxSubjectLen+1),
		"control":         "al\x00ice",
		"newline":         "al\nice",
		"invalid utf-8":   "\xff\xfe",
		"unicode control": "al\u0085ice",
	} {
		if _, err := c.EncryptFor(bg, testPurpose, subject, []byte("x"), nil); !is(err, keyforge.ErrInvalidSubject) {
			t.Errorf("%s: EncryptFor = %v, want ErrInvalidSubject", name, err)
		}
	}
	for _, subject := range []string{"alice", "user:42", "テナント-7", strings.Repeat("a", keyforge.MaxSubjectLen)} {
		if _, err := c.EncryptFor(bg, testPurpose, subject, []byte("x"), nil); err != nil {
			t.Errorf("subject %q refused: %v", subject, err)
		}
	}
}

func TestShreddedSubjectCannotBeWrittenAgain(t *testing.T) {
	en := newEnv(t, perSubject)
	c := en.client()
	e, err := c.EncryptFor(bg, testPurpose, "alice", []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	en.store.shredded = map[curKey]bool{{testPurpose, "alice"}: true}
	en.store.mu.Lock()
	rec := en.store.deks[e.DEKID]
	rec.State = keyforge.DEKDestroyed
	rec.Wrapped = nil
	en.store.deks[e.DEKID] = rec
	delete(en.store.current, curKey{testPurpose, "alice"})
	en.store.mu.Unlock()
	c.Purge()

	if _, err := c.EncryptFor(bg, testPurpose, "alice", []byte("again"), nil); !is(err, keyforge.ErrSubjectShredded) {
		t.Fatalf("EncryptFor a shredded subject = %v, want ErrSubjectShredded", err)
	}
	if is(err, keyforge.ErrKeyUnavailable) {
		t.Fatal("a shredded subject is reported as an outage")
	}
	if _, _, err := c.Decrypt(bg, testPurpose, e, nil); !is(err, keyforge.ErrKeyUnusable) {
		t.Fatalf("Decrypt of a shredded subject's data = %v, want ErrKeyUnusable", err)
	}
	// Other subjects are unaffected.
	if _, err := c.EncryptFor(bg, testPurpose, "bob", []byte("x"), nil); err != nil {
		t.Fatalf("an unrelated subject: %v", err)
	}
}
