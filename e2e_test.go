package keyforge_test

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	"github.com/plexusone/keyforge/registry"
	registrymemory "github.com/plexusone/keyforge/registry/memory"
)

// These tests run the real client over the in-memory providers and registry,
// once for each provider style, with no fakes that count calls or inject
// faults.

type stack struct {
	prov  provider.Provider
	reg   *registrymemory.Store
	kek   provider.KeyRef
	newCl func(opts ...func(*keyforge.Options)) *keyforge.Client
}

func providerStyles() map[string]func() provider.Provider {
	return map[string]func() provider.Provider{
		"keyring": func() provider.Provider { return providermemory.NewKeyring() },
		"native":  func() provider.Provider { return providermemory.NewNative() },
	}
}

func newStack(t *testing.T, mk func() provider.Provider) *stack {
	t.Helper()
	s := &stack{prov: mk(), reg: registrymemory.NewStore()}
	kek, err := s.prov.CreateKey(bg, provider.KeySpec{Purpose: string(testPurpose), Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	s.kek = kek
	if err := s.reg.Bootstrap(bg, testPurpose, kek, 1, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	s.newCl = func(opts ...func(*keyforge.Options)) *keyforge.Client {
		o := keyforge.Options{
			Store:     s.reg,
			Providers: []provider.Provider{s.prov},
			Purposes:  map[keyforge.Purpose]keyforge.PurposeConfig{testPurpose: {}},
		}
		for _, f := range opts {
			f(&o)
		}
		c, err := keyforge.New(o)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return s
}

func (s *stack) deks(t *testing.T) []keyforge.DEKRecord {
	t.Helper()
	recs, err := s.reg.ListDEKs(bg, registry.DEKFilter{Limit: registry.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// rotateKEK adds a KEK version at the provider and makes it active, which is
// what the control plane's rotation will do.
func (s *stack) rotateKEK(t *testing.T) uint32 {
	t.Helper()
	v, err := s.prov.Rotate(bg, s.kek)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_100, 0)
	rec := registry.VersionRecord{KEKID: s.kek.ID, Version: v, State: registry.VersionPending, CreatedAt: at}
	if err := s.reg.AddVersion(bg, rec); err != nil {
		t.Fatal(err)
	}
	opts := registry.TransitionOptions{At: at}
	if err := s.reg.TransitionVersion(bg, s.kek.ID, v, registry.VersionActive, opts); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEndToEndKEKRotationLeavesStoredDataAlone(t *testing.T) {
	for name, mk := range providerStyles() {
		t.Run(name, func(t *testing.T) {
			s := newStack(t, mk)
			small := func(o *keyforge.Options) { o.EncryptionCap, o.ReserveBlock = 5, 5 }
			c := s.newCl(small)

			// Data written before the KEK rotates.
			var before []*keyforge.Envelope
			for i := range 5 {
				e, err := c.Encrypt(bg, testPurpose, fmt.Appendf(nil, "before %d", i), []byte{byte(i)})
				if err != nil {
					t.Fatal(err)
				}
				before = append(before, e)
			}
			inline, err := c.EncryptInline(bg, testPurpose, []byte("an export"), []byte("exp"))
			if err != nil {
				t.Fatal(err)
			}

			v2 := s.rotateKEK(t)

			// Old envelopes are untouched and still decrypt: their data key is
			// wrapped under version 1, which the provider keeps.
			fresh := s.newCl(small)
			for i, e := range before {
				pt, _, err := fresh.Decrypt(bg, testPurpose, e, []byte{byte(i)})
				if err != nil || string(pt) != fmt.Sprintf("before %d", i) {
					t.Fatalf("envelope %d after the KEK rotated: %q, %v", i, pt, err)
				}
			}
			if pt, _, err := fresh.Decrypt(bg, testPurpose, inline, []byte("exp")); err != nil || string(pt) != "an export" {
				t.Fatalf("inline envelope after the KEK rotated: %q, %v", pt, err)
			}

			// The next epoch's data key is wrapped under the new version.
			for i := range 5 {
				if _, err := fresh.Encrypt(bg, testPurpose, fmt.Appendf(nil, "after %d", i), nil); err != nil {
					t.Fatal(err)
				}
			}
			var sawNew bool
			for _, rec := range s.deks(t) {
				if rec.KEKVersion == v2 {
					sawNew = true
				}
			}
			if !sawNew {
				t.Fatalf("no data key was wrapped under KEK version %d; records: %+v", v2, s.deks(t))
			}
		})
	}
}

func TestEndToEndDestroyedKEKVersionFailsClosed(t *testing.T) {
	for name, mk := range providerStyles() {
		t.Run(name, func(t *testing.T) {
			s := newStack(t, mk)
			c := s.newCl(func(o *keyforge.Options) { o.EncryptionCap, o.ReserveBlock = 3, 3 })

			old, err := c.Encrypt(bg, testPurpose, []byte("under version 1"), nil)
			if err != nil {
				t.Fatal(err)
			}
			v2 := s.rotateKEK(t)
			// A client that has seen the rotation moves on to data keys wrapped
			// under the new version. (A client that cached the old active
			// version keeps using it until its cache entry expires, which is
			// why the retirement delay must far exceed the cache TTL.)
			writer := s.newCl(func(o *keyforge.Options) { o.EncryptionCap, o.ReserveBlock = 3, 3 })
			var newer *keyforge.Envelope
			for i := range 10 {
				if newer, err = writer.Encrypt(bg, testPurpose, fmt.Appendf(nil, "later %d", i), nil); err != nil {
					t.Fatal(err)
				}
			}

			if err := s.prov.Destroy(bg, s.kek, 1); err != nil {
				t.Fatal(err)
			}
			fresh := s.newCl()

			// What was wrapped under the destroyed version is gone, and the
			// failure says so without returning anything.
			pt, _, err := fresh.Decrypt(bg, testPurpose, old, nil)
			if err == nil || pt != nil {
				t.Fatalf("Decrypt of a key under a destroyed version = %q, %v", pt, err)
			}
			if !is(err, keyforge.ErrKeyUnavailable) || !is(err, provider.ErrVersionDestroyed) {
				t.Fatalf("error = %v, want ErrKeyUnavailable wrapping ErrVersionDestroyed", err)
			}

			// Data under the new version is unaffected.
			if pt, _, err := fresh.Decrypt(bg, testPurpose, newer, nil); err != nil || !bytes.HasPrefix(pt, []byte("later")) {
				t.Fatalf("data under version %d: %q, %v", v2, pt, err)
			}
		})
	}
}

func TestEndToEndRestartAndReplicas(t *testing.T) {
	for name, mk := range providerStyles() {
		t.Run(name, func(t *testing.T) {
			s := newStack(t, mk)
			const capN = 40
			cfg := func(o *keyforge.Options) { o.EncryptionCap, o.ReserveBlock = capN, 4 }

			// Several replicas share the registry and the provider.
			replicas := []*keyforge.Client{s.newCl(cfg), s.newCl(cfg), s.newCl(cfg)}

			type sealed struct {
				e   *keyforge.Envelope
				msg []byte
				ctx []byte
			}
			var (
				mu  sync.Mutex
				all []sealed
				wg  sync.WaitGroup
			)
			for r, c := range replicas {
				wg.Go(func() {
					for i := range 50 {
						msg := fmt.Appendf(nil, "replica %d message %d", r, i)
						ctx := fmt.Appendf(nil, "r%d-%d", r, i)
						e, err := c.Encrypt(bg, testPurpose, msg, ctx)
						if err != nil {
							t.Errorf("replica %d: %v", r, err)
							return
						}
						mu.Lock()
						all = append(all, sealed{e, msg, ctx})
						mu.Unlock()
					}
				})
			}
			wg.Wait()

			// The cap held across replicas.
			used := map[envelope.ID]int{}
			for _, x := range all {
				used[x.e.DEKID]++
			}
			for id, n := range used {
				if n > capN {
					t.Errorf("data key %s was used %d times across replicas, cap is %d", id, n, capN)
				}
			}
			if len(used) < len(all)/capN {
				t.Errorf("%d data keys for %d encryptions at cap %d", len(used), len(all), capN)
			}

			// A new process, with nothing cached, reads everything any replica wrote.
			restarted := s.newCl(cfg)
			for _, x := range all {
				pt, _, err := restarted.Decrypt(bg, testPurpose, x.e, x.ctx)
				if err != nil || !bytes.Equal(pt, x.msg) {
					t.Fatalf("after restart: %q, %v, want %q", pt, err, x.msg)
				}
			}
		})
	}
}
