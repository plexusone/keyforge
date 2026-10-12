package rotate_test

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/provider"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	"github.com/plexusone/keyforge/registry"
	registrymemory "github.com/plexusone/keyforge/registry/memory"
	"github.com/plexusone/keyforge/rotate"
)

// benchKeys is how many data keys the benchmark rotates. The release target is
// one million; the default is smaller so that a plain -bench run is short. Set
// KEYFORGE_BENCH_KEYS=1000000 to measure the target.
func benchKeys(b *testing.B, def int) int {
	b.Helper()
	v := os.Getenv("KEYFORGE_BENCH_KEYS")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		b.Fatalf("KEYFORGE_BENCH_KEYS = %q", v)
	}
	return n
}

// BenchmarkRotateAndRewrap measures a KEK rotation followed by the re-wrap of
// every data key, over the in-memory registry and provider, so that it measures
// keyforge's own work: unwrap, wrap and a compare-and-set per key. A real
// registry adds its transaction cost per key; see the SQL store's benchmark.
func BenchmarkRotateAndRewrap(b *testing.B) {
	n := benchKeys(b, 100_000)
	store := registrymemory.NewStore()
	prov := providermemory.NewKeyring()
	clock := &clock{t: time.Unix(1_700_000_000, 0)}

	kek, err := prov.CreateKey(bg, provider.KeySpec{Purpose: string(purpose), Algorithm: 1})
	if err != nil {
		b.Fatal(err)
	}
	if err := store.Bootstrap(bg, purpose, kek, 1, clock.Now()); err != nil {
		b.Fatal(err)
	}
	c, err := keyforge.New(keyforge.Options{
		Store: store, Providers: []provider.Provider{prov}, Clock: clock,
		Purposes:  map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {PerSubject: true}},
		CacheSize: 1024,
	})
	if err != nil {
		b.Fatal(err)
	}
	// One data key per subject, so n subjects are n data keys to move.
	for i := range n {
		if _, err := c.EncryptFor(bg, purpose, "s"+strconv.Itoa(i), []byte("x"), nil); err != nil {
			b.Fatalf("seeding %d: %v", i, err)
		}
	}
	rot, err := rotate.New(rotate.Options{Store: store, Providers: []provider.Provider{prov}, Clock: clock})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		if _, err := rot.RotateKEK(bg, purpose); err != nil {
			b.Fatal(err)
		}
		res, err := rot.RewrapAll(bg, kek.ID, rotate.RewrapOptions{BatchSize: registry.MaxPageSize})
		if err != nil || !res.Done {
			b.Fatalf("RewrapAll: %+v, %v", res, err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(n), "keys/op")
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n), "ns/key")
	fmt.Fprintf(os.Stderr, "rotated %d data keys per iteration\n", n)
}
