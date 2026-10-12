package sqlstore_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/provider"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/rotate"
	"github.com/plexusone/keyforge/sqlstore"
)

// BenchmarkRotateAndRewrapSQLite measures a rotation and the re-wrap of every
// data key against a SQLite registry, which adds a transaction per key to what
// the in-memory benchmark measures. The default is small because seeding is
// slow; set KEYFORGE_BENCH_KEYS to measure more.
func BenchmarkRotateAndRewrapSQLite(b *testing.B) {
	n := 5_000
	if v := os.Getenv("KEYFORGE_BENCH_KEYS"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n <= 0 {
			b.Fatalf("KEYFORGE_BENCH_KEYS = %q", v)
		}
	}
	ctx := context.Background()
	store, err := sqlstore.OpenSQLite(ctx, filepath.Join(b.TempDir(), "registry.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			b.Error(err)
		}
	}()
	prov := providermemory.NewKeyring()
	const purpose keyforge.Purpose = "orders"

	rot, err := rotate.New(rotate.Options{Store: store, Providers: []provider.Provider{prov}})
	if err != nil {
		b.Fatal(err)
	}
	kek, err := rot.EnsureKEK(ctx, purpose, prov.Name())
	if err != nil {
		b.Fatal(err)
	}
	c, err := keyforge.New(keyforge.Options{
		Store: store, Providers: []provider.Provider{prov},
		Purposes:  map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {PerSubject: true}},
		CacheSize: 1024, Clock: fixedClock{},
	})
	if err != nil {
		b.Fatal(err)
	}
	for i := range n {
		if _, err := c.EncryptFor(ctx, purpose, "s"+strconv.Itoa(i), []byte("x"), nil); err != nil {
			b.Fatalf("seeding %d: %v", i, err)
		}
	}

	b.ResetTimer()
	for range b.N {
		if _, err := rot.RotateKEK(ctx, purpose); err != nil {
			b.Fatal(err)
		}
		res, err := rot.RewrapAll(ctx, kek.ID, rotate.RewrapOptions{BatchSize: registry.MaxPageSize})
		if err != nil || !res.Done {
			b.Fatalf("RewrapAll: %+v, %v", res, err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(n), "keys/op")
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n), "ns/key")
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0) }
