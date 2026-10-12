package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/provider/memory"
	"github.com/plexusone/keyforge/provider/providertest"
)

func TestKeyringConformance(t *testing.T) {
	providertest.Run(t, func() provider.Provider { return memory.NewKeyring() })
}

func TestNativeConformance(t *testing.T) {
	providertest.Run(t, func() provider.Provider { return memory.NewNative() })
}

func TestNames(t *testing.T) {
	if got := memory.NewKeyring().Name(); got != "memory-keyring" {
		t.Errorf("keyring name = %q", got)
	}
	if got := memory.NewNative().Name(); got != "memory-native" {
		t.Errorf("native name = %q", got)
	}
	if got := memory.NewKeyring(memory.WithName("custom")).Name(); got != "custom" {
		t.Errorf("custom name = %q", got)
	}
}

// TestVersionNumberingDiffersByStyle shows the two styles number versions
// differently, so code that assumes N+1 is caught by the native one.
func TestVersionNumberingDiffersByStyle(t *testing.T) {
	ctx := context.Background()
	spec := provider.KeySpec{Purpose: "p", Algorithm: algorithm.AES256GCM}

	versions := func(p provider.Provider) []uint32 {
		ref, err := p.CreateKey(ctx, spec)
		if err != nil {
			t.Fatal(err)
		}
		out := []uint32{1}
		for range 4 {
			v, err := p.Rotate(ctx, ref)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		return out
	}
	keyring := versions(memory.NewKeyring())
	native := versions(memory.NewNative())

	for i, v := range keyring {
		if v != uint32(i+1) { //nolint:gosec // G115: a small loop index
			t.Fatalf("keyring versions = %v, want 1, 2, 3, ...", keyring)
		}
	}
	consecutive := true
	for i := 1; i < len(native); i++ {
		if native[i] <= native[i-1] {
			t.Fatalf("native versions = %v, must increase", native)
		}
		if native[i] != native[i-1]+1 {
			consecutive = false
		}
	}
	if consecutive {
		t.Fatalf("native versions = %v, want gaps so N+1 is not assumed", native)
	}
}

// TestNativeWrappedKeyNamesItsVersion checks the property that makes the
// native style different: the wrapped key records the version that made it, so
// asking for another version is refused even though both exist.
func TestNativeWrappedKeyNamesItsVersion(t *testing.T) {
	ctx := context.Background()
	p := memory.NewNative()
	ref, err := p.CreateKey(ctx, provider.KeySpec{Purpose: "p", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := p.Rotate(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	w, err := p.Wrap(ctx, ref, 1, make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unwrap(ctx, ref, v2, w, nil); !errors.Is(err, provider.ErrUnwrapFailed) {
		t.Fatalf("Unwrap under another version = %v, want ErrUnwrapFailed", err)
	}
}

func TestOtherProvidersKeysAreNotFound(t *testing.T) {
	ctx := context.Background()
	a, b := memory.NewKeyring(), memory.NewNative()
	ref, err := a.CreateKey(ctx, provider.KeySpec{Purpose: "p", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wrap(ctx, ref, 1, make([]byte, 32), nil); !errors.Is(err, provider.ErrKeyNotFound) {
		t.Fatalf("Wrap = %v, want ErrKeyNotFound for another provider's key", err)
	}
}

func TestDuplicateIDIsRefused(t *testing.T) {
	ctx := context.Background()
	p := memory.NewKeyring()
	ref, err := p.CreateKey(ctx, provider.KeySpec{Purpose: "p", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.CreateKey(ctx, provider.KeySpec{Purpose: "p", Algorithm: algorithm.AES256GCM, ID: ref.ID})
	if !errors.Is(err, provider.ErrInvalidArgument) {
		t.Fatalf("CreateKey with an existing ID = %v, want ErrInvalidArgument", err)
	}
}
