package local

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/grokify/oscompat/fs"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/provider/providertest"
)

var bg = context.Background()

func testRoot(seed byte) RootKeySource {
	k := make([]byte, RootKeySize)
	for i := range k {
		k[i] = seed + byte(i) //nolint:gosec // G115: i < 32
	}
	return StaticSource(k)
}

func newOpts(t *testing.T, seed byte) Options {
	t.Helper()
	return Options{Path: filepath.Join(t.TempDir(), "keyring.kf"), Root: testRoot(seed)}
}

func mustCreate(t *testing.T, opts Options) *Provider {
	t.Helper()
	p, err := Create(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestConformance(t *testing.T) {
	providertest.Run(t, func() provider.Provider {
		dir, err := os.MkdirTemp("", "keyforge-local-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		p, err := Create(bg, Options{Path: filepath.Join(dir, "keyring.kf"), Root: testRoot(1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	})
}

func TestName(t *testing.T) {
	p := mustCreate(t, newOpts(t, 1))
	if p.Name() != "local" {
		t.Fatalf("Name = %q, want local: status must not mistake it for a managed provider", p.Name())
	}
}

func TestCreateOpenRoundTrip(t *testing.T) {
	opts := newOpts(t, 7)
	p := mustCreate(t, opts)
	ref, err := p.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := p.Rotate(bg, ref)
	if err != nil {
		t.Fatal(err)
	}
	dek, aad := bytes.Repeat([]byte{0x42}, 32), []byte("purpose=orders")
	w1, err := p.Wrap(bg, ref, 1, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := p.Wrap(bg, ref, v2, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Destroy(bg, ref, 1); err != nil {
		t.Fatal(err)
	}

	// A new process opens the same file with the same root key.
	re, err := Open(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	if got, err := re.Unwrap(bg, ref, v2, w2, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("version %d after reopening: %v", v2, err)
	}
	if _, err := re.Unwrap(bg, ref, 1, w1, aad); !errors.Is(err, provider.ErrVersionDestroyed) {
		t.Fatalf("a destroyed version after reopening = %v, want ErrVersionDestroyed", err)
	}
	if re.Generation() != p.Generation() {
		t.Fatalf("generation = %d after reopening, want %d", re.Generation(), p.Generation())
	}
}

func TestCreateRefusesAnExistingKeyring(t *testing.T) {
	opts := newOpts(t, 1)
	mustCreate(t, opts)
	if _, err := Create(bg, opts); !errors.Is(err, ErrKeyringExists) {
		t.Fatalf("Create over a keyring = %v, want ErrKeyringExists", err)
	}
}

func TestOpenMissingKeyring(t *testing.T) {
	if _, err := Open(bg, newOpts(t, 1)); !errors.Is(err, ErrKeyringNotFound) {
		t.Fatalf("Open = %v, want ErrKeyringNotFound", err)
	}
}

func TestWrongRootKeyIsReportedAsOne(t *testing.T) {
	opts := newOpts(t, 1)
	mustCreate(t, opts)

	wrong := opts
	wrong.Root = testRoot(2)
	if _, err := Open(bg, wrong); !errors.Is(err, ErrWrongRootKey) {
		t.Fatalf("Open with another root key = %v, want ErrWrongRootKey (not corruption)", err)
	}
	if _, err := Open(bg, opts); err != nil {
		t.Fatalf("Open with the right root key: %v", err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	if _, err := p.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM}); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(opts.Path)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(b []byte) []byte{
		"flipped ciphertext bit":  func(b []byte) []byte { b[len(b)-1] ^= 1; return b },
		"flipped nonce bit":       func(b []byte) []byte { b[headerSize] ^= 1; return b },
		"changed generation":      func(b []byte) []byte { b[31] ^= 1; return b }, // authenticated, so it must not pass
		"truncated":               func(b []byte) []byte { return b[:len(b)-1] },
		"truncated to the header": func(b []byte) []byte { return b[:headerSize] },
		"appended byte":           func(b []byte) []byte { return append(b, 0) },
		"bad magic":               func(b []byte) []byte { b[0] = 'X'; return b },
		"unknown format":          func(b []byte) []byte { b[4] = 9; return b },
		"empty":                   func(b []byte) []byte { return nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(opts.Path, mutate(slices.Clone(orig)), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(bg, opts); !errors.Is(err, ErrCorruptKeyring) {
				t.Fatalf("Open = %v, want ErrCorruptKeyring", err)
			}
		})
	}
}

func TestFileModeAndNoRootKeyOnDisk(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	ref, err := p.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	if fs.PermissionsEnforced() {
		info, err := os.Stat(opts.Path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("keyring mode = %v, %v, want 0600", info.Mode().Perm(), err)
		}
	}

	file, err := os.ReadFile(opts.Path)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := opts.Root.RootKey(bg)
	for name, leak := range map[string][]byte{
		"the root key":            root,
		"the root key in base64":  []byte(base64.StdEncoding.EncodeToString(root)),
		"the root key in hex":     []byte(hex.EncodeToString(root)),
		"the key purpose":         []byte("orders"),
		"the key identifier text": []byte(ref.ID.String()),
	} {
		if bytes.Contains(file, leak) {
			t.Errorf("the keyring file contains %s in the clear", name)
		}
	}
	// Nothing but the keyring, its lock file and its backup state is left beside
	// it: no temporary files.
	entries, err := os.ReadDir(filepath.Dir(opts.Path))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	if want := []string{"keyring.kf", "keyring.kf.backup", "keyring.kf.lock"}; !slices.Equal(names, want) {
		t.Fatalf("directory holds %v, want %v", names, want)
	}
}

func TestInsecureKeyringIsRefused(t *testing.T) {
	if !fs.PermissionsEnforced() {
		t.Skip("file modes are not enforced on Windows")
	}
	opts := newOpts(t, 1)
	mustCreate(t, opts)
	if err := os.Chmod(opts.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bg, opts); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("Open of a world-readable keyring = %v, want ErrInsecurePermissions", err)
	}
}

func TestRootKeyRotation(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	ref, err := p.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	dek, aad := bytes.Repeat([]byte{9}, 32), []byte("a")
	w, err := p.Wrap(bg, ref, 1, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	oldID, oldGen := p.RootKeyID(), p.Generation()

	if err := p.RotateRootKey(bg, testRoot(50)); err != nil {
		t.Fatal(err)
	}
	if p.RootKeyID() == oldID {
		t.Fatal("the root key identifier did not change")
	}
	if p.Generation() != oldGen+1 {
		t.Fatalf("generation = %d, want %d: a root key rotation is a write", p.Generation(), oldGen+1)
	}
	// The same provider keeps working.
	if got, err := p.Unwrap(bg, ref, 1, w, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap after the root key rotated: %v", err)
	}

	// Only the new root key opens the file now, and nothing was lost.
	if _, err := Open(bg, opts); !errors.Is(err, ErrWrongRootKey) {
		t.Fatalf("Open with the old root key = %v, want ErrWrongRootKey", err)
	}
	nu := opts
	nu.Root = testRoot(50)
	re, err := Open(bg, nu)
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	if got, err := re.Unwrap(bg, ref, 1, w, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap under the new root key: %v", err)
	}
}

func TestCrossProcessWritesDoNotInterleave(t *testing.T) {
	opts := newOpts(t, 1)
	first := mustCreate(t, opts)
	ref, err := first.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(bg, opts) // a second "process": its own state and file descriptors
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	const each = 15
	var wg sync.WaitGroup
	versions := make(chan uint32, 2*each)
	for _, p := range []*Provider{first, second} {
		wg.Go(func() {
			for range each {
				v, err := p.Rotate(bg, ref)
				if err != nil {
					t.Errorf("Rotate: %v", err)
					return
				}
				versions <- v
			}
		})
	}
	wg.Wait()
	close(versions)

	seen := map[uint32]bool{}
	for v := range versions {
		if seen[v] {
			t.Errorf("version %d was issued twice: two processes interleaved", v)
		}
		seen[v] = true
	}
	if len(seen) != 2*each {
		t.Fatalf("%d versions issued, want %d", len(seen), 2*each)
	}

	// Each can use what the other wrote.
	dek, aad := bytes.Repeat([]byte{3}, 32), []byte("a")
	var some uint32
	for v := range seen {
		some = max(some, v)
	}
	w, err := first.Wrap(bg, ref, some, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := second.Unwrap(bg, ref, some, w, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("the other process cannot use version %d: %v", some, err)
	}
}

func TestRootKeyBesideKeyringIsRefused(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "root.key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{Path: filepath.Join(dir, "keyring.kf"), Root: FileSource(keyFile)}
	if _, err := Create(bg, opts); !errors.Is(err, ErrRootKeyBesideKeyring) {
		t.Fatalf("Create = %v, want ErrRootKeyBesideKeyring", err)
	}
	opts.AllowRootKeyBesideKeyring = true
	p, err := Create(bg, opts)
	if err != nil {
		t.Fatalf("Create with the override: %v", err)
	}
	p.Close()
}

func TestClosedProviderFailsClosed(t *testing.T) {
	p := mustCreate(t, newOpts(t, 1))
	ref, err := p.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Rotate(bg, ref); !errors.Is(err, ErrClosed) {
		t.Fatalf("Rotate after Close = %v, want ErrClosed", err)
	}
	if err := p.Health(bg); !errors.Is(err, ErrClosed) {
		t.Fatalf("Health after Close = %v, want ErrClosed", err)
	}
}

func TestOptionsAreValidated(t *testing.T) {
	if _, err := Create(bg, Options{Root: testRoot(1)}); err == nil {
		t.Error("Create without a path succeeded")
	}
	if _, err := Create(bg, Options{Path: "x"}); err == nil {
		t.Error("Create without a root key source succeeded")
	}
}

func TestEntropyIsInjectable(t *testing.T) {
	ids := func() string {
		opts := newOpts(t, 1)
		opts.Entropy = &seqReader{}
		p := mustCreate(t, opts)
		ref, err := p.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM})
		if err != nil {
			t.Fatal(err)
		}
		return ref.ID.String()
	}
	if a, b := ids(), ids(); a != b {
		t.Fatalf("identifiers differ under the same entropy: %s vs %s", a, b)
	}
}

type seqReader struct{ n byte }

func (r *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		r.n++
		p[i] = r.n
	}
	return len(p), nil
}

func ExampleCreate() {
	dir, _ := os.MkdirTemp("", "keyforge-example-*")
	defer os.RemoveAll(dir)
	root := make([]byte, RootKeySize) // in practice: 32 random bytes from a secret manager
	for i := range root {
		root[i] = byte(i) //nolint:gosec // G115: i < 32
	}
	p, err := Create(context.Background(), Options{Path: filepath.Join(dir, "keyring.kf"), Root: StaticSource(root)})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer p.Close()
	fmt.Println(p.Name(), p.Generation())
	// Output: local 1
}
