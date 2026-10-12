package embedded_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/embedded"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider/local"
	"github.com/plexusone/keyforge/rotate"
	"github.com/plexusone/keyforge/service"
)

var bg = context.Background()

const purpose keyforge.Purpose = "orders"

func rootKey(seed byte) local.RootKeySource {
	k := make([]byte, local.RootKeySize)
	for i := range k {
		k[i] = seed + byte(i) //nolint:gosec // G115: i < 32
	}
	return local.StaticSource(k)
}

func options(dir string) embedded.Options {
	return embedded.Options{
		Dir:      dir,
		Root:     rootKey(1),
		Purposes: map[keyforge.Purpose]embedded.PurposeOptions{purpose: {}},
	}
}

func open(t *testing.T, o embedded.Options) *embedded.System {
	t.Helper()
	s, err := embedded.Open(bg, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestFirstStartThenReopenKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	o := options(dir)

	first, err := embedded.Open(bg, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{embedded.KeyringFile, embedded.RegistryFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("first start did not create %s: %v", name, err)
		}
	}
	env, err := first.Client.Encrypt(bg, purpose, []byte("order 42"), []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	text := env.String()
	kek, err := first.Registry.KEKForPurpose(bg, purpose)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second := open(t, o)
	again, err := second.Registry.KEKForPurpose(bg, purpose)
	if err != nil || again.ID != kek.ID {
		t.Fatalf("reopening changed the KEK: %v, %v", again.ID, err)
	}
	parsed, err := envelope.ParseText(text)
	if err != nil {
		t.Fatal(err)
	}
	pt, _, err := second.Client.Decrypt(bg, purpose, parsed, []byte("ctx"))
	if err != nil || !bytes.Equal(pt, []byte("order 42")) {
		t.Fatalf("after reopen: %q, %v", pt, err)
	}
}

func TestRotationKeepsOldDataReadable(t *testing.T) {
	s := open(t, options(t.TempDir()))
	env, err := s.Client.Encrypt(bg, purpose, []byte("before"), nil)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := s.Rotator.RotateKEK(bg, purpose)
	if err != nil {
		t.Fatal(err)
	}
	if rot.To != 2 {
		t.Fatalf("rotated to version %d", rot.To)
	}
	if _, err := s.Rotator.RewrapAll(bg, rot.KEK.ID, rotate.RewrapOptions{}); err != nil {
		t.Fatal(err)
	}
	pt, _, err := s.Client.Decrypt(bg, purpose, env, nil)
	if err != nil || string(pt) != "before" {
		t.Fatalf("after rotation: %q, %v", pt, err)
	}
}

func TestMissingKeyringBesideKeysIsNotAFreshStart(t *testing.T) {
	dir := t.TempDir()
	o := options(dir)
	s, err := embedded.Open(bg, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, embedded.KeyringFile)); err != nil {
		t.Fatal(err)
	}
	_, err = embedded.Open(bg, o)
	if !errors.Is(err, embedded.ErrKeyringMissing) {
		t.Fatalf("Open = %v, want ErrKeyringMissing", err)
	}
	if _, err := os.Stat(filepath.Join(dir, embedded.KeyringFile)); err == nil {
		t.Fatal("a new keyring was created beside a registry that holds keys")
	}
}

func TestWrongRootKeyIsRefusedAndChangesNothing(t *testing.T) {
	dir := t.TempDir()
	o := options(dir)
	s, err := embedded.Open(bg, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, embedded.KeyringFile))
	if err != nil {
		t.Fatal(err)
	}

	o.Root = rootKey(9)
	if _, err := embedded.Open(bg, o); !errors.Is(err, local.ErrWrongRootKey) {
		t.Fatalf("Open with the wrong root key = %v, want ErrWrongRootKey", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, embedded.KeyringFile))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the keyring changed: %v", err)
	}
}

func TestRootKeyBesideTheKeyringIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.key")
	if err := os.WriteFile(path, []byte("0000000000000000000000000000000000000000000000000000000000000000"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := options(dir)
	o.Root = local.FileSource(path)
	if _, err := embedded.Open(bg, o); !errors.Is(err, local.ErrRootKeyBesideKeyring) {
		t.Fatalf("Open = %v, want ErrRootKeyBesideKeyring", err)
	}
}

func TestControlPlaneNeedsAnAuthorizer(t *testing.T) {
	s := open(t, options(t.TempDir()))
	if _, err := s.Handler(); err == nil {
		t.Fatal("a control plane was offered with no authorizer")
	}

	o := options(t.TempDir())
	o.Authorizer = service.AuthorizerFunc(func(context.Context, service.Action, string) error { return nil })
	s = open(t, o)
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/status = %d: %s", rec.Code, rec.Body)
	}
}

func TestBackupRegistryAndReady(t *testing.T) {
	dir := t.TempDir()
	s := open(t, options(dir))
	if err := s.Ready(bg); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "registry-backup.db")
	if err := s.BackupRegistry(bg, dest); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dest); err != nil || info.Size() == 0 {
		t.Fatalf("backup: %v", err)
	}
}

func TestRunStopsWhenCancelled(t *testing.T) {
	o := options(t.TempDir())
	s := open(t, o)
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	if err := s.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
}

func TestOptionsAreValidated(t *testing.T) {
	for name, mutate := range map[string]func(*embedded.Options){
		"no dir":      func(o *embedded.Options) { o.Dir = "" },
		"no root":     func(o *embedded.Options) { o.Root = nil },
		"no purposes": func(o *embedded.Options) { o.Purposes = nil },
	} {
		t.Run(name, func(t *testing.T) {
			o := options(t.TempDir())
			mutate(&o)
			if _, err := embedded.Open(bg, o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRestoredOlderKeyringNeedsAcceptance(t *testing.T) {
	dir := t.TempDir()
	o := options(dir)
	keyring := filepath.Join(dir, embedded.KeyringFile)

	s, err := embedded.Open(bg, o)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(keyring)
	if err != nil {
		t.Fatal(err)
	}
	// A rotation advances the keyring's generation past the copy taken above.
	if _, err := s.Rotator.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: the path is inside this test's own temporary directory
	if err := os.WriteFile(keyring, old, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := embedded.Open(bg, o); !errors.Is(err, local.ErrKeyringRolledBack) {
		t.Fatalf("Open with an older keyring = %v, want ErrKeyringRolledBack", err)
	}
	o.AcceptRollback = true
	s2, err := embedded.Open(bg, o)
	if err != nil {
		t.Fatalf("Open with the rollback accepted: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
}
