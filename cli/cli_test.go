package cli_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/cli"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/provider/local"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	registrymemory "github.com/plexusone/keyforge/registry/memory"
	"github.com/plexusone/keyforge/rotate"
	"github.com/plexusone/keyforge/service"
	"github.com/plexusone/keyforge/status"
)

var bg = context.Background()

const (
	purpose keyforge.Purpose = "orders"
	day                      = 24 * time.Hour
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type world struct {
	t       *testing.T
	store   *registrymemory.Store
	kek     provider.KeyRef
	clock   *clock
	handler http.Handler
	client  *keyforge.Client
}

func newWorld(t *testing.T, g guard.Guard) *world {
	t.Helper()
	prov := providermemory.NewKeyring()
	w := &world{t: t, store: registrymemory.NewStore(), clock: &clock{t: time.Unix(1_700_000_000, 0)}}
	kek, err := prov.CreateKey(bg, provider.KeySpec{Purpose: string(purpose), Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	w.kek = kek
	if err := w.store.Bootstrap(bg, purpose, kek, 1, w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	w.client, err = keyforge.New(keyforge.Options{
		Store: w.store, Providers: []provider.Provider{prov}, Clock: w.clock,
		Purposes:      map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {}},
		EncryptionCap: 2, ReserveBlock: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.Set{Default: policy.Policy{KEKInterval: 30 * day, RetainVersions: 2, RetirementDelay: 7 * day}}
	rot, err := rotate.New(rotate.Options{
		Store: w.store, Providers: []provider.Provider{prov}, Policy: pol, Clock: w.clock,
		Audit: &audit.Recorder{}, Guard: g, Epochs: w.client,
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := status.New(status.Options{
		Store: w.store, Rotator: rot, Providers: []provider.Provider{prov},
		Purposes: []keyforge.Purpose{purpose}, Policy: pol, Clock: w.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{
		Store: w.store, Rotator: rot, Reporter: rep, Verifier: w.client, Clock: w.clock,
		Authorizer: service.AuthorizerFunc(func(ctx context.Context, _ service.Action, _ string) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.handler = svc
	return w
}

func (w *world) seed(n int) {
	w.t.Helper()
	for range n {
		if _, err := w.client.Encrypt(bg, purpose, []byte("x"), nil); err != nil {
			w.t.Fatal(err)
		}
	}
}

type out struct {
	stdout, stderr string
}

func run(t *testing.T, opts cli.Options, args ...string) (out, error) {
	t.Helper()
	var o, e bytes.Buffer
	opts.Out, opts.Err = &o, &e
	if opts.Env == nil {
		opts.Env = func(string) string { return "" }
	}
	cmd := cli.NewRootCommand(opts)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(bg)
	return out{o.String(), e.String()}, err
}

func inProcess(w *world) cli.Options { return cli.Options{Handler: w.handler} }

func TestStatusInProcess(t *testing.T) {
	w := newWorld(t, nil)
	w.seed(4)
	o, err := run(t, inProcess(w), "status")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"healthy", "orders", "active version: 1", "AES-256-GCM", "providers:", "memory-keyring"} {
		if !strings.Contains(o.stdout, want) {
			t.Errorf("status output lacks %q:\n%s", want, o.stdout)
		}
	}
}

func TestJSONOutputIsTheResponse(t *testing.T) {
	w := newWorld(t, nil)
	o, err := run(t, inProcess(w), "--json", "status")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(o.stdout), &v); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, o.stdout)
	}
	if v["healthy"] != true || v["purposes"] == nil {
		t.Fatalf("decoded = %v", v)
	}
}

func TestRemoteServerSendsTheToken(t *testing.T) {
	w := newWorld(t, nil)
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		w.handler.ServeHTTP(rw, r)
	}))
	defer srv.Close()

	// From a file.
	tokFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, cli.Options{}, "--server", srv.URL, "--token-file", tokFile, "status"); err != nil {
		t.Fatal(err)
	}
	// From the environment, and the server from the environment too.
	env := func(k string) string {
		return map[string]string{"KEYFORGE_TOKEN": "env-token", "KEYFORGE_SERVER": srv.URL}[k]
	}
	if _, err := run(t, cli.Options{Env: env}, "status"); err != nil {
		t.Fatal(err)
	}
	if len(auth) != 2 || auth[0] != "Bearer file-token" || auth[1] != "Bearer env-token" {
		t.Fatalf("Authorization headers = %q", auth)
	}
}

func TestNoServerIsExplained(t *testing.T) {
	_, err := run(t, cli.Options{}, "status")
	if err == nil || !strings.Contains(err.Error(), "--server") {
		t.Fatalf("err = %v, want it to say how to name a server", err)
	}
}

func TestAnErrorResponseIsReportedWithItsCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte(`{"error":{"code":"forbidden","message":"not permitted"}}`))
	}))
	defer srv.Close()
	_, err := run(t, cli.Options{}, "--server", srv.URL, "--token-file", writeToken(t, "SECRET-TOKEN"), "rotate", "orders")
	var api *cli.APIError
	if !errors.As(err, &api) || api.Status != 403 || api.Code != "forbidden" {
		t.Fatalf("err = %v, want a 403 forbidden", err)
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatal("the error repeats the token")
	}
}

func writeToken(t *testing.T, tok string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUnreachableServerDoesNotEchoTheToken(t *testing.T) {
	_, err := run(t, cli.Options{}, "--server", "http://127.0.0.1:1", "--timeout", "2s", "--token-file", writeToken(t, "SECRET-TOKEN"), "status")
	if err == nil {
		t.Fatal("an unreachable server succeeded")
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("the error echoes the token: %v", err)
	}
}

func TestRotateRollbackRewrap(t *testing.T) {
	w := newWorld(t, nil)
	w.seed(6)

	o, err := run(t, inProcess(w), "rotate", "orders")
	if err != nil || !strings.Contains(o.stdout, "version 2 is now active, replacing 1") {
		t.Fatalf("rotate = %q, %v", o.stdout, err)
	}
	o, err = run(t, inProcess(w), "rewrap", "orders")
	if err != nil || !strings.Contains(o.stdout, "version 1: 3 moved") || !strings.Contains(o.stdout, "done: true") {
		t.Fatalf("rewrap = %q, %v", o.stdout, err)
	}
	o, err = run(t, inProcess(w), "rollback", "orders")
	if err != nil || !strings.Contains(o.stdout, "version 1 is active again") {
		t.Fatalf("rollback = %q, %v", o.stdout, err)
	}
}

func TestRetirementCommands(t *testing.T) {
	w := newWorld(t, guard.AllowAll())
	w.seed(4)
	kek := w.kek.ID.String()
	mustRun := func(args ...string) out {
		t.Helper()
		o, err := run(t, inProcess(w), args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return o
	}
	// Two rotations make version 1 N-2, outside the floor that keeps the
	// active and previous versions.
	mustRun("rotate", "orders")
	mustRun("rotate", "orders")
	mustRun("rewrap", "orders")

	if o := mustRun("retire", "request", kek, "1"); !strings.Contains(o.stdout, "retire-requested") {
		t.Fatalf("request = %q", o.stdout)
	}
	if _, err := run(t, inProcess(w), "retire", "complete", kek, "1"); err == nil {
		t.Fatal("completing inside the delay succeeded")
	} else {
		var api *cli.APIError
		if !errors.As(err, &api) || api.Code != "retire_delay" {
			t.Fatalf("err = %v, want retire_delay", err)
		}
	}
	w.clock.Advance(8 * day)
	if o := mustRun("retire", "complete", kek, "1"); !strings.Contains(o.stdout, "state:   retired") {
		t.Fatalf("complete = %q", o.stdout)
	}
	if o := mustRun("destroy", kek, "1"); !strings.Contains(o.stdout, "destroyed") {
		t.Fatalf("destroy = %q", o.stdout)
	}
}

func TestADenialIsShownAndExitsNonZero(t *testing.T) {
	g := guard.DenyAll("legal hold on orders")
	w := newWorld(t, g)
	w.seed(4)
	kek := w.kek.ID.String()
	for _, a := range [][]string{{"rotate", "orders"}, {"rotate", "orders"}, {"rewrap", "orders"}, {"retire", "request", kek, "1"}} {
		if _, err := run(t, inProcess(w), a...); err != nil {
			t.Fatalf("%v: %v", a, err)
		}
	}
	w.clock.Advance(8 * day)
	o, err := run(t, inProcess(w), "retire", "complete", kek, "1")
	if err == nil {
		t.Fatal("a denial exited zero")
	}
	if !strings.Contains(o.stdout, "outcome: denied") || !strings.Contains(o.stdout, "legal hold on orders") {
		t.Fatalf("the denial was not shown: %q", o.stdout)
	}
}

func TestVerify(t *testing.T) {
	w := newWorld(t, nil)
	o, err := run(t, inProcess(w), "verify")
	if err != nil || !strings.Contains(o.stdout, "orders") || !strings.Contains(o.stdout, "reference") || strings.Contains(o.stdout, "FAILED") {
		t.Fatalf("verify = %q, %v", o.stdout, err)
	}
	// A purpose the client does not know fails, loudly, with a non-zero exit.
	o, err = run(t, inProcess(w), "verify", "--purpose", "unknown")
	if err == nil || !strings.Contains(o.stdout, "FAILED") {
		t.Fatalf("verify of an unknown purpose = %q, %v", o.stdout, err)
	}
}

func TestHealthExitsNonZeroWhenUnhealthy(t *testing.T) {
	w := newWorld(t, nil)
	if _, err := run(t, inProcess(w), "health"); err != nil {
		t.Fatalf("a healthy system: %v", err)
	}
	w.clock.Advance(40 * day) // past the 30-day interval
	o, err := run(t, inProcess(w), "health")
	if err == nil || !strings.Contains(o.stdout, "overdue") {
		t.Fatalf("health = %q, %v", o.stdout, err)
	}
}

func TestPurposesCommands(t *testing.T) {
	w := newWorld(t, nil)
	o, err := run(t, inProcess(w), "purposes", "list")
	if err != nil || !strings.Contains(o.stdout, "orders") {
		t.Fatalf("list = %q, %v", o.stdout, err)
	}
	o, err = run(t, inProcess(w), "purposes", "show", "orders")
	if err != nil || !strings.Contains(o.stdout, "version 1") {
		t.Fatalf("show = %q, %v", o.stdout, err)
	}
	if _, err := run(t, inProcess(w), "purposes", "show", "nothing"); err == nil {
		t.Fatal("an unknown purpose succeeded")
	}
}

func TestEmergencyAndDataKeyCommands(t *testing.T) {
	w := newWorld(t, guard.AllowAll())
	e, err := w.client.Encrypt(bg, purpose, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := run(t, inProcess(w), "datakey", "compromise", e.DEKID.String())
	if err != nil || !strings.Contains(o.stdout, "compromised") {
		t.Fatalf("datakey compromise = %q, %v", o.stdout, err)
	}
	o, err = run(t, inProcess(w), "compromise", "--keep-material", w.kek.ID.String(), "1")
	fields := strings.Join(strings.Fields(o.stdout), " ")
	if err != nil || !strings.Contains(fields, "retired: true") || !strings.Contains(fields, "destroyed: false") {
		t.Fatalf("compromise = %q, %v", o.stdout, err)
	}
	if _, err := run(t, inProcess(w), "datakey", "destroy", e.DEKID.String()); err != nil {
		t.Fatal(err)
	}
}

func TestShredCommands(t *testing.T) {
	w := newWorld(t, nil)
	// A subject that never had keys is erased at once; the commands need only
	// the registry for that.
	if _, err := w.store.ShredSubject(bg, purpose, "never-seen", w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	o, err := run(t, inProcess(w), "shred", "status", "orders", "never-seen")
	if err != nil || !strings.Contains(strings.Join(strings.Fields(o.stdout), " "), "complete: true") {
		t.Fatalf("shred status = %q, %v", o.stdout, err)
	}
	o, err = run(t, inProcess(w), "shred", "request", "orders", "someone")
	if err != nil || !strings.Contains(strings.Join(strings.Fields(o.stdout), " "), "complete: true") {
		t.Fatalf("shred request = %q, %v", o.stdout, err)
	}
}

func TestBackupAckNeedsAGeneration(t *testing.T) {
	w := newWorld(t, nil)
	if _, err := run(t, inProcess(w), "backup", "ack", "local"); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("err = %v, want the missing flag named", err)
	}
	_, err := run(t, inProcess(w), "backup", "ack", "nowhere", "--generation", "1")
	var api *cli.APIError
	if !errors.As(err, &api) || api.Status != 404 {
		t.Fatalf("err = %v, want 404 for an unknown provider", err)
	}
}

func TestOfflineCommands(t *testing.T) {
	// A keyring's header is readable without its root key.
	root := bytes.Repeat([]byte{9}, local.RootKeySize)
	path := filepath.Join(t.TempDir(), "keyring.kf")
	p, err := local.Create(bg, local.Options{Path: path, Root: local.StaticSource(root)})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	o, err := run(t, cli.Options{}, "keyring", "inspect", path)
	if err != nil || !strings.Contains(o.stdout, "generation:  1") || !strings.Contains(o.stdout, p.RootKeyID()) {
		t.Fatalf("inspect = %q, %v", o.stdout, err)
	}
	if _, err := run(t, cli.Options{}, "keyring", "inspect", path+".missing"); err == nil {
		t.Fatal("inspecting a missing file succeeded")
	}

	// A generated root key is 32 random bytes and is not repeated.
	a, err := run(t, cli.Options{}, "rootkey", "generate")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := run(t, cli.Options{}, "rootkey", "generate")
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a.stdout))
	if err != nil || len(raw) != local.RootKeySize {
		t.Fatalf("generated key = %q (%v), want 32 bytes of base64", a.stdout, err)
	}
	if a.stdout == b.stdout {
		t.Fatal("two generated root keys are identical")
	}
	if !strings.Contains(a.stderr, "secret manager") {
		t.Fatalf("no warning about keeping it: %q", a.stderr)
	}
	// The key it printed is one the local provider accepts.
	t.Setenv("KEYFORGE_TEST_ROOT", strings.TrimSpace(a.stdout))
	if _, err := local.EnvSource("KEYFORGE_TEST_ROOT").RootKey(bg); err != nil {
		t.Fatalf("the generated key is not accepted as a root key: %v", err)
	}
}

func TestUsageErrorsDoNotDumpHelp(t *testing.T) {
	w := newWorld(t, nil)
	o, err := run(t, inProcess(w), "rotate")
	if err == nil {
		t.Fatal("rotate with no purpose succeeded")
	}
	if strings.Contains(o.stdout+o.stderr, "Usage:") {
		t.Fatalf("a usage error printed the whole help: %q", o.stdout+o.stderr)
	}
}
