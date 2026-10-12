package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/provider/local"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	"github.com/plexusone/keyforge/registry"
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

// recordingAuthz records what it was asked and answers from a function.
type recordingAuthz struct {
	mu    sync.Mutex
	asked []string
	allow func(a service.Action, purpose string) error
}

func (r *recordingAuthz) Authorize(_ context.Context, a service.Action, purpose string) error {
	r.mu.Lock()
	r.asked = append(r.asked, fmt.Sprintf("%s:%s", a, purpose))
	r.mu.Unlock()
	if r.allow == nil {
		return nil
	}
	return r.allow(a, purpose)
}

func (r *recordingAuthz) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.asked) == 0 {
		return ""
	}
	return r.asked[len(r.asked)-1]
}

type fixture struct {
	t      *testing.T
	store  *registrymemory.Store
	prov   provider.Provider
	kek    provider.KeyRef
	clock  *clock
	audit  *audit.Recorder
	authz  *recordingAuthz
	client *keyforge.Client
	srv    *httptest.Server
}

type fixtureOpts struct {
	pol    policy.Set
	g      guard.Guard
	prov   provider.Provider
	acker  map[string]service.BackupAcker
	backup map[string]status.BackupFunc
	audit  audit.Sink
}

func newFixture(t *testing.T, fo fixtureOpts) *fixture {
	t.Helper()
	if fo.prov == nil {
		fo.prov = providermemory.NewKeyring()
	}
	f := &fixture{
		t: t, store: registrymemory.NewStore(), prov: fo.prov,
		clock: &clock{t: time.Unix(1_700_000_000, 0)}, audit: &audit.Recorder{}, authz: &recordingAuthz{},
	}
	kek, err := f.prov.CreateKey(bg, provider.KeySpec{Purpose: string(purpose), Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	f.kek = kek
	if err := f.store.Bootstrap(bg, purpose, kek, 1, f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	f.client, err = keyforge.New(keyforge.Options{
		Store: f.store, Providers: []provider.Provider{f.prov}, Clock: f.clock,
		Purposes:      map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {PerSubject: false}},
		EncryptionCap: 2, ReserveBlock: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sink audit.Sink = f.audit
	if fo.audit != nil {
		sink = fo.audit
	}
	rot, err := rotate.New(rotate.Options{
		Store: f.store, Providers: []provider.Provider{f.prov}, Policy: fo.pol, Clock: f.clock,
		Audit: sink, Guard: fo.g, Epochs: f.client,
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := status.New(status.Options{
		Store: f.store, Rotator: rot, Providers: []provider.Provider{f.prov},
		Purposes: []keyforge.Purpose{purpose}, Policy: fo.pol, Clock: f.clock, Backups: fo.backup,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{
		Store: f.store, Rotator: rot, Reporter: rep, Authorizer: f.authz, Backups: fo.acker, Audit: sink, Clock: f.clock,
		Verifier: f.client,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The host's middleware authenticates and names the actor.
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc.ServeHTTP(w, r.WithContext(audit.WithActor(r.Context(), "alice@example.com")))
	}))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) seed(n int) {
	f.t.Helper()
	for range n {
		if _, err := f.client.Encrypt(bg, purpose, []byte("x"), nil); err != nil {
			f.t.Fatal(err)
		}
	}
}

type resp struct {
	code int
	body map[string]any
	raw  string
}

func (f *fixture) do(method, path string, body any) resp {
	f.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return f.send(req)
}

func (f *fixture) send(req *http.Request) resp {
	f.t.Helper()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		f.t.Fatal(err)
	}
	out := resp{code: res.StatusCode, raw: buf.String()}
	_ = json.Unmarshal(buf.Bytes(), &out.body)
	return out
}

func errCode(r resp) string {
	e, _ := r.body["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func (f *fixture) kekPath(version uint32, tail string) string {
	return fmt.Sprintf("/v1/keks/%s/versions/%d/%s", f.kek.ID, version, tail)
}

func TestAnAuthorizerIsRequired(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	rot, err := rotate.New(rotate.Options{Store: f.store, Providers: []provider.Provider{f.prov}})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := status.New(status.Options{Store: f.store, Rotator: rot, Purposes: []keyforge.Purpose{purpose}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.New(service.Options{Store: f.store, Rotator: rot, Reporter: rep}); err == nil {
		t.Fatal("a service with no authorizer was constructed: it would be open by omission")
	}
}

func TestAuthorizationHappensBeforeAnythingIsRevealed(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	f.authz.allow = func(service.Action, string) error { return errors.New("no") }

	// Whether the key exists must not be learnable without permission.
	known := f.do("POST", f.kekPath(1, "retire"), nil)
	unknown := f.do("POST", "/v1/keks/00000000000000000000000000000001/versions/1/retire", nil)
	if known.code != 403 || unknown.code != 403 || known.raw != unknown.raw {
		t.Fatalf("known %d %q, unknown %d %q: an unauthorized caller can tell them apart", known.code, known.raw, unknown.code, unknown.raw)
	}

	// Permitted, an unknown key is simply not found.
	f.authz.allow = nil
	if r := f.do("POST", "/v1/keks/00000000000000000000000000000001/versions/1/retire", nil); r.code != 404 {
		t.Fatalf("an unknown key for an authorized caller = %d, want 404", r.code)
	}
}

func TestAuthorizerSeesTheActionAndPurpose(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	for _, tc := range []struct{ method, path, want string }{
		{"GET", "/v1/status", "status.read:"},
		{"GET", "/v1/purposes", "keys.list:"},
		{"GET", "/v1/purposes/orders", "keys.list:orders"},
		{"POST", "/v1/purposes/orders/rotate", "keys.rotate:orders"},
		{"POST", "/v1/keks/" + f.kek.ID.String() + "/versions/1/destroy", "keys.destroy:orders"}, // purpose resolved from the KEK
	} {
		f.do(tc.method, tc.path, nil)
		if got := f.authz.last(); got != tc.want {
			t.Errorf("%s %s asked %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestUnauthenticatedIs401AndForbiddenIs403(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	f.authz.allow = func(service.Action, string) error { return service.ErrUnauthenticated }
	if r := f.do("GET", "/v1/status", nil); r.code != 401 || errCode(r) != "unauthenticated" {
		t.Fatalf("no identity = %d %q", r.code, errCode(r))
	}
	f.authz.allow = func(a service.Action, _ string) error {
		if a == service.ActionStatus {
			return nil
		}
		return errors.New("viewers may not rotate")
	}
	if r := f.do("GET", "/v1/status", nil); r.code != 200 {
		t.Fatalf("a permitted read = %d", r.code)
	}
	r := f.do("POST", "/v1/purposes/orders/rotate", nil)
	if r.code != 403 || errCode(r) != "forbidden" {
		t.Fatalf("a forbidden action = %d %q", r.code, errCode(r))
	}
	// The reason the authorizer gave is not echoed to the caller.
	if strings.Contains(r.raw, "viewers") {
		t.Fatalf("the response repeats the authorizer's reason: %s", r.raw)
	}
	if kv, err := f.store.ActiveKEK(bg, purpose); err != nil || kv.Version != 1 {
		t.Fatalf("a forbidden rotation changed state: %+v, %v", kv, err)
	}
}

func TestStatusAndHealth(t *testing.T) {
	f := newFixture(t, fixtureOpts{pol: policy.Set{Default: policy.Policy{KEKInterval: 30 * day}}})
	f.seed(4)

	r := f.do("GET", "/v1/status", nil)
	if r.code != 200 || r.body["healthy"] != true {
		t.Fatalf("status = %d %v", r.code, r.body)
	}
	for _, leak := range []string{`"wrapped"`, `"material"`} {
		if strings.Contains(r.raw, leak) {
			t.Errorf("the status response has %s", leak)
		}
	}
	if r := f.do("GET", "/v1/health", nil); r.code != 200 || r.body["healthy"] != true {
		t.Fatalf("health = %d", r.code)
	}

	f.clock.Advance(31 * day)
	r = f.do("GET", "/v1/health", nil)
	if r.code != 503 || r.body["healthy"] != false {
		t.Fatalf("health with an overdue rotation = %d %v", r.code, r.body)
	}
	if probs, _ := r.body["problems"].([]any); len(probs) == 0 {
		t.Fatalf("no problems listed: %v", r.body)
	}
}

func TestReadsAreAudited(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	f.do("GET", "/v1/status", nil)
	f.do("GET", "/v1/purposes/orders", nil)
	evs := f.audit.Events()
	if len(evs) != 2 {
		t.Fatalf("events = %+v, want one per read", evs)
	}
	for _, e := range evs {
		if e.Action != audit.AdminRead || e.Actor != "alice@example.com" {
			t.Errorf("event = %+v", e)
		}
	}
}

func TestListAndGetPurposes(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	r := f.do("GET", "/v1/purposes", nil)
	ps, _ := r.body["purposes"].([]any)
	if r.code != 200 || len(ps) != 1 {
		t.Fatalf("list = %d %v", r.code, r.body)
	}
	r = f.do("GET", "/v1/purposes/orders", nil)
	if r.code != 200 || r.body["purpose"] != "orders" || r.body["activeVersion"] != float64(1) {
		t.Fatalf("get = %d %v", r.code, r.body)
	}
	if r := f.do("GET", "/v1/purposes/nothing", nil); r.code != 404 {
		t.Fatalf("an unknown purpose = %d, want 404", r.code)
	}
}

func TestRotateRewrapAndRollback(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	f.seed(6)

	r := f.do("POST", "/v1/purposes/orders/rotate", nil)
	if r.code != 200 || r.body["from"] != float64(1) || r.body["to"] != float64(2) || r.body["kekId"] != f.kek.ID.String() {
		t.Fatalf("rotate = %d %v", r.code, r.body)
	}
	if e := f.audit.Events(); e[0].Actor != "alice@example.com" {
		t.Fatalf("the rotation is attributed to %q, want the actor the host named", e[0].Actor)
	}

	r = f.do("POST", "/v1/purposes/orders/rewrap", nil)
	vs, _ := r.body["versions"].(map[string]any)
	if r.code != 200 || r.body["done"] != true || len(vs) != 1 {
		t.Fatalf("rewrap = %d %v", r.code, r.body)
	}
	one, _ := vs["1"].(map[string]any)
	if one["rewrapped"] != float64(3) {
		t.Fatalf("rewrapped = %v, want 3", one)
	}

	r = f.do("POST", "/v1/purposes/orders/rollback", nil)
	if r.code != 200 || r.body["to"] != float64(1) {
		t.Fatalf("rollback = %d %v", r.code, r.body)
	}
	// Version 2 is now the only decrypt-only version, so rolling back again
	// returns to it, and with nothing decrypt-only there is nothing to return to.
	r = f.do("POST", "/v1/purposes/orders/rollback", nil)
	if r.code != 200 || r.body["to"] != float64(2) {
		t.Fatalf("second rollback = %d %v", r.code, r.body)
	}
}

func TestRollbackWithNothingToReturnTo(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	if r := f.do("POST", "/v1/purposes/orders/rollback", nil); r.code != 409 || errCode(r) != "no_rollback_target" {
		t.Fatalf("rollback with one version = %d %q", r.code, errCode(r))
	}
}

func TestRetirementOverHTTP(t *testing.T) {
	pol := policy.Set{Default: policy.Policy{RetainVersions: 1, RetirementDelay: 7 * day}}
	f := newFixture(t, fixtureOpts{pol: pol, g: guard.AllowAll()})
	f.seed(4)
	f.do("POST", "/v1/purposes/orders/rotate", nil)
	f.do("POST", "/v1/purposes/orders/rewrap", nil)

	// A version that is not decrypt-only cannot be put forward.
	if r := f.do("POST", f.kekPath(2, "retire"), nil); r.code != 409 || errCode(r) != "invalid_state" {
		t.Fatalf("retiring the active version = %d %q", r.code, errCode(r))
	}
	if r := f.do("POST", f.kekPath(1, "retire"), nil); r.code != 200 || r.body["state"] != "retire-requested" {
		t.Fatalf("request = %d %v", r.code, r.body)
	}
	if r := f.do("POST", f.kekPath(1, "retire/complete"), nil); r.code != 409 || errCode(r) != "retire_delay" {
		t.Fatalf("completing inside the delay = %d %q", r.code, errCode(r))
	}
	f.clock.Advance(8 * day)
	if r := f.do("POST", f.kekPath(1, "retire/complete"), nil); r.code != 200 || r.body["state"] != "retired" {
		t.Fatalf("complete = %d %v", r.code, r.body)
	}
	if r := f.do("POST", f.kekPath(1, "destroy"), nil); r.code != 200 || r.body["state"] != "destroyed" {
		t.Fatalf("destroy = %d %v", r.code, r.body)
	}
	if r := f.do("POST", f.kekPath(1, "destroy"), nil); r.code != 409 {
		t.Fatalf("destroying twice = %d, want 409", r.code)
	}
}

func TestGuardAnswersMapToStatuses(t *testing.T) {
	pol := policy.Set{Default: policy.Policy{RetainVersions: 1, RetirementDelay: 7 * day}}
	answers := []guard.Decision{guard.AwaitApproval("ticket 7"), guard.Deny("legal hold")}
	i := 0
	g := guard.Func(func(context.Context, guard.Request) (guard.Decision, error) {
		d := answers[min(i, len(answers)-1)]
		i++
		return d, nil
	})
	f := newFixture(t, fixtureOpts{pol: pol, g: g})
	f.seed(4)
	f.do("POST", "/v1/purposes/orders/rotate", nil)
	f.do("POST", "/v1/purposes/orders/rewrap", nil)
	f.do("POST", f.kekPath(1, "retire"), nil)
	f.clock.Advance(8 * day)

	r := f.do("POST", f.kekPath(1, "retire/complete"), nil)
	if r.code != 202 || r.body["outcome"] != "pending" || r.body["reason"] != "ticket 7" {
		t.Fatalf("a pending approval = %d %v, want 202", r.code, r.body)
	}
	r = f.do("POST", f.kekPath(1, "retire/complete"), nil)
	if r.code != 409 || r.body["outcome"] != "denied" || r.body["state"] != "decrypt-only" {
		t.Fatalf("a denial = %d %v, want 409 with the key back in service", r.code, r.body)
	}
}

func TestCancelRetirement(t *testing.T) {
	pol := policy.Set{Default: policy.Policy{RetainVersions: 1}}
	f := newFixture(t, fixtureOpts{pol: pol, g: guard.AllowAll()})
	f.seed(2)
	f.do("POST", "/v1/purposes/orders/rotate", nil)
	f.do("POST", "/v1/purposes/orders/rewrap", nil)
	f.do("POST", f.kekPath(1, "retire"), nil)
	if r := f.do("POST", f.kekPath(1, "retire/cancel"), nil); r.code != 200 || r.body["state"] != "decrypt-only" {
		t.Fatalf("cancel = %d %v", r.code, r.body)
	}
}

func TestEmergencyKEK(t *testing.T) {
	f := newFixture(t, fixtureOpts{}) // no guard: it is recorded, not obeyed
	f.seed(6)
	r := f.do("POST", f.kekPath(1, "compromise"), map[string]any{})
	if r.code != 200 || r.body["destroyed"] != true || r.body["retired"] != true || r.body["rewrapped"] != float64(3) || r.body["replacement"] != float64(2) {
		t.Fatalf("compromise = %d %v", r.code, r.body)
	}
	if r := f.do("POST", f.kekPath(1, "compromise"), nil); r.code != 409 {
		t.Fatalf("compromising a destroyed version = %d, want 409", r.code)
	}
	if r := f.do("POST", f.kekPath(2, "compromise"), map[string]any{"keepMaterial": "yes"}); r.code != 400 {
		t.Fatalf("a malformed body = %d, want 400", r.code)
	}
}

func TestEmergencyDEK(t *testing.T) {
	f := newFixture(t, fixtureOpts{g: guard.AllowAll()})
	e, err := f.client.Encrypt(bg, purpose, []byte("exposed"), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := f.do("POST", "/v1/datakeys/"+e.DEKID.String()+"/compromise", nil)
	if r.code != 200 || r.body["state"] != "compromised" || r.body["replacement"] == nil {
		t.Fatalf("compromise = %d %v", r.code, r.body)
	}
	r = f.do("POST", "/v1/datakeys/"+e.DEKID.String()+"/destroy", nil)
	if r.code != 200 || r.body["state"] == "" {
		t.Fatalf("destroy = %d %v", r.code, r.body)
	}
	if r := f.do("POST", "/v1/datakeys/00000000000000000000000000000002/compromise", nil); r.code != 404 {
		t.Fatalf("an unknown data key = %d, want 404", r.code)
	}
}

func TestBackupAcknowledgement(t *testing.T) {
	root := bytes.Repeat([]byte{3}, local.RootKeySize)
	lp, err := local.Create(bg, local.Options{Path: filepath.Join(t.TempDir(), "keyring.kf"), Root: local.StaticSource(root)})
	if err != nil {
		t.Fatal(err)
	}
	defer lp.Close()
	f := newFixture(t, fixtureOpts{
		prov:   lp,
		acker:  map[string]service.BackupAcker{lp.Name(): lp},
		backup: map[string]status.BackupFunc{lp.Name(): status.LocalBackup(lp)},
	})

	st, err := lp.BackupStatus(bg)
	if err != nil {
		t.Fatal(err)
	}
	r := f.do("POST", "/v1/backups/local/ack", map[string]any{"generation": st.Generation + 5, "note": "x"})
	if r.code != 409 || errCode(r) != "ack_refused" {
		t.Fatalf("acknowledging a generation not reached = %d %q", r.code, errCode(r))
	}
	r = f.do("POST", "/v1/backups/local/ack", map[string]any{"generation": st.Generation, "note": "offsite"})
	if r.code != 200 || r.body["acknowledged"] != float64(st.Generation) {
		t.Fatalf("ack = %d %v", r.code, r.body)
	}
	if now, _ := lp.BackupStatus(bg); now.Note != "offsite" || !now.UpToDate() {
		t.Fatalf("the acknowledgement was not recorded: %+v", now)
	}
	if r := f.do("POST", "/v1/backups/nowhere/ack", map[string]any{"generation": 1}); r.code != 404 {
		t.Fatalf("an unknown provider = %d, want 404", r.code)
	}
	if r := f.do("POST", "/v1/backups/local/ack", map[string]any{"note": "no generation"}); r.code != 400 {
		t.Fatalf("no generation = %d, want 400", r.code)
	}
}

func TestShredOverHTTP(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	perSubject, err := keyforge.New(keyforge.Options{
		Store: f.store, Providers: []provider.Provider{f.prov}, Clock: f.clock,
		Purposes: map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {PerSubject: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	subject := "user 42/a b"
	if _, err := perSubject.EncryptFor(bg, purpose, subject, []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	path := "/v1/purposes/orders/subjects/" + url.PathEscape(subject) + "/shred"

	r := f.do("POST", path, nil)
	if r.code != 202 || r.body["complete"] != false || r.body["dataKeys"] != float64(1) {
		t.Fatalf("shred = %d %v, want 202 pending", r.code, r.body)
	}
	r = f.do("GET", path, nil)
	if r.code != 200 || r.body["complete"] != false || r.body["pendingVersions"] != float64(1) || r.body["expectedBy"] == nil {
		t.Fatalf("status = %d %v", r.code, r.body)
	}
	if r := f.do("GET", "/v1/purposes/orders/subjects/nobody/shred", nil); r.code != 404 {
		t.Fatalf("an unshredded subject = %d, want 404", r.code)
	}
}

func TestRequestHandling(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	for name, tc := range map[string]struct {
		method, path string
		body         string
		ct           string
		want         int
	}{
		"bad KEK id":           {"POST", "/v1/keks/zz/versions/1/retire", "", "", 400},
		"short KEK id":         {"POST", "/v1/keks/abcd/versions/1/retire", "", "", 400},
		"version zero":         {"POST", "/v1/keks/" + f.kek.ID.String() + "/versions/0/retire", "", "", 400},
		"version not a number": {"POST", "/v1/keks/" + f.kek.ID.String() + "/versions/x/retire", "", "", 400},
		"unknown field":        {"POST", "/v1/keks/" + f.kek.ID.String() + "/versions/1/compromise", `{"keep":true}`, "application/json", 400},
		"wrong content type":   {"POST", "/v1/keks/" + f.kek.ID.String() + "/versions/1/compromise", `{"keepMaterial":true}`, "text/plain", 415},
		"too large":            {"POST", "/v1/keks/" + f.kek.ID.String() + "/versions/1/compromise", `{"keepMaterial":true,"x":"` + strings.Repeat("a", service.MaxBodyBytes) + `"}`, "application/json", 413},
		"method not allowed":   {"DELETE", "/v1/status", "", "", 405},
		"unknown route":        {"GET", "/v2/status", "", "", 404},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, f.srv.URL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			if r := f.send(req); r.code != tc.want {
				t.Fatalf("%s %s = %d (%s), want %d", tc.method, tc.path, r.code, r.raw, tc.want)
			}
		})
	}
}

func TestAnAuditGapIsAWarningNotAFailure(t *testing.T) {
	down := &audit.Recorder{Err: errors.New("sink down")}
	f := newFixture(t, fixtureOpts{audit: down})
	r := f.do("POST", "/v1/purposes/orders/rotate", nil)
	if r.code != 200 {
		t.Fatalf("a rotation that happened was reported as %d", r.code)
	}
	if w, _ := r.body["warnings"].([]any); len(w) != 1 {
		t.Fatalf("warnings = %v, want the gap reported", r.body["warnings"])
	}
	// The change stands.
	if kv, err := f.store.ActiveKEK(bg, purpose); err != nil || kv.Version != 2 {
		t.Fatalf("ActiveKEK = %+v, %v", kv, err)
	}
}

// failingStore is a registry that fails with a message that must not reach a caller.
type failingStore struct {
	registry.Store
}

func (failingStore) KEKForPurpose(context.Context, keyforge.Purpose) (registry.KEK, error) {
	return registry.KEK{}, errors.New("dial tcp 10.1.2.3:5432: password authentication failed for user keyforge_admin")
}

func TestUnexpectedFailuresDoNotLeakDetail(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	rot, err := rotate.New(rotate.Options{Store: failingStore{f.store}, Providers: []provider.Provider{f.prov}, Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := status.New(status.Options{Store: f.store, Rotator: rot, Purposes: []keyforge.Purpose{purpose}})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: f.store, Rotator: rot, Reporter: rep, Authorizer: &recordingAuthz{}})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	svc.ServeHTTP(rr, httptest.NewRequest("POST", "/v1/purposes/orders/rotate", nil))
	if rr.Code != 500 {
		t.Fatalf("status = %d", rr.Code)
	}
	for _, leak := range []string{"10.1.2.3", "password", "keyforge_admin", "5432"} {
		if strings.Contains(rr.Body.String(), leak) {
			t.Fatalf("the response leaks %q: %s", leak, rr.Body.String())
		}
	}
}

func TestVerifyEndpoint(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	r := f.do("POST", "/v1/verify", nil)
	if r.code != 200 || r.body["ok"] != true {
		t.Fatalf("verify = %d %v", r.code, r.body)
	}
	if got := f.authz.last(); got != "keys.verify:" {
		t.Fatalf("authorizer asked %q", got)
	}
	if r := f.do("POST", "/v1/verify?purpose=orders", nil); r.code != 200 || f.authz.last() != "keys.verify:orders" {
		t.Fatalf("verify one purpose = %d, asked %q", r.code, f.authz.last())
	}
	if r := f.do("POST", "/v1/verify?purpose=unknown", nil); r.code != 503 || r.body["ok"] != false {
		t.Fatalf("verify an unconfigured purpose = %d %v, want 503 with ok false", r.code, r.body)
	}
	for _, leak := range []string{"wrapped", "material"} {
		if strings.Contains(f.do("POST", "/v1/verify", nil).raw, leak) {
			t.Errorf("the verify response has %q", leak)
		}
	}
}
