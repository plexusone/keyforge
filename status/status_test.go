package status_test

import (
	"bytes"
	"context"
	"crypto/fips140"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/jobs"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/provider/local"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	"github.com/plexusone/keyforge/registry"
	registrymemory "github.com/plexusone/keyforge/registry/memory"
	"github.com/plexusone/keyforge/rotate"
	"github.com/plexusone/keyforge/status"
)

var bg = context.Background()

const (
	purpose keyforge.Purpose = "orders"
	day                      = 24 * time.Hour
)

type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// sick is a provider that reports itself unhealthy.
type sick struct {
	provider.Provider
	err error
}

func (s sick) Health(context.Context) error { return s.err }

type world struct {
	t     *testing.T
	store *registrymemory.Store
	prov  provider.Provider
	kek   provider.KeyRef
	clock *clock
	pol   policy.Set
}

func newWorld(t *testing.T, prov provider.Provider, pol policy.Set) *world {
	t.Helper()
	w := &world{t: t, store: registrymemory.NewStore(), prov: prov, clock: &clock{t: time.Unix(1_700_000_000, 0)}, pol: pol}
	kek, err := prov.CreateKey(bg, provider.KeySpec{Purpose: string(purpose), Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	w.kek = kek
	if err := w.store.Bootstrap(bg, purpose, kek, 1, w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) rotator() *rotate.Rotator {
	w.t.Helper()
	r, err := rotate.New(rotate.Options{
		Store: w.store, Providers: []provider.Provider{w.prov}, Policy: w.pol, Clock: w.clock,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func (w *world) reporter(mutate func(*status.Options)) *status.Reporter {
	w.t.Helper()
	o := status.Options{
		Store: w.store, Rotator: w.rotator(), Providers: []provider.Provider{w.prov},
		Purposes: []keyforge.Purpose{purpose}, Policy: w.pol, Clock: w.clock,
	}
	if mutate != nil {
		mutate(&o)
	}
	r, err := status.New(o)
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func (w *world) seed(n int) {
	w.t.Helper()
	c, err := keyforge.New(keyforge.Options{
		Store: w.store, Providers: []provider.Provider{w.prov},
		Purposes: map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {}}, Clock: w.clock,
		EncryptionCap: 2, ReserveBlock: 2,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	for range n {
		if _, err := c.Encrypt(bg, purpose, []byte("x"), nil); err != nil {
			w.t.Fatal(err)
		}
	}
}

func TestHealthyReport(t *testing.T) {
	w := newWorld(t, providermemory.NewKeyring(), policy.Set{Default: policy.Policy{KEKInterval: 30 * day}})
	w.seed(6)
	w.clock.Advance(5 * day)

	rep := w.reporter(nil).Report(bg)
	if !rep.Healthy || len(rep.Problems) != 0 {
		t.Fatalf("Healthy = %v, problems %v", rep.Healthy, rep.Problems)
	}
	if len(rep.Providers) != 1 || !rep.Providers[0].Healthy || rep.Providers[0].Name != "memory-keyring" {
		t.Fatalf("Providers = %+v", rep.Providers)
	}
	if len(rep.Purposes) != 1 {
		t.Fatalf("Purposes = %+v", rep.Purposes)
	}
	p := rep.Purposes[0]
	if p.Purpose != "orders" || p.ActiveVersion != 1 || p.Overdue || p.Error != "" || p.KEKID != w.kek.ID.String() {
		t.Fatalf("purpose = %+v", p)
	}
	if want := w.clock.t.Add(25 * day); !p.NextRotation.Equal(want) {
		t.Fatalf("NextRotation = %v, want %v", p.NextRotation, want)
	}
	if p.DataKeys["active"] != 1 || p.DataKeys["decrypt-only"] != 2 {
		t.Fatalf("DataKeys = %v, want 1 active and 2 decrypt-only (three epochs at a cap of two)", p.DataKeys)
	}
	if p.Policy.KEKInterval != 30*day || p.Policy.RetainVersions != 2 || p.Policy.RetirementDelay != 30*day {
		t.Fatalf("Policy = %+v", p.Policy)
	}
	if len(p.Versions) != 1 || p.Versions[0].State != "active" || p.Versions[0].References != 3 || p.Versions[0].Retirable {
		t.Fatalf("Versions = %+v", p.Versions)
	}
}

func TestCryptoStatus(t *testing.T) {
	w := newWorld(t, providermemory.NewKeyring(), policy.Set{})
	sel, err := algorithm.NewSelector(algorithm.Config{Profile: algorithm.ProfileFIPS})
	if err != nil {
		t.Fatal(err)
	}
	c := w.reporter(func(o *status.Options) { o.Selector = sel }).Report(bg).Crypto
	if c.Profile != "fips" || c.FIPSMode != fips140.Enabled() || c.FIPSEnforced != fips140.Enforced() || c.ModuleVersion == "" {
		t.Fatalf("Crypto = %+v", c)
	}
	if len(c.Algorithms) != 1 || c.Algorithms[0] != "AES-256-GCM" {
		t.Fatalf("Algorithms = %v, want the exact name", c.Algorithms)
	}
	// With no selector the profile follows FIPS mode.
	def := w.reporter(nil).Report(bg).Crypto
	want := "standard"
	if fips140.Enabled() {
		want = "fips"
	}
	if def.Profile != want {
		t.Fatalf("default profile = %q, want %q", def.Profile, want)
	}
}

func TestOverdueRotationIsAProblem(t *testing.T) {
	w := newWorld(t, providermemory.NewKeyring(), policy.Set{Default: policy.Policy{KEKInterval: 30 * day}})
	w.clock.Advance(32 * day)

	rep := w.reporter(nil).Report(bg)
	p := rep.Purposes[0]
	if rep.Healthy || !p.Overdue || p.OverdueBy != 2*day {
		t.Fatalf("Healthy=%v Overdue=%v OverdueBy=%v", rep.Healthy, p.Overdue, p.OverdueBy)
	}
	if len(rep.Problems) != 1 || !strings.Contains(rep.Problems[0], "overdue") {
		t.Fatalf("Problems = %v", rep.Problems)
	}
}

func TestVersionsShowRetirability(t *testing.T) {
	pol := policy.Set{Default: policy.Policy{KEKInterval: 30 * day, RetainVersions: 1}}
	w := newWorld(t, providermemory.NewKeyring(), pol)
	w.seed(4)
	rot := w.rotator()
	if _, err := rot.RotateKEK(bg, purpose); err != nil {
		t.Fatal(err)
	}

	v := w.reporter(nil).Report(bg).Purposes[0].Versions
	if len(v) != 2 || v[0].State != "decrypt-only" || v[0].References != 2 || v[0].Retirable {
		t.Fatalf("Versions = %+v, want version 1 referenced and not retirable", v)
	}
	if len(v[0].Reasons) == 0 || strings.Contains(strings.Join(v[0].Reasons, " "), "wrapped under it") == false {
		t.Fatalf("Reasons = %v, want the reference named", v[0].Reasons)
	}
	if _, err := rot.Rewrap(bg, w.kek.ID, 1, rotate.RewrapOptions{}); err != nil {
		t.Fatal(err)
	}
	v = w.reporter(nil).Report(bg).Purposes[0].Versions
	if !v[0].Retirable || v[0].References != 0 || v[1].State != "active" || v[1].ActivatedAt.IsZero() {
		t.Fatalf("after the re-wrap: %+v", v)
	}
}

func TestAnUnhealthyProviderDoesNotHideTheRest(t *testing.T) {
	w := newWorld(t, providermemory.NewKeyring(), policy.Set{})
	bad := sick{Provider: w.prov, err: errors.New("credentials expired for /srv/keys/ring.kf")}
	var logs bytes.Buffer
	rep := w.reporter(func(o *status.Options) {
		o.Providers = []provider.Provider{bad}
		o.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	}).Report(bg)

	if rep.Healthy || rep.Providers[0].Healthy || rep.Providers[0].Error == "" {
		t.Fatalf("provider status = %+v, healthy %v", rep.Providers[0], rep.Healthy)
	}
	// What the report says names the kind of failure, not the error's text,
	// which can hold paths; the text goes to the log.
	shown := rep.Providers[0].Error + " " + strings.Join(rep.Problems, " ")
	if strings.Contains(shown, "credentials expired") || strings.Contains(shown, "/srv/keys") {
		t.Fatalf("the report shows the error's text: %q", shown)
	}
	if !strings.Contains(logs.String(), "credentials expired") {
		t.Fatalf("the detail was not logged: %q", logs.String())
	}
	// The purposes are still reported.
	if len(rep.Purposes) != 1 || rep.Purposes[0].ActiveVersion != 1 {
		t.Fatalf("Purposes = %+v", rep.Purposes)
	}
}

func TestLocalBackupStaleAndCurrent(t *testing.T) {
	root := bytes.Repeat([]byte{7}, local.RootKeySize)
	lp, err := local.Create(bg, local.Options{Path: filepath.Join(t.TempDir(), "keyring.kf"), Root: local.StaticSource(root)})
	if err != nil {
		t.Fatal(err)
	}
	defer lp.Close()
	w := newWorld(t, lp, policy.Set{})
	mk := func() status.Report {
		return w.reporter(func(o *status.Options) {
			o.Backups = map[string]status.BackupFunc{lp.Name(): status.LocalBackup(lp)}
		}).Report(bg)
	}

	rep := mk()
	b := rep.Providers[0].Backup
	if rep.Healthy || b == nil || b.UpToDate || b.Behind == 0 || b.Acknowledged != 0 {
		t.Fatalf("an unacknowledged keyring: healthy %v, backup %+v", rep.Healthy, b)
	}
	if !strings.Contains(strings.Join(rep.Problems, "; "), "ahead of its acknowledged backup") {
		t.Fatalf("Problems = %v", rep.Problems)
	}

	st, err := lp.BackupStatus(bg)
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.AckBackup(bg, st.Generation, w.clock.Now(), "offsite"); err != nil {
		t.Fatal(err)
	}
	rep = mk()
	if b = rep.Providers[0].Backup; !rep.Healthy || b == nil || !b.UpToDate || b.Note != "offsite" {
		t.Fatalf("after acknowledging: healthy %v, backup %+v, problems %v", rep.Healthy, b, rep.Problems)
	}
}

func TestPurposeWithNoUsableKeyIsReported(t *testing.T) {
	w := newWorld(t, providermemory.NewKeyring(), policy.Set{})
	if err := w.store.TransitionVersion(bg, w.kek.ID, 1, registry.VersionCompromised, registry.TransitionOptions{At: w.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	rep := w.reporter(nil).Report(bg)
	if rep.Healthy || rep.Purposes[0].ActiveVersion != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Problems, "; "), "no active key version") {
		t.Fatalf("Problems = %v", rep.Problems)
	}

	// A purpose with no KEK at all is reported, and the others still are.
	rep = w.reporter(func(o *status.Options) { o.Purposes = []keyforge.Purpose{"missing", purpose} }).Report(bg)
	if len(rep.Purposes) != 2 || rep.Purposes[0].Error == "" {
		t.Fatalf("Purposes = %+v", rep.Purposes)
	}
}

func TestCompromisedDataKeysAreAProblem(t *testing.T) {
	w := newWorld(t, providermemory.NewKeyring(), policy.Set{})
	w.seed(2)
	recs, err := w.store.ListDEKs(bg, registry.DEKFilter{})
	if err != nil || len(recs) != 1 {
		t.Fatal(err)
	}
	if err := w.store.MarkDEK(bg, recs[0].ID, keyforge.DEKCompromised); err != nil {
		t.Fatal(err)
	}
	rep := w.reporter(nil).Report(bg)
	if rep.Healthy || rep.Purposes[0].DataKeys["compromised"] != 1 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestPendingErasuresAreListedWithAnEstimate(t *testing.T) {
	w := newWorld(t, providermemory.NewKeyring(), policy.Set{})
	c, err := keyforge.New(keyforge.Options{
		Store: w.store, Providers: []provider.Provider{w.prov}, Clock: w.clock,
		Purposes: map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {PerSubject: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.EncryptFor(bg, purpose, "alice", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.rotator().RequestShred(bg, purpose, "alice"); err != nil {
		t.Fatal(err)
	}
	rep := w.reporter(nil).Report(bg)
	if len(rep.Shreds) != 1 || rep.Shreds[0].Subject != "alice" || rep.Shreds[0].PendingVersions != 1 || rep.Shreds[0].ExpectedBy.IsZero() {
		t.Fatalf("Shreds = %+v", rep.Shreds)
	}
}

func TestJobFailuresComeFromTheScheduler(t *testing.T) {
	pol := policy.Set{Default: policy.Policy{KEKInterval: 30 * day}}
	w := newWorld(t, providermemory.NewKeyring(), pol)
	w.seed(2)
	rot := w.rotator()
	e, err := jobs.NewEmbedded(jobs.EmbeddedOptions{SchedulerOptions: jobs.SchedulerOptions{
		Rotator: rot, Store: w.store, Purposes: []keyforge.Purpose{purpose}, Clock: w.clock,
	}})
	if err != nil {
		t.Fatal(err)
	}
	// Before any tick the scheduler has nothing to say.
	if rep := w.reporter(func(o *status.Options) { o.Scheduler = e.Scheduler }).Report(bg); rep.Jobs == nil || len(rep.Jobs.Failed) != 0 {
		t.Fatalf("Jobs = %+v", rep.Jobs)
	}
	// An overdue rotation is in the scheduler's result and in the report.
	w.clock.Advance(31 * day)
	if _, err := e.Scheduler.Tick(bg); err != nil {
		t.Fatal(err)
	}
	rep := w.reporter(func(o *status.Options) { o.Scheduler = e.Scheduler }).Report(bg)
	if rep.Jobs == nil || rep.Jobs.InFlight != 0 {
		t.Fatalf("Jobs = %+v", rep.Jobs)
	}
	if !rep.Purposes[0].Overdue {
		t.Fatal("the overdue rotation is not reported")
	}
}

func TestReportHoldsNoKeyMaterial(t *testing.T) {
	w := newWorld(t, providermemory.NewKeyring(), policy.Set{})
	w.seed(4)
	b, err := json.Marshal(w.reporter(nil).Report(bg))
	if err != nil {
		t.Fatal(err)
	}
	recs, err := w.store.ListDEKs(bg, registry.DEKFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		for _, leak := range []string{string(r.Wrapped)} {
			if bytes.Contains(b, []byte(leak)) {
				t.Fatal("the report contains a wrapped key")
			}
		}
	}
	for _, field := range []string{`"wrapped"`, `"material"`, `"key"`, `"secret"`} {
		if strings.Contains(string(b), field) {
			t.Errorf("the report has a field %s", field)
		}
	}
}

func TestNewValidates(t *testing.T) {
	w := newWorld(t, providermemory.NewKeyring(), policy.Set{})
	good := status.Options{Store: w.store, Rotator: w.rotator(), Purposes: []keyforge.Purpose{purpose}}
	if _, err := status.New(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*status.Options){
		"no store":    func(o *status.Options) { o.Store = nil },
		"no rotator":  func(o *status.Options) { o.Rotator = nil },
		"no purposes": func(o *status.Options) { o.Purposes = nil },
	} {
		o := good
		mutate(&o)
		if _, err := status.New(o); err == nil {
			t.Errorf("%s: New accepted the options", name)
		}
	}
}
