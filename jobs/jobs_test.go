package jobs_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/omniworkflow"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/jobs"
	"github.com/plexusone/keyforge/metrics"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	"github.com/plexusone/keyforge/registry"
	registrymemory "github.com/plexusone/keyforge/registry/memory"
	"github.com/plexusone/keyforge/rotate"
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

// failRotate makes the provider's Rotate fail, as an outage would.
type failRotate struct {
	provider.Provider
	mu   sync.Mutex
	fail bool
	// block, when set, makes Rotate wait for the context, as a call in flight
	// when the process dies does.
	block bool
	calls int
}

func (f *failRotate) Rotate(ctx context.Context, ref provider.KeyRef) (uint32, error) {
	f.mu.Lock()
	f.calls++
	fail, block := f.fail, f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if fail {
		return 0, errors.New("provider unavailable")
	}
	return f.Provider.Rotate(ctx, ref)
}

func (f *failRotate) set(fail, block bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail, f.block = fail, block
}

type world struct {
	t     *testing.T
	store *registrymemory.Store
	prov  *failRotate
	kek   provider.KeyRef
	clock *clock
	audit *audit.Recorder
	pol   policy.Set
	g     guard.Guard
}

func newWorld(t *testing.T, pol policy.Set, g guard.Guard) *world {
	t.Helper()
	w := &world{
		t: t, store: registrymemory.NewStore(), prov: &failRotate{Provider: providermemory.NewKeyring()},
		clock: &clock{t: time.Unix(1_700_000_000, 0)}, audit: &audit.Recorder{}, pol: pol, g: g,
	}
	kek, err := w.prov.CreateKey(bg, provider.KeySpec{Purpose: string(purpose), Algorithm: algorithm.AES256GCM})
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
		Store: w.store, Providers: []provider.Provider{w.prov}, Policy: w.pol,
		Clock: w.clock, Audit: w.audit, Guard: w.g,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func (w *world) embedded(stateDir string, mutate func(*jobs.EmbeddedOptions)) *jobs.Embedded {
	w.t.Helper()
	o := jobs.EmbeddedOptions{
		SchedulerOptions: jobs.SchedulerOptions{
			Rotator: w.rotator(), Store: w.store, Purposes: []keyforge.Purpose{purpose},
			Clock: w.clock, Audit: w.audit, Interval: time.Hour,
		},
		StateDir: stateDir,
	}
	if mutate != nil {
		mutate(&o)
	}
	e, err := jobs.NewEmbedded(o)
	if err != nil {
		w.t.Fatal(err)
	}
	return e
}

// run starts only the embedded worker, and stops it with the test. The tests
// tick the scheduler themselves, so that what runs when is deterministic.
func (w *world) run(e *jobs.Embedded) context.CancelFunc {
	w.t.Helper()
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { defer close(done); _ = e.Work(ctx) }()
	w.t.Cleanup(func() { cancel(); <-done })
	return func() { cancel(); <-done }
}

// seed writes data keys under the current KEK version, two messages per key.
func (w *world) seed(n int) []keyforge.Envelope {
	w.t.Helper()
	c, err := keyforge.New(keyforge.Options{
		Store: w.store, Providers: []provider.Provider{w.prov},
		Purposes:      map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {}},
		Clock:         w.clock,
		EncryptionCap: 2, ReserveBlock: 2,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	var out []keyforge.Envelope
	for range n {
		e, err := c.Encrypt(bg, purpose, []byte("data"), nil)
		if err != nil {
			w.t.Fatal(err)
		}
		out = append(out, *e)
	}
	return out
}

func (w *world) states() map[uint32]registry.VersionState {
	w.t.Helper()
	vs, err := w.store.ListVersions(bg, w.kek.ID)
	if err != nil {
		w.t.Fatal(err)
	}
	out := map[uint32]registry.VersionState{}
	for _, v := range vs {
		out[v.Version] = v.State
	}
	return out
}

// settle waits for every run a tick started to finish and returns the statuses.
func settle(t *testing.T, e *jobs.Embedded, started []jobs.Started) map[string]omniworkflow.RunStatus {
	t.Helper()
	out := map[string]omniworkflow.RunStatus{}
	deadline := time.Now().Add(10 * time.Second)
	for _, s := range started {
		for {
			r, err := e.Provider.Get(bg, s.RunID)
			if err != nil {
				t.Fatal(err)
			}
			if r.Status.IsTerminal() {
				out[s.RunID] = r.Status
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("run %s did not finish: %v", s.RunID, r.Status)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	return out
}

func mustTick(t *testing.T, e *jobs.Embedded) jobs.TickResult {
	t.Helper()
	res, err := e.Scheduler.Tick(bg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func kinds(res jobs.TickResult) []jobs.Kind {
	var out []jobs.Kind
	for _, s := range res.Started {
		out = append(out, s.Spec.Kind)
	}
	return out
}

func TestRotationIsStartedWhenDueAndDrains(t *testing.T) {
	w := newWorld(t, policy.Set{Default: policy.Policy{KEKInterval: 30 * day, RetainVersions: 2}}, nil)
	data := w.seed(8) // four data keys under version 1
	e := w.embedded("", nil)
	w.run(e)

	if res := mustTick(t, e); res.Wanted != 0 || len(res.Started) != 0 || len(res.Overdue) != 0 {
		t.Fatalf("a tick before anything is due = %+v", res)
	}

	w.clock.Advance(31 * day)
	res := mustTick(t, e)
	if len(res.Overdue) != 1 || res.Overdue[0].Purpose != purpose || res.Overdue[0].Late != day {
		t.Fatalf("Overdue = %+v, want one rotation one day late", res.Overdue)
	}
	if got := kinds(res); len(got) != 1 || got[0] != jobs.RotateKEK {
		t.Fatalf("started %v, want one rotation; result %+v", got, res)
	}
	for id, st := range settle(t, e, res.Started) {
		if st != omniworkflow.StatusSucceeded {
			t.Fatalf("run %s ended %s", id, st)
		}
	}

	// The new version is active, and the job's second step drained the old one.
	if got := w.states(); got[1] != registry.VersionDecryptOnly || got[2] != registry.VersionActive {
		t.Fatalf("versions = %v", got)
	}
	if n, _ := w.store.CountDEKs(bg, w.kek.ID, 1); n != 0 {
		t.Fatalf("%d data keys are still under version 1", n)
	}

	// Nothing is due now, and the data is intact.
	after := mustTick(t, e)
	if after.Wanted != 0 || len(after.Started) != 0 || len(after.Overdue) != 0 {
		t.Fatalf("the next tick = %+v, want quiet", after)
	}
	c, err := keyforge.New(keyforge.Options{Store: w.store, Providers: []provider.Provider{w.prov}, Purposes: map[keyforge.Purpose]keyforge.PurposeConfig{purpose: {}}, Clock: w.clock})
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		if _, _, err := c.Decrypt(bg, purpose, &data[i], nil); err != nil {
			t.Fatalf("data %d after the job: %v", i, err)
		}
	}
}

// TestReplicasStartTheSameRun is the property that replaces leader election:
// two schedulers over one provider find the same work due, and one execution
// results.
func TestReplicasStartTheSameRun(t *testing.T) {
	w := newWorld(t, policy.Set{Default: policy.Policy{KEKInterval: 30 * day}}, nil)
	w.seed(4)
	e := w.embedded("", nil)
	w.run(e)

	// A second scheduler, as another replica would be, over the same provider.
	other, err := jobs.NewScheduler(jobs.SchedulerOptions{
		Provider: e.Provider, Rotator: w.rotator(), Store: w.store, Purposes: []keyforge.Purpose{purpose},
		Clock: w.clock, Audit: w.audit,
	})
	if err != nil {
		t.Fatal(err)
	}

	w.clock.Advance(31 * day)
	var wg sync.WaitGroup
	results := make([]jobs.TickResult, 2)
	for i, tick := range []func(context.Context) (jobs.TickResult, error){e.Scheduler.Tick, other.Tick} {
		wg.Go(func() {
			r, err := tick(bg)
			if err != nil {
				t.Errorf("tick %d: %v", i, err)
			}
			results[i] = r
		})
	}
	wg.Wait()

	// Both may have asked to start the rotation; the provider ran it once. (The
	// second replica may also have seen the first's rotation land and started a
	// re-wrap, which is idempotent and is a different job.)
	var started []jobs.Started
	rotations := map[string]bool{}
	for _, r := range results {
		for _, s := range r.Started {
			started = append(started, s)
			if s.Spec.Kind == jobs.RotateKEK {
				rotations[s.RunID] = true
			}
		}
	}
	if len(rotations) != 1 {
		t.Fatalf("the replicas started %d different rotations, want one: %v", len(rotations), rotations)
	}
	settle(t, e, started)
	if got := w.states(); len(got) != 2 {
		t.Fatalf("versions = %v, want exactly one rotation (two versions)", got)
	}
}

func TestRetirementAndDestructionRunOverTicks(t *testing.T) {
	pol := policy.Set{Default: policy.Policy{KEKInterval: 30 * day, RetirementDelay: 7 * day, RetainVersions: 2}}
	w := newWorld(t, pol, guard.AllowAll())
	w.seed(4)
	e := w.embedded("", nil)
	w.run(e)

	step := func(want jobs.Kind) {
		t.Helper()
		res := mustTick(t, e)
		found := false
		for _, k := range kinds(res) {
			found = found || k == want
		}
		if !found {
			t.Fatalf("tick started %v, want %s; result %+v; versions %v", kinds(res), want, res, w.states())
		}
		for id, st := range settle(t, e, res.Started) {
			if st != omniworkflow.StatusSucceeded {
				t.Fatalf("run %s ended %s", id, st)
			}
		}
	}

	w.clock.Advance(31 * day)
	step(jobs.RotateKEK)
	// Version 1 is now the previous version, the rollback margin, which the
	// floor of two keeps: nothing is due until the next rotation.
	if res := mustTick(t, e); len(res.Started) != 0 {
		t.Fatalf("a tick with version 1 inside the floor started %v", kinds(res))
	}
	w.clock.Advance(31 * day)
	step(jobs.RotateKEK)
	step(jobs.RequestRetirement) // version 1 is now N-2, outside the floor, and drained
	if got := w.states()[1]; got != registry.VersionRetireRequested {
		t.Fatalf("version 1 is %s", got)
	}
	// Inside the delay there is nothing to do.
	if res := mustTick(t, e); len(res.Started) != 0 {
		t.Fatalf("a tick inside the retirement delay started %v", kinds(res))
	}

	w.clock.Advance(8 * day)
	step(jobs.CompleteRetirement)
	if got := w.states()[1]; got != registry.VersionRetired {
		t.Fatalf("version 1 is %s", got)
	}
	step(jobs.Destroy)
	if got := w.states()[1]; got != registry.VersionDestroyed {
		t.Fatalf("version 1 is %s", got)
	}
	if _, err := w.prov.Wrap(bg, w.kek, 1, make([]byte, 32), nil); !errors.Is(err, provider.ErrVersionDestroyed) {
		t.Fatalf("the provider still holds version 1: %v", err)
	}
}

func TestAPendingGuardIsAskedAgainOnlyAfterTheRecheck(t *testing.T) {
	pol := policy.Set{Default: policy.Policy{KEKInterval: 30 * day, RetirementDelay: 7 * day, RetainVersions: 2}}
	asked := 0
	answers := []guard.Decision{guard.AwaitApproval("ticket 41"), guard.AwaitApproval("ticket 41"), guard.Allow(), guard.Allow()}
	g := guard.Func(func(context.Context, guard.Request) (guard.Decision, error) {
		d := answers[min(asked, len(answers)-1)]
		asked++
		return d, nil
	})
	w := newWorld(t, pol, g)
	w.seed(4)
	e := w.embedded("", func(o *jobs.EmbeddedOptions) { o.Recheck = 10 * time.Minute })
	w.run(e)

	// Rotate twice so version 1 is N-2, outside the floor of two, then request
	// its retirement.
	w.clock.Advance(31 * day)
	res := mustTick(t, e)
	settle(t, e, res.Started)
	w.clock.Advance(31 * day)
	for range 2 { // rotate, then request retirement
		res = mustTick(t, e)
		settle(t, e, res.Started)
	}
	w.clock.Advance(8 * day)

	res = mustTick(t, e)
	settle(t, e, res.Started)
	if asked != 1 || w.states()[1] != registry.VersionRetireRequested {
		t.Fatalf("after the first pass: asked %d, version 1 is %s", asked, w.states()[1])
	}

	// Right away there is no new run: the answer was pending, not an error, and
	// the scheduler waits before asking again.
	res = mustTick(t, e)
	if len(res.Started) != 0 || res.Waiting != 1 || asked != 1 {
		t.Fatalf("an immediate second tick = %+v, asked %d, want it to wait", res, asked)
	}

	w.clock.Advance(11 * time.Minute)
	res = mustTick(t, e)
	settle(t, e, res.Started)
	if asked != 2 || w.states()[1] != registry.VersionRetireRequested {
		t.Fatalf("after the recheck: asked %d, version 1 is %s", asked, w.states()[1])
	}

	w.clock.Advance(11 * time.Minute)
	res = mustTick(t, e)
	settle(t, e, res.Started)
	if w.states()[1] != registry.VersionRetired {
		t.Fatalf("the approval came and version 1 is %s", w.states()[1])
	}
}

func TestFailedJobsAreReportedAndRetriedWithBackoff(t *testing.T) {
	w := newWorld(t, policy.Set{Default: policy.Policy{KEKInterval: 30 * day}}, nil)
	w.seed(4)
	e := w.embedded("", func(o *jobs.EmbeddedOptions) { o.Backoff, o.MaxBackoff = time.Minute, time.Hour })
	w.run(e)
	w.prov.set(true, false)

	w.clock.Advance(31 * day)
	res := mustTick(t, e)
	if st := settle(t, e, res.Started); len(st) != 1 {
		t.Fatal("no job started")
	} else {
		for _, s := range st {
			if s != omniworkflow.StatusFailed {
				t.Fatalf("the job ended %s, want failed", s)
			}
		}
	}

	// It is reported, with the audit event, and not started again at once.
	res = mustTick(t, e)
	if len(res.Failed) != 1 || res.Failed[0].Consecutive != 1 || res.Failed[0].Spec.Kind != jobs.RotateKEK {
		t.Fatalf("Failed = %+v", res.Failed)
	}
	if len(res.Started) != 0 || res.Waiting != 1 {
		t.Fatalf("tick = %+v, want the retry to wait", res)
	}
	if len(res.Overdue) != 1 {
		t.Fatalf("Overdue = %+v, want the rotation still reported late", res.Overdue)
	}
	var failedEvents int
	for _, a := range w.audit.Actions() {
		if a == audit.JobFailed {
			failedEvents++
		}
	}
	if failedEvents != 1 {
		t.Fatalf("%d job.failed events, want exactly one", failedEvents)
	}

	// After the backoff a second attempt starts, and fails, and waits twice as long.
	w.clock.Advance(61 * time.Second)
	res = mustTick(t, e)
	if len(res.Started) != 1 || res.Started[0].Attempt != 2 {
		t.Fatalf("started %+v, want attempt 2", res.Started)
	}
	settle(t, e, res.Started)
	res = mustTick(t, e)
	if len(res.Failed) != 1 || res.Failed[0].Consecutive != 2 {
		t.Fatalf("Failed = %+v, want two consecutive failures", res.Failed)
	}
	w.clock.Advance(61 * time.Second) // only half the doubled wait
	if res = mustTick(t, e); len(res.Started) != 0 {
		t.Fatalf("the doubled backoff was not honored: started %v", kinds(res))
	}

	// The outage ends and the next attempt does the rotation.
	w.prov.set(false, false)
	w.clock.Advance(2 * time.Minute)
	res = mustTick(t, e)
	if len(res.Started) != 1 || res.Started[0].Attempt != 3 {
		t.Fatalf("started %+v, want attempt 3", res.Started)
	}
	for id, st := range settle(t, e, res.Started) {
		if st != omniworkflow.StatusSucceeded {
			t.Fatalf("run %s ended %s", id, st)
		}
	}
	if got := w.states(); got[2] != registry.VersionActive {
		t.Fatalf("versions = %v", got)
	}
}

// TestRunsResumeAfterARestart kills the process while a rotation is in flight
// and starts another on the same state directory. The run finishes under its
// original identity, and the rotation happens once.
func TestRunsResumeAfterARestart(t *testing.T) {
	w := newWorld(t, policy.Set{Default: policy.Policy{KEKInterval: 30 * day}}, nil)
	w.seed(4)
	dir := t.TempDir()

	// The first process: the provider hangs in Rotate, so the step is in flight.
	w.prov.set(false, true)
	first := w.embedded(dir, nil)
	stop := w.run(first)
	w.clock.Advance(31 * day)
	res := mustTick(t, first)
	if len(res.Started) != 1 {
		t.Fatalf("started %v", kinds(res))
	}
	id := res.Started[0].RunID
	deadline := time.Now().Add(5 * time.Second)
	for {
		w.prov.mu.Lock()
		calls := w.prov.calls
		w.prov.mu.Unlock()
		if calls > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the step never reached the provider")
		}
		time.Sleep(2 * time.Millisecond)
	}
	stop() // the "crash": the worker stops with the run unfinished
	if got := w.states(); len(got) != 1 {
		t.Fatalf("versions = %v, want the rotation not to have happened yet", got)
	}

	// The second process, with the provider healthy, on the same directory.
	w.prov.set(false, false)
	second := w.embedded(dir, nil)
	w.run(second)
	settle(t, second, []jobs.Started{{RunID: id}})

	r, err := second.Provider.Get(bg, id)
	if err != nil || r.Status != omniworkflow.StatusSucceeded {
		t.Fatalf("resumed run = %+v, %v", r, err)
	}
	if got := w.states(); len(got) != 2 || got[2] != registry.VersionActive {
		t.Fatalf("versions = %v, want exactly one rotation", got)
	}
}

func TestUnconfiguredPurposeIsLeftAlone(t *testing.T) {
	w := newWorld(t, policy.Set{}, nil)
	e := w.embedded("", func(o *jobs.EmbeddedOptions) { o.Purposes = []keyforge.Purpose{"not-set-up"} })
	if res, err := e.Scheduler.Tick(bg); err != nil || res.Wanted != 0 {
		t.Fatalf("Tick = %+v, %v", res, err)
	}
}

func TestOpenErasuresAreWatched(t *testing.T) {
	w := newWorld(t, policy.Set{}, nil)
	if _, err := w.store.ShredSubject(bg, purpose, "alice", w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	// A shred with no keys completes at once, so there is nothing to watch.
	e := w.embedded("", nil)
	if res := mustTick(t, e); res.Wanted != 0 {
		t.Fatalf("a completed shred is wanted: %+v", res)
	}
}

func TestExecutorDecodesGenericJSONAndRefusesBadInput(t *testing.T) {
	w := newWorld(t, policy.Set{}, nil)
	x := jobs.NewExecutor(w.rotator(), w.store)

	// A provider hands the input back as generic JSON.
	out, err := x.ExecuteStep(bg, "run", omniworkflow.PlanStep{ID: "s", Input: map[string]any{"kind": "complete-shreds"}})
	if err != nil {
		t.Fatalf("ExecuteStep = %v", err)
	}
	if m, ok := out.(map[string]any); !ok || m["completed"] != 0 {
		t.Fatalf("output = %#v", out)
	}

	for name, in := range map[string]any{
		"unknown kind":  map[string]any{"kind": "reticulate-splines"},
		"bad KEK id":    map[string]any{"kind": "rewrap", "kekId": "not-hex"},
		"wrong KEK len": map[string]any{"kind": "destroy", "kekId": "abcd", "version": 1},
		"not an object": []int{1, 2, 3},
	} {
		if _, err := x.ExecuteStep(bg, "run", omniworkflow.PlanStep{ID: "s", Input: in}); err == nil {
			t.Errorf("%s: ExecuteStep accepted the input", name)
		}
	}
}

func TestRotationStepChecksThatItIsStillDue(t *testing.T) {
	w := newWorld(t, policy.Set{Default: policy.Policy{KEKInterval: 30 * day}}, nil)
	x := jobs.NewExecutor(w.rotator(), w.store)
	spec := jobs.Spec{Kind: jobs.RotateKEK, Purpose: string(purpose)}

	// A step delivered after the rotation already happened does nothing.
	out, err := x.ExecuteStep(bg, "r", omniworkflow.PlanStep{ID: "rotate", Input: spec})
	if err != nil {
		t.Fatal(err)
	}
	if m := out.(map[string]any); m["rotated"] != false {
		t.Fatalf("output = %v, want not rotated", m)
	}
	if len(w.states()) != 1 {
		t.Fatalf("versions = %v", w.states())
	}
	// An operator's forced rotation does it.
	spec.Force = true
	if _, err := x.ExecuteStep(bg, "r", omniworkflow.PlanStep{ID: "rotate", Input: spec}); err != nil {
		t.Fatal(err)
	}
	if len(w.states()) != 2 {
		t.Fatalf("versions = %v after a forced rotation", w.states())
	}
}

func TestNewSchedulerValidates(t *testing.T) {
	w := newWorld(t, policy.Set{}, nil)
	good := jobs.SchedulerOptions{Rotator: w.rotator(), Store: w.store, Purposes: []keyforge.Purpose{purpose}}
	e := w.embedded("", nil)
	good.Provider = e.Provider
	if _, err := jobs.NewScheduler(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*jobs.SchedulerOptions){
		"no provider": func(o *jobs.SchedulerOptions) { o.Provider = nil },
		"no rotator":  func(o *jobs.SchedulerOptions) { o.Rotator = nil },
		"no store":    func(o *jobs.SchedulerOptions) { o.Store = nil },
		"no purposes": func(o *jobs.SchedulerOptions) { o.Purposes = nil },
		"bad purpose": func(o *jobs.SchedulerOptions) { o.Purposes = []keyforge.Purpose{"Bad Purpose"} },
	} {
		o := good
		mutate(&o)
		if _, err := jobs.NewScheduler(o); err == nil {
			t.Errorf("%s: NewScheduler accepted the options", name)
		}
	}
}

// TestRunTicksOnItsOwn checks the unattended path: with nothing driving it by
// hand, the embedded runner notices an overdue rotation and does it.
func TestRunTicksOnItsOwn(t *testing.T) {
	w := newWorld(t, policy.Set{Default: policy.Policy{KEKInterval: 30 * day}}, nil)
	w.seed(4)
	w.clock.Advance(31 * day)
	e := w.embedded("", func(o *jobs.EmbeddedOptions) { o.Interval = 10 * time.Millisecond })

	ctx, cancel := context.WithCancel(bg)
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for w.states()[2] != registry.VersionActive {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("the rotation never happened: %v", w.states())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v, want a clean stop", err)
	}
	if got := w.states(); len(got) != 2 {
		t.Fatalf("versions = %v, want exactly one rotation", got)
	}
}

func TestSchedulerReportsOverdueAndJobMetrics(t *testing.T) {
	rec := metrics.NewRecorder()
	w := newWorld(t, policy.Set{Default: policy.Policy{KEKInterval: 30 * day}}, nil)
	w.seed(4)
	e := w.embedded("", func(o *jobs.EmbeddedOptions) { o.Metrics = rec; o.Backoff, o.MaxBackoff = time.Minute, time.Hour })
	w.run(e)
	p := metrics.L("purpose", string(purpose))

	mustTick(t, e)
	if v, ok := rec.GaugeValue(metrics.RotationOverdue, p); !ok || v != 0 {
		t.Fatalf("overdue gauge before the date = %v, %v, want a reported zero", v, ok)
	}

	w.prov.set(true, false) // the rotation will fail
	w.clock.Advance(31*day + time.Hour)
	res := mustTick(t, e)
	if v, _ := rec.GaugeValue(metrics.RotationOverdue, p); v != float64((day + time.Hour).Seconds()) {
		t.Fatalf("overdue gauge = %v, want %v seconds", v, (day + time.Hour).Seconds())
	}
	if got := rec.Counter(metrics.JobsStarted, metrics.L("kind", "rotate-kek")); got != 1 {
		t.Fatalf("jobs started = %d, want 1", got)
	}
	settle(t, e, res.Started)
	mustTick(t, e) // notices the failure
	if got := rec.Counter(metrics.JobsFailed, metrics.L("kind", "rotate-kek")); got != 1 {
		t.Fatalf("jobs failed = %d, want 1", got)
	}

	// Recovery clears the gauge; it does not merely stop updating it.
	w.prov.set(false, false)
	w.clock.Advance(2 * time.Minute)
	res = mustTick(t, e)
	settle(t, e, res.Started)
	mustTick(t, e)
	if v, ok := rec.GaugeValue(metrics.RotationOverdue, p); !ok || v != 0 {
		t.Fatalf("overdue gauge after the rotation = %v, %v, want zero", v, ok)
	}
}
