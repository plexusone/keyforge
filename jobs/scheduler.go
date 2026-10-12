package jobs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/plexusone/omniworkflow"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/metrics"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/rotate"
)

// Defaults for [SchedulerOptions].
const (
	// DefaultInterval is how often the scheduler looks for work.
	DefaultInterval = time.Minute
	// DefaultRecheck is how long to wait before starting a job again for a
	// condition that is still true after the last one succeeded, such as a guard
	// that is still pending. It keeps a long wait for an approval from filling
	// the run store with identical runs.
	DefaultRecheck = 10 * time.Minute
	// DefaultBackoff and DefaultMaxBackoff bound the wait before retrying a job
	// that failed. The wait doubles with each consecutive failure.
	DefaultBackoff    = time.Minute
	DefaultMaxBackoff = time.Hour

	maxAttempts = 100_000
)

// SchedulerOptions configures a [Scheduler].
type SchedulerOptions struct {
	// Provider runs the jobs. Required. Any OmniWorkflow provider will do.
	Provider omniworkflow.WorkflowProvider
	// Rotator supplies due dates and eligibility. Required.
	Rotator *rotate.Rotator
	// Store is the registry the scheduler reads. Required.
	Store registry.Store
	// Purposes are the purposes whose keys are managed. Required.
	Purposes []keyforge.Purpose
	// Clock defaults to the system clock.
	Clock keyforge.Clock
	// Audit receives job failures. The default discards them.
	Audit audit.Sink
	// Metrics receives job counts and how overdue each rotation is. The default
	// discards them.
	Metrics metrics.Metrics
	// Interval is the time between ticks of [Scheduler.Run].
	Interval time.Duration
	// Recheck, Backoff and MaxBackoff are described on the defaults above.
	Recheck    time.Duration
	Backoff    time.Duration
	MaxBackoff time.Duration
}

// Scheduler notices what lifecycle work is due and starts a job for it.
//
// It is stateless in the sense that matters: everything it decides comes from
// the registry, and a job's identity is derived from what it does, so a
// scheduler that restarts, or several that run at once, start the same runs and
// not extra ones. The few things it remembers (when to look again) only space
// out retries.
type Scheduler struct {
	provider omniworkflow.WorkflowProvider
	rotator  *rotate.Rotator
	store    registry.Store
	purposes []keyforge.Purpose
	clock    keyforge.Clock
	audit    audit.Sink
	metrics  metrics.Metrics
	interval time.Duration
	recheck  time.Duration
	backoff  time.Duration
	maxBack  time.Duration

	mu       sync.Mutex
	attempt  map[string]int       // last attempt number seen per job
	notAfter map[string]time.Time // do not start this job before then
	failures map[string]int       // consecutive failures per job
	seen     map[string]bool      // finished runs already accounted for
	started  map[string]time.Time // when this process started a run
	last     TickResult           // the most recent tick's result
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// NewScheduler returns a scheduler.
func NewScheduler(o SchedulerOptions) (*Scheduler, error) {
	switch {
	case o.Provider == nil:
		return nil, errors.New("jobs: SchedulerOptions.Provider is required")
	case o.Rotator == nil:
		return nil, errors.New("jobs: SchedulerOptions.Rotator is required")
	case o.Store == nil:
		return nil, errors.New("jobs: SchedulerOptions.Store is required")
	case len(o.Purposes) == 0:
		return nil, errors.New("jobs: at least one purpose is required")
	}
	for _, p := range o.Purposes {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	s := &Scheduler{
		provider: o.Provider, rotator: o.Rotator, store: o.Store, purposes: slices.Clone(o.Purposes),
		clock: o.Clock, audit: o.Audit, metrics: o.Metrics, interval: o.Interval, recheck: o.Recheck, backoff: o.Backoff, maxBack: o.MaxBackoff,
		attempt: map[string]int{}, notAfter: map[string]time.Time{}, failures: map[string]int{}, seen: map[string]bool{}, started: map[string]time.Time{},
	}
	if s.clock == nil {
		s.clock = systemClock{}
	}
	if s.audit == nil {
		s.audit = audit.Discard
	}
	if s.metrics == nil {
		s.metrics = metrics.Discard
	}
	for _, d := range []struct {
		v   *time.Duration
		def time.Duration
	}{{&s.interval, DefaultInterval}, {&s.recheck, DefaultRecheck}, {&s.backoff, DefaultBackoff}, {&s.maxBack, DefaultMaxBackoff}} {
		if *d.v <= 0 {
			*d.v = d.def
		}
	}
	return s, nil
}

// Started describes a job a tick started.
type Started struct {
	RunID   string
	Spec    Spec
	Attempt int
}

// Overdue describes a KEK version past its rotation date that has not been
// rotated, so it is reported and not silently kept.
type Overdue struct {
	Purpose keyforge.Purpose
	Version uint32
	DueAt   time.Time
	Late    time.Duration
}

// FailedJob describes a run that failed.
type FailedJob struct {
	RunID string
	Spec  Spec
	// Consecutive is how many attempts in a row have failed.
	Consecutive int
}

// TickResult reports what one tick found and did.
type TickResult struct {
	// Wanted is how many pieces of work were due.
	Wanted int
	// Started lists the jobs this tick started.
	Started []Started
	// InFlight is how many due pieces of work already had a run in progress.
	InFlight int
	// Waiting is how many were held back by a retry or recheck interval.
	Waiting int
	// Overdue lists rotations that are past due.
	Overdue []Overdue
	// Failed lists runs that failed and have not succeeded since.
	Failed []FailedJob
}

// want is one piece of due work.
type want struct {
	base string
	spec Spec
}

// Tick looks at the registry once, starts a job for each piece of work that is
// due and has no run in progress, and reports. It does not wait for the jobs.
func (s *Scheduler) Tick(ctx context.Context) (TickResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var res TickResult
	wants, overdue, err := s.evaluate(ctx)
	if err != nil {
		return res, err
	}
	res.Overdue = overdue
	res.Wanted = len(wants)

	for _, w := range wants {
		if err := s.ensure(ctx, w, &res); err != nil {
			return res, err
		}
	}
	s.report(res)
	s.last = res
	return res, nil
}

// report publishes a tick's findings as metrics. Every configured purpose gets
// an overdue gauge, zero when nothing is late, so a recovered rotation clears the
// alert and not only the alert's absence.
func (s *Scheduler) report(res TickResult) {
	late := map[keyforge.Purpose]time.Duration{}
	for _, o := range res.Overdue {
		late[o.Purpose] = o.Late
	}
	for _, p := range s.purposes {
		s.metrics.Gauge(metrics.RotationOverdue, late[p].Seconds(), metrics.L("purpose", string(p)))
	}
	for _, st := range res.Started {
		s.metrics.Count(metrics.JobsStarted, 1, metrics.L("kind", string(st.Spec.Kind)))
	}
	s.metrics.Gauge(metrics.JobsWaiting, float64(res.Waiting))
	s.metrics.Gauge(metrics.JobsInFlight, float64(res.InFlight))
}

// Last returns the result of the most recent tick, or the zero value before the
// first. It is what a status report shows of the scheduler: the work that is
// overdue, in flight, waiting or failed.
func (s *Scheduler) Last() TickResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.last
	r.Started = slices.Clone(r.Started)
	r.Overdue = slices.Clone(r.Overdue)
	r.Failed = slices.Clone(r.Failed)
	return r
}

// evaluate lists the work that is due from the registry's current state.
func (s *Scheduler) evaluate(ctx context.Context) ([]want, []Overdue, error) {
	var wants []want
	var overdue []Overdue
	now := s.clock.Now()

	for _, purpose := range s.purposes {
		kek, err := s.store.KEKForPurpose(ctx, purpose)
		if errors.Is(err, keyforge.ErrKEKNotFound) {
			continue // not set up yet; nothing to manage
		}
		if err != nil {
			return nil, nil, err
		}

		if due, err := s.rotator.Due(ctx, purpose); err == nil && due.Overdue {
			wants = append(wants, want{
				base: fmt.Sprintf("keyforge/%s/%s/%d", RotateKEK, kek.ID, due.Version),
				spec: Spec{Kind: RotateKEK, Purpose: string(purpose), KEKID: kek.ID.String(), Version: due.Version},
			})
			overdue = append(overdue, Overdue{Purpose: purpose, Version: due.Version, DueAt: due.DueAt, Late: now.Sub(due.DueAt)})
		}

		versions, err := s.store.ListVersions(ctx, kek.ID)
		if err != nil {
			return nil, nil, err
		}
		var hasActive bool
		for _, v := range versions {
			hasActive = hasActive || v.State == registry.VersionActive
		}
		drain := false
		for _, v := range versions {
			spec := Spec{KEKID: kek.ID.String(), Version: v.Version}
			switch v.State {
			case registry.VersionDecryptOnly, registry.VersionRetireRequested:
				if hasActive && !drain {
					if n, err := s.store.CountDEKs(ctx, kek.ID, v.Version); err == nil && n > 0 {
						drain = true
						spec.Kind = Rewrap
						spec.Version = 0
						wants = append(wants, want{base: fmt.Sprintf("keyforge/%s/%s", Rewrap, kek.ID), spec: spec})
					}
				}
			}
			switch v.State {
			case registry.VersionDecryptOnly:
				if el, err := s.rotator.Eligibility(ctx, kek.ID, v.Version); err == nil && el.Eligible {
					spec.Kind = RequestRetirement
					wants = append(wants, want{base: fmt.Sprintf("keyforge/%s/%s/%d", RequestRetirement, kek.ID, v.Version), spec: spec})
				}
			case registry.VersionRetireRequested:
				if !now.Before(v.RetireAfter) {
					if n, err := s.store.CountDEKs(ctx, kek.ID, v.Version); err == nil && n == 0 {
						spec.Kind = CompleteRetirement
						wants = append(wants, want{base: fmt.Sprintf("keyforge/%s/%s/%d", CompleteRetirement, kek.ID, v.Version), spec: spec})
					}
				}
			case registry.VersionRetired:
				spec.Kind = Destroy
				wants = append(wants, want{base: fmt.Sprintf("keyforge/%s/%s/%d", Destroy, kek.ID, v.Version), spec: spec})
			}
		}
	}

	// Erasures wait on KEK versions being destroyed; look whenever one is open.
	shreds, err := s.store.ListShreds(ctx)
	if err != nil {
		return nil, nil, err
	}
	if slices.ContainsFunc(shreds, func(r registry.ShredRecord) bool { return !r.Complete() }) {
		wants = append(wants, want{base: "keyforge/" + string(CompleteShreds), spec: Spec{Kind: CompleteShreds}})
	}
	return wants, overdue, nil
}

// ensure makes sure a run exists for a piece of work, numbering attempts. A run
// that is in progress is left alone. When the latest run has finished, whether
// it succeeded or failed, a new attempt follows once its wait has passed: the
// condition that made the work due is still true, or it would not be wanted.
func (s *Scheduler) ensure(ctx context.Context, w want, res *TickResult) error {
	now := s.clock.Now()
	var last *omniworkflow.Run // the most recent finished attempt
	for n := max(s.attempt[w.base], 1); n <= maxAttempts; n++ {
		id := fmt.Sprintf("%s#%d", w.base, n)
		run, err := s.provider.Get(ctx, id)
		switch {
		case errors.Is(err, omniworkflow.ErrRunNotFound):
			if last != nil {
				s.settle(ctx, w, last, now, res)
			}
			if until, ok := s.notAfter[w.base]; ok && now.Before(until) {
				res.Waiting++
				return nil
			}
			if _, err := s.provider.Start(ctx, omniworkflow.StartRequest{ID: id, Plan: Plan(w.spec)}); err != nil {
				return fmt.Errorf("jobs: starting %s: %w", id, err)
			}
			s.attempt[w.base] = n
			s.started[id] = now
			res.Started = append(res.Started, Started{RunID: id, Spec: w.spec, Attempt: n})
			return nil
		case err != nil:
			return fmt.Errorf("jobs: looking up %s: %w", id, err)
		case run.Status == omniworkflow.StatusRunning:
			s.attempt[w.base] = n
			res.InFlight++
			return nil
		default:
			last = run
		}
	}
	return fmt.Errorf("%w: %s", ErrTooManyAttempts, w.base)
}

// settle accounts for the most recent finished attempt the first time it is
// seen: a success starts the recheck wait, a failure is reported, audited and
// followed by a backoff that doubles with each consecutive failure. A failure
// stays in the tick result for as long as it is the latest word.
func (s *Scheduler) settle(ctx context.Context, w want, run *omniworkflow.Run, now time.Time, res *TickResult) {
	first := !s.seen[run.ID]
	s.seen[run.ID] = true

	if run.Status == omniworkflow.StatusSucceeded {
		if first {
			s.failures[w.base] = 0
			// The wait runs from when the job started, so noticing it a tick
			// late does not lengthen it. A run this process did not start, after
			// a restart, waits from now.
			from := now
			if at, ok := s.started[run.ID]; ok {
				from = at
			}
			s.notAfter[w.base] = from.Add(s.recheck)
		}
		return
	}
	if first {
		s.failures[w.base]++
		wait := s.backoff << min(s.failures[w.base]-1, 20)
		if wait <= 0 || wait > s.maxBack {
			wait = s.maxBack
		}
		s.notAfter[w.base] = now.Add(wait)
		s.metrics.Count(metrics.JobsFailed, 1, metrics.L("kind", string(w.spec.Kind)))
		_ = s.audit.Emit(ctx, audit.Event{ //nolint:errcheck // the failure is also in the tick result; the sink is best-effort here
			ID: run.ID, Time: now, Action: audit.JobFailed, Purpose: w.spec.Purpose, KEKID: w.spec.KEKID, Version: w.spec.Version,
			Outcome: audit.Failure, Reason: fmt.Sprintf("%s job ended %s", w.spec.Kind, run.Status),
		})
	}
	res.Failed = append(res.Failed, FailedJob{RunID: run.ID, Spec: w.spec, Consecutive: s.failures[w.base]})
}

// Run ticks until ctx is cancelled. A tick that fails is reported through the
// audit sink and does not stop the loop: an outage of the registry is not a
// reason for the scheduler to give up.
func (s *Scheduler) Run(ctx context.Context) error {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		if _, err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			_ = s.audit.Emit(ctx, audit.Event{ //nolint:errcheck // nothing further to do if the sink is also down
				Time: s.clock.Now(), Action: audit.JobFailed, Outcome: audit.Failure, Reason: "scheduler tick failed: " + err.Error(),
			})
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
