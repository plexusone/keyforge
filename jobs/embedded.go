package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/plexusone/omniworkflow"
	"github.com/plexusone/omniworkflow/durable"
	"github.com/plexusone/omniworkflow/inmemory"
)

// EmbeddedOptions configures an [Embedded] runner: a scheduler, a provider and
// a worker in one process.
type EmbeddedOptions struct {
	SchedulerOptions
	// StateDir is where the durable provider keeps run state, so jobs resume
	// after a restart. Empty uses the in-memory provider, which keeps nothing:
	// right for tests, and for a deployment that can lose a run because the next
	// tick starts another.
	StateDir string
}

// Embedded runs keyforge's lifecycle jobs inside the host process: the
// scheduler, an OmniWorkflow provider and its worker. It is the default way to
// run keyforge unattended on one host.
//
// The durable provider is single-process. Deployments with several replicas
// give the scheduler and the worker a shared provider such as Temporal or Step
// Functions instead, with the same [Scheduler] and [Executor].
type Embedded struct {
	// Scheduler is the scheduler, for ticking by hand and for reading its
	// results.
	Scheduler *Scheduler
	// Provider is the provider running the jobs.
	Provider omniworkflow.WorkflowProvider

	worker omniworkflow.Worker
}

// NewEmbedded wires a provider, a worker running the executor, and a scheduler.
// SchedulerOptions.Provider is ignored.
func NewEmbedded(o EmbeddedOptions) (*Embedded, error) {
	if o.Rotator == nil || o.Store == nil {
		return nil, errors.New("jobs: Rotator and Store are required")
	}
	exec := NewExecutor(o.Rotator, o.Store)

	var (
		provider omniworkflow.WorkflowProvider
		worker   omniworkflow.Worker
	)
	if o.StateDir != "" {
		store, err := durable.NewFileStore(o.StateDir)
		if err != nil {
			return nil, fmt.Errorf("jobs: run state directory: %w", err)
		}
		p := durable.New(store)
		provider, worker = p, p.NewWorker(exec)
	} else {
		p := inmemory.New()
		provider, worker = p, p.NewWorker(exec)
	}

	so := o.SchedulerOptions
	so.Provider = provider
	sched, err := NewScheduler(so)
	if err != nil {
		return nil, err
	}
	return &Embedded{Scheduler: sched, Provider: provider, worker: worker}, nil
}

// Work runs only the worker: it resumes any run a previous process left
// unfinished and executes steps until ctx is cancelled. The scheduler is not
// ticked, so the host drives it by calling Scheduler.Tick from its own timer or
// cron. Use Run to have the embedded scheduler tick itself.
func (e *Embedded) Work(ctx context.Context) error { return e.worker.Run(ctx) }

// Run starts the worker, which first resumes any run a previous process left
// unfinished, and the scheduler's loop, and blocks until ctx is cancelled. The
// first error ends both.
func (e *Embedded) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	run := func(name string, f func(context.Context) error) {
		wg.Go(func() {
			if err := f(ctx); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("jobs: %s: %w", name, err))
				mu.Unlock()
				cancel()
			}
		})
	}
	run("worker", e.worker.Run)
	run("scheduler", e.Scheduler.Run)
	wg.Wait()
	return errors.Join(errs...)
}
