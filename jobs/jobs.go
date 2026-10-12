// Package jobs runs keyforge's lifecycle work as durable jobs on OmniWorkflow.
//
// Rotation, re-wrapping, retirement and destruction are already idempotent and
// resumable operations. This package supplies what turns them into a system
// that runs unattended: a scheduler that notices what is due, and the
// [omniworkflow.StepExecutor] that does each unit of work, so that any
// OmniWorkflow provider (in-memory, durable, Temporal, Step Functions) can run
// it and restart it.
//
// # Exactly one execution
//
// Every job has a deterministic run ID built from what it does and to what.
// OmniWorkflow's Start is idempotent by run ID, so several replicas that each
// find the same work due all start the same run, and one execution results.
// There is no leader election and no lease in keyforge.
//
// # Time
//
// A plan has no timers, so time is the scheduler's: it evaluates what is due on
// each tick and starts a short job for it. A retirement delay, a guard that is
// still pending, and a version waiting to be destroyed are all conditions the
// next tick finds still true or no longer true.
package jobs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/plexusone/omniworkflow"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/rotate"
)

// Kind names a unit of lifecycle work.
type Kind string

// Kinds.
const (
	// RotateKEK activates the next KEK version for a purpose and then moves
	// every data key off the older ones.
	RotateKEK Kind = "rotate-kek"
	// Rewrap moves data keys off every non-active version of a KEK.
	Rewrap Kind = "rewrap"
	// RequestRetirement starts the retirement delay for a version outside the
	// retained floor.
	RequestRetirement Kind = "request-retirement"
	// CompleteRetirement retires a version whose delay has passed, if the guard
	// allows.
	CompleteRetirement Kind = "complete-retirement"
	// Destroy destroys a retired version's material, if the guard allows.
	Destroy Kind = "destroy"
	// CompleteShreds records every subject erasure whose KEK versions are all
	// destroyed.
	CompleteShreds Kind = "complete-shreds"
)

// Spec is the input of one step. It crosses the provider boundary as JSON.
type Spec struct {
	Kind Kind `json:"kind"`
	// Purpose names the purpose for a rotation.
	Purpose string `json:"purpose,omitempty"`
	// KEKID is the KEK's identifier as lowercase hex.
	KEKID string `json:"kekId,omitempty"`
	// Version is the KEK version the step concerns.
	Version uint32 `json:"version,omitempty"`
	// Force makes a rotation run although the version is not yet due, for an
	// operator who asked for it. A scheduled rotation never sets it.
	Force bool `json:"force,omitempty"`
}

func (s Spec) kekID() (envelope.ID, error) {
	var id envelope.ID
	raw, err := hex.DecodeString(s.KEKID)
	if err != nil || len(raw) != len(id) {
		return id, fmt.Errorf("jobs: malformed KEK identifier %q", s.KEKID)
	}
	copy(id[:], raw)
	return id, nil
}

// Plan returns the plan that does the work a spec describes.
func Plan(s Spec) omniworkflow.Plan {
	switch s.Kind {
	case RotateKEK:
		drain := Spec{Kind: Rewrap, KEKID: s.KEKID}
		return omniworkflow.Plan{Steps: []omniworkflow.PlanStep{
			{ID: "rotate", Input: s},
			{ID: "rewrap", DependsOn: []string{"rotate"}, Input: drain},
		}}
	default:
		return omniworkflow.Plan{Steps: []omniworkflow.PlanStep{{ID: string(s.Kind), Input: s}}}
	}
}

// Executor does the work of each step by calling the rotation operations. It is
// the [omniworkflow.StepExecutor] a provider's worker is given.
//
// Steps are delivered at least once, and every operation here is safe to repeat:
// a rotation re-checks that it is due, a re-wrap moves only what has not moved,
// and the guarded steps ask the guard again.
type Executor struct {
	rotator *rotate.Rotator
	store   registry.Store
}

var _ omniworkflow.StepExecutor = (*Executor)(nil)

// NewExecutor returns an executor over a rotator and its registry.
func NewExecutor(r *rotate.Rotator, s registry.Store) *Executor {
	return &Executor{rotator: r, store: s}
}

// decodeSpec reads a step's input, which a provider may have turned into
// generic JSON.
func decodeSpec(in any) (Spec, error) {
	if s, ok := in.(Spec); ok {
		return s, nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return Spec{}, fmt.Errorf("jobs: step input: %w", err)
	}
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return Spec{}, fmt.Errorf("jobs: step input: %w", err)
	}
	return s, nil
}

// ExecuteStep implements [omniworkflow.StepExecutor]. A step that did its work
// returns a small, JSON-serializable summary. A step that could not returns an
// error, which fails the run; the scheduler reports it and tries again.
func (e *Executor) ExecuteStep(ctx context.Context, _ string, step omniworkflow.PlanStep) (any, error) {
	spec, err := decodeSpec(step.Input)
	if err != nil {
		return nil, err
	}
	switch spec.Kind {
	case RotateKEK:
		return e.rotate(ctx, spec)
	case Rewrap:
		id, err := spec.kekID()
		if err != nil {
			return nil, err
		}
		res, err := e.rotator.RewrapAll(ctx, id, rotate.RewrapOptions{})
		if err != nil {
			return nil, err
		}
		moved, failed := 0, 0
		for _, v := range res.Versions {
			moved += v.Rewrapped
			failed += v.FailedCount
		}
		if !res.Done {
			return nil, fmt.Errorf("jobs: %d data keys could not be moved off older versions", failed)
		}
		return map[string]any{"rewrapped": moved}, nil
	case RequestRetirement:
		id, err := spec.kekID()
		if err != nil {
			return nil, err
		}
		r, err := e.rotator.RequestRetirement(ctx, id, spec.Version)
		return summary(r.State.String(), r.Reason), err
	case CompleteRetirement:
		id, err := spec.kekID()
		if err != nil {
			return nil, err
		}
		r, err := e.rotator.CompleteRetirement(ctx, id, spec.Version)
		return outcome(r), err
	case Destroy:
		id, err := spec.kekID()
		if err != nil {
			return nil, err
		}
		r, err := e.rotator.Destroy(ctx, id, spec.Version)
		return outcome(r), err
	case CompleteShreds:
		done, err := e.rotator.CompleteShreds(ctx)
		return map[string]any{"completed": len(done)}, err
	default:
		return nil, fmt.Errorf("jobs: unknown job kind %q", spec.Kind)
	}
}

func (e *Executor) rotate(ctx context.Context, spec Spec) (any, error) {
	purpose := keyforge.Purpose(spec.Purpose)
	if !spec.Force {
		// The step may be delivered twice. Whether it is due is checked here
		// again, so a rotation that already happened is not done a second time.
		due, err := e.rotator.Due(ctx, purpose)
		if err != nil {
			return nil, err
		}
		if !due.Overdue {
			return map[string]any{"rotated": false, "reason": "not due"}, nil
		}
	}
	r, err := e.rotator.RotateKEK(ctx, purpose)
	if err != nil {
		return nil, err
	}
	return map[string]any{"rotated": true, "from": r.From, "to": r.To}, nil
}

func summary(state, reason string) map[string]any {
	m := map[string]any{"state": state}
	if reason != "" {
		m["reason"] = reason
	}
	return m
}

func outcome(r rotate.RetireResult) map[string]any {
	m := summary(r.State.String(), r.Reason)
	m["outcome"] = r.Outcome.String()
	return m
}

// Errors reported by the scheduler.
var (
	// ErrTooManyAttempts is returned when a job has been attempted so often that
	// the scheduler stops numbering new attempts.
	ErrTooManyAttempts = errors.New("jobs: too many attempts of one job")
)
