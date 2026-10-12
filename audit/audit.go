// Package audit defines the events keyforge emits for key lifecycle changes and
// the sink that receives them.
//
// An event records who did what to which key, when, and with what outcome. It
// never carries key material, wrapped keys, plaintext or additional data.
// Ordinary encrypt and decrypt are not events: their rates and failures are
// metered instead.
package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Action names what happened.
type Action string

// Actions. The set is closed: a sink can switch on it.
const (
	KeyCreated           Action = "key.created"
	KeyRotated           Action = "key.rotated"
	KeyActivated         Action = "key.activated"
	KeyRolledBack        Action = "key.rolled_back"
	KeyRetireRequested   Action = "key.retire_requested"
	KeyRetireCancelled   Action = "key.retire_cancelled"
	KeyRetired           Action = "key.retired"
	KeyDestroyed         Action = "key.destroyed"
	KeyCompromised       Action = "key.compromised"
	DataKeyCompromised   Action = "dek.compromised"
	DataKeyDestroyed     Action = "dek.destroyed"
	WrapFailed           Action = "wrap.failed"
	AdminRead            Action = "admin.read"
	GuardDenied          Action = "guard.denied"
	GuardPending         Action = "guard.pending"
	JobFailed            Action = "job.failed"
	BackupStale          Action = "backup.stale"
	SubjectShredRequest  Action = "subject.shred_requested"
	SubjectShredComplete Action = "subject.shred_completed"
)

// Outcome says how it went.
type Outcome string

// Outcomes.
const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
	Pending Outcome = "pending"
)

// Event is one audit record.
type Event struct {
	// ID identifies the event.
	ID string
	// Time is when it happened, from the emitter's clock.
	Time time.Time
	// Actor is who did it, as the host application supplied it: see
	// [WithActor]. It is empty for work the scheduler does on its own.
	Actor string
	// Action is what happened.
	Action Action
	// Purpose is the purpose concerned, if any.
	Purpose string
	// KEKID and Version identify the key version concerned, if any, and DEKID
	// the data key. They are identifiers, never material.
	KEKID   string
	Version uint32
	DEKID   string
	// Outcome is how it went, and Reason is why, in words that name no key
	// material.
	Outcome Outcome
	Reason  string
}

// Sink receives events. It must be safe for concurrent use.
type Sink interface {
	Emit(ctx context.Context, e Event) error
}

// ErrNotRecorded is returned, wrapping the sink's error, when an operation
// succeeded but its audit event could not be delivered. The change was made;
// the caller must treat the gap in the trail as an incident.
var ErrNotRecorded = errors.New("audit: the change was made but its event was not recorded")

// NotRecorded wraps a sink error as [ErrNotRecorded].
func NotRecorded(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrNotRecorded, err)
}

type discard struct{}

func (discard) Emit(context.Context, Event) error { return nil }

// Discard is a sink that drops every event.
var Discard Sink = discard{}

// Recorder is a sink that keeps events in memory, for tests and examples. It is
// safe for concurrent use.
type Recorder struct {
	mu     sync.Mutex
	events []Event
	// Err, when set, is returned by Emit instead of recording.
	Err error
}

// Emit implements [Sink].
func (r *Recorder) Emit(_ context.Context, e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Err != nil {
		return r.Err
	}
	r.events = append(r.events, e)
	return nil
}

// Events returns a copy of the recorded events.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// Actions returns the recorded actions in order.
func (r *Recorder) Actions() []Action {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Action, len(r.events))
	for i, e := range r.events {
		out[i] = e.Action
	}
	return out
}

type actorKey struct{}

// WithActor returns a context that names who is acting. keyforge does not
// authenticate anyone: the host application does, and passes the result here
// so the events it causes are attributed.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// ActorFrom returns the actor named by [WithActor], or "".
func ActorFrom(ctx context.Context) string {
	a, _ := ctx.Value(actorKey{}).(string)
	return a
}
