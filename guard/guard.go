// Package guard defines the veto a host application holds over retiring and
// destroying keys.
//
// Destroying a key is irreversible, and whether it is safe depends on things
// keyforge cannot see: a legal hold, a retention duty, an export or snapshot in
// the inline mode that no registry record points at, a backup that must stay
// restorable. The host knows. A [Guard] is how it says so.
//
// A guard is consulted before a version is retired and again before it is
// destroyed. It may allow, deny with a reason, or answer that an approval is
// still outstanding. Only an allow advances the state; anything else leaves the
// key usable.
package guard

import (
	"context"
	"errors"
	"fmt"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/envelope"
)

// Action is what is being asked.
type Action string

// Actions.
const (
	// Retire asks to move a version from retire-requested to retired.
	Retire Action = "retire"
	// Destroy asks to destroy a retired version's material at the provider.
	Destroy Action = "destroy"
)

// Outcome is a guard's answer.
type Outcome uint8

const (
	// Allowed lets the action proceed.
	Allowed Outcome = iota + 1
	// Denied refuses the action. The key stays usable.
	Denied
	// Pending says an approval is outstanding. The key stays usable and the
	// guard is asked again later.
	Pending
)

// String returns the outcome's name.
func (o Outcome) String() string {
	switch o {
	case Allowed:
		return "allowed"
	case Denied:
		return "denied"
	case Pending:
		return "pending"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(o))
	}
}

// Request describes what the guard is asked to decide.
type Request struct {
	Action  Action
	Purpose keyforge.Purpose
	KEKID   envelope.ID
	Version uint32
	// Actor is who asked, as the host named them, if anyone.
	Actor string
	// References is how many data keys in the registry are still wrapped under
	// the version. It is zero when retirement completes; it says nothing about
	// data outside the registry, which only the host knows about.
	References int
	// Emergency is true during an emergency rotation. The guard is consulted and
	// its answer is recorded, but it cannot block the procedure.
	Emergency bool
}

// Decision is a guard's answer and why.
type Decision struct {
	Outcome Outcome
	// Reason is recorded in the audit trail. It must not name key material.
	Reason string
}

// Allow returns a decision that lets the action proceed.
func Allow() Decision { return Decision{Outcome: Allowed} }

// Deny returns a decision that refuses with a reason.
func Deny(reason string) Decision { return Decision{Outcome: Denied, Reason: reason} }

// AwaitApproval returns a decision that says an approval is outstanding.
func AwaitApproval(reason string) Decision { return Decision{Outcome: Pending, Reason: reason} }

// Guard decides whether a retirement or destruction may proceed.
//
// An error is not an answer: a guard that cannot decide returns it, and the
// action does not proceed.
type Guard interface {
	Check(ctx context.Context, req Request) (Decision, error)
}

// Func adapts a function to a [Guard].
type Func func(ctx context.Context, req Request) (Decision, error)

// Check implements [Guard].
func (f Func) Check(ctx context.Context, req Request) (Decision, error) { return f(ctx, req) }

// AllowAll returns a guard that allows everything. Use it only where nothing
// is held: it is the absence of a veto.
func AllowAll() Guard {
	return Func(func(context.Context, Request) (Decision, error) { return Allow(), nil })
}

// DenyAll returns a guard that refuses everything with a reason.
func DenyAll(reason string) Guard {
	return Func(func(context.Context, Request) (Decision, error) { return Deny(reason), nil })
}

// ErrNoGuard is the reason recorded when no guard is configured. With none,
// nothing is retired or destroyed: the absence of a veto is not consent.
const ErrNoGuard = "no destroy guard is configured"

// All combines guards: every one is consulted, a denial from any refuses, and
// otherwise a pending answer from any is pending; the action proceeds only if
// all allow. An error from any guard is an error. With no guards it denies.
func All(guards ...Guard) Guard {
	return Func(func(ctx context.Context, req Request) (Decision, error) {
		if len(guards) == 0 {
			return Deny(ErrNoGuard), nil
		}
		var pending *Decision
		for i, g := range guards {
			d, err := g.Check(ctx, req)
			if err != nil {
				return Decision{}, fmt.Errorf("guard %d: %w", i, err)
			}
			switch d.Outcome {
			case Allowed:
			case Denied:
				return d, nil
			case Pending:
				if pending == nil {
					dd := d
					pending = &dd
				}
			default:
				return Decision{}, fmt.Errorf("guard %d: %w: outcome %d", i, ErrBadDecision, uint8(d.Outcome))
			}
		}
		if pending != nil {
			return *pending, nil
		}
		return Allow(), nil
	})
}

// ErrBadDecision is returned when a guard answers with an outcome that is not
// one of the three.
var ErrBadDecision = errors.New("guard: not a valid decision")
