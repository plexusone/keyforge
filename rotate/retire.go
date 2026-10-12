package rotate

import (
	"context"
	"errors"
	"fmt"

	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/registry"
)

// ErrNotEligible is returned when a version cannot be put forward for
// retirement. The error lists why.
var ErrNotEligible = errors.New("rotate: the version is not eligible for retirement")

// ErrWrongState is returned when an operation needs a version in a state it is
// not in.
var ErrWrongState = errors.New("rotate: the version is not in the state this operation needs")

// RetireResult is the outcome of a retirement or destruction step.
type RetireResult struct {
	// Outcome is the guard's answer. Allowed means the step happened.
	Outcome guard.Outcome
	// Reason is the guard's reason when it did not allow.
	Reason string
	// State is the version's state afterwards.
	State registry.VersionState
}

// RequestRetirement starts the retirement of a version: it moves it from
// decrypt-only to retire-requested and starts the delay, whose length is the
// purpose's policy. The version stays usable throughout.
//
// The version must be outside the retained-versions floor. It need not be
// unreferenced yet: the re-wrap can finish during the delay, and completion
// checks. The guard is consulted at completion, not here.
func (r *Rotator) RequestRetirement(ctx context.Context, kekID envelope.ID, version uint32) (RetireResult, error) {
	kek, err := r.store.GetKEK(ctx, kekID)
	if err != nil {
		return RetireResult{}, err
	}
	el, err := r.Eligibility(ctx, kekID, version)
	if err != nil {
		return RetireResult{}, err
	}
	if el.State != registry.VersionDecryptOnly {
		return RetireResult{State: el.State}, fmt.Errorf("%w: the version is %s, and retirement is requested for a decrypt-only version", ErrWrongState, el.State)
	}
	// References do not stop the request; the floor does.
	if el.InFloor {
		return RetireResult{State: el.State}, fmt.Errorf("%w: the version is within the retained-versions floor", ErrNotEligible)
	}

	now := r.clock.Now()
	opts := registry.TransitionOptions{At: now, RetireAfter: now.Add(r.policy.For(kek.Purpose).RetirementDelay)}
	if err := r.store.TransitionVersion(ctx, kekID, version, registry.VersionRetireRequested, opts); err != nil {
		return RetireResult{State: el.State}, err
	}
	res := RetireResult{Outcome: guard.Allowed, State: registry.VersionRetireRequested}
	return res, r.emit(ctx, audit.Event{
		Action: audit.KeyRetireRequested, Purpose: string(kek.Purpose), KEKID: kekID.String(), Version: version, Outcome: audit.Success,
		Reason: fmt.Sprintf("retirement may complete after %s", opts.RetireAfter.UTC().Format("2006-01-02T15:04:05Z")),
	})
}

// consult asks the guard and records its answer. A guard that is absent denies,
// and an error is returned as an error: neither advances anything.
func (r *Rotator) consult(ctx context.Context, kek registry.KEK, version uint32, action guard.Action, refs int, emergency bool) (guard.Decision, error) {
	if r.guard == nil {
		return guard.Deny(guard.ErrNoGuard), nil
	}
	d, err := r.guard.Check(ctx, guard.Request{
		Action: action, Purpose: kek.Purpose, KEKID: kek.ID, Version: version,
		Actor: audit.ActorFrom(ctx), References: refs, Emergency: emergency,
	})
	if err != nil {
		return guard.Decision{}, fmt.Errorf("rotate: the destroy guard failed: %w", err)
	}
	switch d.Outcome {
	case guard.Allowed, guard.Denied, guard.Pending:
		return d, nil
	default:
		return guard.Decision{}, fmt.Errorf("rotate: the destroy guard: %w", guard.ErrBadDecision)
	}
}

// CompleteRetirement finishes a retirement whose delay has run: it checks the
// delay and that nothing in the registry still references the version, asks the
// guard, and only on an allow moves the version to retired.
//
// A denial returns the version to decrypt-only, usable, with the denial
// recorded; a version whose retirement is denied can be requested again later.
// A pending answer leaves it retire-requested and the guard is asked again on
// the next call. A guard that fails, or is absent, advances nothing.
func (r *Rotator) CompleteRetirement(ctx context.Context, kekID envelope.ID, version uint32) (RetireResult, error) {
	kek, err := r.store.GetKEK(ctx, kekID)
	if err != nil {
		return RetireResult{}, err
	}
	rec, err := r.store.GetVersion(ctx, kekID, version)
	if err != nil {
		return RetireResult{}, err
	}
	if rec.State != registry.VersionRetireRequested {
		return RetireResult{State: rec.State}, fmt.Errorf("%w: the version is %s, and completion needs retire-requested", ErrWrongState, rec.State)
	}
	now := r.clock.Now()
	if now.Before(rec.RetireAfter) {
		return RetireResult{State: rec.State}, fmt.Errorf("%w: until %s", registry.ErrRetireDelay, rec.RetireAfter.UTC().Format("2006-01-02T15:04:05Z"))
	}
	refs, err := r.store.CountDEKs(ctx, kekID, version)
	if err != nil {
		return RetireResult{State: rec.State}, err
	}
	if refs > 0 {
		return RetireResult{State: rec.State}, fmt.Errorf("%w: %d data keys", registry.ErrVersionReferenced, refs)
	}

	d, err := r.consult(ctx, kek, version, guard.Retire, refs, false)
	if err != nil {
		return RetireResult{State: rec.State}, err
	}
	base := audit.Event{Purpose: string(kek.Purpose), KEKID: kekID.String(), Version: version}

	switch d.Outcome {
	case guard.Allowed:
		if err := r.store.TransitionVersion(ctx, kekID, version, registry.VersionRetired, registry.TransitionOptions{At: now}); err != nil {
			return RetireResult{State: rec.State}, err
		}
		e := base
		e.Action, e.Outcome, e.Reason = audit.KeyRetired, audit.Success, "the guard allowed it"
		return RetireResult{Outcome: guard.Allowed, State: registry.VersionRetired}, r.emit(ctx, e)

	case guard.Pending:
		e := base
		e.Action, e.Outcome, e.Reason = audit.GuardPending, audit.Pending, d.Reason
		return RetireResult{Outcome: guard.Pending, Reason: d.Reason, State: rec.State}, r.emit(ctx, e)

	default: // Denied
		if err := r.store.TransitionVersion(ctx, kekID, version, registry.VersionDecryptOnly, registry.TransitionOptions{At: now}); err != nil {
			return RetireResult{State: rec.State}, err
		}
		e1 := base
		e1.Action, e1.Outcome, e1.Reason = audit.GuardDenied, audit.Denied, d.Reason
		e2 := base
		e2.Action, e2.Outcome, e2.Reason = audit.KeyRetireCancelled, audit.Success, "the guard denied retirement"
		err := r.emit(ctx, e1)
		if err2 := r.emit(ctx, e2); err == nil {
			err = err2
		}
		return RetireResult{Outcome: guard.Denied, Reason: d.Reason, State: registry.VersionDecryptOnly}, err
	}
}

// CancelRetirement returns a retire-requested version to decrypt-only before
// its delay has run, for an operator who has changed their mind.
func (r *Rotator) CancelRetirement(ctx context.Context, kekID envelope.ID, version uint32) (RetireResult, error) {
	kek, err := r.store.GetKEK(ctx, kekID)
	if err != nil {
		return RetireResult{}, err
	}
	if err := r.store.TransitionVersion(ctx, kekID, version, registry.VersionDecryptOnly, registry.TransitionOptions{At: r.clock.Now()}); err != nil {
		return RetireResult{}, err
	}
	return RetireResult{Outcome: guard.Allowed, State: registry.VersionDecryptOnly}, r.emit(ctx, audit.Event{
		Action: audit.KeyRetireCancelled, Purpose: string(kek.Purpose), KEKID: kekID.String(), Version: version,
		Outcome: audit.Success, Reason: "cancelled by an operator",
	})
}

// Destroy destroys a retired version's key material at the provider and records
// it. The guard is asked again, because retirement and destruction are separate
// decisions and the facts can change between them.
//
// Destruction is irreversible. The order is: the guard allows, the provider
// destroys, then the registry records it. Destroying at the provider is
// idempotent, so a crash between the last two is repaired by calling Destroy
// again; the reverse order could record a destruction that did not happen.
func (r *Rotator) Destroy(ctx context.Context, kekID envelope.ID, version uint32) (RetireResult, error) {
	kek, err := r.store.GetKEK(ctx, kekID)
	if err != nil {
		return RetireResult{}, err
	}
	rec, err := r.store.GetVersion(ctx, kekID, version)
	if err != nil {
		return RetireResult{}, err
	}
	if rec.State != registry.VersionRetired {
		return RetireResult{State: rec.State}, fmt.Errorf("%w: the version is %s, and destruction needs retired", ErrWrongState, rec.State)
	}
	refs, err := r.store.CountDEKs(ctx, kekID, version)
	if err != nil {
		return RetireResult{State: rec.State}, err
	}
	if refs > 0 {
		return RetireResult{State: rec.State}, fmt.Errorf("%w: %d data keys", registry.ErrVersionReferenced, refs)
	}
	prov, err := r.providerFor(kek)
	if err != nil {
		return RetireResult{State: rec.State}, err
	}

	d, err := r.consult(ctx, kek, version, guard.Destroy, refs, false)
	if err != nil {
		return RetireResult{State: rec.State}, err
	}
	base := audit.Event{Purpose: string(kek.Purpose), KEKID: kekID.String(), Version: version}
	switch d.Outcome {
	case guard.Pending:
		e := base
		e.Action, e.Outcome, e.Reason = audit.GuardPending, audit.Pending, d.Reason
		return RetireResult{Outcome: guard.Pending, Reason: d.Reason, State: rec.State}, r.emit(ctx, e)
	case guard.Denied:
		e := base
		e.Action, e.Outcome, e.Reason = audit.GuardDenied, audit.Denied, d.Reason
		return RetireResult{Outcome: guard.Denied, Reason: d.Reason, State: rec.State}, r.emit(ctx, e)
	}

	if err := prov.Destroy(ctx, kek.Ref(), version); err != nil {
		return RetireResult{State: rec.State}, fmt.Errorf("rotate: destroying version %d at the provider: %w", version, err)
	}
	if err := r.store.TransitionVersion(ctx, kekID, version, registry.VersionDestroyed, registry.TransitionOptions{At: r.clock.Now()}); err != nil {
		return RetireResult{State: rec.State}, fmt.Errorf("rotate: the provider destroyed version %d but the registry did not record it; call Destroy again: %w", version, err)
	}
	e := base
	e.Action, e.Outcome, e.Reason = audit.KeyDestroyed, audit.Success, "the guard allowed it"
	return RetireResult{Outcome: guard.Allowed, State: registry.VersionDestroyed}, r.emit(ctx, e)
}
