package rotate

import (
	"context"
	"errors"
	"fmt"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/registry"
)

// ErrEmergencyIncomplete is returned when an emergency rotation could not finish
// every step: data keys remain under the compromised version, so it was neither
// retired nor destroyed. The procedure is idempotent; call it again.
var ErrEmergencyIncomplete = errors.New("rotate: the emergency rotation is not complete")

// ErrNoEpochAdvancer is returned when replacing an exposed data key needs a way
// to create the next epoch and none was configured.
var ErrNoEpochAdvancer = errors.New("rotate: no epoch advancer is configured")

// EpochAdvancer creates the next data key epoch for a purpose and subject.
type EpochAdvancer interface {
	AdvanceEpoch(ctx context.Context, purpose keyforge.Purpose, subject string) (keyforge.DEKRecord, error)
}

// EmergencyKEKOptions tunes the response to a compromised KEK version.
type EmergencyKEKOptions struct {
	// KeepMaterial stops after the version is retired and leaves its material at
	// the provider, so that data outside the registry (inline envelopes,
	// exports, snapshots) can be recovered and re-encrypted before the material
	// goes. The default destroys it, which is the procedure's last step.
	KeepMaterial bool
	// Rewrap tunes the re-wrap of the data keys.
	Rewrap RewrapOptions
}

// EmergencyKEKResult reports a response to a compromised KEK version.
type EmergencyKEKResult struct {
	// Replacement is the rotation that moved writes off the version, or the
	// zero value if another version was already active.
	Replacement Rotation
	// Rewrap is the re-wrap of the data keys that were under it.
	Rewrap RewrapResult
	// Remaining is how many data keys in the registry are still wrapped under
	// the compromised version.
	Remaining int
	// Guard is what the guard answered. It was asked and recorded, and did not
	// decide: it cannot block this procedure.
	Guard guard.Decision
	// Retired and Destroyed say how far the procedure got.
	Retired   bool
	Destroyed bool
}

// CompromiseKEK responds to a KEK version that is known or suspected to be
// exposed.
//
// It replaces the version so that nothing new is wrapped under it, marks it
// compromised, re-wraps every data key away from it, then retires and destroys
// it. It differs from a scheduled rotation in three ways: it does not wait for a
// backup to be acknowledged, it has no retirement delay, and the guard is asked
// and its answer recorded but it cannot block.
//
// It is idempotent and resumable. If any data key cannot be moved the version is
// left compromised and referenced, not retired, and the call returns
// [ErrEmergencyIncomplete] with the progress; calling it again continues.
//
// Data outside the registry that is wrapped under the version is not covered by
// the re-wrap and is lost when the version is destroyed: set KeepMaterial to
// stop short of that, recover what is needed, and call Destroy.
func (r *Rotator) CompromiseKEK(ctx context.Context, kekID envelope.ID, version uint32, opts EmergencyKEKOptions) (EmergencyKEKResult, error) {
	kek, err := r.store.GetKEK(ctx, kekID)
	if err != nil {
		return EmergencyKEKResult{}, err
	}
	rec, err := r.store.GetVersion(ctx, kekID, version)
	if err != nil {
		return EmergencyKEKResult{}, err
	}
	switch rec.State {
	case registry.VersionActive, registry.VersionDecryptOnly, registry.VersionRetireRequested, registry.VersionCompromised:
	default:
		return EmergencyKEKResult{}, fmt.Errorf("%w: the version is %s, which is not in service", ErrWrongState, rec.State)
	}

	var res EmergencyKEKResult
	var auditErr error
	note := func(err error) {
		if err != nil && auditErr == nil {
			auditErr = err
		}
	}

	// 1. Stop new wrapping under the version. If it is active, replace it; the
	// activation demotes it in the same transaction, so there is no moment
	// without an active version and no wrap under it after this point (a client
	// holding a cached view can wrap until its entry expires; the re-wrap below
	// covers those, and a repeat call picks up stragglers).
	if rec.State == registry.VersionActive {
		rot, err := r.rotateKEK(ctx, kek.Purpose, true)
		if err != nil && !errors.Is(err, audit.ErrNotRecorded) {
			return res, fmt.Errorf("rotate: replacing the compromised version: %w", err)
		}
		note(err)
		res.Replacement = rot
	}

	// 2. Mark it. The activation above demoted it, so this is a transition from
	// decrypt-only; an already compromised version is left as it is.
	if rec.State != registry.VersionCompromised {
		err := r.store.TransitionVersion(ctx, kekID, version, registry.VersionCompromised, registry.TransitionOptions{At: r.clock.Now()})
		if err != nil {
			return res, fmt.Errorf("rotate: marking version %d compromised: %w", version, err)
		}
		note(r.emit(ctx, audit.Event{
			Action: audit.KeyCompromised, Purpose: string(kek.Purpose), KEKID: kekID.String(), Version: version,
			Outcome: audit.Success, Reason: "marked compromised; emergency rotation started",
		}))
	}

	// 3. Move every data key off it.
	rw, err := r.Rewrap(ctx, kekID, version, opts.Rewrap)
	res.Rewrap = rw
	if errors.Is(err, audit.ErrNotRecorded) {
		note(err)
		err = nil
	}
	if err != nil && !errors.Is(err, ErrNothingToRewrap) {
		return res, err
	}
	res.Remaining, err = r.store.CountDEKs(ctx, kekID, version)
	if err != nil {
		return res, err
	}
	if res.Remaining > 0 {
		return res, fmt.Errorf("%w: %d data keys are still wrapped under version %d (%d could not be moved)",
			ErrEmergencyIncomplete, res.Remaining, version, rw.FailedCount)
	}

	// 4. Ask the guard, and record what it said. It does not decide.
	d, gerr := r.consult(ctx, kek, version, guard.Destroy, 0, true)
	if gerr != nil {
		d = guard.Decision{Outcome: guard.Pending, Reason: "the guard could not be reached: " + gerr.Error()}
	}
	res.Guard = d
	outcome := audit.Success
	switch d.Outcome {
	case guard.Denied:
		outcome = audit.Denied
	case guard.Pending:
		outcome = audit.Pending
	}
	if d.Outcome != guard.Allowed {
		action := audit.GuardDenied
		if d.Outcome == guard.Pending {
			action = audit.GuardPending
		}
		note(r.emit(ctx, audit.Event{
			Action: action, Purpose: string(kek.Purpose), KEKID: kekID.String(), Version: version, Outcome: outcome,
			Reason: "recorded and not obeyed: emergency rotation; " + d.Reason,
		}))
	}

	// 5. Retire, and destroy unless asked to keep the material.
	if err := r.store.TransitionVersion(ctx, kekID, version, registry.VersionRetired, registry.TransitionOptions{At: r.clock.Now()}); err != nil {
		return res, fmt.Errorf("rotate: retiring version %d: %w", version, err)
	}
	res.Retired = true
	note(r.emit(ctx, audit.Event{
		Action: audit.KeyRetired, Purpose: string(kek.Purpose), KEKID: kekID.String(), Version: version,
		Outcome: audit.Success, Reason: "emergency rotation",
	}))
	if opts.KeepMaterial {
		return res, auditErr
	}

	prov, err := r.providerFor(kek)
	if err != nil {
		return res, err
	}
	if err := prov.Destroy(ctx, kek.Ref(), version); err != nil {
		return res, fmt.Errorf("rotate: destroying version %d at the provider: %w", version, err)
	}
	if err := r.store.TransitionVersion(ctx, kekID, version, registry.VersionDestroyed, registry.TransitionOptions{At: r.clock.Now()}); err != nil {
		return res, fmt.Errorf("rotate: the provider destroyed version %d but the registry did not record it; call again: %w", version, err)
	}
	res.Destroyed = true
	note(r.emit(ctx, audit.Event{
		Action: audit.KeyDestroyed, Purpose: string(kek.Purpose), KEKID: kekID.String(), Version: version,
		Outcome: audit.Success, Reason: "emergency rotation",
	}))
	return res, auditErr
}

// ExposedDEK reports the response to an exposed data key.
type ExposedDEK struct {
	// Exposed is the data key that was marked compromised.
	Exposed keyforge.DEKRecord
	// Replacement is the epoch that writes use now, or the zero value if the
	// exposed key was not the current one.
	Replacement keyforge.DEKRecord
	// EncryptionsUpperBound is the most encryptions that can have been made
	// under the exposed key: the registry's reserved high-water mark. It bounds
	// how much data is affected, and it counts blocks reserved by processes that
	// may not have used them, so it can overstate.
	EncryptionsUpperBound uint64
}

// CompromiseDEK responds to a data key that is known or suspected to be exposed.
//
// If it is the current epoch, the next epoch is created first so that writes
// move off it at once, then the key is marked compromised. It stays readable:
// the host re-encrypts what it protects, with [keyforge.Client.Reencrypt] as it
// finds each record or in a pass of its own, and keyforge cannot do that for it,
// since the data is the application's. [Rotator.DestroyDEK] removes the key when
// the host is done.
//
// The report gives an upper bound on how much was encrypted under the key,
// which is all the registry can know; which records are affected is the host's
// to find, by the data key identifier their envelopes carry.
func (r *Rotator) CompromiseDEK(ctx context.Context, id envelope.ID) (ExposedDEK, error) {
	rec, err := r.store.GetDEK(ctx, id)
	if err != nil {
		return ExposedDEK{}, err
	}
	var out ExposedDEK

	cur, cerr := r.store.CurrentDEK(ctx, rec.Purpose, rec.Subject)
	if cerr == nil && cur.ID == rec.ID {
		if r.epochs == nil {
			return out, ErrNoEpochAdvancer
		}
		next, err := r.epochs.AdvanceEpoch(ctx, rec.Purpose, rec.Subject)
		if err != nil {
			return out, fmt.Errorf("rotate: creating the replacement epoch: %w", err)
		}
		out.Replacement = next
	} else if cerr != nil && !errors.Is(cerr, keyforge.ErrDEKNotFound) {
		return out, cerr
	}

	// Marking is idempotent: a key already compromised is left as it is.
	if rec.State != keyforge.DEKCompromised {
		if err := r.store.MarkDEK(ctx, id, keyforge.DEKCompromised); err != nil {
			return out, fmt.Errorf("rotate: marking data key %s compromised: %w", id, err)
		}
	}
	marked, err := r.store.GetDEK(ctx, id)
	if err != nil {
		return out, err
	}
	out.Exposed = marked
	out.EncryptionsUpperBound = marked.Reserved
	return out, r.emit(ctx, audit.Event{
		Action: audit.DataKeyCompromised, Purpose: string(rec.Purpose), DEKID: id.String(), Outcome: audit.Success,
		Reason: "marked compromised; the host re-encrypts what it protects",
	})
}

// DestroyDEK removes an exposed or superseded data key once the host has
// re-encrypted what it protects. It asks the guard, and only an allow destroys
// the wrapped key; the record remains as the trail of what existed.
func (r *Rotator) DestroyDEK(ctx context.Context, id envelope.ID) (RetireResult, error) {
	rec, err := r.store.GetDEK(ctx, id)
	if err != nil {
		return RetireResult{}, err
	}
	if r.guard == nil {
		return r.dekDenied(ctx, rec, guard.Deny(guard.ErrNoGuard))
	}
	d, err := r.guard.Check(ctx, guard.Request{
		Action: guard.Destroy, Purpose: rec.Purpose, DEKID: id, Actor: audit.ActorFrom(ctx),
	})
	if err != nil {
		return RetireResult{}, fmt.Errorf("rotate: the destroy guard failed: %w", err)
	}
	switch d.Outcome {
	case guard.Allowed:
	case guard.Denied, guard.Pending:
		return r.dekDenied(ctx, rec, d)
	default:
		return RetireResult{}, fmt.Errorf("rotate: the destroy guard: %w", guard.ErrBadDecision)
	}
	if err := r.store.MarkDEK(ctx, id, keyforge.DEKDestroyed); err != nil {
		return RetireResult{}, err
	}
	return RetireResult{Outcome: guard.Allowed}, r.emit(ctx, audit.Event{
		Action: audit.DataKeyDestroyed, Purpose: string(rec.Purpose), DEKID: id.String(), Outcome: audit.Success,
		Reason: "the guard allowed it",
	})
}

func (r *Rotator) dekDenied(ctx context.Context, rec keyforge.DEKRecord, d guard.Decision) (RetireResult, error) {
	action, outcome := audit.GuardDenied, audit.Denied
	if d.Outcome == guard.Pending {
		action, outcome = audit.GuardPending, audit.Pending
	}
	return RetireResult{Outcome: d.Outcome, Reason: d.Reason}, r.emit(ctx, audit.Event{
		Action: action, Purpose: string(rec.Purpose), DEKID: rec.ID.String(), Outcome: outcome, Reason: d.Reason,
	})
}
