package rotate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/registry"
)

// RequestShred erases a subject: it destroys every data key the subject has
// under the purpose, which makes its data unrecoverable from the live registry
// at once, and records which KEK versions have to be destroyed before the
// erasure is complete. A shredded subject stays shredded: a new key for it is
// refused.
//
// The erasure is not complete when this returns. Registry backups still hold
// the subject's keys wrapped under the KEK versions that were active while the
// keys existed, and while any of those versions survives, a restored backup can
// unwrap them. [Rotator.ShredStatus] reports what is outstanding and when it is
// expected, and [Rotator.CompleteShreds] records completion once the last
// version is destroyed.
//
// Clients cache unwrapped keys, so a process that has the subject's key cached
// keeps using it until its entry expires or [keyforge.Client.Purge] is called.
// A host that needs the erasure to take effect at once purges its clients.
func (r *Rotator) RequestShred(ctx context.Context, purpose keyforge.Purpose, subject string) (registry.ShredRecord, error) {
	if err := keyforge.ValidateSubject(subject); err != nil {
		return registry.ShredRecord{}, err
	}
	// A purpose that has no key is a mistake, such as a mistyped name, and an
	// erasure "complete: no keys" for it would be a false assurance.
	if _, err := r.store.KEKForPurpose(ctx, purpose); err != nil {
		return registry.ShredRecord{}, fmt.Errorf("rotate: cannot shred under purpose %q: %w", string(purpose), err)
	}
	rec, err := r.store.ShredSubject(ctx, purpose, subject, r.clock.Now())
	if err != nil {
		return registry.ShredRecord{}, err
	}
	auditErr := r.emit(ctx, audit.Event{
		Action: audit.SubjectShredRequest, Purpose: string(purpose), Outcome: audit.Success,
		Reason: fmt.Sprintf("%d data keys destroyed; complete once %d KEK versions are destroyed", rec.DEKs, len(rec.Versions)),
	})
	if rec.Complete() {
		if err := r.emit(ctx, audit.Event{
			Action: audit.SubjectShredComplete, Purpose: string(purpose), Outcome: audit.Success,
			Reason: "no KEK version wrapped the subject's keys",
		}); err != nil && auditErr == nil {
			auditErr = err
		}
	}
	return rec, auditErr
}

// PendingVersion is a KEK version that must be destroyed before a shred is
// complete.
type PendingVersion struct {
	Version keyforge.KEKVersionRef
	State   registry.VersionState
	// ExpectedBy is when the version is expected to be destroyed if rotation
	// and retirement proceed on schedule, under the purpose's policy.
	ExpectedBy time.Time
}

// ShredStatus reports a shred.
type ShredStatus struct {
	Record registry.ShredRecord
	// Complete is true once every version has been destroyed and the shred
	// recorded as complete.
	Complete bool
	// Pending lists the versions still to be destroyed.
	Pending []PendingVersion
	// ExpectedBy is when the last pending version is expected to be destroyed,
	// or the zero value if the shred is complete.
	ExpectedBy time.Time
}

// ShredStatus reports what is outstanding for a subject's erasure and when it
// is expected to finish.
//
// The estimate follows from policy and assumes rotation proceeds on schedule. A
// version stays until it is outside the retained-versions floor, which takes
// that many further rotations at the KEK interval, and then waits out the
// retirement delay. With the defaults (a 365-day interval, two retained
// versions, a 30-day delay) that is more than two years for a version that is
// active today, which is why a purpose that needs a faster erasure guarantee
// sets a shorter KEK interval.
func (r *Rotator) ShredStatus(ctx context.Context, purpose keyforge.Purpose, subject string) (ShredStatus, error) {
	rec, err := r.store.GetShred(ctx, purpose, subject)
	if err != nil {
		return ShredStatus{}, err
	}
	out := ShredStatus{Record: rec, Complete: rec.Complete()}
	if out.Complete {
		return out, nil
	}
	cache := map[envelope.ID][]registry.VersionRecord{}
	for _, ref := range rec.Versions {
		vs, ok := cache[ref.KEKID]
		if !ok {
			if vs, err = r.store.ListVersions(ctx, ref.KEKID); err != nil {
				return ShredStatus{}, err
			}
			cache[ref.KEKID] = vs
		}
		idx := slices.IndexFunc(vs, func(v registry.VersionRecord) bool { return v.Version == ref.Version })
		if idx < 0 || vs[idx].State == registry.VersionDestroyed {
			continue
		}
		p := PendingVersion{Version: ref, State: vs[idx].State, ExpectedBy: r.expectedDestruction(vs, vs[idx], purpose)}
		out.Pending = append(out.Pending, p)
		if p.ExpectedBy.After(out.ExpectedBy) {
			out.ExpectedBy = p.ExpectedBy
		}
	}
	return out, nil
}

// expectedDestruction estimates when a version will be destroyed.
func (r *Rotator) expectedDestruction(versions []registry.VersionRecord, v registry.VersionRecord, purpose keyforge.Purpose) time.Time {
	now := r.clock.Now()
	pol := r.policy.For(purpose)

	switch v.State {
	case registry.VersionRetired, registry.VersionCompromised:
		return now
	case registry.VersionRetireRequested:
		return later(v.RetireAfter, now)
	}

	// Rank the readable versions by recency, the active one first. A version is
	// outside the floor once its rank reaches the retained count, so it needs
	// that many minus its rank further rotations.
	var live []uint32
	var activeSince time.Time
	for _, x := range versions {
		if x.State == registry.VersionActive || x.State == registry.VersionDecryptOnly {
			live = append(live, x.Version)
		}
		if x.State == registry.VersionActive {
			activeSince = x.ActivatedAt
			if activeSince.IsZero() {
				activeSince = x.CreatedAt
			}
		}
	}
	slices.SortFunc(live, func(a, b uint32) int { return int(b) - int(a) }) //nolint:gosec // G115: orders a short list of version numbers
	rank := slices.Index(live, v.Version)
	if rank < 0 {
		rank = 0
	}
	needed := max(pol.RetainVersions-rank, 0)

	eligible := now
	if needed > 0 && !activeSince.IsZero() {
		eligible = activeSince.Add(time.Duration(needed) * pol.KEKInterval)
	}
	return later(eligible, now).Add(pol.RetirementDelay)
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// CompleteShreds records completion for every shred whose KEK versions have all
// been destroyed, and returns those it completed. It is safe to call
// repeatedly: a scheduler calls it after each destruction.
func (r *Rotator) CompleteShreds(ctx context.Context) ([]registry.ShredRecord, error) {
	all, err := r.store.ListShreds(ctx)
	if err != nil {
		return nil, err
	}
	var done []registry.ShredRecord
	var auditErr error
	for _, rec := range all {
		if rec.Complete() {
			continue
		}
		got, err := r.store.CompleteShred(ctx, rec.Purpose, rec.Subject, r.clock.Now())
		if err != nil {
			if errors.Is(err, registry.ErrShredPending) {
				continue
			}
			return done, err
		}
		done = append(done, got)
		if err := r.emit(ctx, audit.Event{
			Action: audit.SubjectShredComplete, Purpose: string(got.Purpose), Outcome: audit.Success,
			Reason: fmt.Sprintf("every one of %d KEK versions that wrapped the subject's keys is destroyed", len(got.Versions)),
		}); err != nil && auditErr == nil {
			auditErr = err
		}
	}
	return done, auditErr
}
