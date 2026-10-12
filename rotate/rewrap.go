package rotate

import (
	"context"
	"errors"
	"fmt"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/registry"
)

// DefaultBatchSize is how many data keys one re-wrap batch handles.
const DefaultBatchSize = registry.DefaultPageSize

// maxReportedFailures bounds the failures a result lists, so a mass failure
// cannot make the result unbounded. FailedCount is always exact.
const maxReportedFailures = 100

// RewrapOptions tunes a re-wrap run.
type RewrapOptions struct {
	// BatchSize is how many records to read and move at a time. Zero means
	// [DefaultBatchSize].
	BatchSize int
	// After resumes after a data key identifier, from a previous result's
	// Cursor. Because a moved record no longer matches the filter, restarting
	// from the beginning is also correct and only does extra reading.
	After envelope.ID
	// Progress, if set, is called after every batch.
	Progress func(RewrapResult)
}

// RewrapFailure describes a data key that could not be moved.
type RewrapFailure struct {
	DEKID envelope.ID
	Err   error
}

// RewrapResult reports a re-wrap run.
type RewrapResult struct {
	// Rewrapped is how many data keys were moved to the new version.
	Rewrapped int
	// Skipped is how many were already moved, by an earlier run or another
	// worker, or had been destroyed.
	Skipped int
	// FailedCount is how many could not be moved. Failed lists the first few.
	FailedCount int
	Failed      []RewrapFailure
	// Cursor is the last identifier handled, to resume from.
	Cursor envelope.ID
	// Done is true when every data key under the old version has been moved.
	// It is false when any failed, so a caller does not retire a version that
	// is still referenced.
	Done bool
}

// Rewrap moves every data key wrapped under version from of a KEK to the KEK's
// active version, in batches.
//
// It unwraps each key with the old version and wraps it again under the new one
// with the same additional data, then replaces the record with a compare-and-set
// on the version it was read under. The step is idempotent, so a run that is
// interrupted, or two that overlap, leave nothing half done: it can be started
// again at any point. Stored application data is not touched, because it names
// only its data key.
//
// A key that cannot be moved does not stop the run; it is counted, reported,
// and leaves Done false. A context that ends returns the progress made so far
// with the context's error.
func (r *Rotator) Rewrap(ctx context.Context, kekID envelope.ID, from uint32, opts RewrapOptions) (RewrapResult, error) {
	kek, err := r.store.GetKEK(ctx, kekID)
	if err != nil {
		return RewrapResult{}, err
	}
	prov, err := r.providerFor(kek)
	if err != nil {
		return RewrapResult{}, err
	}
	versions, err := r.store.ListVersions(ctx, kek.ID)
	if err != nil {
		return RewrapResult{}, err
	}
	var to uint32
	var fromState registry.VersionState
	for _, v := range versions {
		if v.State == registry.VersionActive {
			to = v.Version
		}
		if v.Version == from {
			fromState = v.State
		}
	}
	switch {
	case fromState == 0:
		return RewrapResult{}, fmt.Errorf("%w: %s version %d", registry.ErrVersionNotFound, kek.ID, from)
	case to == 0:
		return RewrapResult{}, fmt.Errorf("%w: %q has no active version to move keys to", keyforge.ErrNoActiveKEK, string(kek.Purpose))
	case to == from:
		return RewrapResult{}, ErrNothingToRewrap
	case !fromState.CanUnwrap():
		return RewrapResult{}, fmt.Errorf("%w: version %d is %s and cannot be unwrapped", registry.ErrVersionUnusable, from, fromState)
	}

	batch := opts.BatchSize
	if batch <= 0 {
		batch = DefaultBatchSize
	}
	res := RewrapResult{Cursor: opts.After}
	ref := kek.Ref()

	fail := func(id envelope.ID, err error) {
		res.FailedCount++
		if len(res.Failed) < maxReportedFailures {
			res.Failed = append(res.Failed, RewrapFailure{DEKID: id, Err: err})
		}
		_ = r.emit(ctx, audit.Event{ //nolint:errcheck // the failure is reported in the result; a missing event is secondary
			Action: audit.WrapFailed, Purpose: string(kek.Purpose), KEKID: kek.ID.String(), Version: from,
			DEKID: id.String(), Outcome: audit.Failure, Reason: "data key could not be moved to the new version",
		})
	}

	for {
		recs, err := r.store.ListDEKs(ctx, registry.DEKFilter{KEKID: kek.ID, KEKVersion: from, After: res.Cursor, Limit: batch})
		if err != nil {
			return res, fmt.Errorf("rotate: listing data keys: %w", err)
		}
		for _, rec := range recs {
			res.Cursor = rec.ID
			if rec.State == keyforge.DEKDestroyed || len(rec.Wrapped) == 0 {
				res.Skipped++
				continue
			}
			if err := ctx.Err(); err != nil {
				return res, err
			}
			aad := keyforge.DEKWrapAAD(rec.Purpose, rec.Subject, rec.ID, rec.KEKID)
			dek, err := prov.Unwrap(ctx, ref, from, rec.Wrapped, aad)
			if err != nil {
				fail(rec.ID, fmt.Errorf("unwrapping: %w", err))
				continue
			}
			wrapped, err := prov.Wrap(ctx, ref, to, dek, aad)
			clear(dek)
			if err != nil {
				fail(rec.ID, fmt.Errorf("wrapping: %w", err))
				continue
			}
			err = r.store.RewrapDEK(ctx, registry.Rewrap{
				ID: rec.ID, FromKEKID: kek.ID, FromVersion: from, ToKEKID: kek.ID, ToVersion: to, Wrapped: wrapped,
			})
			switch {
			case err == nil:
				res.Rewrapped++
			case errors.Is(err, registry.ErrConflict):
				// Another worker moved it, or it changed. Look again.
				now, gerr := r.store.GetDEK(ctx, rec.ID)
				if gerr == nil && now.KEKID == kek.ID && now.KEKVersion == to {
					res.Skipped++
				} else {
					fail(rec.ID, err)
				}
			default:
				fail(rec.ID, err)
			}
		}
		if opts.Progress != nil {
			opts.Progress(res)
		}
		if len(recs) < batch {
			break
		}
	}

	res.Done = res.FailedCount == 0
	var audErr error
	if res.Done {
		audErr = r.emit(ctx, audit.Event{
			Action: audit.KeyRotated, Purpose: string(kek.Purpose), KEKID: kek.ID.String(), Version: to, Outcome: audit.Success,
			Reason: fmt.Sprintf("re-wrapped %d data keys from version %d to %d", res.Rewrapped, from, to),
		})
	}
	return res, audErr
}

// RewrapAllResult reports a drain of every version of a KEK that still holds
// data keys.
type RewrapAllResult struct {
	// Versions is each version that was drained and how it went.
	Versions map[uint32]RewrapResult
	// Done is true when no readable version other than the active one is left
	// holding a data key.
	Done bool
}

// RewrapAll moves every data key off every readable version of a KEK that is
// not the active one. It is [Rotator.Rewrap] for each such version, and it is
// self-contained: it needs only the KEK, so a scheduled job can run it without
// being told which version to drain.
//
// Compromised versions are left to the emergency procedure, which a person
// starts, and a KEK with no active version is not drained at all.
func (r *Rotator) RewrapAll(ctx context.Context, kekID envelope.ID, opts RewrapOptions) (RewrapAllResult, error) {
	versions, err := r.store.ListVersions(ctx, kekID)
	if err != nil {
		return RewrapAllResult{}, err
	}
	out := RewrapAllResult{Versions: map[uint32]RewrapResult{}, Done: true}
	var hasActive bool
	for _, v := range versions {
		hasActive = hasActive || v.State == registry.VersionActive
	}
	if !hasActive {
		return out, fmt.Errorf("%w: KEK %s", keyforge.ErrNoActiveKEK, kekID)
	}
	var audErr error
	for _, v := range versions {
		switch v.State {
		case registry.VersionDecryptOnly, registry.VersionRetireRequested:
		default:
			continue
		}
		n, err := r.store.CountDEKs(ctx, kekID, v.Version)
		if err != nil {
			return out, err
		}
		if n == 0 {
			continue
		}
		res, err := r.Rewrap(ctx, kekID, v.Version, opts)
		if errors.Is(err, audit.ErrNotRecorded) {
			audErr, err = err, nil
		}
		if err != nil {
			return out, err
		}
		out.Versions[v.Version] = res
		out.Done = out.Done && res.Done
	}
	return out, audErr
}
