package rotate

import (
	"context"
	"fmt"
	"slices"

	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/registry"
)

// Eligibility says whether a KEK version may be retired now, and if not why.
type Eligibility struct {
	// Eligible is true when nothing here stops retirement.
	Eligible bool
	// State is the version's state.
	State registry.VersionState
	// References is how many data keys in the registry are still wrapped under
	// the version.
	References int
	// Reasons lists what stops retirement, in words that name no key material.
	Reasons []string
}

// Eligibility reports whether a version may be retired.
//
// A version is eligible only when all of these hold: it is decrypt-only, or
// compromised, since an active or pending version is not retired; it is outside
// the retained-versions floor; and no data key in the registry is wrapped under
// it. The floor is a minimum on retention and never a trigger to delete: the
// active version and the most recent decrypt-only ones, up to the policy's
// count, are kept even when nothing references them, so a bad rotation can be
// rolled back with nothing to recover.
//
// Data outside the registry (an inline envelope, an export, a snapshot, a
// backup) is not counted. A version that protects such data is held until the
// host asserts through the guard that none remains or accepts its loss.
func (r *Rotator) Eligibility(ctx context.Context, kekID envelope.ID, version uint32) (Eligibility, error) {
	kek, err := r.store.GetKEK(ctx, kekID)
	if err != nil {
		return Eligibility{}, err
	}
	versions, err := r.store.ListVersions(ctx, kekID)
	if err != nil {
		return Eligibility{}, err
	}
	var rec *registry.VersionRecord
	for i := range versions {
		if versions[i].Version == version {
			rec = &versions[i]
		}
	}
	if rec == nil {
		return Eligibility{}, fmt.Errorf("%w: %s version %d", registry.ErrVersionNotFound, kekID, version)
	}
	refs, err := r.store.CountDEKs(ctx, kekID, version)
	if err != nil {
		return Eligibility{}, err
	}

	out := Eligibility{State: rec.State, References: refs}
	switch rec.State {
	case registry.VersionDecryptOnly, registry.VersionCompromised:
	default:
		out.Reasons = append(out.Reasons, fmt.Sprintf("the version is %s, and only a decrypt-only or compromised version is retired", rec.State))
	}

	if rec.State == registry.VersionDecryptOnly {
		keep := r.policy.For(kek.Purpose).RetainVersions
		// Rank the versions that are still readable by recency: the active one
		// first, then decrypt-only ones from the newest.
		var live []uint32
		for _, v := range versions {
			if v.State == registry.VersionActive || v.State == registry.VersionDecryptOnly {
				live = append(live, v.Version)
			}
		}
		slices.SortFunc(live, func(a, b uint32) int { return int(b) - int(a) }) //nolint:gosec // G115: orders a short list of version numbers
		if rank := slices.Index(live, version); rank >= 0 && rank < keep {
			out.Reasons = append(out.Reasons, fmt.Sprintf("the version is within the retained-versions floor of %d", keep))
		}
	}
	if refs > 0 {
		out.Reasons = append(out.Reasons, fmt.Sprintf("%d data keys are still wrapped under it", refs))
	}
	out.Eligible = len(out.Reasons) == 0
	return out, nil
}
