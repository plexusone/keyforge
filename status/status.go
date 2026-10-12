// Package status assembles what an operator needs to see: the state of every
// key, when each is next due, what is overdue, whether the keyring is backed up,
// whether each provider is healthy, and what the scheduler is struggling with.
//
// A report holds identifiers, states, counts and times. It never holds key
// material, wrapped keys or plaintext, so it is safe to log, serve and attach to
// a ticket.
package status

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/jobs"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/rotate"
)

// BackupInfo is the state of a provider's keyring backup.
type BackupInfo struct {
	Generation     uint64    `json:"generation"`
	Acknowledged   uint64    `json:"acknowledged"`
	AcknowledgedAt time.Time `json:"acknowledgedAt,omitzero"`
	Note           string    `json:"note,omitempty"`
	// Behind is how many generations the keyring is ahead of its backup.
	Behind   uint64 `json:"behind"`
	UpToDate bool   `json:"upToDate"`
}

// BackupFunc reports one provider's backup state.
type BackupFunc func(ctx context.Context) (BackupInfo, error)

// Options configures a [Reporter].
type Options struct {
	// Store is the registry. Required.
	Store registry.Store
	// Rotator supplies due dates, eligibility and erasure status. Required.
	Rotator *rotate.Rotator
	// Providers are checked for health.
	Providers []provider.Provider
	// Purposes are the purposes to report. Required.
	Purposes []keyforge.Purpose
	// Policy is the policy in force, to show each purpose's settings.
	Policy policy.Set
	// Selector, when set, supplies the active algorithm profile.
	Selector *algorithm.Selector
	// Backups reports backup state by provider name, for providers that have a
	// keyring to back up.
	Backups map[string]BackupFunc
	// Scheduler, when set, supplies the latest tick's overdue and failed work.
	Scheduler *jobs.Scheduler
	// Clock defaults to the system clock.
	Clock keyforge.Clock
}

// Reporter builds status reports.
type Reporter struct {
	o Options
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// New returns a reporter.
func New(o Options) (*Reporter, error) {
	switch {
	case o.Store == nil:
		return nil, errors.New("status: Options.Store is required")
	case o.Rotator == nil:
		return nil, errors.New("status: Options.Rotator is required")
	case len(o.Purposes) == 0:
		return nil, errors.New("status: at least one purpose is required")
	}
	if o.Clock == nil {
		o.Clock = systemClock{}
	}
	return &Reporter{o: o}, nil
}

// Report is a point-in-time view of the whole system.
type Report struct {
	GeneratedAt time.Time `json:"generatedAt"`
	// Healthy is false when anything below needs an operator: an unhealthy
	// provider, an overdue rotation, a stale backup, a failed job, a pending
	// erasure past its estimate, or a purpose with no usable key.
	Healthy bool `json:"healthy"`
	// Problems lists in plain words what makes Healthy false.
	Problems []string `json:"problems,omitempty"`

	Crypto    CryptoStatus     `json:"crypto"`
	Providers []ProviderStatus `json:"providers"`
	Purposes  []PurposeStatus  `json:"purposes"`
	Shreds    []ShredSummary   `json:"shreds,omitempty"`
	Jobs      *JobsStatus      `json:"jobs,omitempty"`
}

// CryptoStatus reports the algorithm profile and the Go cryptographic module.
type CryptoStatus struct {
	// Profile is the active algorithm profile, "standard" or "fips".
	Profile string `json:"profile"`
	// FIPSMode is whether the process runs in FIPS 140-3 mode.
	FIPSMode bool `json:"fipsMode"`
	// FIPSEnforced is whether non-approved algorithms are refused outright
	// (GODEBUG=fips140=only).
	FIPSEnforced bool `json:"fipsEnforced"`
	// ModuleVersion is the version of the Go cryptographic module in use.
	ModuleVersion string `json:"moduleVersion"`
	// Algorithms lists the exact names in the active profile.
	Algorithms []string `json:"algorithms"`
}

// ProviderStatus reports one provider.
type ProviderStatus struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
	// Error says why it is not healthy. It names no key material.
	Error  string      `json:"error,omitempty"`
	Backup *BackupInfo `json:"backup,omitempty"`
	// BackupError says why the backup state could not be read.
	BackupError string `json:"backupError,omitempty"`
}

// VersionStatus reports one version of a KEK.
type VersionStatus struct {
	Version     uint32    `json:"version"`
	State       string    `json:"state"`
	ActivatedAt time.Time `json:"activatedAt,omitzero"`
	RotatedAt   time.Time `json:"rotatedAt,omitzero"`
	RetireAfter time.Time `json:"retireAfter,omitzero"`
	// References is how many data keys are still wrapped under it.
	References int `json:"references"`
	// Retirable is whether it may be retired now, and Reasons says why not.
	Retirable bool     `json:"retirable"`
	Reasons   []string `json:"reasons,omitempty"`
}

// PurposeStatus reports one purpose.
type PurposeStatus struct {
	Purpose  string `json:"purpose"`
	Provider string `json:"provider,omitempty"`
	KEKID    string `json:"kekId,omitempty"`
	// ActiveVersion is zero when the purpose has no usable key, which is a
	// problem: writes fail closed.
	ActiveVersion uint32          `json:"activeVersion"`
	Versions      []VersionStatus `json:"versions,omitempty"`

	// NextRotation is when the active version is due, and Overdue says whether
	// that is past.
	NextRotation time.Time     `json:"nextRotation,omitzero"`
	Overdue      bool          `json:"overdue"`
	OverdueBy    time.Duration `json:"overdueBy,omitempty"`

	// DataKeys counts the purpose's data keys by state.
	DataKeys map[string]int `json:"dataKeys,omitempty"`

	Policy PolicyStatus `json:"policy"`
	// Error is set when the purpose could not be read.
	Error string `json:"error,omitempty"`
}

// PolicyStatus shows the policy in force for a purpose.
type PolicyStatus struct {
	KEKInterval       time.Duration `json:"kekInterval"`
	DEKMaxAge         time.Duration `json:"dekMaxAge"`
	DEKMaxEncryptions uint64        `json:"dekMaxEncryptions"`
	RetirementDelay   time.Duration `json:"retirementDelay"`
	RetainVersions    int           `json:"retainVersions"`
	RequireBackup     bool          `json:"requireBackup"`
}

// ShredSummary reports an erasure that is not yet complete.
type ShredSummary struct {
	Purpose         string    `json:"purpose"`
	Subject         string    `json:"subject"`
	RequestedAt     time.Time `json:"requestedAt"`
	PendingVersions int       `json:"pendingVersions"`
	ExpectedBy      time.Time `json:"expectedBy,omitzero"`
}

// JobsStatus reports the scheduler's latest tick.
type JobsStatus struct {
	InFlight int         `json:"inFlight"`
	Waiting  int         `json:"waiting"`
	Failed   []FailedJob `json:"failed,omitempty"`
}

// FailedJob is a job whose latest attempt failed.
type FailedJob struct {
	Kind        string `json:"kind"`
	Purpose     string `json:"purpose,omitempty"`
	KEKID       string `json:"kekId,omitempty"`
	Version     uint32 `json:"version,omitempty"`
	Consecutive int    `json:"consecutive"`
}

// Report builds a status report. A part that cannot be read is reported as such
// and does not hide the rest: an outage of one provider is what the report is
// for.
func (r *Reporter) Report(ctx context.Context) Report {
	now := r.o.Clock.Now()
	rep := Report{GeneratedAt: now, Healthy: true}
	problem := func(format string, args ...any) {
		rep.Healthy = false
		rep.Problems = append(rep.Problems, fmt.Sprintf(format, args...))
	}

	rep.Crypto = r.crypto()

	for _, p := range r.o.Providers {
		ps := ProviderStatus{Name: p.Name(), Healthy: true}
		if err := p.Health(ctx); err != nil {
			ps.Healthy, ps.Error = false, err.Error()
			problem("provider %q is not healthy: %v", p.Name(), err)
		}
		if f, ok := r.o.Backups[p.Name()]; ok {
			info, err := f(ctx)
			switch {
			case err != nil:
				ps.BackupError = err.Error()
				problem("the backup state of provider %q cannot be read: %v", p.Name(), err)
			default:
				ps.Backup = &info
				if !info.UpToDate {
					problem("the keyring of provider %q is %d generation(s) ahead of its acknowledged backup", p.Name(), info.Behind)
				}
			}
		}
		rep.Providers = append(rep.Providers, ps)
	}

	for _, purpose := range r.o.Purposes {
		pur := r.purpose(ctx, purpose, now)
		if pur.Error != "" {
			problem("purpose %q: %s", purpose, pur.Error)
		} else {
			if pur.ActiveVersion == 0 {
				problem("purpose %q has no active key version: writes fail closed", purpose)
			}
			if pur.Overdue {
				problem("purpose %q is overdue for rotation by %s", purpose, pur.OverdueBy.Round(time.Second))
			}
			if n := pur.DataKeys["compromised"]; n > 0 {
				problem("purpose %q has %d compromised data key(s) not yet destroyed", purpose, n)
			}
		}
		rep.Purposes = append(rep.Purposes, pur)
	}

	shreds, err := r.o.Store.ListShreds(ctx)
	if err != nil {
		problem("erasures cannot be read: %v", err)
	}
	for _, rec := range shreds {
		if rec.Complete() {
			continue
		}
		st, err := r.o.Rotator.ShredStatus(ctx, rec.Purpose, rec.Subject)
		if err != nil {
			problem("an erasure under %q cannot be read: %v", rec.Purpose, err)
			continue
		}
		rep.Shreds = append(rep.Shreds, ShredSummary{
			Purpose: string(rec.Purpose), Subject: rec.Subject, RequestedAt: rec.RequestedAt,
			PendingVersions: len(st.Pending), ExpectedBy: st.ExpectedBy,
		})
	}

	if r.o.Scheduler != nil {
		last := r.o.Scheduler.Last()
		js := &JobsStatus{InFlight: last.InFlight, Waiting: last.Waiting}
		for _, f := range last.Failed {
			js.Failed = append(js.Failed, FailedJob{
				Kind: string(f.Spec.Kind), Purpose: f.Spec.Purpose, KEKID: f.Spec.KEKID,
				Version: f.Spec.Version, Consecutive: f.Consecutive,
			})
			problem("a %s job has failed %d time(s) in a row", f.Spec.Kind, f.Consecutive)
		}
		rep.Jobs = js
	}

	sort.Strings(rep.Problems)
	return rep
}

func (r *Reporter) crypto() CryptoStatus {
	profile := algorithm.DefaultProfile()
	if r.o.Selector != nil {
		profile = r.o.Selector.Profile()
	}
	cs := CryptoStatus{
		Profile: profile.String(), FIPSMode: fips140.Enabled(), FIPSEnforced: fips140.Enforced(),
		ModuleVersion: fips140.Version(),
	}
	for _, id := range profile.Algorithms() {
		cs.Algorithms = append(cs.Algorithms, id.String())
	}
	return cs
}

func (r *Reporter) purpose(ctx context.Context, purpose keyforge.Purpose, now time.Time) PurposeStatus {
	pol := r.o.Policy.For(purpose)
	out := PurposeStatus{
		Purpose: string(purpose),
		Policy: PolicyStatus{
			KEKInterval: pol.KEKInterval, DEKMaxAge: pol.DEKMaxAge, DEKMaxEncryptions: pol.DEKMaxEncryptions,
			RetirementDelay: pol.RetirementDelay, RetainVersions: pol.RetainVersions, RequireBackup: pol.RequireBackup,
		},
	}

	kek, err := r.o.Store.KEKForPurpose(ctx, purpose)
	if err != nil {
		out.Error = "no key-encryption key is registered: " + err.Error()
		return out
	}
	out.Provider, out.KEKID = kek.Provider, kek.ID.String()

	versions, err := r.o.Store.ListVersions(ctx, kek.ID)
	if err != nil {
		out.Error = "versions cannot be read: " + err.Error()
		return out
	}
	for _, v := range versions {
		vs := VersionStatus{
			Version: v.Version, State: v.State.String(),
			ActivatedAt: v.ActivatedAt, RotatedAt: v.RotatedAt, RetireAfter: v.RetireAfter,
		}
		if v.State == registry.VersionActive {
			out.ActiveVersion = v.Version
		}
		if el, err := r.o.Rotator.Eligibility(ctx, kek.ID, v.Version); err == nil {
			vs.References, vs.Retirable, vs.Reasons = el.References, el.Eligible, el.Reasons
		}
		out.Versions = append(out.Versions, vs)
	}

	if due, err := r.o.Rotator.Due(ctx, purpose); err == nil {
		out.NextRotation, out.Overdue = due.DueAt, due.Overdue
		if due.Overdue {
			out.OverdueBy = now.Sub(due.DueAt)
		}
	}

	if counts, err := r.o.Store.CountDEKStates(ctx, purpose); err == nil && len(counts) > 0 {
		out.DataKeys = map[string]int{}
		for st, n := range counts {
			out.DataKeys[st.String()] = n
		}
	}
	return out
}
