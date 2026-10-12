// Package rotate rotates key-encryption keys: it creates and activates the next
// version, re-wraps the data keys that still sit under the old one, rolls back,
// and says when a version may be retired.
//
// Rotation never touches stored application data. A data key is wrapped by a
// KEK version, and rotating moves the wrapping; the ciphertext of the data
// itself, which names only its data key, is unchanged.
package rotate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/registry"
)

// SentinelPlaintext and SentinelContext are the fixed, non-secret values a
// sentinel envelope is sealed with. The recovery drill decrypts the sentinel of
// every retained version and compares the result with SentinelPlaintext.
const (
	SentinelPlaintext = "keyforge-sentinel-v1"
	SentinelContext   = "keyforge/sentinel/v1"
)

// Typed errors.
var (
	// ErrBackupStale is returned when policy requires a verified backup and the
	// keyring's backup has not been acknowledged as current. Rotation waits.
	ErrBackupStale = errors.New("rotate: the keyring backup is not acknowledged as current")
	// ErrBackupUnknown is returned when policy requires a verified backup and
	// the provider has no way to say whether it has one. Rotation fails closed.
	ErrBackupUnknown = errors.New("rotate: cannot tell whether the keyring is backed up")
	// ErrNothingToRewrap is returned when the from version is the active one.
	ErrNothingToRewrap = errors.New("rotate: the version to re-wrap from is the active version")
)

// Backup reports whether a provider's keyring has a backup acknowledged as
// current. The local provider implements it.
type Backup interface {
	UpToDate(ctx context.Context) (bool, error)
}

// Options configures a [Rotator].
type Options struct {
	// Store is the registry. Required.
	Store registry.Store
	// Providers hold the KEKs, matched to a key by name. At least one is
	// required.
	Providers []provider.Provider
	// Policy is the rotation and retirement policy. The zero value is the
	// default policy for every purpose.
	Policy policy.Set
	// Backups reports backup state by provider name, for purposes whose policy
	// requires a verified backup.
	Backups map[string]Backup
	// Clock defaults to the system clock.
	Clock keyforge.Clock
	// Audit receives lifecycle events. The default discards them.
	Audit audit.Sink
	// Entropy supplies sentinel keys and event identifiers. The default is
	// crypto/rand.
	Entropy io.Reader
}

// Rotator performs KEK rotation. It is safe for concurrent use; the registry's
// atomic operations are what keep concurrent rotators correct.
type Rotator struct {
	store     registry.Store
	providers map[string]provider.Provider
	policy    policy.Set
	backups   map[string]Backup
	clock     keyforge.Clock
	audit     audit.Sink
	entropy   io.Reader
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// New returns a rotator.
func New(opts Options) (*Rotator, error) {
	if opts.Store == nil {
		return nil, errors.New("rotate: Options.Store is required")
	}
	if len(opts.Providers) == 0 {
		return nil, errors.New("rotate: at least one provider is required")
	}
	providers := make(map[string]provider.Provider, len(opts.Providers))
	for _, p := range opts.Providers {
		if _, dup := providers[p.Name()]; dup {
			return nil, fmt.Errorf("rotate: two providers are named %q", p.Name())
		}
		providers[p.Name()] = p
	}
	if err := opts.Policy.Validate(0); err != nil {
		return nil, err
	}
	r := &Rotator{
		store: opts.Store, providers: providers, policy: opts.Policy, backups: opts.Backups,
		clock: opts.Clock, audit: opts.Audit, entropy: opts.Entropy,
	}
	if r.clock == nil {
		r.clock = systemClock{}
	}
	if r.audit == nil {
		r.audit = audit.Discard
	}
	if r.entropy == nil {
		r.entropy = rand.Reader
	}
	return r, nil
}

// emit sends an event, filling in what the rotator knows. A sink failure is
// returned as [audit.ErrNotRecorded]: the change has been made.
func (r *Rotator) emit(ctx context.Context, e audit.Event) error {
	var id [16]byte
	if _, err := io.ReadFull(r.entropy, id[:]); err != nil {
		return audit.NotRecorded(fmt.Errorf("event identifier: %w", err))
	}
	e.ID = hex.EncodeToString(id[:])
	e.Time = r.clock.Now()
	if e.Actor == "" {
		e.Actor = audit.ActorFrom(ctx)
	}
	return audit.NotRecorded(r.audit.Emit(ctx, e))
}

func (r *Rotator) providerFor(kek registry.KEK) (provider.Provider, error) {
	p, ok := r.providers[kek.Provider]
	if !ok {
		return nil, fmt.Errorf("rotate: no provider named %q for KEK %s", kek.Provider, kek.ID)
	}
	return p, nil
}

// Due describes when a purpose's KEK is next due for rotation.
type Due struct {
	Purpose     keyforge.Purpose
	KEK         registry.KEK
	Version     uint32
	ActivatedAt time.Time
	DueAt       time.Time
	Overdue     bool
}

// Due reports when the purpose's active KEK version is due for rotation. The
// interval is measured from when the version was last activated.
func (r *Rotator) Due(ctx context.Context, purpose keyforge.Purpose) (Due, error) {
	kek, err := r.store.KEKForPurpose(ctx, purpose)
	if err != nil {
		return Due{}, err
	}
	versions, err := r.store.ListVersions(ctx, kek.ID)
	if err != nil {
		return Due{}, err
	}
	for _, v := range versions {
		if v.State != registry.VersionActive {
			continue
		}
		since := v.ActivatedAt
		if since.IsZero() {
			since = v.CreatedAt
		}
		due := since.Add(r.policy.For(purpose).KEKInterval)
		return Due{Purpose: purpose, KEK: kek, Version: v.Version, ActivatedAt: since, DueAt: due, Overdue: !r.clock.Now().Before(due)}, nil
	}
	return Due{}, fmt.Errorf("%w: %q", keyforge.ErrNoActiveKEK, string(purpose))
}

// Rotation is the outcome of [Rotator.RotateKEK].
type Rotation struct {
	KEK  registry.KEK
	From uint32 // the version that was active, or zero if none was
	To   uint32 // the version that is active now
	At   time.Time
}

// RotateKEK creates the next version at the provider, registers and activates
// it, and records a sentinel for it. The previous version becomes decrypt-only
// in the same registry transaction, and stays usable. Data keys wrapped under it
// are moved by [Rotator.Rewrap], which the caller starts straight away so the
// old version drains.
//
// It resumes: a version left pending by an interrupted rotation is activated
// instead of creating another.
//
// A failure to record an audit event is returned as [audit.ErrNotRecorded]
// alongside a valid Rotation.
func (r *Rotator) RotateKEK(ctx context.Context, purpose keyforge.Purpose) (Rotation, error) {
	kek, err := r.store.KEKForPurpose(ctx, purpose)
	if err != nil {
		return Rotation{}, err
	}
	if err := r.checkBackup(ctx, kek); err != nil {
		return Rotation{}, err
	}
	prov, err := r.providerFor(kek)
	if err != nil {
		return Rotation{}, err
	}
	versions, err := r.store.ListVersions(ctx, kek.ID)
	if err != nil {
		return Rotation{}, err
	}
	var from, pending uint32
	for _, v := range versions {
		switch v.State {
		case registry.VersionActive:
			from = v.Version
		case registry.VersionPending:
			pending = v.Version
		}
	}

	at := r.clock.Now()
	next := pending
	if next == 0 {
		next, err = prov.Rotate(ctx, kek.Ref())
		if err != nil {
			return Rotation{}, fmt.Errorf("rotate: creating the next version at the provider: %w", err)
		}
		rec := registry.VersionRecord{KEKID: kek.ID, Version: next, State: registry.VersionPending, CreatedAt: at}
		if err := r.store.AddVersion(ctx, rec); err != nil {
			return Rotation{}, fmt.Errorf("rotate: registering version %d: %w", next, err)
		}
	}
	if err := r.store.TransitionVersion(ctx, kek.ID, next, registry.VersionActive, registry.TransitionOptions{At: at}); err != nil {
		return Rotation{}, fmt.Errorf("rotate: activating version %d: %w", next, err)
	}

	res := Rotation{KEK: kek, From: from, To: next, At: at}
	// The sentinel is recorded after activation. A failure is returned, and
	// the rotation stands: a version without a sentinel is reported by the
	// recovery drill, which is the right place to learn of it.
	sentErr := r.putSentinel(ctx, kek, prov, next, at)

	var audErr error
	for _, e := range []audit.Event{
		{Action: audit.KeyRotated, Purpose: string(purpose), KEKID: kek.ID.String(), Version: next, Outcome: audit.Success,
			Reason: fmt.Sprintf("version %d created", next)},
		{Action: audit.KeyActivated, Purpose: string(purpose), KEKID: kek.ID.String(), Version: next, Outcome: audit.Success,
			Reason: fmt.Sprintf("version %d active, replacing %d", next, from)},
	} {
		if err := r.emit(ctx, e); err != nil && audErr == nil {
			audErr = err
		}
	}
	if sentErr != nil {
		return res, fmt.Errorf("rotate: version %d is active but its sentinel was not recorded: %w", next, sentErr)
	}
	return res, audErr
}

func (r *Rotator) checkBackup(ctx context.Context, kek registry.KEK) error {
	if !r.policy.For(kek.Purpose).RequireBackup {
		return nil
	}
	b, ok := r.backups[kek.Provider]
	if !ok {
		return fmt.Errorf("%w: provider %q does not report backups", ErrBackupUnknown, kek.Provider)
	}
	ok, err := b.UpToDate(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBackupUnknown, err)
	}
	if !ok {
		_ = r.emit(ctx, audit.Event{Action: audit.BackupStale, Purpose: string(kek.Purpose), KEKID: kek.ID.String(), //nolint:errcheck // the refusal below is what the caller needs
			Outcome: audit.Denied, Reason: "rotation waits for the keyring backup to be acknowledged"})
		return ErrBackupStale
	}
	return nil
}

// putSentinel seals the fixed marker under a fresh data key wrapped by the
// version, as an inline envelope the client can open, and stores it.
func (r *Rotator) putSentinel(ctx context.Context, kek registry.KEK, prov provider.Provider, version uint32, at time.Time) error {
	if _, err := r.store.GetSentinel(ctx, kek.ID, version); err == nil {
		return nil
	}
	alg, err := algorithm.NewSelector(algorithm.Config{})
	if err != nil {
		return err
	}
	id, err := alg.Select(algorithm.Selection{})
	if err != nil {
		return err
	}
	dek := make([]byte, id.KeySize())
	defer clear(dek)
	if _, err := io.ReadFull(r.entropy, dek); err != nil {
		return err
	}
	wrapped, err := prov.Wrap(ctx, kek.Ref(), version, dek, keyforge.InlineWrapAAD(kek.Purpose, kek.ID))
	if err != nil {
		return err
	}
	aead, err := algorithm.New(id, dek)
	if err != nil {
		return err
	}
	e, err := envelope.Seal(aead, envelope.Header{
		Mode: envelope.ModeInline, Algorithm: id, Purpose: string(kek.Purpose),
		KEKID: kek.ID, KEKVersion: version, Wrapped: wrapped,
	}, []byte(SentinelPlaintext), []byte(SentinelContext))
	if err != nil {
		return err
	}
	return r.store.PutSentinel(ctx, registry.Sentinel{KEKID: kek.ID, Version: version, Envelope: e.String(), CreatedAt: at})
}

// Rollback reactivates the most recent decrypt-only version of the purpose's
// KEK, demoting the active one in the same transaction. It is for a version
// that turns out to be bad (a provider fault, a wrong configuration): nothing
// needs recovering, because the earlier version was kept. Data keys already
// wrapped under the demoted version still unwrap under it.
func (r *Rotator) Rollback(ctx context.Context, purpose keyforge.Purpose) (Rotation, error) {
	kek, err := r.store.KEKForPurpose(ctx, purpose)
	if err != nil {
		return Rotation{}, err
	}
	versions, err := r.store.ListVersions(ctx, kek.ID)
	if err != nil {
		return Rotation{}, err
	}
	var from, target uint32
	for _, v := range versions {
		switch v.State {
		case registry.VersionActive:
			from = v.Version
		case registry.VersionDecryptOnly:
			target = max(target, v.Version)
		}
	}
	if target == 0 {
		return Rotation{}, fmt.Errorf("%w: %q has no decrypt-only version to return to", registry.ErrNoRollbackTarget, string(purpose))
	}
	at := r.clock.Now()
	if err := r.store.TransitionVersion(ctx, kek.ID, target, registry.VersionActive, registry.TransitionOptions{At: at}); err != nil {
		return Rotation{}, fmt.Errorf("rotate: rolling back to version %d: %w", target, err)
	}
	res := Rotation{KEK: kek, From: from, To: target, At: at}
	return res, r.emit(ctx, audit.Event{
		Action: audit.KeyRolledBack, Purpose: string(purpose), KEKID: kek.ID.String(), Version: target, Outcome: audit.Success,
		Reason: fmt.Sprintf("version %d reactivated, replacing %d", target, from),
	})
}
