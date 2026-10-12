// Package registry defines the record of keys: key-encryption keys, their
// versions and states, and the data keys wrapped under them.
//
// The registry is the system of record for key state. A [Store] holds it, and
// every implementation passes the conformance suite in package storetest. The
// store enforces what can be enforced structurally and atomically (the
// transition table, one active version per key, that a version still
// referenced by a data key is not retired). Policy lives above it: when to
// rotate, how many versions to retain, and whether a guard allows a
// destruction.
package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
)

// KeyState is the state of a KEK as a whole.
type KeyState uint8

const (
	// KeyActive is the KEK a purpose is currently served by. At most one KEK
	// per purpose is active.
	KeyActive KeyState = iota + 1
	// KeyRetired is a KEK that has been replaced, for example by moving a
	// purpose to another provider. Its versions remain for reading.
	KeyRetired
)

// String returns the state's name.
func (s KeyState) String() string {
	switch s {
	case KeyActive:
		return "active"
	case KeyRetired:
		return "retired"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// KEK is the registry's record of a key-encryption key. The key material
// belongs to the provider and is never recorded here.
type KEK struct {
	ID          envelope.ID
	Purpose     keyforge.Purpose
	Provider    string
	ProviderRef string
	State       KeyState
	CreatedAt   time.Time
}

// Ref returns the provider reference for the key.
func (k KEK) Ref() provider.KeyRef {
	return provider.KeyRef{ID: k.ID, Provider: k.Provider, ProviderRef: k.ProviderRef}
}

// Validate checks that the record is complete and well formed.
func (k KEK) Validate() error {
	switch {
	case k.ID.IsZero():
		return fmt.Errorf("%w: KEK has no ID", ErrInvalid)
	case k.Provider == "" || k.ProviderRef == "":
		return fmt.Errorf("%w: KEK %s has no provider reference", ErrInvalid, k.ID)
	case k.State != KeyActive && k.State != KeyRetired:
		return fmt.Errorf("%w: KEK %s has state %d", ErrInvalid, k.ID, uint8(k.State))
	}
	if err := k.Purpose.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

// VersionState is the state of one version of a KEK.
type VersionState uint8

const (
	// VersionPending is created and not yet in use.
	VersionPending VersionState = iota + 1
	// VersionActive wraps new data keys and unwraps. At most one version of a
	// KEK is active, and exactly one once the first has been activated.
	VersionActive
	// VersionDecryptOnly is rotated out and kept until nothing references it.
	VersionDecryptOnly
	// VersionRetireRequested has had retirement asked for; its delay is
	// running and the guard is consulted before it advances.
	VersionRetireRequested
	// VersionRetired has its material removed from use, recoverable only from
	// backups.
	VersionRetired
	// VersionDestroyed has had its material destroyed at the provider.
	VersionDestroyed
	// VersionCompromised is marked by an operator and leads to the emergency
	// procedure.
	VersionCompromised
)

var versionStateNames = map[VersionState]string{
	VersionPending:         "pending",
	VersionActive:          "active",
	VersionDecryptOnly:     "decrypt-only",
	VersionRetireRequested: "retire-requested",
	VersionRetired:         "retired",
	VersionDestroyed:       "destroyed",
	VersionCompromised:     "compromised",
}

// VersionStates lists every state in lifecycle order.
var VersionStates = []VersionState{
	VersionPending, VersionActive, VersionDecryptOnly, VersionRetireRequested,
	VersionRetired, VersionDestroyed, VersionCompromised,
}

// String returns the state's name as used in logs and status.
func (s VersionState) String() string {
	if n, ok := versionStateNames[s]; ok {
		return n
	}
	return fmt.Sprintf("unknown(%d)", uint8(s))
}

// Valid reports whether s is a defined state.
func (s VersionState) Valid() bool {
	_, ok := versionStateNames[s]
	return ok
}

// CanWrap reports whether a data key may be newly wrapped under a version in
// this state.
func (s VersionState) CanWrap() bool { return s == VersionActive }

// CanUnwrap reports whether data keys wrapped under a version in this state
// may be unwrapped. A compromised version can be unwrapped so that what it
// protects can be re-wrapped away from it.
func (s VersionState) CanUnwrap() bool {
	switch s {
	case VersionActive, VersionDecryptOnly, VersionRetireRequested, VersionCompromised:
		return true
	}
	return false
}

// VersionRecord is the registry's record of one version of a KEK.
type VersionRecord struct {
	KEKID       envelope.ID
	Version     uint32
	State       VersionState
	ProviderRef string // the provider's identifier for this version, if it has one
	CreatedAt   time.Time
	ActivatedAt time.Time // when the version last became active
	RotatedAt   time.Time // when the version stopped being active
	RetireAfter time.Time // earliest time retirement may complete
}

// ShredRecord is the registry's record of an erasure: a subject whose data keys
// have been destroyed.
//
// Destroying the data keys makes the subject's data unrecoverable from the live
// registry at once. It is not complete until every KEK version that ever wrapped
// those keys is destroyed too, because a registry backup taken earlier holds
// them wrapped under one of those versions, and while any survives a restored
// backup can unwrap them.
type ShredRecord struct {
	Purpose     keyforge.Purpose
	Subject     string
	RequestedAt time.Time
	// Versions is every KEK version that ever wrapped one of the subject's
	// data keys, in order of KEK and version.
	Versions []keyforge.KEKVersionRef
	// DEKs is how many data keys were destroyed.
	DEKs int
	// CompletedAt is when the last of Versions was destroyed. It is zero while
	// the shred is pending.
	CompletedAt time.Time
}

// Complete reports whether every version has been destroyed.
func (r ShredRecord) Complete() bool { return !r.CompletedAt.IsZero() }

// Sentinel is an envelope kept for one KEK version whose plaintext is a fixed,
// non-secret marker. The disaster-recovery drill decrypts it to prove that a
// restored registry and keyring can still use the version. It holds no key
// material: it is a sealed envelope, as any stored ciphertext is.
type Sentinel struct {
	KEKID     envelope.ID
	Version   uint32
	Envelope  string // the envelope's text form
	CreatedAt time.Time
}

// Ref returns the KEK version the record describes, resolved against kek.
func (v VersionRecord) Ref(kek KEK) keyforge.KEKVersion {
	return keyforge.KEKVersion{Ref: kek.Ref(), Version: v.Version}
}

// Typed errors. Callers match them with [errors.Is].
var (
	// ErrInvalid is returned for a malformed record or argument.
	ErrInvalid = errors.New("registry: invalid record")
	// ErrKEKExists is returned when a KEK identifier is already registered.
	ErrKEKExists = errors.New("registry: KEK already exists")
	// ErrPurposeBound is returned when a purpose already has an active KEK.
	ErrPurposeBound = errors.New("registry: purpose already has an active KEK")
	// ErrVersionExists is returned for a version that is already registered or
	// is not greater than the latest.
	ErrVersionExists = errors.New("registry: KEK version already exists or is not newer")
	// ErrVersionNotFound is returned for a version the registry does not hold.
	ErrVersionNotFound = errors.New("registry: KEK version not found")
	// ErrInvalidTransition is returned for a state change the table forbids.
	// The record is unchanged.
	ErrInvalidTransition = errors.New("registry: invalid state transition")
	// ErrNoRollbackTarget is returned when reactivating a version that is not
	// the most recent decrypt-only one.
	ErrNoRollbackTarget = errors.New("registry: not the most recent decrypt-only version")
	// ErrRetireDelay is returned when retirement is attempted before its delay
	// has passed.
	ErrRetireDelay = errors.New("registry: retirement delay has not passed")
	// ErrVersionReferenced is returned when a version is retired or destroyed
	// while a data key is still wrapped under it.
	ErrVersionReferenced = errors.New("registry: KEK version is still referenced by data keys")
	// ErrVersionUnusable is returned when a data key is wrapped under a
	// version that cannot wrap.
	ErrVersionUnusable = errors.New("registry: KEK version cannot wrap data keys")
	// ErrConflict is returned when a compare-and-set finds the record other
	// than the caller expected.
	ErrConflict = errors.New("registry: record changed")
	// ErrSentinelNotFound is returned for a version that has no sentinel.
	ErrSentinelNotFound = errors.New("registry: sentinel not found")
	// ErrShredNotFound is returned for a subject that has not been shredded.
	ErrShredNotFound = errors.New("registry: shred not found")
	// ErrShredPending is returned when completing a shred while a KEK version
	// that wrapped the subject's keys still exists.
	ErrShredPending = errors.New("registry: a KEK version that wrapped the subject's keys still exists")
)

// TransitionError is returned for a forbidden state change. It matches
// [ErrInvalidTransition].
type TransitionError struct {
	From, To VersionState
}

// Error implements error.
func (e *TransitionError) Error() string {
	return fmt.Sprintf("%v: %s to %s", ErrInvalidTransition, e.From, e.To)
}

// Unwrap lets [errors.Is] match [ErrInvalidTransition].
func (e *TransitionError) Unwrap() error { return ErrInvalidTransition }

// versionTransitions is the permitted set, the transition table in the TRD.
// Anything not listed is refused.
var versionTransitions = map[VersionState][]VersionState{
	VersionPending:         {VersionActive},
	VersionActive:          {VersionDecryptOnly, VersionCompromised},
	VersionDecryptOnly:     {VersionActive, VersionRetireRequested, VersionCompromised},
	VersionRetireRequested: {VersionDecryptOnly, VersionRetired, VersionCompromised},
	VersionRetired:         {VersionDestroyed},
	VersionCompromised:     {VersionRetired},
	VersionDestroyed:       nil,
}

// CanTransition reports whether the table permits from to to.
func CanTransition(from, to VersionState) bool {
	for _, t := range versionTransitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// CheckTransition returns a [*TransitionError] unless the table permits from
// to to.
func CheckTransition(from, to VersionState) error {
	if !CanTransition(from, to) {
		return &TransitionError{From: from, To: to}
	}
	return nil
}

// dekTransitions is the permitted set for data keys. A current key is demoted
// only by advancing to the next epoch, never directly.
var dekTransitions = map[keyforge.DEKState][]keyforge.DEKState{
	keyforge.DEKActive:      {keyforge.DEKDecryptOnly, keyforge.DEKCompromised},
	keyforge.DEKDecryptOnly: {keyforge.DEKCompromised, keyforge.DEKDestroyed},
	keyforge.DEKCompromised: {keyforge.DEKDestroyed},
	keyforge.DEKDestroyed:   nil,
}

// CheckDEKTransition returns a [*DEKTransitionError] unless the table permits
// from to to.
func CheckDEKTransition(from, to keyforge.DEKState) error {
	for _, t := range dekTransitions[from] {
		if t == to {
			return nil
		}
	}
	return &DEKTransitionError{From: from, To: to}
}

// DEKTransitionError is returned for a forbidden data key state change. It
// matches [ErrInvalidTransition].
type DEKTransitionError struct {
	From, To keyforge.DEKState
}

// Error implements error.
func (e *DEKTransitionError) Error() string {
	return fmt.Sprintf("%v: data key %s to %s", ErrInvalidTransition, e.From, e.To)
}

// Unwrap lets [errors.Is] match [ErrInvalidTransition].
func (e *DEKTransitionError) Unwrap() error { return ErrInvalidTransition }

// TransitionOptions carries what a transition needs besides its target.
type TransitionOptions struct {
	// At is when the change happens, from the caller's clock. Required.
	At time.Time
	// RetireAfter is the earliest time retirement may complete. Required, and
	// later than At, when moving to retire-requested.
	RetireAfter time.Time
}

// DEKFilter selects data key records. Results are ordered by identifier so a
// caller can page with a cursor and resume after a crash.
type DEKFilter struct {
	// KEKID and KEKVersion select the records wrapped under a KEK, or under
	// one of its versions when KEKVersion is non-zero.
	KEKID      envelope.ID
	KEKVersion uint32
	// Purpose selects one purpose when non-empty.
	Purpose keyforge.Purpose
	// After is the cursor: only identifiers greater than it are returned.
	After envelope.ID
	// Limit is the page size. Zero means [DefaultPageSize].
	Limit int
}

// DefaultPageSize and MaxPageSize bound a page of data key records.
const (
	DefaultPageSize = 100
	MaxPageSize     = 1000
)

// PageSize returns the effective page size for the filter.
func (f DEKFilter) PageSize() int {
	switch {
	case f.Limit <= 0:
		return DefaultPageSize
	case f.Limit > MaxPageSize:
		return MaxPageSize
	}
	return f.Limit
}

// Rewrap describes moving a data key's wrapping to another KEK version.
type Rewrap struct {
	ID envelope.ID
	// FromKEKID and FromVersion are what the caller believes the record is
	// wrapped under now. The change applies only if that is still so.
	FromKEKID   envelope.ID
	FromVersion uint32
	// ToKEKID and ToVersion are the active version to wrap under, and Wrapped
	// is the key wrapped under it.
	ToKEKID   envelope.ID
	ToVersion uint32
	Wrapped   []byte
}

// Store is the registry. It includes [keyforge.Store], so a registry can serve
// a client directly, and adds the administration of keys and versions.
//
// Operations that change state are atomic. A call that fails changes nothing.
type Store interface {
	keyforge.Store

	// CreateKEK registers a KEK. It returns [ErrKEKExists] for a known
	// identifier and [ErrPurposeBound] if the purpose already has an active
	// KEK.
	CreateKEK(ctx context.Context, k KEK) error
	// GetKEK returns a KEK by identifier, or [keyforge.ErrKEKNotFound].
	GetKEK(ctx context.Context, id envelope.ID) (KEK, error)
	// KEKForPurpose returns the active KEK for a purpose, or
	// [keyforge.ErrKEKNotFound].
	KEKForPurpose(ctx context.Context, purpose keyforge.Purpose) (KEK, error)
	// ListKEKs returns every KEK ordered by identifier.
	ListKEKs(ctx context.Context) ([]KEK, error)

	// AddVersion registers a new version, which must be pending and greater
	// than the KEK's latest. Version numbers need not be consecutive: a
	// managed provider assigns them.
	AddVersion(ctx context.Context, v VersionRecord) error
	// GetVersion returns one version, or [ErrVersionNotFound].
	GetVersion(ctx context.Context, kekID envelope.ID, version uint32) (VersionRecord, error)
	// ListVersions returns a KEK's versions in ascending order.
	ListVersions(ctx context.Context, kekID envelope.ID) ([]VersionRecord, error)
	// TransitionVersion moves a version to a new state under the transition
	// table. Activating a version demotes the previous active version in the
	// same transaction, and reactivating one is allowed only for the most
	// recent decrypt-only version. Retirement is refused before its delay has
	// passed and while any data key is wrapped under the version.
	TransitionVersion(ctx context.Context, kekID envelope.ID, version uint32, to VersionState, opts TransitionOptions) error

	// ListDEKs returns data key records matching the filter, ordered by
	// identifier, at most one page.
	ListDEKs(ctx context.Context, f DEKFilter) ([]keyforge.DEKRecord, error)
	// CountDEKs returns how many data keys are wrapped under a KEK version, in
	// any state but destroyed.
	CountDEKs(ctx context.Context, kekID envelope.ID, version uint32) (int, error)
	// RewrapDEK moves a data key to a new KEK version and wrapped value. It is
	// a compare-and-set on the version the key is wrapped under now and is
	// idempotent: repeating a completed rewrap succeeds, so a resumed job is
	// safe. The target must be active.
	RewrapDEK(ctx context.Context, r Rewrap) error
	// MarkDEK moves a data key to compromised or destroyed. A current key is
	// demoted only by advancing the epoch. Destroying a key removes its wrapped
	// value; the record remains.
	MarkDEK(ctx context.Context, id envelope.ID, to keyforge.DEKState) error

	// ShredSubject destroys every data key of a subject under a purpose, in
	// every state, removes their wrapped values, clears the current key, and
	// records the KEK versions that ever wrapped them, atomically. It leaves a
	// tombstone: a new key for the subject is refused with
	// [keyforge.ErrSubjectShredded]. Repeating it returns the existing record
	// and changes nothing. The subject must not be empty. If the subject had no
	// keys the shred is complete at once.
	ShredSubject(ctx context.Context, purpose keyforge.Purpose, subject string, at time.Time) (ShredRecord, error)
	// GetShred returns a subject's shred record, or [ErrShredNotFound].
	GetShred(ctx context.Context, purpose keyforge.Purpose, subject string) (ShredRecord, error)
	// ListShreds returns every shred record ordered by purpose and subject.
	ListShreds(ctx context.Context) ([]ShredRecord, error)
	// CompleteShred records that the shred is complete, provided every KEK
	// version in it has been destroyed. Otherwise it is [ErrShredPending] and
	// nothing changes. Repeating it on a complete shred returns the record.
	CompleteShred(ctx context.Context, purpose keyforge.Purpose, subject string, at time.Time) (ShredRecord, error)

	// PutSentinel stores the sentinel for a KEK version. The version must
	// exist. A version has one sentinel: storing an identical one again
	// succeeds, and a different one is [ErrConflict].
	PutSentinel(ctx context.Context, s Sentinel) error
	// GetSentinel returns a version's sentinel, or [ErrSentinelNotFound].
	GetSentinel(ctx context.Context, kekID envelope.ID, version uint32) (Sentinel, error)
	// ListSentinels returns a KEK's sentinels in ascending version order.
	ListSentinels(ctx context.Context, kekID envelope.ID) ([]Sentinel, error)
}
