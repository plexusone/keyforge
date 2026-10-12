package keyforge

import (
	"context"
	"errors"

	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
)

// Store is what the [Client] needs from the registry. It is defined here, where
// it is used, and kept to the operations the data path performs. The
// registry's own interface satisfies it.
//
// A Store is safe for concurrent use. Operations that change state are atomic:
// two replicas calling them at once see a single winner.
type Store interface {
	// ActiveKEK returns the KEK version new data keys for purpose are wrapped
	// under. It returns [ErrNoActiveKEK] if the purpose has none.
	ActiveKEK(ctx context.Context, purpose Purpose) (KEKVersion, error)

	// KEK returns the provider reference for a KEK identifier. It returns
	// [ErrKEKNotFound] for an identifier the registry does not hold.
	KEK(ctx context.Context, id envelope.ID) (provider.KeyRef, error)

	// KEKVersionUsable reports whether data keys wrapped under a KEK version
	// may be unwrapped: it is active, decrypt-only, retire-requested or
	// compromised. A pending, retired or destroyed version is not usable, even
	// while the provider still holds its material. It returns
	// [ErrKEKNotFound] for a KEK the registry does not hold, and false for a
	// version it does not hold.
	KEKVersionUsable(ctx context.Context, id envelope.ID, version uint32) (bool, error)

	// CurrentDEK returns the data key that new writes for purpose and subject
	// use. It returns [ErrDEKNotFound] if none exists yet.
	CurrentDEK(ctx context.Context, purpose Purpose, subject string) (DEKRecord, error)

	// GetDEK returns a data key by identifier, in any state. It returns
	// [ErrDEKNotFound] for an identifier the registry does not hold.
	GetDEK(ctx context.Context, id envelope.ID) (DEKRecord, error)

	// AdvanceDEK installs next as the current data key for purpose and
	// subject if the current epoch is still from (zero when there is none),
	// and marks the previous one decrypt-only, atomically. If the current
	// epoch is no longer from, it changes nothing and returns the record that
	// is current, so concurrent callers converge on one key.
	AdvanceDEK(ctx context.Context, purpose Purpose, subject string, from uint32, next DEKRecord) (DEKRecord, error)

	// ReserveEncryptions grants up to n more encryptions on a data key,
	// advancing its reserved high-water mark, but never past limit. It grants
	// zero when the key has no capacity left or is no longer the current
	// epoch, which tells the caller to advance.
	ReserveEncryptions(ctx context.Context, id envelope.ID, n, limit uint64) (granted uint64, err error)
}

// Typed errors. Callers match them with [errors.Is].
var (
	// ErrUnknownPurpose is returned for a purpose the client is not
	// configured for.
	ErrUnknownPurpose = errors.New("keyforge: unknown purpose")
	// ErrPurposeMismatch is returned when an envelope names a different
	// purpose than the one the caller asked to decrypt under.
	ErrPurposeMismatch = errors.New("keyforge: envelope purpose does not match")
	// ErrKeyUnavailable is returned when no usable key can be obtained: the
	// registry or provider failed and the key is not cached. Operations fail
	// closed; they never fall back to a weaker path.
	ErrKeyUnavailable = errors.New("keyforge: key unavailable")
	// ErrKeyUnusable is returned for a data key whose state forbids the
	// operation, such as a destroyed key.
	ErrKeyUnusable = errors.New("keyforge: key unusable")
	// ErrInvalidEnvelope is returned when an envelope is inconsistent with the
	// registry's record of its key.
	ErrInvalidEnvelope = errors.New("keyforge: envelope inconsistent with its key")
	// ErrDEKNotFound is returned by a Store for a data key it does not hold.
	ErrDEKNotFound = errors.New("keyforge: data key not found")
	// ErrKEKNotFound is returned by a Store for a KEK it does not hold.
	ErrKEKNotFound = errors.New("keyforge: key-encryption key not found")
	// ErrNoActiveKEK is returned by a Store for a purpose with no active KEK.
	ErrNoActiveKEK = errors.New("keyforge: no active key-encryption key")
	// ErrSubjectShredded is returned when a subject has been shredded and a
	// new key would be created for it. A shredded subject stays shredded: an
	// erasure that quietly re-enrolled the subject would not be one.
	ErrSubjectShredded = errors.New("keyforge: the subject has been shredded")
	// ErrSubjectRequired is returned when a purpose is per-subject and no
	// subject was given.
	ErrSubjectRequired = errors.New("keyforge: this purpose is per-subject and needs a subject")
	// ErrSubjectNotAllowed is returned when a subject is given for a purpose
	// that is not per-subject.
	ErrSubjectNotAllowed = errors.New("keyforge: this purpose is not per-subject")
	// ErrInvalidSubject is returned for a subject that is empty, too long, not
	// valid UTF-8, or contains control characters.
	ErrInvalidSubject = errors.New("keyforge: invalid subject")
)
