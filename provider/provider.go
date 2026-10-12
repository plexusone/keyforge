// Package provider defines the interface to a key-encryption-key (KEK)
// holder: the local keyring, or a managed key service.
//
// A provider wraps and unwraps data keys and never returns KEK material. It
// knows nothing of purposes, policy, retirement or the registry; those belong
// to keyforge. It holds key versions and answers for them until they are
// destroyed.
//
// Every provider passes the conformance suite in package providertest.
package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
)

// KeyRef identifies a KEK.
//
// ID is keyforge's identifier, the one written in envelopes. ProviderRef is
// the provider's own opaque identifier (a keyring entry, a KMS key ARN or
// resource name) and is stored in the registry. The envelope carries only ID,
// so it stays provider-neutral and a key can move between providers by
// updating the registry and not the data.
type KeyRef struct {
	ID          envelope.ID
	Provider    string
	ProviderRef string
}

// Validate checks that the reference names a provider and a key.
func (r KeyRef) Validate() error {
	switch {
	case r.ID.IsZero():
		return fmt.Errorf("%w: key reference has no ID", ErrInvalidArgument)
	case r.Provider == "":
		return fmt.Errorf("%w: key reference has no provider", ErrInvalidArgument)
	case r.ProviderRef == "":
		return fmt.Errorf("%w: key reference has no provider reference", ErrInvalidArgument)
	}
	return nil
}

// KeySpec describes a KEK to create.
type KeySpec struct {
	// Purpose is the purpose name the key serves. A provider may use it to
	// label the key; it does not interpret it. It must be a valid purpose
	// name ([envelope.ValidPurpose]).
	Purpose string
	// Algorithm is the algorithm the key wraps with, from the registry.
	Algorithm algorithm.ID
	// ID, when non-zero, is the identifier the new key takes. Otherwise the
	// provider generates one. A key moved from another provider keeps its ID.
	ID envelope.ID
}

// Provider holds KEK versions and wraps and unwraps data keys with them.
//
// Versions are numbered from 1 and increase. A new key has version 1. Rotate
// adds the next version and leaves earlier versions usable for Unwrap until
// they are destroyed; which version is active is the registry's decision and
// not the provider's.
//
// Wrap and Unwrap bind aad, the purpose and key identity, so a wrapped key
// cannot be used for another purpose or key. A KMS provider maps it to the
// service's encryption context. Neither method retains or modifies its
// inputs, and each returns a slice the caller owns.
//
// Methods must honor ctx: with a cancelled context they return an error that
// wraps ctx.Err and change nothing. Errors never contain key material, wrapped
// keys or aad. All methods are safe for concurrent use.
type Provider interface {
	// Name identifies the provider type, for example "local". It is stable
	// and is the Provider field of every KeyRef the provider returns.
	Name() string

	// CreateKey creates a KEK with version 1.
	CreateKey(ctx context.Context, spec KeySpec) (KeyRef, error)

	// Rotate adds a new version and returns its number, which is greater than
	// every earlier one. A provider that rotates natively reports the version
	// the service assigned; one that does not generates it.
	Rotate(ctx context.Context, ref KeyRef) (version uint32, err error)

	// Wrap protects dek under the given version of the KEK.
	Wrap(ctx context.Context, ref KeyRef, version uint32, dek, aad []byte) ([]byte, error)

	// Unwrap recovers a data key. It returns [ErrUnwrapFailed], with no
	// further detail, for a wrong aad, a wrong version or key, or a modified
	// or truncated wrapped key.
	Unwrap(ctx context.Context, ref KeyRef, version uint32, wrapped, aad []byte) ([]byte, error)

	// Destroy irreversibly removes the key material of one version. After it,
	// Wrap and Unwrap for that version fail with [ErrVersionDestroyed].
	// Destroying a destroyed version succeeds, so a retried job is safe.
	Destroy(ctx context.Context, ref KeyRef, version uint32) error

	// Health reports whether the provider can serve requests now.
	Health(ctx context.Context) error
}

// Typed errors. Callers match them with [errors.Is].
var (
	// ErrKeyNotFound is returned for a key the provider does not hold.
	ErrKeyNotFound = errors.New("provider: key not found")
	// ErrVersionNotFound is returned for a version the key never had.
	ErrVersionNotFound = errors.New("provider: key version not found")
	// ErrVersionDestroyed is returned for a version that has been destroyed.
	ErrVersionDestroyed = errors.New("provider: key version destroyed")
	// ErrUnwrapFailed is returned when a wrapped key does not authenticate.
	// It deliberately carries no detail about why.
	ErrUnwrapFailed = errors.New("provider: unwrap failed")
	// ErrUnsupportedAlgorithm is returned by CreateKey for an algorithm the
	// provider cannot hold a key for.
	ErrUnsupportedAlgorithm = errors.New("provider: unsupported algorithm")
	// ErrInvalidArgument is returned for a malformed reference, spec or
	// input, such as an empty data key.
	ErrInvalidArgument = errors.New("provider: invalid argument")
)
