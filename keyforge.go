package keyforge

import (
	"fmt"
	"time"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
)

// Re-exports of the types a caller meets first.
type (
	// KeyRef identifies a KEK. See [provider.KeyRef].
	KeyRef = provider.KeyRef
	// KeySpec describes a KEK to create. See [provider.KeySpec].
	KeySpec = provider.KeySpec
	// Envelope is a sealed ciphertext. See [envelope.Envelope].
	Envelope = envelope.Envelope
)

// Purpose is a named use of encryption, such as "session-secrets". Keys are
// scoped to a purpose, and the purpose is bound into every ciphertext.
type Purpose string

// Validate reports whether p is a legal purpose name.
func (p Purpose) Validate() error {
	if !envelope.ValidPurpose(string(p)) {
		return fmt.Errorf("%w: %q", envelope.ErrInvalidPurpose, string(p))
	}
	return nil
}

// KEKVersion names one version of a KEK.
type KEKVersion struct {
	Ref     provider.KeyRef
	Version uint32
}

// DEKState is the lifecycle state of a data key.
type DEKState uint8

const (
	// DEKActive is the current epoch: used for new writes and for reads.
	DEKActive DEKState = iota + 1
	// DEKDecryptOnly is an earlier epoch: read, never written.
	DEKDecryptOnly
	// DEKCompromised is marked by an operator and is read only as policy
	// allows.
	DEKCompromised
	// DEKDestroyed has no usable wrapped key.
	DEKDestroyed
)

// String returns the state's name.
func (s DEKState) String() string {
	switch s {
	case DEKActive:
		return "active"
	case DEKDecryptOnly:
		return "decrypt-only"
	case DEKCompromised:
		return "compromised"
	case DEKDestroyed:
		return "destroyed"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// DEKRecord is the registry's record of a data key. It never holds the
// unwrapped key.
type DEKRecord struct {
	ID         envelope.ID
	Purpose    Purpose
	Subject    string // empty for a purpose-wide key
	Epoch      uint32 // starts at 1 and increases per purpose and subject
	Algorithm  algorithm.ID
	KEKID      envelope.ID
	KEKVersion uint32
	Wrapped    []byte
	State      DEKState
	Reserved   uint64 // high-water mark of reserved encryptions
	CreatedAt  time.Time
}
