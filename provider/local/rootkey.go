package local

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// RootKeySize is the size in bytes of a root key.
const RootKeySize = 32

// RootKeySource supplies the root key that protects the keyring file. The
// root key never touches disk beside the keyring: it comes from an environment
// variable, from a file kept elsewhere, or from a secret manager.
//
// The root key is 32 random bytes, for example the output of
// `openssl rand -base64 32`. keyforge does not stretch a passphrase: a
// passphrase is not a key, and a source that holds one belongs in the secret
// manager that derives the key from it.
type RootKeySource interface {
	// RootKey returns the root key. The caller zeroes the returned slice when
	// done with it.
	RootKey(ctx context.Context) ([]byte, error)
}

// Typed errors for root key sources.
var (
	// ErrBadRootKey is returned when a source yields something that is not a
	// root key. The error never contains what was read.
	ErrBadRootKey = errors.New("local: root key is not 32 bytes of base64 or hex")
	// ErrRootKeyUnavailable is returned when a source cannot supply a key: an
	// unset variable or a missing file.
	ErrRootKeyUnavailable = errors.New("local: root key unavailable")
	// ErrInsecureRootKeyFile is returned for a root key file that other users
	// can read.
	ErrInsecureRootKeyFile = errors.New("local: root key file is readable by others")
)

// decodeRootKey parses a root key from its text form: 32 bytes as standard
// base64 or as 64 hex digits, with surrounding whitespace ignored.
func decodeRootKey(text []byte) ([]byte, error) {
	s := strings.TrimSpace(string(text))
	defer func() { clear(text) }()
	if s == "" {
		return nil, ErrBadRootKey
	}
	if len(s) == 2*RootKeySize {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == RootKeySize {
		return b, nil
	}
	return nil, ErrBadRootKey
}

type envSource struct{ name string }

// EnvSource reads the root key from an environment variable.
func EnvSource(name string) RootKeySource { return envSource{name: name} }

func (s envSource) RootKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, ok := os.LookupEnv(s.name)
	if !ok || v == "" {
		return nil, fmt.Errorf("%w: environment variable %s is not set", ErrRootKeyUnavailable, s.name)
	}
	return decodeRootKey([]byte(v))
}

type fileSource struct{ path string }

// FileSource reads the root key from a file. On Unix the file must not be
// readable by group or others.
func FileSource(path string) RootKeySource { return fileSource{path: path} }

func (s fileSource) RootKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRootKeyUnavailable, err)
	}
	defer f.Close()
	if runtime.GOOS != "windows" {
		info, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRootKeyUnavailable, err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%w: %s has mode %04o", ErrInsecureRootKeyFile, s.path, info.Mode().Perm())
		}
	}
	text, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRootKeyUnavailable, err)
	}
	return decodeRootKey(text)
}

// Path returns the file the source reads, so the provider can refuse a root key
// kept beside the keyring.
func (s fileSource) Path() string { return s.path }

type staticSource struct{ key []byte }

// StaticSource returns a source that holds a key in memory, for tests and for
// callers that obtained the key some other way. It keeps its own copy.
func StaticSource(key []byte) RootKeySource {
	return staticSource{key: append([]byte(nil), key...)}
}

func (s staticSource) RootKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(s.key) != RootKeySize {
		return nil, ErrBadRootKey
	}
	return append([]byte(nil), s.key...), nil
}

// pathed is implemented by sources that read a file.
type pathed interface{ Path() string }

// besideKeyring reports whether src reads a file in the keyring's directory.
func besideKeyring(src RootKeySource, keyringPath string) bool {
	p, ok := src.(pathed)
	if !ok {
		return false
	}
	a, errA := filepath.Abs(filepath.Dir(p.Path()))
	b, errB := filepath.Abs(filepath.Dir(keyringPath))
	return errA == nil && errB == nil && a == b
}

const (
	infoKeyringKey  = "keyforge/keyring/encryption-key/v1"
	infoRootKeyID   = "keyforge/keyring/root-key-id/v1"
	rootKeyIDSize   = 16
	derivedKeyBytes = 32
)

// deriveKeys returns the key that encrypts the keyring and the non-secret
// identifier of the root key, both derived with HKDF-SHA-256 under distinct
// context strings so neither reveals the other or the root key.
func deriveKeys(root []byte) (encKey []byte, id [rootKeyIDSize]byte, err error) {
	if len(root) != RootKeySize {
		return nil, id, ErrBadRootKey
	}
	encKey, err = hkdf.Key(sha256.New, root, nil, infoKeyringKey, derivedKeyBytes)
	if err != nil {
		return nil, id, fmt.Errorf("local: deriving the keyring key: %w", err)
	}
	raw, err := hkdf.Key(sha256.New, root, nil, infoRootKeyID, rootKeyIDSize)
	if err != nil {
		clear(encKey)
		return nil, id, fmt.Errorf("local: deriving the root key identifier: %w", err)
	}
	copy(id[:], raw)
	return encKey, id, nil
}
