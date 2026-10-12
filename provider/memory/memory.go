// Package memory provides in-memory providers for tests and examples.
//
// They are not for production: key material is held in process memory only,
// nothing persists, and no root key protects it. Their purpose is to exercise
// the client and the control plane against both styles of provider keyforge
// has to support:
//
//   - [NewKeyring] behaves like the local keyring: it holds every version
//     itself and numbers them 1, 2, 3 and so on.
//   - [NewNative] behaves like a managed key service: the service assigns
//     version numbers, which only increase and are not consecutive, and a
//     wrapped key records the version that wrapped it.
//
// A caller that assumes the next version is the previous plus one passes
// against the first and fails against the second.
package memory

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
)

// style selects how versions are numbered and how wrapped keys are formed.
type style uint8

const (
	styleKeyring style = iota + 1
	styleNative
)

// Provider is an in-memory [provider.Provider].
type Provider struct {
	name    string
	style   style
	entropy io.Reader

	mu   sync.Mutex
	keys map[envelope.ID]*key
}

type key struct {
	ref      provider.KeyRef
	alg      algorithm.ID
	versions map[uint32]*version
	latest   uint32
}

type version struct {
	aead      cipher.AEAD // nil once destroyed
	destroyed bool
}

// Option configures a [Provider].
type Option func(*Provider)

// WithName sets the provider's name, which is the Provider field of every key
// reference it returns. The default is "memory-keyring" or "memory-native".
func WithName(name string) Option { return func(p *Provider) { p.name = name } }

// WithEntropy sets the source of key material and identifiers. The default is
// crypto/rand. Tests inject a deterministic reader.
func WithEntropy(r io.Reader) Option { return func(p *Provider) { p.entropy = r } }

// NewKeyring returns a provider that behaves like the local keyring.
func NewKeyring(opts ...Option) *Provider { return newProvider("memory-keyring", styleKeyring, opts) }

// NewNative returns a provider that behaves like a managed key service.
func NewNative(opts ...Option) *Provider { return newProvider("memory-native", styleNative, opts) }

func newProvider(name string, s style, opts []Option) *Provider {
	p := &Provider{name: name, style: s, entropy: rand.Reader, keys: map[envelope.ID]*key{}}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name implements [provider.Provider].
func (p *Provider) Name() string { return p.name }

// Health implements [provider.Provider].
func (p *Provider) Health(ctx context.Context) error { return ctx.Err() }

func (p *Provider) newVersion(alg algorithm.ID) (*version, error) {
	material := make([]byte, alg.KeySize())
	defer clear(material)
	if _, err := io.ReadFull(p.entropy, material); err != nil {
		return nil, fmt.Errorf("provider: entropy source: %w", err)
	}
	aead, err := algorithm.New(alg, material)
	if err != nil {
		return nil, err
	}
	return &version{aead: aead}, nil
}

// CreateKey implements [provider.Provider].
func (p *Provider) CreateKey(ctx context.Context, spec provider.KeySpec) (provider.KeyRef, error) {
	if err := ctx.Err(); err != nil {
		return provider.KeyRef{}, err
	}
	if !envelope.ValidPurpose(spec.Purpose) {
		return provider.KeyRef{}, fmt.Errorf("%w: purpose %q", provider.ErrInvalidArgument, spec.Purpose)
	}
	if !spec.Algorithm.Valid() {
		return provider.KeyRef{}, fmt.Errorf("%w: %v", provider.ErrUnsupportedAlgorithm, spec.Algorithm)
	}

	id := spec.ID
	if id.IsZero() {
		if _, err := io.ReadFull(p.entropy, id[:]); err != nil {
			return provider.KeyRef{}, fmt.Errorf("provider: entropy source: %w", err)
		}
	}
	v, err := p.newVersion(spec.Algorithm)
	if err != nil {
		return provider.KeyRef{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.keys[id]; exists {
		return provider.KeyRef{}, fmt.Errorf("%w: key %s already exists", provider.ErrInvalidArgument, id)
	}
	prefix := "keyring/"
	if p.style == styleNative {
		prefix = "native/key-"
	}
	ref := provider.KeyRef{ID: id, Provider: p.name, ProviderRef: prefix + id.String()}
	p.keys[id] = &key{ref: ref, alg: spec.Algorithm, versions: map[uint32]*version{1: v}, latest: 1}
	return ref, nil
}

// Rotate implements [provider.Provider].
func (p *Provider) Rotate(ctx context.Context, ref provider.KeyRef) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, err := p.find(ref)
	if err != nil {
		return 0, err
	}
	next := k.latest + 1
	if p.style == styleNative {
		// The service assigns the number; it only has to increase.
		next = k.latest * 2
	}
	if next <= k.latest {
		return 0, errors.New("provider: version numbers exhausted")
	}
	v, err := p.newVersion(k.alg)
	if err != nil {
		return 0, err
	}
	k.versions[next] = v
	k.latest = next
	return next, nil
}

// find returns the key a reference names. The caller holds p.mu.
func (p *Provider) find(ref provider.KeyRef) (*key, error) {
	k, ok := p.keys[ref.ID]
	if !ok || ref.Provider != p.name {
		return nil, provider.ErrKeyNotFound
	}
	return k, nil
}

// usable returns the live version of a key. The caller holds p.mu.
func (p *Provider) usable(ref provider.KeyRef, ver uint32) (*version, error) {
	k, err := p.find(ref)
	if err != nil {
		return nil, err
	}
	v, ok := k.versions[ver]
	switch {
	case !ok:
		return nil, provider.ErrVersionNotFound
	case v.destroyed:
		return nil, provider.ErrVersionDestroyed
	}
	return v, nil
}

// Wrap implements [provider.Provider].
func (p *Provider) Wrap(ctx context.Context, ref provider.KeyRef, ver uint32, dek, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(dek) == 0 {
		return nil, fmt.Errorf("%w: empty data key", provider.ErrInvalidArgument)
	}
	p.mu.Lock()
	v, err := p.usable(ref, ver)
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	sealed := v.aead.Seal(nil, nil, dek, aad) //nolint:gosec // G407: a nil nonce is the API of the registry's random-nonce AEAD
	if p.style == styleNative {
		// A managed service's ciphertext blob names the key version that made it.
		sealed = append(binary.BigEndian.AppendUint32(nil, ver), sealed...)
	}
	return sealed, nil
}

// Unwrap implements [provider.Provider].
func (p *Provider) Unwrap(ctx context.Context, ref provider.KeyRef, ver uint32, wrapped, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	v, err := p.usable(ref, ver)
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	body := wrapped
	if p.style == styleNative {
		if len(wrapped) < 4 || binary.BigEndian.Uint32(wrapped) != ver {
			return nil, provider.ErrUnwrapFailed
		}
		body = wrapped[4:]
	}
	dek, err := v.aead.Open(nil, nil, body, aad)
	if err != nil {
		return nil, provider.ErrUnwrapFailed
	}
	return dek, nil
}

// Destroy implements [provider.Provider].
func (p *Provider) Destroy(ctx context.Context, ref provider.KeyRef, ver uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, err := p.find(ref)
	if err != nil {
		return err
	}
	v, ok := k.versions[ver]
	if !ok {
		return provider.ErrVersionNotFound
	}
	v.aead, v.destroyed = nil, true
	return nil
}
