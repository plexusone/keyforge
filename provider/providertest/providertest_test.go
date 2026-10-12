package providertest_test

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/provider/providertest"
)

// mutation selects one deliberate defect in the reference provider.
type mutation int

const (
	none mutation = iota
	ignoreAAD
	plaintextWrap
	dropEarlierVersions
	ignoreContext
	leakInErrors
	shareOutputs
	destroyIsNoop
	destroyNotIdempotent
	constantRotate
	wrongErrorForUnknownKey
)

// reference is a small in-memory provider used to test the suite itself. It
// wraps with AES-256-GCM from the registry.
type reference struct {
	mu   sync.Mutex
	mut  mutation
	keys map[envelope.ID]*refKey

	cache map[string][]byte // used by shareOutputs
}

type refKey struct {
	ref      provider.KeyRef
	versions map[uint32]*refVersion
	latest   uint32
}

type refVersion struct {
	aead      cipher.AEAD
	destroyed bool
}

func newReference(m mutation) *reference {
	return &reference{mut: m, keys: map[envelope.ID]*refKey{}, cache: map[string][]byte{}}
}

func (r *reference) Name() string { return "reference" }

func (r *reference) ctxErr(ctx context.Context) error {
	if r.mut == ignoreContext {
		return nil
	}
	return ctx.Err()
}

func (r *reference) Health(ctx context.Context) error { return r.ctxErr(ctx) }

func (r *reference) newVersion() (*refVersion, error) {
	key := make([]byte, algorithm.AES256GCM.KeySize())
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	aead, err := algorithm.New(algorithm.AES256GCM, key)
	if err != nil {
		return nil, err
	}
	return &refVersion{aead: aead}, nil
}

func (r *reference) CreateKey(ctx context.Context, spec provider.KeySpec) (provider.KeyRef, error) {
	if err := r.ctxErr(ctx); err != nil {
		return provider.KeyRef{}, err
	}
	if !envelope.ValidPurpose(spec.Purpose) {
		return provider.KeyRef{}, fmt.Errorf("%w: purpose %q", provider.ErrInvalidArgument, spec.Purpose)
	}
	if spec.Algorithm != algorithm.AES256GCM {
		return provider.KeyRef{}, fmt.Errorf("%w: %v", provider.ErrUnsupportedAlgorithm, spec.Algorithm)
	}
	id := spec.ID
	if id.IsZero() {
		if _, err := rand.Read(id[:]); err != nil {
			return provider.KeyRef{}, err
		}
	}
	v, err := r.newVersion()
	if err != nil {
		return provider.KeyRef{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ref := provider.KeyRef{ID: id, Provider: r.Name(), ProviderRef: "ref/" + id.String()}
	r.keys[id] = &refKey{ref: ref, versions: map[uint32]*refVersion{1: v}, latest: 1}
	return ref, nil
}

func (r *reference) find(ref provider.KeyRef) (*refKey, error) {
	k, ok := r.keys[ref.ID]
	if !ok {
		if r.mut == wrongErrorForUnknownKey {
			return nil, provider.ErrVersionNotFound
		}
		return nil, provider.ErrKeyNotFound
	}
	return k, nil
}

func (r *reference) version(ref provider.KeyRef, version uint32) (*refVersion, error) {
	k, err := r.find(ref)
	if err != nil {
		return nil, err
	}
	v, ok := k.versions[version]
	if !ok {
		return nil, provider.ErrVersionNotFound
	}
	if v.destroyed {
		return nil, provider.ErrVersionDestroyed
	}
	return v, nil
}

func (r *reference) Rotate(ctx context.Context, ref provider.KeyRef) (uint32, error) {
	if err := r.ctxErr(ctx); err != nil {
		return 0, err
	}
	nv, err := r.newVersion()
	if err != nil {
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k, err := r.find(ref)
	if err != nil {
		return 0, err
	}
	k.latest++
	if r.mut == dropEarlierVersions {
		k.versions = map[uint32]*refVersion{}
	}
	k.versions[k.latest] = nv
	if r.mut == constantRotate {
		return 2, nil
	}
	return k.latest, nil
}

func (r *reference) Wrap(ctx context.Context, ref provider.KeyRef, version uint32, dek, aad []byte) ([]byte, error) {
	if err := r.ctxErr(ctx); err != nil {
		return nil, err
	}
	if len(dek) == 0 {
		return nil, fmt.Errorf("%w: empty data key", provider.ErrInvalidArgument)
	}
	r.mu.Lock()
	v, err := r.version(ref, version)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if r.mut == plaintextWrap {
		return append([]byte(nil), dek...), nil
	}
	if r.mut == ignoreAAD {
		aad = nil
	}
	return v.aead.Seal(nil, nil, dek, aad), nil //nolint:gosec // G407: a nil nonce is the API of the registry's random-nonce AEAD
}

func (r *reference) Unwrap(ctx context.Context, ref provider.KeyRef, version uint32, wrapped, aad []byte) ([]byte, error) {
	if err := r.ctxErr(ctx); err != nil {
		return nil, err
	}
	r.mu.Lock()
	v, err := r.version(ref, version)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if r.mut == plaintextWrap {
		return append([]byte(nil), wrapped...), nil
	}
	if r.mut == ignoreAAD {
		aad = nil
	}
	if r.mut == shareOutputs {
		r.mu.Lock()
		defer r.mu.Unlock()
		if got, ok := r.cache[string(wrapped)]; ok {
			return got, nil
		}
	}
	dek, err := v.aead.Open(nil, nil, wrapped, aad)
	if err != nil {
		if r.mut == leakInErrors {
			return nil, fmt.Errorf("%w: cannot open %x", provider.ErrUnwrapFailed, wrapped)
		}
		return nil, provider.ErrUnwrapFailed
	}
	if r.mut == shareOutputs {
		r.cache[string(wrapped)] = dek
	}
	return dek, nil
}

func (r *reference) Destroy(ctx context.Context, ref provider.KeyRef, version uint32) error {
	if err := r.ctxErr(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k, err := r.find(ref)
	if err != nil {
		return err
	}
	v, ok := k.versions[version]
	if !ok {
		return provider.ErrVersionNotFound
	}
	if v.destroyed && r.mut == destroyNotIdempotent {
		return fmt.Errorf("version %d already destroyed", version)
	}
	if r.mut != destroyIsNoop {
		v.destroyed = true
	}
	return nil
}

// TestReferencePasses shows that a correct provider passes every case, with
// the race detector watching the concurrent one.
func TestReferencePasses(t *testing.T) {
	providertest.Run(t, func() provider.Provider { return newReference(none) })
}

// recorder is a TB that records failures instead of failing a test.
type recorder struct {
	mu     sync.Mutex
	failed bool
	msgs   []string
}

type abort struct{}

func (r *recorder) Helper()             {}
func (r *recorder) Logf(string, ...any) {}
func (r *recorder) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	panic(abort{})
}

// failingCases runs every case against a provider built with m and returns
// the names of the cases that failed.
func failingCases(m mutation) map[string]bool {
	out := map[string]bool{}
	for _, c := range providertest.Cases() {
		rec := &recorder{}
		func() {
			defer func() {
				if v := recover(); v != nil {
					if _, ok := v.(abort); !ok {
						panic(v)
					}
				}
			}()
			c.Run(rec, newReference(m))
		}()
		if rec.failed {
			out[c.Name] = true
		}
	}
	return out
}

// TestSuiteRejectsBrokenProviders gives the suite a provider with one defect
// at a time. Each defect must be caught by the case that exists to catch it,
// so a conformance suite that has gone soft is noticed.
func TestSuiteRejectsBrokenProviders(t *testing.T) {
	tests := []struct {
		name string
		mut  mutation
		want string
	}{
		{"ignores the additional data", ignoreAAD, "UnwrapBindsAAD"},
		{"returns the data key in the clear", plaintextWrap, "WrapHidesTheDataKey"},
		{"drops earlier versions on rotate", dropEarlierVersions, "RotateKeepsEarlierVersions"},
		{"ignores the context", ignoreContext, "ContextCancellation"},
		{"puts the wrapped key in an error", leakInErrors, "ErrorsCarryNoKeyMaterial"},
		{"shares returned slices", shareOutputs, "InputsAndOutputsAreNotShared"},
		{"destroy has no effect", destroyIsNoop, "DestroyRemovesOneVersion"},
		{"destroy is not idempotent", destroyNotIdempotent, "DestroyIsIdempotent"},
		{"rotate does not increase", constantRotate, "RotateIsMonotonic"},
		{"unknown key reported as unknown version", wrongErrorForUnknownKey, "UnknownKeyAndVersion"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failed := failingCases(tt.mut)
			if !failed[tt.want] {
				t.Fatalf("case %s did not fail; cases that failed: %v", tt.want, failed)
			}
		})
	}
}

// TestSuiteCasesAreNamedOnce guards against two cases sharing a name, which
// would hide one of them in a subtest report.
func TestSuiteCasesAreNamedOnce(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range providertest.Cases() {
		if seen[c.Name] {
			t.Errorf("case %q appears twice", c.Name)
		}
		seen[c.Name] = true
	}
	if len(seen) < 15 {
		t.Errorf("only %d cases; the suite has shrunk", len(seen))
	}
}
