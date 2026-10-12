// Package local is the keyring-file provider: KEKs held in an encrypted file
// on the local disk, for development and single-host deployments.
//
// The provider is reported as "local" in status and in the startup log so it
// is not mistaken for a managed key service. It is as safe as the host and
// the source of its root key. It is not an HSM, and where managed keys are
// required a managed provider is the right one.
//
// # Protection
//
// KEK versions are held in a file that is sealed with AES-256-GCM under a key
// derived from a root key. The root key comes from a [RootKeySource] and never
// touches disk beside the keyring. The file is created with mode 0600 and a
// keyring that other users can read is refused.
//
// # Writes
//
// A change is made by taking an advisory lock, re-reading the file, applying
// the change, writing a temporary file, flushing it, renaming it over the
// keyring and flushing the directory. A crash leaves the previous keyring or
// the new one, never a mixture, and concurrent processes do not interleave.
package local

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
)

// DefaultName is the provider name reported in key references and status.
const DefaultName = "local"

// ErrRootKeyBesideKeyring is returned when the root key file is in the same
// directory as the keyring, which defeats the point of the root key.
var ErrRootKeyBesideKeyring = errors.New("local: the root key file is in the keyring's directory")

// Options configures a provider.
type Options struct {
	// Path is the keyring file. Required.
	Path string
	// Root supplies the root key. Required.
	Root RootKeySource
	// Name overrides [DefaultName].
	Name string
	// Entropy supplies key material and identifiers. The default is
	// crypto/rand. Tests inject a deterministic reader.
	Entropy io.Reader
	// AllowRootKeyBesideKeyring permits a root key file in the keyring's
	// directory. Leave it false outside tests.
	AllowRootKeyBesideKeyring bool
	// AcceptRollback opens a keyring that is older than one this host has
	// seen, which is what restoring from backup produces. Set it only after
	// confirming that the restore was intended; new writes continue from the
	// highest generation seen, so generations are never reused.
	AcceptRollback bool
}

// Provider is the keyring-file provider. It is safe for concurrent use, within
// a process and across processes sharing the file.
type Provider struct {
	name     string
	path     string
	lockPath string
	entropy  io.Reader

	mu     sync.Mutex
	root   RootKeySource
	aead   cipher.AEAD // seals and opens the file under the key derived from the root key
	rootID [rootKeyIDSize]byte
	st     *state
	gen    uint64

	hook func(stage string) error // test seam for crash points; nil in production
}

var _ provider.Provider = (*Provider)(nil)

func newProvider(opts Options) (*Provider, error) {
	switch {
	case opts.Path == "":
		return nil, errors.New("local: Options.Path is required")
	case opts.Root == nil:
		return nil, errors.New("local: Options.Root is required")
	}
	if besideKeyring(opts.Root, opts.Path) && !opts.AllowRootKeyBesideKeyring {
		return nil, ErrRootKeyBesideKeyring
	}
	name, entropy := opts.Name, opts.Entropy
	if name == "" {
		name = DefaultName
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &Provider{
		name:     name,
		path:     opts.Path,
		lockPath: opts.Path + ".lock",
		entropy:  entropy,
		root:     opts.Root,
	}, nil
}

// useRoot derives the keyring key from a root key source and installs it.
func (p *Provider) useRoot(ctx context.Context, src RootKeySource) error {
	root, err := src.RootKey(ctx)
	if err != nil {
		return err
	}
	defer clear(root)
	enc, id, err := deriveKeys(root)
	if err != nil {
		return err
	}
	defer clear(enc)
	aead, err := algorithm.New(keyringAlgorithm, enc)
	if err != nil {
		return err
	}
	p.aead, p.rootID, p.root = aead, id, src
	return nil
}

// Create makes a new, empty keyring. It fails with [ErrKeyringExists] if the
// file is already there.
func Create(ctx context.Context, opts Options) (*Provider, error) {
	p, err := newProvider(opts)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.useRoot(ctx, opts.Root); err != nil {
		return nil, err
	}
	unlock, err := lockFile(ctx, p.lockPath)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if _, err := os.Stat(p.path); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyringExists, p.path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("local: %w", err)
	}
	st := newState()
	if err := p.persist(st, 1); err != nil {
		return nil, err
	}
	if err := p.notePersisted(1); err != nil {
		return nil, err
	}
	p.st, p.gen = st, 1
	return p, nil
}

// Open opens an existing keyring. It fails with [ErrKeyringNotFound] if there
// is none, with [ErrWrongRootKey] if the root key is not the one it was
// written under, and with [ErrCorruptKeyring] if the file does not
// authenticate.
func Open(ctx context.Context, opts Options) (*Provider, error) {
	p, err := newProvider(opts)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.useRoot(ctx, opts.Root); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st, gen, err := p.read()
	if err != nil {
		return nil, err
	}
	if err := p.checkRollback(ctx, gen, opts.AcceptRollback); err != nil {
		st.wipe()
		return nil, err
	}
	p.st, p.gen = st, gen
	return p, nil
}

// checkRollback compares the generation just read with the highest this host
// has seen. It refuses an older keyring unless the caller has accepted the
// rollback, and records a higher generation when the file is ahead.
func (p *Provider) checkRollback(ctx context.Context, gen uint64, accept bool) error {
	unlock, err := lockFile(ctx, p.lockPath)
	if err != nil {
		return err
	}
	defer unlock()
	f, err := p.loadBackup()
	if err != nil {
		return err
	}
	if gen < f.Highest {
		if !accept {
			return &RollbackError{Found: gen, Highest: f.Highest}
		}
		// An acknowledged generation beyond the restored keyring is not a
		// statement about it. The high-water mark stays, so writes continue
		// above every generation seen.
		f.Acknowledged = min(f.Acknowledged, gen)
		return p.saveBackup(f)
	}
	return p.notePersisted(gen)
}

// ErrClosed is returned by a provider after Close.
var ErrClosed = errors.New("local: provider is closed")

// read loads and authenticates the keyring file. The caller holds p.mu.
func (p *Provider) read() (*state, uint64, error) {
	if p.aead == nil {
		return nil, 0, ErrClosed
	}
	info, err := os.Stat(p.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, fmt.Errorf("%w: %s", ErrKeyringNotFound, p.path)
		}
		return nil, 0, fmt.Errorf("local: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, 0, fmt.Errorf("%w: %s has mode %04o", ErrInsecurePermissions, p.path, info.Mode().Perm())
	}
	file, err := os.ReadFile(p.path)
	if err != nil {
		return nil, 0, fmt.Errorf("local: %w", err)
	}
	h, err := peek(file)
	if err != nil {
		return nil, 0, err
	}
	if h.rootKeyID != p.rootID {
		return nil, 0, ErrWrongRootKey
	}
	_, payload, err := open(p.aead, file)
	if err != nil {
		return nil, 0, err
	}
	defer clear(payload)
	st, err := unmarshalState(payload)
	if err != nil {
		return nil, 0, err
	}
	return st, h.generation, nil
}

// persist writes st at generation gen atomically. The caller holds the file
// lock and p.mu.
func (p *Provider) persist(st *state, gen uint64) error {
	payload, err := st.marshal()
	if err != nil {
		return fmt.Errorf("local: encoding the keyring: %w", err)
	}
	defer clear(payload)
	data := seal(p.aead, header{rootKeyID: p.rootID, generation: gen}, payload)
	return atomicWrite(p.path, data, p.hook)
}

// mutate applies fn to a fresh copy of the keyring under the file lock and
// persists the result. The in-memory keyring changes only if the write
// succeeded, so a failure leaves the provider as it was.
func (p *Provider) mutate(ctx context.Context, fn func(st *state) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	unlock, err := lockFile(ctx, p.lockPath)
	if err != nil {
		return err
	}
	defer unlock()
	removeStaleTemps(p.path)
	removeStaleTemps(p.backupPath())

	st, gen, err := p.read()
	if err != nil {
		return err
	}
	if gen < p.gen {
		// An older copy was put in place while this provider was running.
		// Writing on top of it would give stale content a new generation and
		// launder it past the rollback check at Open, and could reuse a
		// version number with different key material.
		st.wipe()
		return &RollbackError{Found: gen, Highest: p.gen}
	}
	if err := fn(st); err != nil {
		st.wipe()
		return err
	}
	next, err := p.nextGeneration(gen)
	if err != nil {
		st.wipe()
		return err
	}
	if err := p.persist(st, next); err != nil {
		st.wipe()
		return err
	}
	if err := p.notePersisted(next); err != nil {
		st.wipe()
		return err
	}
	p.st.wipe()
	p.st, p.gen = st, next
	return nil
}

// Name implements [provider.Provider].
func (p *Provider) Name() string { return p.name }

// Generation returns the generation of the keyring this provider last wrote or
// read. It increases with every change.
func (p *Provider) Generation() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gen
}

// RootKeyID returns the non-secret identifier of the root key in use, derived
// from it, as lowercase hex.
func (p *Provider) RootKeyID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Sprintf("%x", p.rootID[:])
}

// Path returns the keyring file.
func (p *Provider) Path() string { return p.path }

// Health implements [provider.Provider]: it reports whether the keyring can be
// read and authenticated with the root key in use.
func (p *Provider) Health(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st, _, err := p.read()
	if err != nil {
		return err
	}
	st.wipe()
	return nil
}

// Close zeroes the key material held in memory. The provider cannot be used
// afterwards.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.st != nil {
		p.st.wipe()
		p.st = newState()
	}
	p.aead = nil
	return nil
}

func (p *Provider) randomID() (envelope.ID, error) {
	var id envelope.ID
	if _, err := io.ReadFull(p.entropy, id[:]); err != nil {
		return id, fmt.Errorf("local: entropy source: %w", err)
	}
	return id, nil
}

// CreateKey implements [provider.Provider].
func (p *Provider) CreateKey(ctx context.Context, spec provider.KeySpec) (provider.KeyRef, error) {
	if !envelope.ValidPurpose(spec.Purpose) {
		return provider.KeyRef{}, fmt.Errorf("%w: purpose %q", provider.ErrInvalidArgument, spec.Purpose)
	}
	if !spec.Algorithm.Valid() {
		return provider.KeyRef{}, fmt.Errorf("%w: %v", provider.ErrUnsupportedAlgorithm, spec.Algorithm)
	}
	id := spec.ID
	if id.IsZero() {
		var err error
		if id, err = p.randomID(); err != nil {
			return provider.KeyRef{}, err
		}
	}
	material := make([]byte, spec.Algorithm.KeySize())
	if _, err := io.ReadFull(p.entropy, material); err != nil {
		return provider.KeyRef{}, fmt.Errorf("local: entropy source: %w", err)
	}
	defer clear(material)

	err := p.mutate(ctx, func(st *state) error {
		if _, exists := st.keys[id]; exists {
			return fmt.Errorf("%w: key %s already exists", provider.ErrInvalidArgument, id)
		}
		st.keys[id] = &keyState{
			id: id, purpose: spec.Purpose, alg: spec.Algorithm, latest: 1,
			versions: map[uint32]*versionState{1: {material: slices.Clone(material)}},
		}
		return nil
	})
	if err != nil {
		return provider.KeyRef{}, err
	}
	return p.ref(id), nil
}

func (p *Provider) ref(id envelope.ID) provider.KeyRef {
	return provider.KeyRef{ID: id, Provider: p.name, ProviderRef: "local/" + id.String()}
}

// Rotate implements [provider.Provider]. Versions are numbered 1, 2, 3, and so on.
func (p *Provider) Rotate(ctx context.Context, ref provider.KeyRef) (uint32, error) {
	if err := p.checkRef(ref); err != nil {
		return 0, err
	}
	// The key's algorithm is not known until the keyring has been read, so
	// material is drawn inside the mutation.
	var next uint32
	err := p.mutate(ctx, func(st *state) error {
		k, ok := st.keys[ref.ID]
		if !ok {
			return provider.ErrKeyNotFound
		}
		material := make([]byte, k.alg.KeySize())
		defer clear(material)
		if _, err := io.ReadFull(p.entropy, material); err != nil {
			return fmt.Errorf("local: entropy source: %w", err)
		}
		if k.latest == ^uint32(0) {
			return errors.New("local: version numbers exhausted")
		}
		k.latest++
		k.versions[k.latest] = &versionState{material: slices.Clone(material)}
		next = k.latest
		return nil
	})
	if err != nil {
		return 0, err
	}
	return next, nil
}

// checkRef rejects a reference that names another provider.
func (p *Provider) checkRef(ref provider.KeyRef) error {
	if ref.Provider != p.name {
		return provider.ErrKeyNotFound
	}
	return nil
}

// version returns the live version of a key, reloading the keyring once if it
// is not known, since another process may have added it. The caller holds p.mu.
func (p *Provider) version(ref provider.KeyRef, ver uint32) (*keyState, *versionState, error) {
	lookup := func() (*keyState, *versionState, error) {
		k, ok := p.st.keys[ref.ID]
		if !ok {
			return nil, nil, provider.ErrKeyNotFound
		}
		v, ok := k.versions[ver]
		switch {
		case !ok:
			return nil, nil, provider.ErrVersionNotFound
		case v.destroyed:
			return nil, nil, provider.ErrVersionDestroyed
		}
		return k, v, nil
	}
	k, v, err := lookup()
	if errors.Is(err, provider.ErrKeyNotFound) || errors.Is(err, provider.ErrVersionNotFound) {
		// Another process may have created it, or destroyed it since.
		// A generation lower than the one held is a restored copy, not news.
		if st, gen, rerr := p.read(); rerr == nil && gen > p.gen {
			p.st.wipe()
			p.st, p.gen = st, gen
			return lookup()
		} else if rerr == nil {
			st.wipe()
		}
	}
	return k, v, err
}

func (v *versionState) cipher(alg algorithm.ID) (cipher.AEAD, error) {
	if v.aead == nil {
		a, err := algorithm.New(alg, v.material)
		if err != nil {
			return nil, err
		}
		v.aead = a
	}
	return v.aead, nil
}

// Wrap implements [provider.Provider].
func (p *Provider) Wrap(ctx context.Context, ref provider.KeyRef, ver uint32, dek, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(dek) == 0 {
		return nil, fmt.Errorf("%w: empty data key", provider.ErrInvalidArgument)
	}
	if err := p.checkRef(ref); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, v, err := p.version(ref, ver)
	if err != nil {
		return nil, err
	}
	a, err := v.cipher(k.alg)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nil, dek, aad), nil //nolint:gosec // G407: a nil nonce is the API of the registry's random-nonce AEAD
}

// Unwrap implements [provider.Provider].
func (p *Provider) Unwrap(ctx context.Context, ref provider.KeyRef, ver uint32, wrapped, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.checkRef(ref); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, v, err := p.version(ref, ver)
	if err != nil {
		return nil, err
	}
	a, err := v.cipher(k.alg)
	if err != nil {
		return nil, err
	}
	dek, err := a.Open(nil, nil, wrapped, aad)
	if err != nil {
		return nil, provider.ErrUnwrapFailed
	}
	return dek, nil
}

// Destroy implements [provider.Provider]. The material is removed from the
// keyring file; it survives only in backups taken before.
func (p *Provider) Destroy(ctx context.Context, ref provider.KeyRef, ver uint32) error {
	if err := p.checkRef(ref); err != nil {
		return err
	}
	return p.mutate(ctx, func(st *state) error {
		k, ok := st.keys[ref.ID]
		if !ok {
			return provider.ErrKeyNotFound
		}
		v, ok := k.versions[ver]
		if !ok {
			return provider.ErrVersionNotFound
		}
		clear(v.material)
		v.material, v.destroyed, v.aead = nil, true, nil
		return nil
	})
}

// RotateRootKey re-encrypts the keyring under a new root key in one atomic
// write. Until the write completes the old root key still opens the keyring;
// afterwards only the new one does, so the caller keeps the old key until it
// has confirmed the new one is stored.
func (p *Provider) RotateRootKey(ctx context.Context, next RootKeySource) error {
	if next == nil {
		return errors.New("local: a new root key source is required")
	}
	if besideKeyring(next, p.path) {
		return ErrRootKeyBesideKeyring
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := next.RootKey(ctx)
	if err != nil {
		return err
	}
	defer clear(root)
	enc, id, err := deriveKeys(root)
	if err != nil {
		return err
	}
	defer clear(enc)
	newAEAD, err := algorithm.New(keyringAlgorithm, enc)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	unlock, err := lockFile(ctx, p.lockPath)
	if err != nil {
		return err
	}
	defer unlock()

	st, gen, err := p.read()
	if err != nil {
		return err
	}
	payload, err := st.marshal()
	if err != nil {
		st.wipe()
		return fmt.Errorf("local: encoding the keyring: %w", err)
	}
	defer clear(payload)
	nextGen, err := p.nextGeneration(gen)
	if err != nil {
		st.wipe()
		return err
	}
	data := seal(newAEAD, header{rootKeyID: id, generation: nextGen}, payload)
	if err := atomicWrite(p.path, data, p.hook); err != nil {
		st.wipe()
		return err
	}
	if err := p.notePersisted(nextGen); err != nil {
		st.wipe()
		return err
	}
	p.st.wipe()
	p.st, p.gen = st, nextGen
	p.aead, p.rootID, p.root = newAEAD, id, next
	return nil
}

// atomicWrite replaces path with data so that a crash leaves the old file or
// the new one: write a temporary file in the same directory, flush it, rename
// it over the target, then flush the directory.
//
// hook, when set, is called at each stage so tests can stop there. A returned
// errSimulatedCrash leaves everything as it was at that moment, as a killed
// process would.
func atomicWrite(path string, data []byte, hook func(string) error) error {
	stage := func(name string) error {
		if hook == nil {
			return nil
		}
		return hook(name)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+tempMarker+"*")
	if err != nil {
		return fmt.Errorf("local: creating a temporary keyring: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func(cause error) error {
		if !errors.Is(cause, errSimulatedCrash) {
			_ = tmp.Close()        //nolint:errcheck // already failing; the first error is the one to report
			_ = os.Remove(tmpName) //nolint:errcheck // best-effort removal of a partial file
		}
		return cause
	}

	if err := stage("temp-created"); err != nil {
		return cleanup(err)
	}
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		return cleanup(fmt.Errorf("local: %w", err))
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("local: writing the keyring: %w", err))
	}
	if err := stage("temp-written"); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("local: flushing the keyring: %w", err))
	}
	if err := stage("temp-synced"); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		return cleanup(fmt.Errorf("local: %w", err))
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName) //nolint:errcheck // best-effort removal of the partial file
		return fmt.Errorf("local: replacing the keyring: %w", err)
	}
	if err := stage("renamed"); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("local: flushing the keyring directory: %w", err)
	}
	return stage("dir-synced")
}

// tempMarker separates a keyring's name from the suffix of its temporary files.
const tempMarker = ".tmp-"

// errSimulatedCrash is returned by a test hook to stop a write as a killed
// process would, leaving files exactly as they are.
var errSimulatedCrash = errors.New("local: simulated crash")

// removeStaleTemps deletes temporary files left by a write that did not finish.
// The caller holds the file lock, so none belongs to a live writer.
func removeStaleTemps(path string) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), base+tempMarker) {
			_ = os.Remove(filepath.Join(dir, e.Name())) //nolint:errcheck // best-effort cleanup of an abandoned temporary file
		}
	}
}
