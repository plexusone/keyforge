package keyforge

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/metrics"
	"github.com/plexusone/keyforge/provider"
)

// Defaults and limits.
const (
	// DefaultCacheTTL is how long an unwrapped data key stays cached.
	DefaultCacheTTL = 5 * time.Minute
	// DefaultCacheSize is the most data keys held unwrapped at once.
	DefaultCacheSize = 1024
	// DefaultEncryptionCap is the most encryptions made under one data key
	// before it is replaced by a new epoch. It stays well below the NIST limit
	// of 2^32 invocations for random 96-bit nonces.
	DefaultEncryptionCap uint64 = 1 << 30
	// MaxEncryptionCap is the largest cap a configuration may set.
	MaxEncryptionCap uint64 = 1 << 31
	// DefaultReserveBlock is how many encryptions a process reserves from the
	// registry at a time.
	DefaultReserveBlock uint64 = 1 << 16
	// DefaultMaxAge is how long a data key epoch is used for writes before a
	// new epoch is created.
	DefaultMaxAge = 90 * 24 * time.Hour
)

// maxAdvanceAttempts bounds how often one write retries after the epoch moved.
// Each retry means another writer used up the key's capacity first, so the cap
// should be far larger than the block size times the number of writers; with a
// sensible cap a write needs one attempt, or two when it crosses an epoch.
const maxAdvanceAttempts = 8

// Clock supplies the time. Tests inject one so cache expiry is deterministic.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// PurposeConfig is the configuration of one purpose.
type PurposeConfig struct {
	// Algorithms narrows the algorithms used for this purpose. See
	// [algorithm.Selection].
	Algorithms algorithm.Selection
	// EncryptionCap overrides [Options.EncryptionCap] for this purpose. Zero
	// uses the client's.
	EncryptionCap uint64
	// MaxAge overrides [Options.MaxAge] for this purpose. Zero uses the
	// client's.
	MaxAge time.Duration
	// PerSubject gives each subject (a user, a tenant) data key epochs of its
	// own, so that destroying one subject's keys makes that subject's data
	// unrecoverable wherever it was copied. A per-subject purpose is written
	// with [Client.EncryptFor]; any other purpose is written with
	// [Client.Encrypt].
	PerSubject bool
}

// Options configures a [Client].
type Options struct {
	// Store is the registry. Required.
	Store Store
	// Providers are the KEK holders, matched to a key by [provider.Provider]
	// Name. At least one is required.
	Providers []provider.Provider
	// Selector chooses algorithms and enforces the profile. The zero value
	// uses [algorithm.DefaultProfile].
	Selector *algorithm.Selector
	// Purposes lists the purposes this client may use. Anything else fails
	// with [ErrUnknownPurpose].
	Purposes map[Purpose]PurposeConfig
	// Clock defaults to the system clock.
	Clock Clock
	// Entropy supplies data keys and identifiers, and defaults to
	// crypto/rand. Tests inject a deterministic reader. Nonces come from the
	// AEAD's own generator and are not drawn from it.
	Entropy io.Reader
	// CacheTTL and CacheSize bound the unwrapped-key cache.
	CacheTTL  time.Duration
	CacheSize int
	// EncryptionCap and ReserveBlock set the per-key cap and the size of the
	// blocks reserved from the registry. Zero uses the defaults.
	EncryptionCap uint64
	ReserveBlock  uint64
	// MaxAge is how long a data key epoch is used for writes. Zero means
	// [DefaultMaxAge].
	MaxAge time.Duration
	// Metrics receives operation rates, failures and cache behavior. The
	// default discards them.
	Metrics metrics.Metrics
}

// Info describes how an envelope was protected, as reported by Decrypt.
type Info struct {
	Mode    envelope.Mode
	Subject string
	// Epoch is the data key's epoch (reference mode).
	Epoch uint32
	// KEKVersion is the KEK version that wraps the key (inline mode).
	KEKVersion uint32
	// Stale reports that the envelope was written under a data key that is no
	// longer current, or an inline key under an older KEK version, so the
	// caller can rewrite it on its next write. It is advisory: it is computed
	// from a cached view, and a registry outage can hide it.
	Stale bool
}

// Client encrypts and decrypts under named purposes. It is safe for
// concurrent use.
type Client struct {
	store     Store
	providers map[string]provider.Provider
	sel       *algorithm.Selector
	purposes  map[Purpose]PurposeConfig
	clock     Clock
	entropy   io.Reader
	encCap    uint64
	block     uint64
	maxAge    time.Duration
	metrics   metrics.Metrics

	handles *lru[envelope.ID, *dekHandle] // unwrapped data keys by identifier
	inline  *lru[[32]byte, *dekHandle]    // unwrapped inline data keys by digest
	current *lru[currentKey, DEKRecord]   // current data key per purpose and subject
	active  *lru[Purpose, KEKVersion]     // active KEK version per purpose
	keks    *lru[envelope.ID, provider.KeyRef]
	usable  *lru[kekVersion, bool] // whether a KEK version may be unwrapped

	entropyMu sync.Mutex
}

type kekVersion struct {
	id      envelope.ID
	version uint32
}

type currentKey struct {
	purpose Purpose
	subject string
}

// dekHandle is a data key ready for use: its record, the AEAD built from the
// unwrapped key, and the encryptions left in the block this process reserved.
type dekHandle struct {
	rec  DEKRecord
	aead cipher.AEAD

	mu     sync.Mutex
	remain uint64
}

// New returns a client. It validates every purpose against the selector's
// profile, so a configuration that widens it fails here and not on first use.
func New(opts Options) (*Client, error) {
	if opts.Store == nil {
		return nil, errors.New("keyforge: Options.Store is required")
	}
	if len(opts.Providers) == 0 {
		return nil, errors.New("keyforge: at least one provider is required")
	}
	providers := make(map[string]provider.Provider, len(opts.Providers))
	for _, p := range opts.Providers {
		name := p.Name()
		if _, dup := providers[name]; dup {
			return nil, fmt.Errorf("keyforge: two providers are named %q", name)
		}
		providers[name] = p
	}

	sel := opts.Selector
	if sel == nil {
		var err error
		if sel, err = algorithm.NewSelector(algorithm.Config{}); err != nil {
			return nil, err
		}
	}

	capN, block := opts.EncryptionCap, opts.ReserveBlock
	if capN == 0 {
		capN = DefaultEncryptionCap
	}
	if block == 0 {
		block = DefaultReserveBlock
	}
	if capN > MaxEncryptionCap {
		return nil, fmt.Errorf("keyforge: encryption cap %d exceeds the maximum %d", capN, MaxEncryptionCap)
	}
	maxAge := opts.MaxAge
	if maxAge < 0 {
		return nil, fmt.Errorf("keyforge: maximum data key age %s is negative", maxAge)
	}
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}

	selections := make(map[string]algorithm.Selection, len(opts.Purposes))
	purposes := make(map[Purpose]PurposeConfig, len(opts.Purposes))
	for p, cfg := range opts.Purposes {
		if err := p.Validate(); err != nil {
			return nil, err
		}
		if cfg.EncryptionCap > MaxEncryptionCap {
			return nil, fmt.Errorf("keyforge: purpose %q: encryption cap %d exceeds the maximum %d", p, cfg.EncryptionCap, MaxEncryptionCap)
		}
		if cfg.MaxAge < 0 {
			return nil, fmt.Errorf("keyforge: purpose %q: maximum data key age %s is negative", p, cfg.MaxAge)
		}
		selections[string(p)] = cfg.Algorithms
		purposes[p] = cfg
	}
	if err := sel.Validate(selections); err != nil {
		return nil, err
	}

	clock := opts.Clock
	if clock == nil {
		clock = systemClock{}
	}
	entropy := opts.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	ttl, size := opts.CacheTTL, opts.CacheSize
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	if size <= 0 {
		size = DefaultCacheSize
	}
	now := clock.Now

	return &Client{
		store: opts.Store, providers: providers, sel: sel, purposes: purposes,
		clock: clock, entropy: entropy, encCap: capN, block: block, maxAge: maxAge, metrics: opts.Metrics,
		handles: newLRU[envelope.ID, *dekHandle](size, ttl, now),
		inline:  newLRU[[32]byte, *dekHandle](size, ttl, now),
		current: newLRU[currentKey, DEKRecord](size, ttl, now),
		active:  newLRU[Purpose, KEKVersion](size, ttl, now),
		keks:    newLRU[envelope.ID, provider.KeyRef](size, ttl, now),
		usable:  newLRU[kekVersion, bool](size, ttl, now),
	}, nil
}

// outcomeOf classifies an error into the small fixed set of outcomes a metric
// may carry. It never returns the error's text: that would be unbounded.
func outcomeOf(err error) string {
	switch {
	case err == nil:
		return metrics.OutcomeOK
	case errors.Is(err, ErrKeyUnavailable):
		return metrics.OutcomeUnavailable
	case errors.Is(err, ErrKeyUnusable):
		return metrics.OutcomeUnusable
	case errors.Is(err, envelope.ErrAuthentication):
		return metrics.OutcomeAuthentication
	case errors.Is(err, ErrSubjectShredded):
		return metrics.OutcomeShredded
	case errors.Is(err, algorithm.ErrNotPermitted), errors.Is(err, algorithm.ErrNoPermitted):
		return metrics.OutcomeRefused
	case errors.Is(err, ErrUnknownPurpose), errors.Is(err, ErrPurposeMismatch), errors.Is(err, ErrInvalidEnvelope),
		errors.Is(err, ErrSubjectRequired), errors.Is(err, ErrSubjectNotAllowed), errors.Is(err, ErrInvalidSubject):
		return metrics.OutcomeInvalid
	default:
		return metrics.OutcomeError
	}
}

// purposeLabel returns the purpose as a metric label, or "unknown" for one the
// client is not configured for, so a caller cannot make labels unbounded.
func (c *Client) purposeLabel(p Purpose) string {
	if _, ok := c.purposes[p]; ok {
		return string(p)
	}
	return "unknown"
}

// begin starts timing an operation. The result is passed to measure.
func (c *Client) begin() time.Time {
	if c.metrics == nil {
		return time.Time{}
	}
	return c.clock.Now()
}

// measure reports one operation: its count by outcome and its duration.
func (c *Client) measure(op string, purpose Purpose, start time.Time, err *error) {
	if c.metrics == nil {
		return
	}
	p := metrics.L("purpose", c.purposeLabel(purpose))
	c.metrics.Count(metrics.Operations, 1, metrics.L("op", op), p, metrics.L("outcome", outcomeOf(*err)))
	c.metrics.Observe(metrics.OperationDuration, c.clock.Now().Sub(start), metrics.L("op", op), p)
}

// cacheLookup reports a cache hit or miss.
func (c *Client) cacheLookup(cache string, hit bool) {
	if c.metrics == nil {
		return
	}
	result := "miss"
	if hit {
		result = "hit"
	}
	c.metrics.Count(metrics.CacheLookups, 1, metrics.L("cache", cache), metrics.L("result", result))
}

// Purge drops every cached key and view. Use it when a key must stop being
// usable at once, for example after destroying it; otherwise a cached key can
// outlive its destruction by up to the cache TTL.
func (c *Client) Purge() {
	c.handles.clear()
	c.inline.clear()
	c.current.clear()
	c.active.clear()
	c.keks.clear()
	c.usable.clear()
}

func (c *Client) purposeConfig(p Purpose) (PurposeConfig, error) {
	cfg, ok := c.purposes[p]
	if !ok {
		return PurposeConfig{}, fmt.Errorf("%w: %q", ErrUnknownPurpose, string(p))
	}
	return cfg, nil
}

// ageLimit returns the maximum age of a data key epoch in force for cfg.
func (c *Client) ageLimit(cfg PurposeConfig) time.Duration {
	if cfg.MaxAge != 0 {
		return cfg.MaxAge
	}
	return c.maxAge
}

// limits returns the cap and the block size in force for cfg. A block is never
// larger than the cap.
func (c *Client) limits(cfg PurposeConfig) (capN, block uint64) {
	capN = c.encCap
	if cfg.EncryptionCap != 0 {
		capN = cfg.EncryptionCap
	}
	return capN, min(c.block, capN)
}

// Encrypt encrypts plaintext under purpose in reference mode: the envelope
// names the data key, and rotating the KEK does not touch it. context is bound
// into the ciphertext, so it cannot be moved to another record.
//
// A per-subject purpose is written with [Client.EncryptFor]; Encrypt on one is
// [ErrSubjectRequired].
func (c *Client) Encrypt(ctx context.Context, purpose Purpose, plaintext, context []byte) (e *Envelope, err error) {
	defer c.measure("encrypt", purpose, c.begin(), &err)
	cfg, err := c.purposeConfig(purpose)
	if err != nil {
		return nil, err
	}
	if cfg.PerSubject {
		return nil, fmt.Errorf("%w: %q", ErrSubjectRequired, string(purpose))
	}
	return c.encrypt(ctx, purpose, "", plaintext, context)
}

// MaxSubjectLen is the longest subject in bytes.
const MaxSubjectLen = 255

// ValidateSubject checks a subject: 1 to [MaxSubjectLen] bytes of valid UTF-8
// with no control characters, so it is unambiguous in logs and in the additional
// data a data key is wrapped with.
func ValidateSubject(subject string) error {
	if subject == "" || len(subject) > MaxSubjectLen {
		return fmt.Errorf("%w: length %d, want 1 to %d bytes", ErrInvalidSubject, len(subject), MaxSubjectLen)
	}
	if !utf8.ValidString(subject) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidSubject)
	}
	for _, r := range subject {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: contains a control character", ErrInvalidSubject)
		}
	}
	return nil
}

// EncryptFor encrypts plaintext under a per-subject purpose with the subject's
// own data key, creating the subject's first epoch if it has none. The subject
// is not part of the envelope: the envelope names its data key, and the registry
// knows whose key that is.
//
// A subject that has been shredded is [ErrSubjectShredded]. A purpose that is
// not per-subject is [ErrSubjectNotAllowed].
func (c *Client) EncryptFor(ctx context.Context, purpose Purpose, subject string, plaintext, context []byte) (e *Envelope, err error) {
	defer c.measure("encrypt_for", purpose, c.begin(), &err)
	cfg, err := c.purposeConfig(purpose)
	if err != nil {
		return nil, err
	}
	if !cfg.PerSubject {
		return nil, fmt.Errorf("%w: %q", ErrSubjectNotAllowed, string(purpose))
	}
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}
	return c.encrypt(ctx, purpose, subject, plaintext, context)
}

func (c *Client) encrypt(ctx context.Context, purpose Purpose, subject string, plaintext, bound []byte) (*Envelope, error) {
	cfg, err := c.purposeConfig(purpose)
	if err != nil {
		return nil, err
	}
	capN, block := c.limits(cfg)

	for range maxAdvanceAttempts {
		h, err := c.currentHandle(ctx, purpose, subject, cfg)
		if err != nil {
			return nil, err
		}
		if h.rec.State != DEKActive {
			// The current key was marked compromised or destroyed. Writing
			// moves to a new epoch; the old key stays readable as policy
			// allows, so what it protects can be re-encrypted.
			if _, err := c.advance(ctx, purpose, subject, cfg, h.rec.Epoch, "not_active"); err != nil {
				return nil, err
			}
			continue
		}
		// An epoch that has reached its age is replaced even though it still
		// has capacity: a data key has a lifetime as well as a volume. The
		// record's creation time comes from the registry, so every replica
		// agrees on it, and the compare-and-set makes one of them the winner.
		if created := h.rec.CreatedAt; !created.IsZero() && !c.clock.Now().Before(created.Add(c.ageLimit(cfg))) {
			if _, err := c.advance(ctx, purpose, subject, cfg, h.rec.Epoch, "age"); err != nil {
				return nil, err
			}
			continue
		}
		if err := c.sel.CheckWrite(h.rec.Algorithm, cfg.Algorithms); err != nil {
			return nil, err
		}
		ok, err := h.take(ctx, c.store, capN, block)
		if err != nil {
			return nil, fmt.Errorf("%w: reserving encryptions: %w", ErrKeyUnavailable, err)
		}
		if !ok {
			// The key has no capacity left, or is no longer current.
			if _, err := c.advance(ctx, purpose, subject, cfg, h.rec.Epoch, "cap"); err != nil {
				return nil, err
			}
			continue
		}
		hdr := envelope.Header{
			Mode:      envelope.ModeReference,
			Algorithm: h.rec.Algorithm,
			Purpose:   string(purpose),
			DEKID:     h.rec.ID,
		}
		return envelope.Seal(h.aead, hdr, plaintext, bound)
	}
	return nil, fmt.Errorf("%w: no data key with capacity after %d attempts", ErrKeyUnavailable, maxAdvanceAttempts)
}

// take reserves one encryption on the key, asking the registry for a new block
// only when the block this process holds is spent. It reports false when the
// key has no capacity left.
func (h *dekHandle) take(ctx context.Context, store Store, capN, block uint64) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.remain > 0 {
		h.remain--
		return true, nil
	}
	granted, err := store.ReserveEncryptions(ctx, h.rec.ID, block, capN)
	if err != nil {
		return false, err
	}
	if granted == 0 {
		return false, nil
	}
	h.remain = granted - 1
	return true, nil
}

// EncryptInline encrypts plaintext in inline mode: a fresh data key per
// object, wrapped under the purpose's active KEK and carried in the envelope.
// It suits standalone objects such as exports and snapshots.
//
// Unlike reference mode it contacts the provider once per object, to wrap the
// key, so it is not for a hot path against a managed key service.
func (c *Client) EncryptInline(ctx context.Context, purpose Purpose, plaintext, bound []byte) (e *Envelope, err error) {
	defer c.measure("encrypt_inline", purpose, c.begin(), &err)
	cfg, err := c.purposeConfig(purpose)
	if err != nil {
		return nil, err
	}
	kv, err := c.activeKEK(ctx, purpose)
	if err != nil {
		return nil, err
	}
	prov, err := c.providerFor(kv.Ref)
	if err != nil {
		return nil, err
	}
	alg, err := c.sel.Select(cfg.Algorithms)
	if err != nil {
		return nil, err
	}

	dek := make([]byte, alg.KeySize())
	defer clear(dek)
	if err := c.readEntropy(dek); err != nil {
		return nil, err
	}
	wrapped, err := prov.Wrap(ctx, kv.Ref, kv.Version, dek, InlineWrapAAD(purpose, kv.Ref.ID))
	if err != nil {
		return nil, fmt.Errorf("%w: wrapping: %w", ErrKeyUnavailable, err)
	}
	aead, err := algorithm.New(alg, dek)
	if err != nil {
		return nil, err
	}
	hdr := envelope.Header{
		Mode:       envelope.ModeInline,
		Algorithm:  alg,
		Purpose:    string(purpose),
		KEKID:      kv.Ref.ID,
		KEKVersion: kv.Version,
		Wrapped:    wrapped,
	}
	e, err = envelope.Seal(aead, hdr, plaintext, bound)
	if err != nil {
		return nil, err
	}
	// The same process reading its own object back needs no provider call.
	c.inline.put(inlineDigest(kv.Ref.ID, kv.Version, wrapped), &dekHandle{
		rec:  DEKRecord{Purpose: purpose, Algorithm: alg, KEKID: kv.Ref.ID, KEKVersion: kv.Version},
		aead: aead,
	})
	return e, nil
}

// Decrypt authenticates and decrypts an envelope under purpose, with the same
// context that was given to Encrypt. A wrong key, a changed header or context
// and a modified ciphertext all fail with [envelope.ErrAuthentication].
//
// Info.Stale reports an envelope that is not under the current key, so the
// caller can rewrite it on its next write. No rewrite is needed for
// correctness.
func (c *Client) Decrypt(ctx context.Context, purpose Purpose, e *Envelope, bound []byte) (pt []byte, info Info, err error) {
	defer c.measure("decrypt", purpose, c.begin(), &err)
	cfg, err := c.purposeConfig(purpose)
	if err != nil {
		return nil, Info{}, err
	}
	if e == nil {
		return nil, Info{}, fmt.Errorf("%w: nil envelope", ErrInvalidEnvelope)
	}
	if e.Purpose != string(purpose) {
		return nil, Info{}, fmt.Errorf("%w: envelope is for %q, asked for %q", ErrPurposeMismatch, e.Purpose, string(purpose))
	}
	// Reads follow the profile, so a purpose's write list does not strand data.
	if err := c.sel.Check(e.Algorithm, cfg.Algorithms); err != nil {
		return nil, Info{}, err
	}

	switch e.Mode {
	case envelope.ModeReference:
		return c.decryptReference(ctx, purpose, e, bound)
	case envelope.ModeInline:
		return c.decryptInline(ctx, purpose, e, bound)
	default:
		return nil, Info{}, &envelope.ValueError{Kind: envelope.ErrUnknownMode, Value: uint8(e.Mode)}
	}
}

func (c *Client) decryptReference(ctx context.Context, purpose Purpose, e *Envelope, bound []byte) ([]byte, Info, error) {
	h, err := c.handleByID(ctx, e.DEKID)
	if err != nil {
		return nil, Info{}, err
	}
	if h.rec.Purpose != purpose || h.rec.Algorithm != e.Algorithm {
		return nil, Info{}, fmt.Errorf("%w: data key %s is for %q and %s", ErrInvalidEnvelope, e.DEKID, string(h.rec.Purpose), h.rec.Algorithm)
	}
	pt, err := e.Open(h.aead, bound)
	if err != nil {
		return nil, Info{}, err
	}
	info := Info{Mode: envelope.ModeReference, Subject: h.rec.Subject, Epoch: h.rec.Epoch}
	if cur, ok := c.currentView(ctx, purpose, h.rec.Subject); ok {
		info.Stale = h.rec.Epoch < cur.Epoch
	}
	return pt, info, nil
}

func (c *Client) decryptInline(ctx context.Context, purpose Purpose, e *Envelope, bound []byte) ([]byte, Info, error) {
	digest := inlineDigest(e.KEKID, e.KEKVersion, e.Wrapped)
	h, ok := c.inline.get(digest)
	c.cacheLookup("inline", ok)
	if !ok {
		if err := c.requireUsable(ctx, e.KEKID, e.KEKVersion); err != nil {
			return nil, Info{}, err
		}
		ref, err := c.kekRef(ctx, e.KEKID)
		if err != nil {
			return nil, Info{}, err
		}
		prov, err := c.providerFor(ref)
		if err != nil {
			return nil, Info{}, err
		}
		dek, err := prov.Unwrap(ctx, ref, e.KEKVersion, e.Wrapped, InlineWrapAAD(purpose, e.KEKID))
		if err != nil {
			return nil, Info{}, fmt.Errorf("%w: unwrapping: %w", ErrKeyUnavailable, err)
		}
		aead, err := algorithm.New(e.Algorithm, dek)
		clear(dek)
		if err != nil {
			return nil, Info{}, err
		}
		h = &dekHandle{rec: DEKRecord{Purpose: purpose, Algorithm: e.Algorithm, KEKID: e.KEKID, KEKVersion: e.KEKVersion}, aead: aead}
		c.inline.put(digest, h)
	}
	pt, err := e.Open(h.aead, bound)
	if err != nil {
		return nil, Info{}, err
	}
	info := Info{Mode: envelope.ModeInline, KEKVersion: e.KEKVersion}
	if kv, err := c.activeKEK(ctx, purpose); err == nil && kv.Ref.ID == e.KEKID {
		info.Stale = e.KEKVersion < kv.Version
	}
	return pt, info, nil
}

// Reencrypt decrypts an envelope and encrypts it again under the current key,
// in the same mode, so a caller can bring old data up to date. It always
// produces a new envelope; use the Stale report from Decrypt to skip the ones
// that are already current.
func (c *Client) Reencrypt(ctx context.Context, purpose Purpose, e *Envelope, bound []byte) (_ *Envelope, err error) {
	defer c.measure("reencrypt", purpose, c.begin(), &err)
	pt, info, err := c.Decrypt(ctx, purpose, e, bound)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	if info.Mode == envelope.ModeInline {
		return c.EncryptInline(ctx, purpose, pt, bound)
	}
	return c.encrypt(ctx, purpose, info.Subject, pt, bound)
}

// currentHandle returns the data key new writes use, creating the first epoch
// if there is none. The current record is cached, so a write makes no registry
// call until the cache entry expires or the key's block is spent.
func (c *Client) currentHandle(ctx context.Context, purpose Purpose, subject string, cfg PurposeConfig) (*dekHandle, error) {
	key := currentKey{purpose, subject}
	rec, ok := c.current.get(key)
	c.cacheLookup("current", ok)
	if !ok {
		var err error
		rec, err = c.store.CurrentDEK(ctx, purpose, subject)
		switch {
		case errors.Is(err, ErrDEKNotFound):
			if rec, err = c.advance(ctx, purpose, subject, cfg, 0, "first"); err != nil {
				return nil, err
			}
		case err != nil:
			return nil, fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
		default:
			c.current.put(key, rec)
		}
	}
	return c.handleFor(ctx, rec)
}

// currentView returns the cached current record for a purpose and subject,
// consulting the registry once when the cache has expired. It reports whether
// a record is known; an outage yields false and never fails a read.
func (c *Client) currentView(ctx context.Context, purpose Purpose, subject string) (DEKRecord, bool) {
	key := currentKey{purpose, subject}
	if rec, ok := c.current.get(key); ok {
		return rec, true
	}
	rec, err := c.store.CurrentDEK(ctx, purpose, subject)
	if err != nil {
		return DEKRecord{}, false
	}
	c.current.put(key, rec)
	return rec, true
}

// advance creates the next epoch for a purpose and subject, from the epoch the
// caller saw, and returns the record that is current afterwards, which is
// another replica's if it won the race.
func (c *Client) advance(ctx context.Context, purpose Purpose, subject string, cfg PurposeConfig, from uint32, reason string) (DEKRecord, error) {
	kv, err := c.activeKEK(ctx, purpose)
	if err != nil {
		return DEKRecord{}, err
	}
	prov, err := c.providerFor(kv.Ref)
	if err != nil {
		return DEKRecord{}, err
	}
	alg, err := c.sel.Select(cfg.Algorithms)
	if err != nil {
		return DEKRecord{}, err
	}

	dek := make([]byte, alg.KeySize())
	defer clear(dek)
	var id envelope.ID
	if err := c.readEntropy(dek); err != nil {
		return DEKRecord{}, err
	}
	if err := c.readEntropy(id[:]); err != nil {
		return DEKRecord{}, err
	}
	if id.IsZero() {
		return DEKRecord{}, fmt.Errorf("%w: entropy source returned a zero identifier", ErrKeyUnavailable)
	}

	rec := DEKRecord{
		ID: id, Purpose: purpose, Subject: subject, Epoch: from + 1,
		Algorithm: alg, KEKID: kv.Ref.ID, KEKVersion: kv.Version,
		State: DEKActive, CreatedAt: c.clock.Now(),
	}
	rec.Wrapped, err = prov.Wrap(ctx, kv.Ref, kv.Version, dek, DEKWrapAAD(purpose, subject, id, kv.Ref.ID))
	if err != nil {
		return DEKRecord{}, fmt.Errorf("%w: wrapping a new data key: %w", ErrKeyUnavailable, err)
	}
	aead, err := algorithm.New(alg, dek)
	if err != nil {
		return DEKRecord{}, err
	}

	winner, err := c.store.AdvanceDEK(ctx, purpose, subject, from, rec)
	if errors.Is(err, ErrSubjectShredded) {
		return DEKRecord{}, fmt.Errorf("%w: %q for %q", err, string(purpose), subject)
	}
	if err != nil {
		return DEKRecord{}, fmt.Errorf("%w: advancing the data key: %w", ErrKeyUnavailable, err)
	}
	if winner.ID == rec.ID {
		c.handles.put(rec.ID, &dekHandle{rec: winner, aead: aead})
		if c.metrics != nil {
			c.metrics.Count(metrics.EpochAdvances, 1, metrics.L("purpose", c.purposeLabel(purpose)), metrics.L("reason", reason))
		}
	}
	c.current.put(currentKey{purpose, subject}, winner)
	return winner, nil
}

// AdvanceEpoch creates the next data key epoch for a purpose and subject now,
// rather than waiting for the volume or age trigger, and returns the record
// that is current afterwards. The previous current key becomes decrypt-only.
// It is the first step of replacing an exposed key: writes move to the new
// epoch at once, and the old one stays readable so what it protects can be
// re-encrypted.
func (c *Client) AdvanceEpoch(ctx context.Context, purpose Purpose, subject string) (DEKRecord, error) {
	cfg, err := c.purposeConfig(purpose)
	if err != nil {
		return DEKRecord{}, err
	}
	var from uint32
	cur, err := c.store.CurrentDEK(ctx, purpose, subject)
	switch {
	case err == nil:
		from = cur.Epoch
	case errors.Is(err, ErrDEKNotFound):
	default:
		return DEKRecord{}, fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	return c.advance(ctx, purpose, subject, cfg, from, "manual")
}

// handleFor returns the usable handle for a record, unwrapping its key through
// the provider only when it is not cached.
func (c *Client) handleFor(ctx context.Context, rec DEKRecord) (*dekHandle, error) {
	h, ok := c.handles.get(rec.ID)
	c.cacheLookup("dek", ok)
	if ok {
		return h, nil
	}
	if rec.State == DEKDestroyed {
		return nil, fmt.Errorf("%w: data key %s is %s", ErrKeyUnusable, rec.ID, rec.State)
	}
	if err := c.requireUsable(ctx, rec.KEKID, rec.KEKVersion); err != nil {
		return nil, err
	}
	ref, err := c.kekRef(ctx, rec.KEKID)
	if err != nil {
		return nil, err
	}
	prov, err := c.providerFor(ref)
	if err != nil {
		return nil, err
	}
	dek, err := prov.Unwrap(ctx, ref, rec.KEKVersion, rec.Wrapped, DEKWrapAAD(rec.Purpose, rec.Subject, rec.ID, rec.KEKID))
	if err != nil {
		return nil, fmt.Errorf("%w: unwrapping data key %s: %w", ErrKeyUnavailable, rec.ID, err)
	}
	aead, err := algorithm.New(rec.Algorithm, dek)
	clear(dek)
	if err != nil {
		return nil, err
	}
	h = &dekHandle{rec: rec, aead: aead}
	c.handles.put(rec.ID, h)
	return h, nil
}

// handleByID returns the handle for a data key named by an envelope.
func (c *Client) handleByID(ctx context.Context, id envelope.ID) (*dekHandle, error) {
	h, ok := c.handles.get(id)
	c.cacheLookup("dek", ok)
	if ok {
		return h, nil
	}
	rec, err := c.store.GetDEK(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w: data key %s: %w", ErrKeyUnavailable, id, err)
	}
	if rec.State == DEKDestroyed {
		return nil, fmt.Errorf("%w: data key %s is %s", ErrKeyUnusable, id, rec.State)
	}
	return c.handleFor(ctx, rec)
}

func (c *Client) activeKEK(ctx context.Context, purpose Purpose) (KEKVersion, error) {
	if kv, ok := c.active.get(purpose); ok {
		return kv, nil
	}
	kv, err := c.store.ActiveKEK(ctx, purpose)
	if err != nil {
		return KEKVersion{}, fmt.Errorf("%w: active key-encryption key for %q: %w", ErrKeyUnavailable, string(purpose), err)
	}
	c.active.put(purpose, kv)
	return kv, nil
}

func (c *Client) kekRef(ctx context.Context, id envelope.ID) (provider.KeyRef, error) {
	if ref, ok := c.keks.get(id); ok {
		return ref, nil
	}
	ref, err := c.store.KEK(ctx, id)
	if err != nil {
		return provider.KeyRef{}, fmt.Errorf("%w: key-encryption key %s: %w", ErrKeyUnavailable, id, err)
	}
	c.keks.put(id, ref)
	return ref, nil
}

// requireUsable fails with [ErrKeyUnusable] for a KEK version the registry has
// retired, destroyed or never activated, even if the provider still holds its
// material. The answer is cached, so it costs a registry call only when a key
// is first unwrapped.
func (c *Client) requireUsable(ctx context.Context, id envelope.ID, version uint32) error {
	k := kekVersion{id, version}
	ok, cached := c.usable.get(k)
	if !cached {
		var err error
		ok, err = c.store.KEKVersionUsable(ctx, id, version)
		if err != nil {
			return fmt.Errorf("%w: state of key-encryption key %s version %d: %w", ErrKeyUnavailable, id, version, err)
		}
		c.usable.put(k, ok)
	}
	if !ok {
		return fmt.Errorf("%w: key-encryption key %s version %d is retired, destroyed or not yet active", ErrKeyUnusable, id, version)
	}
	return nil
}

func (c *Client) providerFor(ref provider.KeyRef) (provider.Provider, error) {
	p, ok := c.providers[ref.Provider]
	if !ok {
		return nil, fmt.Errorf("%w: no provider named %q", ErrKeyUnavailable, ref.Provider)
	}
	return p, nil
}

// readEntropy fills b from the entropy source, serialized so an injected
// reader need not be safe for concurrent use.
func (c *Client) readEntropy(b []byte) error {
	c.entropyMu.Lock()
	defer c.entropyMu.Unlock()
	if _, err := io.ReadFull(c.entropy, b); err != nil {
		return fmt.Errorf("%w: entropy source: %w", ErrKeyUnavailable, err)
	}
	return nil
}

// DEKWrapAAD is the additional data a data key is wrapped with. It binds the
// wrapped key to its purpose, subject, and its own and its KEK's identity, so a
// wrapped key cannot be moved to another record. The layout is part of the
// stored format: changing it makes existing wrapped keys unreadable.
//
// The client uses it when it creates a data key, and the re-wrap job uses it to
// move a key to a new KEK version, so both must produce the same bytes.
func DEKWrapAAD(purpose Purpose, subject string, dekID, kekID envelope.ID) []byte {
	b := append([]byte(nil), "keyforge/dek/v1\x00"...)
	b = appendLengthPrefixed(b, string(purpose))
	b = appendLengthPrefixed(b, subject)
	b = append(b, dekID[:]...)
	return append(b, kekID[:]...)
}

// InlineWrapAAD is the additional data an inline data key is wrapped with. Like
// [DEKWrapAAD] it is stored format.
func InlineWrapAAD(purpose Purpose, kekID envelope.ID) []byte {
	b := append([]byte(nil), "keyforge/inline/v1\x00"...)
	b = appendLengthPrefixed(b, string(purpose))
	return append(b, kekID[:]...)
}

func appendLengthPrefixed(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // G115: a purpose is at most 255 bytes and a subject is bounded by the registry
	return append(b, s...)
}

// inlineDigest keys the cache of unwrapped inline keys. SHA-256 is used here
// as an identifier and not to protect anything.
func inlineDigest(kekID envelope.ID, version uint32, wrapped []byte) [32]byte {
	h := sha256.New()
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], version)
	h.Write(kekID[:])
	h.Write(v[:])
	h.Write(wrapped)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
