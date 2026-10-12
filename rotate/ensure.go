package rotate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/registry"
)

// EnsureKEK makes sure a purpose has an active KEK, creating it at the named
// provider when it has none. It is how a deployment starts: call it once for
// each purpose at startup, and it does nothing after the first time.
//
// It resumes. A KEK registered without an active version, or with only a
// pending one, is completed instead of replaced. If two processes start at
// once, the registry admits one KEK for the purpose and the other adopts it; the
// key the loser created at the provider is left unused, and can be destroyed at
// the provider.
//
// A purpose already served by a KEK at a different provider is an error: moving
// a purpose between providers is a deliberate migration, not a startup side
// effect.
//
// A failure to record an audit event is returned as [audit.ErrNotRecorded]
// alongside a valid KEK.
func (r *Rotator) EnsureKEK(ctx context.Context, purpose keyforge.Purpose, providerName string) (registry.KEK, error) {
	if err := purpose.Validate(); err != nil {
		return registry.KEK{}, err
	}
	prov, ok := r.providers[providerName]
	if !ok {
		return registry.KEK{}, fmt.Errorf("rotate: no provider named %q", providerName)
	}
	at := r.clock.Now()

	kek, err := r.store.KEKForPurpose(ctx, purpose)
	created := false
	switch {
	case err == nil:
		if kek.Provider != providerName {
			return registry.KEK{}, fmt.Errorf("rotate: purpose %q is served by provider %q, not %q", string(purpose), kek.Provider, providerName)
		}
	case errors.Is(err, keyforge.ErrKEKNotFound):
		if kek, created, err = r.createKEK(ctx, purpose, prov, at); err != nil {
			return registry.KEK{}, err
		}
	default:
		return registry.KEK{}, err
	}

	versions, err := r.store.ListVersions(ctx, kek.ID)
	if err != nil {
		return registry.KEK{}, err
	}
	var pending uint32
	for _, v := range versions {
		switch v.State {
		case registry.VersionActive:
			return kek, r.emitCreated(ctx, kek, created, 0)
		case registry.VersionPending:
			pending = v.Version
		}
	}
	if pending == 0 {
		// The first version of a new key is 1, at every provider.
		pending = 1
		rec := registry.VersionRecord{KEKID: kek.ID, Version: pending, State: registry.VersionPending, CreatedAt: at}
		if err := r.store.AddVersion(ctx, rec); err != nil {
			return registry.KEK{}, fmt.Errorf("rotate: registering version %d: %w", pending, err)
		}
	}
	if err := r.store.TransitionVersion(ctx, kek.ID, pending, registry.VersionActive, registry.TransitionOptions{At: at}); err != nil {
		return registry.KEK{}, fmt.Errorf("rotate: activating version %d: %w", pending, err)
	}
	if err := r.putSentinel(ctx, kek, prov, pending, at); err != nil {
		return kek, fmt.Errorf("rotate: version %d is active but its sentinel was not recorded: %w", pending, err)
	}
	return kek, r.emitCreated(ctx, kek, created, pending)
}

// createKEK creates the key at the provider and registers it. If another
// process registered a KEK for the purpose first, it returns that one.
func (r *Rotator) createKEK(ctx context.Context, purpose keyforge.Purpose, prov provider.Provider, at time.Time) (registry.KEK, bool, error) {
	sel, err := algorithm.NewSelector(algorithm.Config{})
	if err != nil {
		return registry.KEK{}, false, err
	}
	alg, err := sel.Select(algorithm.Selection{})
	if err != nil {
		return registry.KEK{}, false, err
	}
	ref, err := prov.CreateKey(ctx, provider.KeySpec{Purpose: string(purpose), Algorithm: alg})
	if err != nil {
		return registry.KEK{}, false, fmt.Errorf("rotate: creating the key for %q: %w", string(purpose), err)
	}
	kek := registry.KEK{
		ID: ref.ID, Purpose: purpose, Provider: ref.Provider, ProviderRef: ref.ProviderRef,
		State: registry.KeyActive, CreatedAt: at,
	}
	switch err := r.store.CreateKEK(ctx, kek); {
	case err == nil:
		return kek, true, nil
	case errors.Is(err, registry.ErrPurposeBound):
		won, gerr := r.store.KEKForPurpose(ctx, purpose)
		if gerr != nil {
			return registry.KEK{}, false, gerr
		}
		return won, false, nil
	default:
		return registry.KEK{}, false, fmt.Errorf("rotate: registering the key for %q: %w", string(purpose), err)
	}
}

// emitCreated records that a KEK was created and its first version activated.
// version is zero when nothing was activated.
func (r *Rotator) emitCreated(ctx context.Context, kek registry.KEK, created bool, version uint32) error {
	var events []audit.Event
	if created {
		events = append(events, audit.Event{Action: audit.KeyCreated, Purpose: string(kek.Purpose), KEKID: kek.ID.String(),
			Outcome: audit.Success, Reason: "key created"})
	}
	if version != 0 {
		events = append(events, audit.Event{Action: audit.KeyActivated, Purpose: string(kek.Purpose), KEKID: kek.ID.String(),
			Version: version, Outcome: audit.Success, Reason: fmt.Sprintf("version %d active", version)})
	}
	var first error
	for _, e := range events {
		if err := r.emit(ctx, e); err != nil && first == nil {
			first = err
		}
	}
	return first
}
