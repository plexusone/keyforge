package registry_test

import (
	"errors"
	"testing"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/registry"
)

// TestEveryTransitionPairIsDecided walks all ordered pairs of states so a state
// added later cannot silently inherit a permission.
func TestEveryTransitionPairIsDecided(t *testing.T) {
	allowed := map[[2]registry.VersionState]bool{
		{registry.VersionPending, registry.VersionActive}:              true,
		{registry.VersionActive, registry.VersionDecryptOnly}:          true,
		{registry.VersionActive, registry.VersionCompromised}:          true,
		{registry.VersionDecryptOnly, registry.VersionActive}:          true,
		{registry.VersionDecryptOnly, registry.VersionRetireRequested}: true,
		{registry.VersionDecryptOnly, registry.VersionCompromised}:     true,
		{registry.VersionRetireRequested, registry.VersionDecryptOnly}: true,
		{registry.VersionRetireRequested, registry.VersionRetired}:     true,
		{registry.VersionRetireRequested, registry.VersionCompromised}: true,
		{registry.VersionRetired, registry.VersionDestroyed}:           true,
		{registry.VersionCompromised, registry.VersionRetired}:         true,
	}
	for _, from := range registry.VersionStates {
		for _, to := range registry.VersionStates {
			want := allowed[[2]registry.VersionState{from, to}]
			got := registry.CanTransition(from, to)
			if got != want {
				t.Errorf("CanTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
			err := registry.CheckTransition(from, to)
			if (err == nil) != want {
				t.Errorf("CheckTransition(%s, %s) = %v, want allowed=%v", from, to, err, want)
			}
			if err != nil {
				var te *registry.TransitionError
				if !errors.Is(err, registry.ErrInvalidTransition) || !errors.As(err, &te) || te.From != from || te.To != to {
					t.Errorf("CheckTransition(%s, %s) = %v, want a TransitionError", from, to, err)
				}
			}
		}
	}
}

func TestDestroyedAndRetiredAreOneWay(t *testing.T) {
	for _, from := range []registry.VersionState{registry.VersionDestroyed, registry.VersionRetired} {
		for _, to := range registry.VersionStates {
			if from == registry.VersionRetired && to == registry.VersionDestroyed {
				continue
			}
			if registry.CanTransition(from, to) {
				t.Errorf("%s can move to %s; nothing leaves it but retired to destroyed", from, to)
			}
		}
	}
}

func TestUnknownStatesAreRefused(t *testing.T) {
	for _, bad := range []registry.VersionState{0, 8, 255} {
		if bad.Valid() {
			t.Errorf("%d is valid", uint8(bad))
		}
		for _, s := range registry.VersionStates {
			if registry.CanTransition(bad, s) || registry.CanTransition(s, bad) {
				t.Errorf("a transition involving the undefined state %d was allowed", uint8(bad))
			}
		}
	}
}

func TestStateNamesAreExact(t *testing.T) {
	want := map[registry.VersionState]string{
		registry.VersionPending: "pending", registry.VersionActive: "active",
		registry.VersionDecryptOnly: "decrypt-only", registry.VersionRetireRequested: "retire-requested",
		registry.VersionRetired: "retired", registry.VersionDestroyed: "destroyed",
		registry.VersionCompromised: "compromised",
	}
	for s, name := range want {
		if s.String() != name {
			t.Errorf("%d = %q, want %q", uint8(s), s.String(), name)
		}
	}
	if len(registry.VersionStates) != len(want) {
		t.Errorf("VersionStates lists %d states, want %d", len(registry.VersionStates), len(want))
	}
}

// TestWrapAndUnwrapByState checks the encrypt and decrypt column of the TRD's
// state table.
func TestWrapAndUnwrapByState(t *testing.T) {
	tests := []struct {
		s            registry.VersionState
		wrap, unwrap bool
	}{
		{registry.VersionPending, false, false},
		{registry.VersionActive, true, true},
		{registry.VersionDecryptOnly, false, true},
		{registry.VersionRetireRequested, false, true},
		{registry.VersionRetired, false, false},
		{registry.VersionDestroyed, false, false},
		{registry.VersionCompromised, false, true},
	}
	for _, tt := range tests {
		if tt.s.CanWrap() != tt.wrap || tt.s.CanUnwrap() != tt.unwrap {
			t.Errorf("%s: CanWrap=%v CanUnwrap=%v, want %v %v", tt.s, tt.s.CanWrap(), tt.s.CanUnwrap(), tt.wrap, tt.unwrap)
		}
	}
}

func TestDEKTransitions(t *testing.T) {
	states := []keyforge.DEKState{keyforge.DEKActive, keyforge.DEKDecryptOnly, keyforge.DEKCompromised, keyforge.DEKDestroyed}
	allowed := map[[2]keyforge.DEKState]bool{
		{keyforge.DEKActive, keyforge.DEKDecryptOnly}:      true,
		{keyforge.DEKActive, keyforge.DEKCompromised}:      true,
		{keyforge.DEKDecryptOnly, keyforge.DEKCompromised}: true,
		{keyforge.DEKDecryptOnly, keyforge.DEKDestroyed}:   true,
		{keyforge.DEKCompromised, keyforge.DEKDestroyed}:   true,
	}
	for _, from := range states {
		for _, to := range states {
			err := registry.CheckDEKTransition(from, to)
			if (err == nil) != allowed[[2]keyforge.DEKState{from, to}] {
				t.Errorf("CheckDEKTransition(%s, %s) = %v", from, to, err)
			}
			if err != nil && !errors.Is(err, registry.ErrInvalidTransition) {
				t.Errorf("CheckDEKTransition(%s, %s) = %v, want ErrInvalidTransition", from, to, err)
			}
		}
	}
}

func TestDEKFilterPageSize(t *testing.T) {
	for _, tt := range []struct{ limit, want int }{
		{0, registry.DefaultPageSize}, {-5, registry.DefaultPageSize}, {10, 10},
		{registry.MaxPageSize, registry.MaxPageSize}, {registry.MaxPageSize + 1, registry.MaxPageSize},
	} {
		if got := (registry.DEKFilter{Limit: tt.limit}).PageSize(); got != tt.want {
			t.Errorf("PageSize(%d) = %d, want %d", tt.limit, got, tt.want)
		}
	}
}
