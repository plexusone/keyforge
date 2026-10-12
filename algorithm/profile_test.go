package algorithm_test

import (
	"crypto/fips140"
	"errors"
	"slices"
	"testing"

	"github.com/plexusone/keyforge/algorithm"
)

func TestProfileNamesAreExact(t *testing.T) {
	if algorithm.ProfileStandard.String() != "standard" || algorithm.ProfileFIPS.String() != "fips" {
		t.Fatalf("names = %q, %q", algorithm.ProfileStandard, algorithm.ProfileFIPS)
	}
	for _, name := range []string{"standard", "fips"} {
		p, err := algorithm.ParseProfile(name)
		if err != nil || p.String() != name {
			t.Fatalf("ParseProfile(%q) = %v, %v", name, p, err)
		}
	}
	for _, bad := range []string{"", "FIPS", "Standard", "fips140", "pci"} {
		if _, err := algorithm.ParseProfile(bad); !errors.Is(err, algorithm.ErrUnknownProfile) {
			t.Fatalf("ParseProfile(%q) = %v, want ErrUnknownProfile", bad, err)
		}
	}
}

func TestProfilesHoldOnlyRegisteredAlgorithms(t *testing.T) {
	for _, p := range []algorithm.Profile{algorithm.ProfileStandard, algorithm.ProfileFIPS} {
		members := p.Algorithms()
		if len(members) == 0 {
			t.Fatalf("%s profile is empty", p)
		}
		for _, id := range members {
			if !id.Valid() {
				t.Errorf("%s profile holds %v, which is not in the registry", p, id)
			}
			if !p.Permits(id) {
				t.Errorf("%s profile lists %s but does not permit it", p, id)
			}
		}
	}
	// The first release registers AES-256-GCM only, and both profiles approve it.
	for _, p := range []algorithm.Profile{algorithm.ProfileStandard, algorithm.ProfileFIPS} {
		if got := p.Algorithms(); !slices.Equal(got, []algorithm.ID{algorithm.AES256GCM}) {
			t.Errorf("%s profile = %v, want only AES-256-GCM", p, got)
		}
	}
}

func TestProfileAlgorithmsReturnsACopy(t *testing.T) {
	a := algorithm.ProfileFIPS.Algorithms()
	a[0] = 99
	if algorithm.ProfileFIPS.Algorithms()[0] == 99 {
		t.Fatal("a caller changed the compiled-in profile set")
	}
}

func TestDefaultProfileFollowsFIPSMode(t *testing.T) {
	want := algorithm.ProfileStandard
	if fips140.Enabled() {
		want = algorithm.ProfileFIPS
	}
	if got := algorithm.DefaultProfile(); got != want {
		t.Fatalf("DefaultProfile = %s, want %s", got, want)
	}
	s, err := algorithm.NewSelector(algorithm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Profile() != want {
		t.Fatalf("selector profile = %s, want %s", s.Profile(), want)
	}
}

func TestSelectorWithRegistry(t *testing.T) {
	for _, p := range []algorithm.Profile{algorithm.ProfileStandard, algorithm.ProfileFIPS} {
		s, err := algorithm.NewSelector(algorithm.Config{Profile: p})
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.Select(algorithm.Selection{})
		if err != nil || id != algorithm.AES256GCM {
			t.Fatalf("%s: Select = %v, %v", p, id, err)
		}
		if err := s.Check(algorithm.AES256GCM, algorithm.Selection{}); err != nil {
			t.Fatalf("%s: Check = %v", p, err)
		}
	}
}

func TestSelectorRefusesUnknownAndReserved(t *testing.T) {
	s, err := algorithm.NewSelector(algorithm.Config{Profile: algorithm.ProfileStandard})
	if err != nil {
		t.Fatal(err)
	}
	// Reserved identifiers (ChaCha20-Poly1305, HPKE, signing) are not
	// implemented and must read as unknown, not as unpermitted.
	for _, id := range []algorithm.ID{0, 2, 16, 17, 18, 32, 33, 34, 255} {
		if err := s.Check(id, algorithm.Selection{}); !errors.Is(err, algorithm.ErrUnknown) {
			t.Errorf("Check(%d) = %v, want ErrUnknown", uint8(id), err)
		}
	}
}

func TestSelectorConfigErrors(t *testing.T) {
	if _, err := algorithm.NewSelector(algorithm.Config{Profile: 7}); !errors.Is(err, algorithm.ErrUnknownProfile) {
		t.Fatalf("unknown profile: %v", err)
	}
	if _, err := algorithm.NewSelector(algorithm.Config{Profile: algorithm.ProfileFIPS, Deny: []algorithm.ID{9}}); !errors.Is(err, algorithm.ErrUnknown) {
		t.Fatalf("unknown denied algorithm: %v", err)
	}
}

func TestDenyAllFailsClosed(t *testing.T) {
	s, err := algorithm.NewSelector(algorithm.Config{Profile: algorithm.ProfileStandard, Deny: []algorithm.ID{algorithm.AES256GCM}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Select(algorithm.Selection{}); !errors.Is(err, algorithm.ErrNoPermitted) {
		t.Fatalf("Select = %v, want ErrNoPermitted", err)
	}
	var np *algorithm.NotPermittedError
	err = s.Check(algorithm.AES256GCM, algorithm.Selection{})
	if !errors.Is(err, algorithm.ErrNotPermitted) || !errors.As(err, &np) {
		t.Fatalf("Check = %v, want a NotPermittedError", err)
	}
	if np.Algorithm != algorithm.AES256GCM || np.Profile != algorithm.ProfileStandard {
		t.Fatalf("error reports %s under %s", np.Algorithm, np.Profile)
	}
	if err := s.ValidateSelection(algorithm.Selection{}); !errors.Is(err, algorithm.ErrInvalidSelection) {
		t.Fatalf("ValidateSelection = %v, want ErrInvalidSelection", err)
	}
}
