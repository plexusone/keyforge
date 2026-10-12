package algorithm

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The registry holds one algorithm, so narrowing cannot be exercised against
// it. These tests build a selector over a synthetic registry in which the
// fips profile is a strict subset of the standard one:
//
//	1 AES-256-GCM        fips, standard
//	2 (synthetic)        standard only
//	3 (synthetic)        standard only
var (
	syntheticSets = sets{fips: []ID{1}, standard: []ID{1, 2, 3}}
	syntheticAll  = func(id ID) bool { return id >= 1 && id <= 3 }
)

func syntheticSelector(t *testing.T, cfg Config) *Selector {
	t.Helper()
	s, err := newSelector(cfg, syntheticSets, syntheticAll)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRegisteredFIPSIsSubsetOfStandard(t *testing.T) {
	for _, id := range registered.fips {
		if !slices.Contains(registered.standard, id) {
			t.Errorf("%s is in the fips set but not the standard set", id)
		}
	}
	for _, p := range []Profile{ProfileStandard, ProfileFIPS} {
		seen := map[ID]bool{}
		for _, id := range registered.of(p) {
			if seen[id] {
				t.Errorf("%s lists %s twice", p, id)
			}
			seen[id] = true
			if !id.Valid() {
				t.Errorf("%s lists %d, which is not registered", p, uint8(id))
			}
		}
	}
}

func TestWritesPickTheFirstPermittedInTheList(t *testing.T) {
	std := syntheticSelector(t, Config{Profile: ProfileStandard})
	for _, tt := range []struct {
		name    string
		allowed []ID
		want    ID
	}{
		{"profile order", nil, 1},
		{"list order wins", []ID{3, 2, 1}, 3},
		{"second entry", []ID{2}, 2},
	} {
		t.Run("standard/"+tt.name, func(t *testing.T) {
			got, err := std.Select(Selection{Allowed: tt.allowed})
			if err != nil || got != tt.want {
				t.Fatalf("Select = %v, %v, want %v", got, err, tt.want)
			}
		})
	}

	// Under fips, the list is skipped past entries the profile does not permit.
	fips := syntheticSelector(t, Config{Profile: ProfileFIPS})
	got, err := fips.Select(Selection{Allowed: []ID{3, 2, 1}})
	if err != nil || got != 1 {
		t.Fatalf("fips Select = %v, %v, want 1", got, err)
	}
	if _, err := fips.Select(Selection{Allowed: []ID{3, 2}}); !errors.Is(err, ErrNoPermitted) {
		t.Fatalf("fips Select with nothing permitted = %v, want ErrNoPermitted", err)
	}
}

func TestReadsFollowTheProfileNotTheWriteList(t *testing.T) {
	std := syntheticSelector(t, Config{Profile: ProfileStandard})
	// The purpose now writes with 1 only, but data written with 2 stays readable.
	if err := std.Check(2, Selection{Allowed: []ID{1}}); err != nil {
		t.Fatalf("Check = %v, want data written under a narrowed list to stay readable", err)
	}
	fips := syntheticSelector(t, Config{Profile: ProfileFIPS})
	err := fips.Check(2, Selection{})
	var np *NotPermittedError
	if !errors.Is(err, ErrNotPermitted) || !errors.As(err, &np) || np.Algorithm != 2 || np.Profile != ProfileFIPS {
		t.Fatalf("Check = %v, want NotPermittedError for algorithm 2 under fips", err)
	}
	if !strings.Contains(err.Error(), "fips") {
		t.Fatalf("error %q does not name the profile", err)
	}
}

func TestPinnedProfileNarrowsBothWritesAndReads(t *testing.T) {
	std := syntheticSelector(t, Config{Profile: ProfileStandard})
	pinned := Selection{Profile: ProfileFIPS, Allowed: []ID{1}}
	if err := std.ValidateSelection(pinned); err != nil {
		t.Fatal(err)
	}
	if err := std.Check(2, pinned); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("Check = %v, want ErrNotPermitted under the pinned profile", err)
	}
	if got, err := std.Select(Selection{Profile: ProfileFIPS}); err != nil || got != 1 {
		t.Fatalf("Select = %v, %v, want 1", got, err)
	}
}

func TestConfigurationCannotWiden(t *testing.T) {
	fips := syntheticSelector(t, Config{Profile: ProfileFIPS})
	std := syntheticSelector(t, Config{Profile: ProfileStandard})

	tests := []struct {
		name string
		s    *Selector
		sel  Selection
	}{
		{"pin a wider profile", fips, Selection{Profile: ProfileStandard}},
		{"list an algorithm outside the profile", fips, Selection{Allowed: []ID{1, 2}}},
		{"list an algorithm outside the pinned profile", std, Selection{Profile: ProfileFIPS, Allowed: []ID{2}}},
		{"list an unknown algorithm", std, Selection{Allowed: []ID{9}}},
		{"list an algorithm twice", std, Selection{Allowed: []ID{1, 1}}},
		{"pin an undefined profile", std, Selection{Profile: 9}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.ValidateSelection(tt.sel); !errors.Is(err, ErrInvalidSelection) {
				t.Fatalf("ValidateSelection = %v, want ErrInvalidSelection", err)
			}
		})
	}

	// And the narrowing forms are accepted.
	for _, ok := range []Selection{
		{},
		{Allowed: []ID{3, 1}},
		{Profile: ProfileFIPS},
		{Profile: ProfileStandard, Allowed: []ID{2}},
	} {
		if err := std.ValidateSelection(ok); err != nil {
			t.Errorf("ValidateSelection(%+v) = %v", ok, err)
		}
	}
}

func TestDenyOnlyNarrows(t *testing.T) {
	s := syntheticSelector(t, Config{Profile: ProfileStandard, Deny: []ID{1, 3}})
	if got, err := s.Select(Selection{}); err != nil || got != 2 {
		t.Fatalf("Select = %v, %v, want 2", got, err)
	}
	if err := s.Check(1, Selection{}); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("Check(1) = %v, want ErrNotPermitted", err)
	}
	if err := s.Check(2, Selection{}); err != nil {
		t.Fatalf("Check(2) = %v", err)
	}
	if err := s.ValidateSelection(Selection{Allowed: []ID{1}}); !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("a denied algorithm in the list: %v, want ErrInvalidSelection", err)
	}
	if !strings.Contains(s.String(), "denying") {
		t.Fatalf("String = %q does not report the denials", s.String())
	}
}

func TestValidateReportsEveryPurposeInOrder(t *testing.T) {
	fips := syntheticSelector(t, Config{Profile: ProfileFIPS})
	err := fips.Validate(map[string]Selection{
		"zeta":  {Allowed: []ID{2}},
		"alpha": {Profile: ProfileStandard},
		"fine":  {},
	})
	if !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("Validate = %v, want ErrInvalidSelection", err)
	}
	msg := err.Error()
	if strings.Contains(msg, `"fine"`) {
		t.Errorf("valid purpose reported: %s", msg)
	}
	a, z := strings.Index(msg, `"alpha"`), strings.Index(msg, `"zeta"`)
	if a < 0 || z < 0 || a > z {
		t.Errorf("want both violations, alpha before zeta, got: %s", msg)
	}
	if err := fips.Validate(map[string]Selection{"fine": {}}); err != nil {
		t.Fatalf("Validate = %v for a valid set", err)
	}
}
