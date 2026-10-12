package algorithm

import (
	"crypto/fips140"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Profile is a named set of algorithms. The sets are compiled in and reviewed;
// configuration can narrow a profile and cannot add an algorithm to it.
type Profile uint8

const (
	// ProfileStandard is the default profile outside FIPS mode. Every
	// algorithm in the registry is a member.
	ProfileStandard Profile = 1
	// ProfileFIPS holds only algorithms that FIPS 140-3 approves. It is the
	// default when the process runs in FIPS mode, and may be selected outside
	// it, where it restricts the algorithm set without module validation.
	ProfileFIPS Profile = 2
)

var (
	// ErrNotPermitted is returned when an algorithm is outside the profile in
	// force. It is never answered with a fallback.
	ErrNotPermitted = errors.New("algorithm: not permitted by the profile")
	// ErrNoPermitted is returned when a write finds no algorithm the profile
	// and the purpose's list both permit. The operation fails closed.
	ErrNoPermitted = errors.New("algorithm: no permitted algorithm")
	// ErrInvalidSelection is returned for a purpose configuration that widens
	// a profile or names an algorithm that does not exist.
	ErrInvalidSelection = errors.New("algorithm: invalid selection")
	// ErrUnknownProfile is returned for a profile name or value that is not
	// defined.
	ErrUnknownProfile = errors.New("algorithm: unknown profile")
)

// NotPermittedError reports the algorithm and the profile it was refused by.
type NotPermittedError struct {
	Algorithm ID
	Profile   Profile
}

// Error implements error.
func (e *NotPermittedError) Error() string {
	return fmt.Sprintf("%v: %s is not permitted by the %s profile", ErrNotPermitted, e.Algorithm, e.Profile)
}

// Unwrap lets [errors.Is] match [ErrNotPermitted].
func (e *NotPermittedError) Unwrap() error { return ErrNotPermitted }

// sets holds the membership of each profile. It is a value so that tests can
// exercise narrowing with more algorithms than the registry holds.
type sets struct {
	fips     []ID
	standard []ID
}

// registered is the membership shipped in this build. Adding an algorithm is a
// release: a registry entry, an envelope identifier, known-answer vectors, and
// a line here.
var registered = sets{
	fips:     []ID{AES256GCM},
	standard: []ID{AES256GCM},
}

func (s sets) of(p Profile) []ID {
	switch p {
	case ProfileFIPS:
		return s.fips
	case ProfileStandard:
		return s.standard
	default:
		return nil
	}
}

// Valid reports whether p is a defined profile.
func (p Profile) Valid() bool { return p == ProfileStandard || p == ProfileFIPS }

// String returns the profile's name as used in configuration, logs and status.
func (p Profile) String() string {
	switch p {
	case ProfileStandard:
		return "standard"
	case ProfileFIPS:
		return "fips"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(p))
	}
}

// ParseProfile parses "standard" or "fips".
func ParseProfile(s string) (Profile, error) {
	switch s {
	case "standard":
		return ProfileStandard, nil
	case "fips":
		return ProfileFIPS, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnknownProfile, s)
	}
}

// Algorithms returns the profile's members in preference order. The caller
// owns the returned slice.
func (p Profile) Algorithms() []ID {
	return slices.Clone(registered.of(p))
}

// Permits reports whether id is a member of the profile.
func (p Profile) Permits(id ID) bool {
	return slices.Contains(registered.of(p), id)
}

// DefaultProfile returns the profile a process uses when none is configured:
// FIPS when the process runs in FIPS 140-3 mode, and standard otherwise.
func DefaultProfile() Profile {
	if fips140.Enabled() {
		return ProfileFIPS
	}
	return ProfileStandard
}

// Config configures a [Selector].
type Config struct {
	// Profile is the active profile. The zero value means [DefaultProfile].
	Profile Profile
	// Deny removes algorithms from the active profile. It can only narrow.
	Deny []ID
}

// Selection is a purpose's algorithm configuration. It can only narrow what
// the active profile permits.
type Selection struct {
	// Profile pins the purpose to a profile that is no wider than the active
	// one. The zero value inherits the active profile.
	Profile Profile
	// Allowed is the ordered preference list for writes, a subset of the
	// profile. Empty means the profile's own order.
	Allowed []ID
}

// Selector chooses algorithms for writes and checks algorithms on reads under
// the active profile. It is immutable and safe for concurrent use.
type Selector struct {
	active Profile
	deny   []ID
	sets   sets
	valid  func(ID) bool
}

// NewSelector returns a selector for cfg. It fails if the profile or a denied
// algorithm is not defined.
func NewSelector(cfg Config) (*Selector, error) {
	return newSelector(cfg, registered, ID.Valid)
}

func newSelector(cfg Config, s sets, valid func(ID) bool) (*Selector, error) {
	active := cfg.Profile
	if active == 0 {
		active = DefaultProfile()
	}
	if !active.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownProfile, uint8(active))
	}
	for _, id := range cfg.Deny {
		if !valid(id) {
			return nil, fmt.Errorf("%w: denied %d", ErrUnknown, uint8(id))
		}
	}
	return &Selector{active: active, deny: slices.Clone(cfg.Deny), sets: s, valid: valid}, nil
}

// Profile returns the active profile.
func (s *Selector) Profile() Profile { return s.active }

// effective returns the profile in force for sel.
func (s *Selector) effective(sel Selection) Profile {
	if sel.Profile != 0 {
		return sel.Profile
	}
	return s.active
}

// permits reports whether id is in profile p and not denied.
func (s *Selector) permits(p Profile, id ID) bool {
	return slices.Contains(s.sets.of(p), id) && !slices.Contains(s.deny, id)
}

// Select returns the algorithm to write with: the first entry of the
// purpose's list that the profile in force permits, or the profile's first
// permitted algorithm when the list is empty. If there is none it returns
// [ErrNoPermitted]; it never falls back to an algorithm outside the profile.
func (s *Selector) Select(sel Selection) (ID, error) {
	p := s.effective(sel)
	candidates := sel.Allowed
	if len(candidates) == 0 {
		candidates = s.sets.of(p)
	}
	for _, id := range candidates {
		if s.permits(p, id) {
			return id, nil
		}
	}
	return 0, fmt.Errorf("%w under the %s profile", ErrNoPermitted, p)
}

// Check decides whether an envelope that names id may be read. Reads follow
// the profile in force, not the purpose's write list, so narrowing the list
// does not strand data already written. Migration is a re-encryption in a
// process whose profile permits the old algorithm.
//
// An algorithm outside the profile fails with a [*NotPermittedError] that
// reports the algorithm and the profile; there is no fallback.
func (s *Selector) Check(id ID, sel Selection) error {
	if !s.valid(id) {
		return fmt.Errorf("%w: %d", ErrUnknown, uint8(id))
	}
	p := s.effective(sel)
	if !s.permits(p, id) {
		return &NotPermittedError{Algorithm: id, Profile: p}
	}
	return nil
}

// CheckWrite decides whether id may be used to write under sel: it must pass
// [Selector.Check] and, when the purpose lists algorithms, be one of them.
// A data key created under an algorithm that has since left the list fails
// here, so the caller rotates to a new epoch instead of writing with it.
func (s *Selector) CheckWrite(id ID, sel Selection) error {
	if err := s.Check(id, sel); err != nil {
		return err
	}
	if len(sel.Allowed) > 0 && !slices.Contains(sel.Allowed, id) {
		return &NotPermittedError{Algorithm: id, Profile: s.effective(sel)}
	}
	return nil
}

// ValidateSelection checks one purpose's configuration against the active
// profile: a pinned profile must be no wider, and every listed algorithm must
// exist, appear once, and be permitted. It also requires that a write has an
// algorithm to use.
func (s *Selector) ValidateSelection(sel Selection) error {
	if sel.Profile != 0 {
		if !sel.Profile.Valid() {
			return fmt.Errorf("%w: pinned profile %d: %w", ErrInvalidSelection, uint8(sel.Profile), ErrUnknownProfile)
		}
		for _, id := range s.sets.of(sel.Profile) {
			if !slices.Contains(s.sets.of(s.active), id) {
				return fmt.Errorf("%w: profile %s is wider than the active %s profile", ErrInvalidSelection, sel.Profile, s.active)
			}
		}
	}
	p := s.effective(sel)
	seen := make(map[ID]bool, len(sel.Allowed))
	for _, id := range sel.Allowed {
		switch {
		case !s.valid(id):
			return fmt.Errorf("%w: %w: %d", ErrInvalidSelection, ErrUnknown, uint8(id))
		case seen[id]:
			return fmt.Errorf("%w: %s listed twice", ErrInvalidSelection, id)
		case !s.permits(p, id):
			return fmt.Errorf("%w: %s is not permitted by the %s profile", ErrInvalidSelection, id, p)
		}
		seen[id] = true
	}
	if _, err := s.Select(sel); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSelection, err)
	}
	return nil
}

// Validate checks every purpose's configuration and reports all violations,
// so startup fails fast with the whole list. Purposes are checked in name
// order.
func (s *Selector) Validate(purposes map[string]Selection) error {
	names := make([]string, 0, len(purposes))
	for name := range purposes {
		names = append(names, name)
	}
	sort.Strings(names)

	var errs []error
	for _, name := range names {
		if err := s.ValidateSelection(purposes[name]); err != nil {
			errs = append(errs, fmt.Errorf("purpose %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// String describes the selector for logs and status: the active profile and
// any denied algorithms.
func (s *Selector) String() string {
	if len(s.deny) == 0 {
		return s.active.String()
	}
	names := make([]string, len(s.deny))
	for i, id := range s.deny {
		names[i] = id.String()
	}
	return fmt.Sprintf("%s (denying %s)", s.active, strings.Join(names, ", "))
}
