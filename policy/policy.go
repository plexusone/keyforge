// Package policy holds the rotation, epoch and retirement policy of a purpose.
//
// A policy is data, not behavior: it says how often to rotate and how long to
// wait, and the rotate and retire packages act on it. Every field has a default
// taken from the specification, so an application that configures nothing gets
// the documented behavior, and a purpose overrides only what it must.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
)

// Defaults, from the specification.
const (
	// DefaultKEKInterval is how long a KEK version stays active before the
	// next is activated.
	DefaultKEKInterval = 365 * 24 * time.Hour
	// DefaultDEKMaxAge is how long a data key epoch is used for writes.
	DefaultDEKMaxAge = 90 * 24 * time.Hour
	// DefaultDEKMaxEncryptions is the most encryptions made under one data key.
	DefaultDEKMaxEncryptions = keyforge.DefaultEncryptionCap
	// DefaultRetirementDelay is how long a version waits between a request to
	// retire it and its retirement.
	DefaultRetirementDelay = 30 * 24 * time.Hour
	// DefaultRetainVersions is how many versions are never retired: the active
	// one and the most recent decrypt-only one, which is the rollback margin.
	DefaultRetainVersions = 2
)

// MinRetirementDelayFactor is how many times longer than the client cache TTL
// a retirement delay must be. A client that cached the active KEK version keeps
// wrapping under it until its entry expires, so the delay has to be far longer
// than that window for no new data key to appear under a version that is
// already eligible for retirement.
const MinRetirementDelayFactor = 10

// Policy is the policy of one purpose. In a [Set] a zero field means "not
// specified here" and takes the value from the set's default.
type Policy struct {
	// KEKInterval is how long a KEK version is active before rotation.
	KEKInterval time.Duration
	// DEKMaxAge is how long a data key epoch is current before a new epoch.
	DEKMaxAge time.Duration
	// DEKMaxEncryptions is the cap on encryptions per data key.
	DEKMaxEncryptions uint64
	// RetirementDelay is the wait between a request to retire a version and
	// its retirement.
	RetirementDelay time.Duration
	// RetainVersions is the floor on how many versions are kept: the active
	// version and the most recent decrypt-only ones up to this count are never
	// retired, even when nothing references them. It is a floor on retention,
	// never a trigger to delete.
	RetainVersions int
	// RequireBackup makes rotation wait until the keyring's backup has been
	// acknowledged as current, so that restoring it cannot lose data wrapped
	// under a version it lacks.
	RequireBackup bool
}

// Default returns the policy with every default filled in.
func Default() Policy {
	return Policy{
		KEKInterval:       DefaultKEKInterval,
		DEKMaxAge:         DefaultDEKMaxAge,
		DEKMaxEncryptions: DefaultDEKMaxEncryptions,
		RetirementDelay:   DefaultRetirementDelay,
		RetainVersions:    DefaultRetainVersions,
	}
}

// Validate checks a fully specified policy.
func (p Policy) Validate() error {
	var errs []error
	if p.KEKInterval <= 0 {
		errs = append(errs, errors.New("KEK interval must be positive"))
	}
	if p.DEKMaxAge <= 0 {
		errs = append(errs, errors.New("data key maximum age must be positive"))
	}
	if p.DEKMaxEncryptions == 0 || p.DEKMaxEncryptions > keyforge.MaxEncryptionCap {
		errs = append(errs, fmt.Errorf("data key encryption cap must be between 1 and %d", keyforge.MaxEncryptionCap))
	}
	if p.RetirementDelay <= 0 {
		errs = append(errs, errors.New("retirement delay must be positive"))
	}
	if p.RetainVersions < 1 {
		errs = append(errs, errors.New("retained versions must be at least 1"))
	}
	return errors.Join(errs...)
}

// merge returns p with its zero fields taken from base. RequireBackup is
// combined with OR: a purpose can ask for a backup the default does not
// require, and cannot waive one the default does.
func (p Policy) merge(base Policy) Policy {
	if p.KEKInterval == 0 {
		p.KEKInterval = base.KEKInterval
	}
	if p.DEKMaxAge == 0 {
		p.DEKMaxAge = base.DEKMaxAge
	}
	if p.DEKMaxEncryptions == 0 {
		p.DEKMaxEncryptions = base.DEKMaxEncryptions
	}
	if p.RetirementDelay == 0 {
		p.RetirementDelay = base.RetirementDelay
	}
	if p.RetainVersions == 0 {
		p.RetainVersions = base.RetainVersions
	}
	p.RequireBackup = p.RequireBackup || base.RequireBackup
	return p
}

// Set is the policy of a deployment: a default and per-purpose overrides.
type Set struct {
	// Default applies to every purpose. Its zero fields take the package
	// defaults.
	Default Policy
	// Purposes overrides the default for a purpose. A zero field inherits.
	Purposes map[keyforge.Purpose]Policy
}

// For returns the resolved policy for a purpose. A purpose with no override
// gets the set's default.
func (s Set) For(p keyforge.Purpose) Policy {
	base := s.Default.merge(Default())
	if o, ok := s.Purposes[p]; ok {
		return o.merge(base)
	}
	return base
}

// PurposeConfigs builds the client's per-purpose configuration from the policy:
// each purpose's data key age and volume cap, with the algorithm selection the
// caller gives for it. A purpose with no selection uses the profile's defaults.
func (s Set) PurposeConfigs(selections map[keyforge.Purpose]algorithm.Selection) map[keyforge.Purpose]keyforge.PurposeConfig {
	out := make(map[keyforge.Purpose]keyforge.PurposeConfig, len(selections))
	for p, sel := range selections {
		pol := s.For(p)
		out[p] = keyforge.PurposeConfig{Algorithms: sel, EncryptionCap: pol.DEKMaxEncryptions, MaxAge: pol.DEKMaxAge}
	}
	return out
}

// Validate checks the default and every override as resolved. cacheTTL is the
// client's cache TTL; every retirement delay must exceed it by
// [MinRetirementDelayFactor], and zero skips that check.
func (s Set) Validate(cacheTTL time.Duration) error {
	var errs []error
	check := func(name string, p Policy) {
		if err := p.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		if cacheTTL > 0 && p.RetirementDelay > 0 && p.RetirementDelay < MinRetirementDelayFactor*cacheTTL {
			errs = append(errs, fmt.Errorf("%s: retirement delay %s must be at least %d times the cache TTL %s",
				name, p.RetirementDelay, MinRetirementDelayFactor, cacheTTL))
		}
	}
	check("default", s.For(""))
	names := make([]string, 0, len(s.Purposes))
	for p := range s.Purposes {
		if err := p.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		names = append(names, string(p))
	}
	slices.Sort(names)
	for _, n := range names {
		check(fmt.Sprintf("purpose %q", n), s.For(keyforge.Purpose(n)))
	}
	return errors.Join(errs...)
}

// ParseDuration parses a duration that may use days: "365d", "90d", "36h",
// "30d12h". It is [time.ParseDuration] with a leading day count.
func ParseDuration(s string) (time.Duration, error) {
	orig := s
	var total time.Duration
	if i := strings.IndexByte(s, 'd'); i > 0 {
		days, err := strconv.ParseUint(s[:i], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("policy: invalid duration %q", orig)
		}
		total = time.Duration(days) * 24 * time.Hour
		s = s[i+1:]
		if s == "" {
			return total, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("policy: invalid duration %q", orig)
	}
	return total + d, nil
}

// formatDuration renders whole days as "Nd" and anything else as
// [time.Duration.String].
func formatDuration(d time.Duration) string {
	if d != 0 && d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	return d.String()
}

type policyJSON struct {
	KEKInterval       string `json:"kekInterval,omitempty"`
	DEKMaxAge         string `json:"dekMaxAge,omitempty"`
	DEKMaxEncryptions uint64 `json:"dekMaxEncryptions,omitempty"`
	RetirementDelay   string `json:"retirementDelay,omitempty"`
	RetainVersions    int    `json:"retainVersions,omitempty"`
	RequireBackup     bool   `json:"requireBackup,omitempty"`
}

// MarshalJSON writes durations as strings with a day suffix where they are
// whole days, for configuration files.
func (p Policy) MarshalJSON() ([]byte, error) {
	j := policyJSON{DEKMaxEncryptions: p.DEKMaxEncryptions, RetainVersions: p.RetainVersions, RequireBackup: p.RequireBackup}
	if p.KEKInterval != 0 {
		j.KEKInterval = formatDuration(p.KEKInterval)
	}
	if p.DEKMaxAge != 0 {
		j.DEKMaxAge = formatDuration(p.DEKMaxAge)
	}
	if p.RetirementDelay != 0 {
		j.RetirementDelay = formatDuration(p.RetirementDelay)
	}
	return json.Marshal(j)
}

// UnmarshalJSON reads durations written as strings. An unknown field is an
// error, so a misspelled setting is not silently ignored.
func (p *Policy) UnmarshalJSON(b []byte) error {
	var j policyJSON
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	out := Policy{DEKMaxEncryptions: j.DEKMaxEncryptions, RetainVersions: j.RetainVersions, RequireBackup: j.RequireBackup}
	for _, f := range []struct {
		in  string
		dst *time.Duration
	}{{j.KEKInterval, &out.KEKInterval}, {j.DEKMaxAge, &out.DEKMaxAge}, {j.RetirementDelay, &out.RetirementDelay}} {
		if f.in == "" {
			continue
		}
		d, err := ParseDuration(f.in)
		if err != nil {
			return err
		}
		*f.dst = d
	}
	*p = out
	return nil
}
