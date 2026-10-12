package policy_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/policy"
)

const day = 24 * time.Hour

func TestDefaultsMatchTheSpecification(t *testing.T) {
	d := policy.Default()
	if d.KEKInterval != 365*day || d.DEKMaxAge != 90*day || d.RetirementDelay != 30*day ||
		d.RetainVersions != 2 || d.DEKMaxEncryptions != 1<<30 || d.RequireBackup {
		t.Fatalf("Default = %+v", d)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("the default policy is invalid: %v", err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*policy.Policy)
		want   string
	}{
		{"valid", func(*policy.Policy) {}, ""},
		{"no KEK interval", func(p *policy.Policy) { p.KEKInterval = 0 }, "KEK interval"},
		{"negative age", func(p *policy.Policy) { p.DEKMaxAge = -1 }, "maximum age"},
		{"no cap", func(p *policy.Policy) { p.DEKMaxEncryptions = 0 }, "encryption cap"},
		{"cap above the limit", func(p *policy.Policy) { p.DEKMaxEncryptions = keyforge.MaxEncryptionCap + 1 }, "encryption cap"},
		{"no delay", func(p *policy.Policy) { p.RetirementDelay = 0 }, "retirement delay"},
		{"retain nothing", func(p *policy.Policy) { p.RetainVersions = 0 }, "retained versions"},
		{"retain one", func(p *policy.Policy) { p.RetainVersions = 1 }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := policy.Default()
			tt.mutate(&p)
			err := p.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("Validate = %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Fatalf("Validate = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestSetResolution(t *testing.T) {
	s := policy.Set{
		Default: policy.Policy{KEKInterval: 180 * day, RequireBackup: true},
		Purposes: map[keyforge.Purpose]policy.Policy{
			"sessions": {DEKMaxAge: 7 * day},
			"audit":    {RetainVersions: 5, RequireBackup: false},
		},
	}
	// An unlisted purpose gets the default, with package defaults beneath it.
	got := s.For("orders")
	if got.KEKInterval != 180*day || got.DEKMaxAge != 90*day || !got.RequireBackup || got.RetainVersions != 2 {
		t.Errorf("For(orders) = %+v", got)
	}
	// An override changes only what it sets.
	got = s.For("sessions")
	if got.DEKMaxAge != 7*day || got.KEKInterval != 180*day || got.RetirementDelay != 30*day {
		t.Errorf("For(sessions) = %+v", got)
	}
	// A purpose cannot waive a backup the default requires.
	if got = s.For("audit"); !got.RequireBackup || got.RetainVersions != 5 {
		t.Errorf("For(audit) = %+v, want the backup requirement kept", got)
	}
	// A purpose can ask for one the default does not.
	strict := policy.Set{Purposes: map[keyforge.Purpose]policy.Policy{"keys": {RequireBackup: true}}}
	if !strict.For("keys").RequireBackup || strict.For("other").RequireBackup {
		t.Error("a purpose could not tighten the backup requirement, or it leaked to others")
	}
}

func TestSetValidate(t *testing.T) {
	good := policy.Set{Purposes: map[keyforge.Purpose]policy.Policy{"orders": {}}}
	if err := good.Validate(5 * time.Minute); err != nil {
		t.Fatalf("Validate = %v", err)
	}

	bad := policy.Set{
		Default: policy.Policy{DEKMaxEncryptions: keyforge.MaxEncryptionCap + 1},
		Purposes: map[keyforge.Purpose]policy.Policy{
			"quick":       {RetirementDelay: time.Minute},
			"Bad Purpose": {},
		},
	}
	err := bad.Validate(5 * time.Minute)
	if err == nil {
		t.Fatal("Validate accepted a bad set")
	}
	for _, want := range []string{"default", `purpose "quick"`, "cache TTL", "Bad Purpose"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// With the cache TTL unknown the delay check is skipped.
	short := policy.Set{Purposes: map[keyforge.Purpose]policy.Policy{"quick": {RetirementDelay: time.Minute}}}
	if err := short.Validate(0); err != nil {
		t.Errorf("Validate(0) = %v", err)
	}
	if err := short.Validate(time.Minute); err == nil {
		t.Error("a retirement delay equal to the cache TTL was accepted")
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"365d", 365 * day, true},
		{"1d", day, true},
		{"36h", 36 * time.Hour, true},
		{"30d12h", 30*day + 12*time.Hour, true},
		{"90m", 90 * time.Minute, true},
		{"0d", 0, true},
		{"", 0, false},
		{"d", 0, false},
		{"-5d", 0, false},
		{"1.5d", 0, false},
		{"5 days", 0, false},
		{"abc", 0, false},
	}
	for _, tt := range tests {
		got, err := policy.ParseDuration(tt.in)
		if (err == nil) != tt.ok || (tt.ok && got != tt.want) {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v ok=%v", tt.in, got, err, tt.want, tt.ok)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	in := policy.Policy{KEKInterval: 365 * day, DEKMaxAge: 36 * time.Hour, DEKMaxEncryptions: 1000, RetirementDelay: 30 * day, RetainVersions: 3, RequireBackup: true}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"kekInterval":"365d"`, `"dekMaxAge":"36h0m0s"`, `"retirementDelay":"30d"`, `"requireBackup":true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON %s lacks %s", b, want)
		}
	}
	var out policy.Policy
	if err := json.Unmarshal(b, &out); err != nil || out != in {
		t.Fatalf("round trip = %+v, %v", out, err)
	}
}

func TestJSONRejectsMistakes(t *testing.T) {
	for name, in := range map[string]string{
		"unknown field":      `{"kekIntervall":"365d"}`,
		"bad duration":       `{"kekInterval":"a year"}`,
		"negative cap":       `{"dekMaxEncryptions":-1}`,
		"duration as number": `{"kekInterval":31536000}`,
	} {
		var p policy.Policy
		if err := json.Unmarshal([]byte(in), &p); err == nil {
			t.Errorf("%s: accepted %s", name, in)
		}
	}
	var partial policy.Policy
	if err := json.Unmarshal([]byte(`{"dekMaxAge":"7d"}`), &partial); err != nil || partial.DEKMaxAge != 7*day || partial.KEKInterval != 0 {
		t.Errorf("a partial policy = %+v, %v; unset fields must stay zero so they inherit", partial, err)
	}
}

func TestPurposeConfigsCarryPolicyIntoTheClient(t *testing.T) {
	s := policy.Set{
		Default:  policy.Policy{DEKMaxAge: 30 * day},
		Purposes: map[keyforge.Purpose]policy.Policy{"sessions": {DEKMaxAge: 7 * day, DEKMaxEncryptions: 5000}},
	}
	sel := algorithm.Selection{Allowed: []algorithm.ID{algorithm.AES256GCM}}
	got := s.PurposeConfigs(map[keyforge.Purpose]algorithm.Selection{"sessions": sel, "orders": {}})

	if c := got["sessions"]; c.MaxAge != 7*day || c.EncryptionCap != 5000 || len(c.Algorithms.Allowed) != 1 {
		t.Errorf("sessions = %+v", c)
	}
	if c := got["orders"]; c.MaxAge != 30*day || c.EncryptionCap != policy.DefaultDEKMaxEncryptions {
		t.Errorf("orders = %+v, want the default policy's values", c)
	}
	if len(got) != 2 {
		t.Errorf("%d purposes configured, want only those given", len(got))
	}
}
