package keyforge_test

import (
	"bytes"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/plexusone/keyforge"

// allowedModules are the modules, other than keyforge's own and the standard
// library, that the crypto path may import. Each is a recorded decision (see
// AGENTS.md and the TRD), not a convenience.
//
//   - github.com/grokify/oscompat: operating-system differences (file handling,
//     paths). It has no dependencies of its own, which this test enforces
//     transitively: a dependency it gained would be neither in this list nor in
//     the crypto path, and would fail.
var allowedModules = []string{
	"github.com/grokify/oscompat",
}

// permitted reports whether a package outside the standard library may appear in
// the crypto path's dependencies: a member of the path, or a package of an
// allowed module (the module's own path or one beneath it).
func permitted(dep string) bool {
	if slices.Contains(cryptoPath, dep) {
		return true
	}
	for _, m := range allowedModules {
		if dep == m || strings.HasPrefix(dep, m+"/") {
			return true
		}
	}
	return false
}

// cryptoPath is the set of packages that touch key material, with metrics,
// which they report through and which holds only counters and bounded labels.
// Each may import the standard library, the other members and the allowed
// modules below, and nothing else.
// That is what makes the code that handles keys reviewable: the store, the
// jobs, the CLI and every third-party module sit outside it, and none can be
// reached from it.
var cryptoPath = []string{
	module,
	module + "/metrics",
	module + "/algorithm",
	module + "/envelope",
	module + "/provider",
	module + "/provider/local",
}

func TestCryptoPathImportsOnlyTheStandardLibrary(t *testing.T) {
	for _, pkg := range cryptoPath {
		t.Run(strings.TrimPrefix(pkg, module), func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", pkg)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("go list %s: %v\n%s", pkg, err, stderr.String())
			}
			for _, dep := range strings.Fields(stdout.String()) {
				if !permitted(dep) {
					t.Errorf("%s depends on %s, which is outside the crypto path, the allowed modules and the standard library", pkg, dep)
				}
			}
		})
	}
}

func TestPermittedMatchesWholeModulesOnly(t *testing.T) {
	for dep, want := range map[string]bool{
		module + "/algorithm":                     true,
		module + "/sqlstore":                      false,
		module + "/jobs":                          false,
		"github.com/grokify/oscompat":             true,
		"github.com/grokify/oscompat/fs":          true,
		"github.com/grokify/oscompat/paths":       true,
		"github.com/grokify/oscompatible":         false,
		"github.com/grokify/mogo/log/slogutil":    false,
		"github.com/someone/else/oscompat":        false,
		"golang.org/x/crypto/hkdf":                false,
		"github.com/plexusone/omniworkflow/types": false,
		"github.com/spf13/cobra":                  false,
		"entgo.io/ent":                            false,
		"modernc.org/sqlite":                      false,
	} {
		if got := permitted(dep); got != want {
			t.Errorf("permitted(%q) = %v, want %v", dep, got, want)
		}
	}
}
