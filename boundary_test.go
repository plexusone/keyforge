package keyforge_test

import (
	"bytes"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/plexusone/keyforge"

// cryptoPath is the set of packages that touch key material, with metrics,
// which they report through and which holds only counters and bounded labels.
// Each may import the standard library and the other members, and nothing else.
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
				if !slices.Contains(cryptoPath, dep) {
					t.Errorf("%s depends on %s, which is outside the crypto path and the standard library", pkg, dep)
				}
			}
		})
	}
}
