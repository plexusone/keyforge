package local

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/provider"
)

// crashAt returns a hook that stops a write at the named stage as a killed
// process would: the files are left exactly as they are at that moment.
func crashAt(stage string) func(string) error {
	return func(s string) error {
		if s == stage {
			return errSimulatedCrash
		}
		return nil
	}
}

// snapshot returns the names in dir.
func snapshot(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func tempFiles(names []string) []string {
	var out []string
	for _, n := range names {
		if strings.Contains(n, tempMarker) {
			out = append(out, n)
		}
	}
	return out
}

// TestCrashAtEveryStageLeavesAWholeKeyring stops a write at each stage and
// checks that the keyring that remains is the old one or the new one, whole,
// and that nothing about the crash blocks the next writer.
func TestCrashAtEveryStageLeavesAWholeKeyring(t *testing.T) {
	stages := []struct {
		stage    string
		wantNew  bool // whether the new keyring is the one on disk afterwards
		wantTemp bool // whether a temporary file is left behind
	}{
		{"temp-created", false, true},
		{"temp-written", false, true},
		{"temp-synced", false, true},
		{"renamed", true, false},
		{"dir-synced", true, false},
	}
	for _, tt := range stages {
		t.Run(tt.stage, func(t *testing.T) {
			opts := newOpts(t, 1)
			p := mustCreate(t, opts)
			ref := newKey(t, p) // generation 2
			dek, aad := bytes.Repeat([]byte{7}, 32), []byte("a")
			w1, err := p.Wrap(bg, ref, 1, dek, aad)
			if err != nil {
				t.Fatal(err)
			}

			p.hook = crashAt(tt.stage)
			_, err = p.Rotate(bg, ref) // the write that "crashes"
			if !errors.Is(err, errSimulatedCrash) {
				t.Fatalf("Rotate = %v, want the simulated crash", err)
			}
			p.Close()

			names := snapshot(t, filepath.Dir(opts.Path))
			if got := len(tempFiles(names)) > 0; got != tt.wantTemp {
				t.Fatalf("temporary files left = %v (%v), want %v", got, names, tt.wantTemp)
			}

			// A new process opens whatever is there: whole, and either the old
			// state or the new one.
			r, err := Open(bg, opts)
			if err != nil {
				t.Fatalf("Open after a crash at %s: %v", tt.stage, err)
			}
			defer r.Close()
			wantGen, wantVersions := uint64(2), 1
			if tt.wantNew {
				wantGen, wantVersions = 3, 2
			}
			k := r.st.keys[ref.ID]
			if r.Generation() != wantGen || len(k.versions) != wantVersions || k.latest != uint32(wantVersions) { //nolint:gosec // G115: a small count
				t.Fatalf("after a crash at %s: generation %d with %d versions, want %d with %d",
					tt.stage, r.Generation(), len(k.versions), wantGen, wantVersions)
			}
			if got, err := r.Unwrap(bg, ref, 1, w1, aad); err != nil || !bytes.Equal(got, dek) {
				t.Fatalf("a key wrapped before the crash: %v", err)
			}

			// The next writer proceeds, and cleans up what the crash left.
			r.hook = nil
			if _, err := r.Rotate(bg, ref); err != nil {
				t.Fatalf("the next write after a crash: %v", err)
			}
			if left := tempFiles(snapshot(t, filepath.Dir(opts.Path))); len(left) != 0 {
				t.Fatalf("temporary files survived the next write: %v", left)
			}
			if err := r.Health(bg); err != nil {
				t.Fatalf("Health: %v", err)
			}
		})
	}
}

// TestFailedWriteLeavesTheProviderUnchanged checks that a write that fails
// without crashing does not change what the provider believes, and cleans up.
func TestFailedWriteLeavesTheProviderUnchanged(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	ref := newKey(t, p)
	gen := p.Generation()

	fail := errors.New("disk full")
	p.hook = func(s string) error {
		if s == "temp-written" {
			return fail
		}
		return nil
	}
	if _, err := p.Rotate(bg, ref); !errors.Is(err, fail) {
		t.Fatalf("Rotate = %v, want the write error", err)
	}
	if p.Generation() != gen {
		t.Fatalf("generation = %d after a failed write, want %d", p.Generation(), gen)
	}
	if left := tempFiles(snapshot(t, filepath.Dir(opts.Path))); len(left) != 0 {
		t.Fatalf("a failed write left %v", left)
	}
	// The failed rotation did not happen: the next one gets the next version.
	p.hook = nil
	v, err := p.Rotate(bg, ref)
	if err != nil || v != 2 {
		t.Fatalf("Rotate after a failed write = %d, %v, want version 2", v, err)
	}
}

// TestCrashBetweenKeyringAndBackupStateIsNotARollback checks the ordering that
// makes the backup state safe: it is written after the keyring, so a crash
// between the two can only leave its high-water mark behind, never ahead.
func TestCrashBetweenKeyringAndBackupStateIsNotARollback(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	ref := newKey(t, p)
	data, err := os.ReadFile(opts.Path + ".backup") // backup state at 2
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Rotate(bg, ref); err != nil { // generation 3, backup state at 3
		t.Fatal(err)
	}
	p.Close()

	// Put the backup state back to what it would be had the crash happened
	// after the keyring write and before the state write.
	if err := os.WriteFile(opts.Path+".backup", data, 0o600); err != nil { //nolint:gosec // G703: the path is a test temp directory
		t.Fatal(err)
	}
	r, err := Open(bg, opts)
	if err != nil {
		t.Fatalf("Open = %v, want no false rollback", err)
	}
	defer r.Close()
	if r.Generation() != 3 {
		t.Fatalf("generation = %d, want 3", r.Generation())
	}
}

// TestTornFileIsDetected writes partial prefixes of a valid keyring over the
// file, as a filesystem without atomic rename might leave after a crash.
func TestTornFileIsDetected(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	newKey(t, p)
	whole, err := os.ReadFile(opts.Path)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()

	for n := 0; n < len(whole); n++ {
		if err := os.WriteFile(opts.Path, whole[:n], 0o600); err != nil { //nolint:gosec // G703: the path is a test temp directory
			t.Fatal(err)
		}
		_, err := Open(bg, opts)
		if err == nil {
			t.Fatalf("a keyring cut at %d of %d bytes opened", n, len(whole))
		}
		if !errors.Is(err, ErrCorruptKeyring) && !errors.Is(err, ErrWrongRootKey) {
			t.Fatalf("a keyring cut at %d bytes: %v, want a typed refusal", n, err)
		}
	}
}

// TestKillDuringWrites kills a process that is rotating a key in a loop, at
// random moments, and checks after each kill that the keyring is whole and
// consistent and that the dead process's lock does not block the next writer.
func TestKillDuringWrites(t *testing.T) {
	if os.Getenv("KEYFORGE_CRASH_HELPER") == "1" {
		crashHelper()
		return
	}
	if testing.Short() {
		t.Skip("kills real processes")
	}

	opts := newOpts(t, 1)
	seed := mustCreate(t, opts)
	ref := newKey(t, seed)
	seed.Close()
	rootHex := fmt.Sprintf("%x", rootBytes(t, opts.Root))

	// A fixed seed makes the kill timing reproducible. This is test scheduling, not cryptography.
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: reproducible test timing, not key material
	var lastGen uint64
	var midWrite int // rounds in which the kill left a temporary file: it landed inside a write
	const rounds = 40
	for round := range rounds {
		cmd := exec.Command(os.Args[0], "-test.run=^TestKillDuringWrites$", "-test.count=1") //nolint:gosec // G204: re-runs this test binary as a helper
		cmd.Env = append(os.Environ(),
			"KEYFORGE_CRASH_HELPER=1",
			"KEYFORGE_CRASH_PATH="+opts.Path,
			"KEYFORGE_CRASH_ROOT="+rootHex,
			"KEYFORGE_CRASH_KEY="+ref.ID.String(),
		)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(out).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "ready" {
			_ = cmd.Process.Kill()
			t.Fatalf("round %d: helper did not start: %q, %v", round, line, err)
		}
		time.Sleep(time.Duration(rng.IntN(40)) * time.Millisecond)
		if err := cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = cmd.Wait() //nolint:errcheck // the process was killed; its exit status is expected to be an error
		if len(tempFiles(snapshot(t, filepath.Dir(opts.Path)))) > 0 {
			midWrite++
		}

		r, err := Open(bg, opts)
		if err != nil {
			t.Fatalf("round %d: the keyring did not open after a kill: %v", round, err)
		}
		k := r.st.keys[ref.ID]
		// Each change is one new version and one new generation, so a torn or
		// mixed state breaks this relation.
		if uint64(len(k.versions)) != uint64(k.latest) || r.Generation() != uint64(k.latest)+1 {
			t.Fatalf("round %d: generation %d with %d versions, latest %d", round, r.Generation(), len(k.versions), k.latest)
		}
		for n := uint32(1); n <= k.latest; n++ {
			v, ok := k.versions[n]
			if !ok || v.destroyed || len(v.material) != algorithm.AES256GCM.KeySize() {
				t.Fatalf("round %d: version %d is missing or damaged", round, n)
			}
		}
		if r.Generation() < lastGen {
			t.Fatalf("round %d: generation went backwards from %d to %d", round, lastGen, r.Generation())
		}

		// The dead process's lock does not wedge the next writer.
		ctx, cancel := context.WithTimeout(bg, 5*time.Second)
		_, err = r.Rotate(ctx, ref)
		cancel()
		if err != nil {
			t.Fatalf("round %d: the next write after a kill: %v", round, err)
		}
		lastGen = r.Generation() // the write above counts, so a later round must not go below it
		r.Close()
	}
	if left := tempFiles(snapshot(t, filepath.Dir(opts.Path))); len(left) > 1 {
		t.Fatalf("temporary files accumulated: %v", left)
	}
	t.Logf("%d of %d kills landed inside a write", midWrite, rounds)
	if midWrite == 0 {
		t.Error("no kill landed inside a write, so the test did not exercise what it is for")
	}
}

// crashHelper rotates a key as fast as it can until it is killed.
func crashHelper() {
	opts := Options{
		Path: os.Getenv("KEYFORGE_CRASH_PATH"),
		Root: StaticSource(mustDecodeHex(os.Getenv("KEYFORGE_CRASH_ROOT"))),
	}
	p, err := Open(context.Background(), opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(2)
	}
	var id [16]byte
	copy(id[:], mustDecodeHex(os.Getenv("KEYFORGE_CRASH_KEY")))
	ref := provider.KeyRef{ID: id, Provider: p.Name(), ProviderRef: "local/" + os.Getenv("KEYFORGE_CRASH_KEY")}
	fmt.Println("ready")
	for {
		if _, err := p.Rotate(context.Background(), ref); err != nil {
			fmt.Fprintln(os.Stderr, "helper:", err)
			os.Exit(3)
		}
	}
}

func mustDecodeHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range []byte(s[2*i : 2*i+2]) {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			}
		}
		b[i] = v
	}
	return b
}

func rootBytes(t *testing.T, src RootKeySource) []byte {
	t.Helper()
	b, err := src.RootKey(bg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
