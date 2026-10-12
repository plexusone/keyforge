package local

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/provider"
)

var t0 = time.Unix(1_700_000_000, 0).UTC()

func newKey(t *testing.T, p *Provider) provider.KeyRef {
	t.Helper()
	ref, err := p.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestBackupAcknowledgementLifecycle(t *testing.T) {
	p := mustCreate(t, newOpts(t, 1))

	st, err := p.BackupStatus(bg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 1 || st.Acknowledged != 0 || st.UpToDate() || st.Behind() != 1 {
		t.Fatalf("a new keyring: %+v, want generation 1, nothing acknowledged, behind by 1", st)
	}

	if err := p.AckBackup(bg, 1, t0, "offsite copy"); err != nil {
		t.Fatal(err)
	}
	st, _ = p.BackupStatus(bg)
	if !st.UpToDate() || st.Behind() != 0 || st.Acknowledged != 1 || !st.AcknowledgedAt.Equal(t0) || st.Note != "offsite copy" {
		t.Fatalf("after acknowledging: %+v", st)
	}

	// A change makes the keyring ahead of its backup until the new copy is acknowledged.
	ref := newKey(t, p)
	st, _ = p.BackupStatus(bg)
	if st.UpToDate() || st.Behind() != 1 || st.Generation != 2 {
		t.Fatalf("after a change: %+v, want behind by 1 at generation 2", st)
	}
	if _, err := p.Rotate(bg, ref); err != nil {
		t.Fatal(err)
	}
	st, _ = p.BackupStatus(bg)
	if st.Behind() != 2 {
		t.Fatalf("after two changes behind by %d, want 2", st.Behind())
	}

	if err := p.AckBackup(bg, 3, t0.Add(time.Hour), "second copy"); err != nil {
		t.Fatal(err)
	}
	if st, _ = p.BackupStatus(bg); !st.UpToDate() {
		t.Fatalf("not up to date after acknowledging the current generation: %+v", st)
	}
}

func TestAcknowledgementRules(t *testing.T) {
	p := mustCreate(t, newOpts(t, 1))
	newKey(t, p) // generation 2
	if err := p.AckBackup(bg, 2, t0, "a"); err != nil {
		t.Fatal(err)
	}
	if err := p.AckBackup(bg, 3, t0, "b"); !errors.Is(err, ErrAckAhead) {
		t.Errorf("acknowledging a generation not reached = %v, want ErrAckAhead", err)
	}
	if err := p.AckBackup(bg, 1, t0, "c"); !errors.Is(err, ErrAckRegressed) {
		t.Errorf("acknowledging an older generation = %v, want ErrAckRegressed", err)
	}
	// Repeating the same generation updates the note and time.
	if err := p.AckBackup(bg, 2, t0.Add(time.Minute), "again"); err != nil {
		t.Errorf("repeating an acknowledgement = %v", err)
	}
	if st, _ := p.BackupStatus(bg); st.Note != "again" || st.Acknowledged != 2 {
		t.Errorf("status = %+v", st)
	}
}

func TestAcknowledgementSurvivesReopen(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	newKey(t, p)
	if err := p.AckBackup(bg, 2, t0, "kept"); err != nil {
		t.Fatal(err)
	}
	re, err := Open(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	st, err := re.BackupStatus(bg)
	if err != nil || st.Acknowledged != 2 || st.Note != "kept" {
		t.Fatalf("after reopening: %+v, %v", st, err)
	}
}

// TestRestoringAnOlderKeyringIsDetected is success criterion 4: a backup that
// predates a rotation is reported when opened, before it can lose data.
func TestRestoringAnOlderKeyringIsDetected(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	ref := newKey(t, p)

	backup, err := os.ReadFile(opts.Path) // the copy an operator keeps, at generation 2
	if err != nil {
		t.Fatal(err)
	}
	v2, err := p.Rotate(bg, ref) // generation 3: data may now be wrapped under version 2
	if err != nil {
		t.Fatal(err)
	}
	p.Close()

	if err := os.WriteFile(opts.Path, backup, 0o600); err != nil { //nolint:gosec // G703: the path is a test temp directory; this is the mistaken restore
		t.Fatal(err)
	}
	_, err = Open(bg, opts)
	var re *RollbackError
	if !errors.Is(err, ErrKeyringRolledBack) || !errors.As(err, &re) || re.Found != 2 || re.Highest != 3 {
		t.Fatalf("Open = %v, want a RollbackError for generation 2 against 3", err)
	}

	// An operator who intended the restore says so, and learns what is missing.
	opts.AcceptRollback = true
	r, err := Open(bg, opts)
	if err != nil {
		t.Fatalf("Open with AcceptRollback: %v", err)
	}
	defer r.Close()
	if _, err := r.Wrap(bg, ref, v2, make([]byte, 32), nil); !errors.Is(err, provider.ErrVersionNotFound) {
		t.Fatalf("the restored keyring has version %d: %v", v2, err)
	}

	// Generations are never reused: the next write is above everything seen.
	if _, err := r.Rotate(bg, ref); err != nil {
		t.Fatal(err)
	}
	if r.Generation() != 4 {
		t.Fatalf("generation after a write following a rollback = %d, want 4", r.Generation())
	}
}

func TestRollbackClampsTheAcknowledgement(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	newKey(t, p)
	backup, _ := os.ReadFile(opts.Path) // generation 2
	newKey(t, p)                        // generation 3
	newKey(t, p)                        // generation 4
	if err := p.AckBackup(bg, 4, t0, "x"); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if err := os.WriteFile(opts.Path, backup, 0o600); err != nil { //nolint:gosec // G703: the path is a test temp directory
		t.Fatal(err)
	}
	opts.AcceptRollback = true
	r, err := Open(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	st, err := r.BackupStatus(bg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 2 || st.Acknowledged != 2 {
		t.Fatalf("status = %+v, want an acknowledgement no higher than the restored generation", st)
	}
}

func TestNewerKeyringThanSeenIsAccepted(t *testing.T) {
	// Another process advanced the file; this host has not seen that yet.
	opts := newOpts(t, 1)
	a := mustCreate(t, opts)
	b, err := Open(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	newKey(t, a)
	newKey(t, a)
	c, err := Open(bg, opts)
	if err != nil {
		t.Fatalf("Open of a keyring ahead of what was seen: %v", err)
	}
	defer c.Close()
	if c.Generation() != 3 {
		t.Fatalf("generation = %d, want 3", c.Generation())
	}
}

func TestCorruptBackupStateFailsClosed(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	p.Close()
	if err := os.WriteFile(opts.Path+".backup", []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bg, opts); !errors.Is(err, ErrCorruptBackupState) {
		t.Fatalf("Open = %v, want ErrCorruptBackupState", err)
	}
	if err := os.Remove(opts.Path + ".backup"); err != nil {
		t.Fatal(err)
	}
	r, err := Open(bg, opts)
	if err != nil {
		t.Fatalf("Open after removing the state file: %v", err)
	}
	r.Close()
}

func TestPeekReadsABackupWithoutTheRootKey(t *testing.T) {
	opts := newOpts(t, 1)
	p := mustCreate(t, opts)
	newKey(t, p)
	gen, id, err := Peek(opts.Path)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 2 || id != p.RootKeyID() {
		t.Fatalf("Peek = %d, %s; want 2, %s", gen, id, p.RootKeyID())
	}
	if _, _, err := Peek(opts.Path + ".missing"); !errors.Is(err, ErrKeyringNotFound) {
		t.Fatalf("Peek of a missing file = %v", err)
	}
	junk := opts.Path + ".junk"
	if err := os.WriteFile(junk, []byte("this is not a keyring at all, just text....."), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Peek(junk); !errors.Is(err, ErrCorruptKeyring) {
		t.Fatalf("Peek of a non-keyring = %v, want ErrCorruptKeyring", err)
	}
}

func TestGenerationIncreasesWithEveryChange(t *testing.T) {
	p := mustCreate(t, newOpts(t, 1))
	var seen []uint64
	seen = append(seen, p.Generation())
	ref := newKey(t, p)
	seen = append(seen, p.Generation())
	if _, err := p.Rotate(bg, ref); err != nil {
		t.Fatal(err)
	}
	seen = append(seen, p.Generation())
	if err := p.Destroy(bg, ref, 1); err != nil {
		t.Fatal(err)
	}
	seen = append(seen, p.Generation())
	if !slices.Equal(seen, []uint64{1, 2, 3, 4}) {
		t.Fatalf("generations = %v, want 1 2 3 4", seen)
	}
	// Reads do not change it.
	if err := p.Health(bg); err != nil {
		t.Fatal(err)
	}
	if p.Generation() != 4 {
		t.Fatalf("a read changed the generation to %d", p.Generation())
	}
}

// A keyring replaced by an older copy while the provider is running must not
// be written on top of: that would give the stale content a new generation and
// pass it through the rollback check at Open.
func TestOlderKeyringPutInPlaceWhileRunningIsRefused(t *testing.T) {
	opts := newOpts(t, 3)
	p := mustCreate(t, opts)
	old, err := os.ReadFile(opts.Path)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := p.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM})
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: the path is inside this test's own temporary directory
	if err := os.WriteFile(opts.Path, old, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := p.Rotate(bg, ref); !errors.Is(err, ErrKeyringRolledBack) {
		t.Fatalf("Rotate over an older keyring = %v, want ErrKeyringRolledBack", err)
	}
	if _, err := p.CreateKey(bg, provider.KeySpec{Purpose: "orders", Algorithm: algorithm.AES256GCM}); !errors.Is(err, ErrKeyringRolledBack) {
		t.Fatalf("CreateKey over an older keyring = %v, want ErrKeyringRolledBack", err)
	}
	// The file is still the older copy: nothing was written on top of it.
	now, err := os.ReadFile(opts.Path)
	if err != nil || !bytes.Equal(now, old) {
		t.Fatalf("the keyring file changed: %v", err)
	}
	// And it is still refused when opened, rather than laundered.
	if _, err := Open(bg, opts); !errors.Is(err, ErrKeyringRolledBack) {
		t.Fatalf("Open = %v, want ErrKeyringRolledBack", err)
	}
}
