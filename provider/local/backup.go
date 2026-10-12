package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Backup state is kept in a small file beside the keyring, named
// "<keyring>.backup". It is not part of the keyring: recording an
// acknowledgement there would itself change the keyring's generation, which
// would leave the keyring always one generation ahead of its acknowledgement.
//
// It holds two things:
//
//   - the highest generation this host has seen, so that restoring an older
//     copy of the keyring is detected when it is opened, before it can lose
//     data wrapped under a version the old copy lacks; and
//   - the generation the operator last acknowledged as safely backed up, so
//     status can report a keyring that is ahead of its backup.
//
// The file is not authenticated. Someone who can write beside the keyring can
// hide staleness, but they can already replace the keyring; its purpose is to
// catch mistakes, not an attacker with the host.

// Typed errors for backup state.
var (
	// ErrKeyringRolledBack is returned when the keyring on disk has a lower
	// generation than this host has seen: an older copy was restored over it.
	// Data wrapped under versions the older copy lacks cannot be unwrapped.
	ErrKeyringRolledBack = errors.New("local: the keyring is older than one this host has seen")
	// ErrAckAhead is returned when acknowledging a generation the keyring has
	// not reached.
	ErrAckAhead = errors.New("local: cannot acknowledge a generation the keyring has not reached")
	// ErrAckRegressed is returned when acknowledging a generation lower than
	// the one already acknowledged.
	ErrAckRegressed = errors.New("local: cannot acknowledge an older generation than the last acknowledgement")
	// ErrCorruptBackupState is returned when the backup state file cannot be
	// read. Remove it to start fresh, which also forgets the high-water mark.
	ErrCorruptBackupState = errors.New("local: the backup state file is unreadable")
)

// RollbackError describes a keyring found older than one already seen. It
// matches [ErrKeyringRolledBack].
type RollbackError struct {
	// Found is the generation of the keyring on disk.
	Found uint64
	// Highest is the highest generation this host has seen.
	Highest uint64
}

// Error implements error.
func (e *RollbackError) Error() string {
	return fmt.Sprintf("%v: found generation %d, seen %d", ErrKeyringRolledBack, e.Found, e.Highest)
}

// Unwrap lets [errors.Is] match [ErrKeyringRolledBack].
func (e *RollbackError) Unwrap() error { return ErrKeyringRolledBack }

// BackupStatus reports how the keyring stands against its last acknowledged
// backup.
type BackupStatus struct {
	// Generation is the keyring's current generation.
	Generation uint64
	// Acknowledged is the generation an operator last confirmed as safely
	// backed up, or zero if none has been.
	Acknowledged uint64
	// AcknowledgedAt is when it was acknowledged, from the caller's clock.
	AcknowledgedAt time.Time
	// Note is the free text given with the acknowledgement, such as where the
	// copy is kept.
	Note string
}

// Behind returns how many generations the keyring is ahead of its backup.
func (s BackupStatus) Behind() uint64 {
	if s.Acknowledged >= s.Generation {
		return 0
	}
	return s.Generation - s.Acknowledged
}

// UpToDate reports whether the acknowledged backup is the current keyring. A
// policy that requires a verified backup waits until this is true.
func (s BackupStatus) UpToDate() bool { return s.Acknowledged >= s.Generation }

type backupFile struct {
	Format       int       `json:"format"`
	Highest      uint64    `json:"highestGeneration"`
	Acknowledged uint64    `json:"acknowledgedGeneration"`
	At           time.Time `json:"acknowledgedAt,omitzero"`
	Note         string    `json:"note,omitempty"`
}

const backupFormat = 1

func (p *Provider) backupPath() string { return p.path + ".backup" }

// loadBackup reads the backup state. A missing file is empty state.
func (p *Provider) loadBackup() (backupFile, error) {
	b, err := os.ReadFile(p.backupPath())
	if errors.Is(err, os.ErrNotExist) {
		return backupFile{Format: backupFormat}, nil
	}
	if err != nil {
		return backupFile{}, fmt.Errorf("local: %w", err)
	}
	var f backupFile
	if err := json.Unmarshal(b, &f); err != nil || f.Format != backupFormat {
		return backupFile{}, ErrCorruptBackupState
	}
	return f, nil
}

func (p *Provider) saveBackup(f backupFile) error {
	f.Format = backupFormat
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("local: %w", err)
	}
	return atomicWrite(p.backupPath(), b, nil)
}

// notePersisted records that generation gen has been written. It is called
// after the keyring write succeeds, so a failure between the two leaves the
// high-water mark one behind, which weakens detection by a generation and
// never produces a false rollback. The caller holds the file lock.
func (p *Provider) notePersisted(gen uint64) error {
	f, err := p.loadBackup()
	if err != nil {
		return err
	}
	if gen <= f.Highest {
		return nil
	}
	f.Highest = gen
	return p.saveBackup(f)
}

// nextGeneration returns the generation to write after a file at fileGen. It is
// above everything this host has seen, so generations stay unique even after a
// rollback has been accepted. The caller holds the file lock.
func (p *Provider) nextGeneration(fileGen uint64) (uint64, error) {
	f, err := p.loadBackup()
	if err != nil {
		return 0, err
	}
	return max(fileGen, f.Highest) + 1, nil
}

// BackupStatus returns the keyring's current generation and the last
// acknowledged backup.
func (p *Provider) BackupStatus(ctx context.Context) (BackupStatus, error) {
	if err := ctx.Err(); err != nil {
		return BackupStatus{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h, err := p.currentHeader()
	if err != nil {
		return BackupStatus{}, err
	}
	f, err := p.loadBackup()
	if err != nil {
		return BackupStatus{}, err
	}
	return BackupStatus{Generation: h.generation, Acknowledged: f.Acknowledged, AcknowledgedAt: f.At, Note: f.Note}, nil
}

// UpToDate reports whether the acknowledged backup is the current keyring. It
// satisfies the rotation package's backup check, which waits on it when policy
// requires a verified backup.
func (p *Provider) UpToDate(ctx context.Context) (bool, error) {
	st, err := p.BackupStatus(ctx)
	if err != nil {
		return false, err
	}
	return st.UpToDate(), nil
}

// AckBackup records that the operator has safely stored a copy of the keyring
// at generation gen. It cannot acknowledge a generation the keyring has not
// reached, or one older than the last acknowledgement. Repeating the same
// generation is allowed and updates the time and note.
//
// at is the time of the acknowledgement from the caller's clock.
func (p *Provider) AckBackup(ctx context.Context, gen uint64, at time.Time, note string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	unlock, err := lockFile(ctx, p.lockPath)
	if err != nil {
		return err
	}
	defer unlock()

	h, err := p.currentHeader()
	if err != nil {
		return err
	}
	f, err := p.loadBackup()
	if err != nil {
		return err
	}
	switch {
	case gen > h.generation:
		return fmt.Errorf("%w: generation %d, keyring is at %d", ErrAckAhead, gen, h.generation)
	case gen < f.Acknowledged:
		return fmt.Errorf("%w: generation %d, last acknowledged %d", ErrAckRegressed, gen, f.Acknowledged)
	}
	f.Acknowledged, f.At, f.Note = gen, at, note
	f.Highest = max(f.Highest, h.generation)
	return p.saveBackup(f)
}

// currentHeader reads the header of the keyring file on disk, which another
// process may have advanced. It checks the root key identifier but does not
// decrypt. The caller holds p.mu.
func (p *Provider) currentHeader() (header, error) {
	file, err := os.ReadFile(p.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return header{}, fmt.Errorf("%w: %s", ErrKeyringNotFound, p.path)
		}
		return header{}, fmt.Errorf("local: %w", err)
	}
	h, err := peek(file)
	if err != nil {
		return header{}, err
	}
	if h.rootKeyID != p.rootID {
		return header{}, ErrWrongRootKey
	}
	return h, nil
}

// Peek reports the generation and root key identifier of a keyring file, such
// as a backup copy, without a root key. It is how an operator or the recovery
// drill compares a copy with the live keyring before restoring it.
func Peek(path string) (generation uint64, rootKeyID string, err error) {
	file, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, "", fmt.Errorf("%w: %s", ErrKeyringNotFound, path)
		}
		return 0, "", fmt.Errorf("local: %w", err)
	}
	h, err := peek(file)
	if err != nil {
		return 0, "", err
	}
	return h.generation, fmt.Sprintf("%x", h.rootKeyID[:]), nil
}
