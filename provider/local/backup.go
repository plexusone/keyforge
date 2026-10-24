package local

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// The state is authenticated with HMAC-SHA-256 under a key derived from the
// root key, and bound to the keyring's file name, so it cannot be edited or
// forged without the root key. A missing state file is accepted only beside a
// keyring at generation 1, which is what a crash between creating the keyring
// and writing its state leaves; for any later generation it is refused, so
// deleting the file does not switch rollback detection off. A copy of an
// older, genuine state file restored together with the matching older keyring
// is not detected: protecting against that needs state kept outside the
// keyring's directory.

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
	// read or does not authenticate under the root key. Remove it and open
	// with AcceptRollback to start fresh, which also forgets the high-water
	// mark.
	ErrCorruptBackupState = errors.New("local: the backup state file is unreadable")
	// ErrBackupStateMissing is returned when a keyring past generation 1 has
	// no backup state file, so whether it is older than one this host has
	// seen cannot be checked. Open with AcceptRollback once the keyring is
	// confirmed to be the intended one, for example after moving it to a new
	// host.
	ErrBackupStateMissing = errors.New("local: the backup state file is missing")
	// ErrUnauthenticatedBackupState is returned for a backup state file
	// written by a version of keyforge that did not authenticate it. Open
	// with AcceptRollback once, after confirming the keyring is the intended
	// one, to keep its contents and authenticate it.
	ErrUnauthenticatedBackupState = errors.New("local: the backup state file is not authenticated")
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
	Format       int       `json:"format,omitempty"` // set in files written before the state was authenticated
	Highest      uint64    `json:"highestGeneration"`
	Acknowledged uint64    `json:"acknowledgedGeneration"`
	At           time.Time `json:"acknowledgedAt,omitzero"`
	Note         string    `json:"note,omitempty"`
}

// backupEnvelope is the backup state file: the state and its MACs, one per
// root key it is authenticated under, keyed by the root key identifier in hex.
// There is one MAC except while the root key is being rotated, when the state
// carries one for the old key and one for the new, so that a crash on either
// side of the keyring write leaves state the keyring's root key opens.
type backupEnvelope struct {
	Format int               `json:"format"`
	State  json.RawMessage   `json:"state"`
	MACs   map[string][]byte `json:"macs"`
}

const (
	legacyBackupFormat = 1 // unauthenticated
	backupFormat       = 2
	infoBackupStateMAC = "keyforge/keyring/backup-state-mac/v1"
)

// stateKey is a root key identifier and the backup state MAC key derived from
// that root key.
type stateKey struct {
	id  [rootKeyIDSize]byte
	mac []byte
}

func (p *Provider) backupPath() string { return p.path + ".backup" }

// stateMAC authenticates the encoded state under key, bound to the keyring's
// file name so that the state of one keyring cannot stand in for another's
// under the same root key.
func (p *Provider) stateMAC(key, state []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(infoBackupStateMAC))
	m.Write([]byte{0})
	m.Write([]byte(filepath.Base(p.path)))
	m.Write([]byte{0})
	m.Write(state)
	return m.Sum(nil)
}

// errNoBackupState reports a missing backup state file to loadBackup's
// callers that treat it differently from empty state.
var errNoBackupState = errors.New("local: no backup state file")

// readBackup reads and authenticates the backup state under the root key in
// use. It returns errNoBackupState if there is no file, and
// ErrUnauthenticatedBackupState, with the file's unverified contents, for a
// file in the older unauthenticated format.
func (p *Provider) readBackup() (backupFile, error) {
	b, err := os.ReadFile(p.backupPath())
	if errors.Is(err, os.ErrNotExist) {
		return backupFile{}, errNoBackupState
	}
	if err != nil {
		return backupFile{}, fmt.Errorf("local: %w", err)
	}
	var env backupEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return backupFile{}, ErrCorruptBackupState
	}
	if env.Format == legacyBackupFormat {
		var f backupFile
		if err := json.Unmarshal(b, &f); err != nil {
			return backupFile{}, ErrCorruptBackupState
		}
		f.Format = 0
		return f, ErrUnauthenticatedBackupState
	}
	if env.Format != backupFormat || p.macKey == nil {
		return backupFile{}, ErrCorruptBackupState
	}
	mac, ok := env.MACs[hex.EncodeToString(p.rootID[:])]
	if !ok || !hmac.Equal(mac, p.stateMAC(p.macKey, env.State)) {
		return backupFile{}, fmt.Errorf("%w: it does not authenticate under the root key", ErrCorruptBackupState)
	}
	var f backupFile
	if err := json.Unmarshal(env.State, &f); err != nil {
		return backupFile{}, ErrCorruptBackupState
	}
	return f, nil
}

// loadBackup reads the backup state. A missing file is empty state.
func (p *Provider) loadBackup() (backupFile, error) {
	f, err := p.readBackup()
	if errors.Is(err, errNoBackupState) {
		return backupFile{}, nil
	}
	return f, err
}

// saveBackup writes the backup state authenticated under the root key in use.
func (p *Provider) saveBackup(f backupFile) error {
	return p.saveBackupUnder(f, stateKey{id: p.rootID, mac: p.macKey})
}

// saveBackupUnder writes the backup state authenticated under each of keys.
func (p *Provider) saveBackupUnder(f backupFile, keys ...stateKey) error {
	f.Format = 0
	state, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("local: %w", err)
	}
	env := backupEnvelope{Format: backupFormat, State: state, MACs: make(map[string][]byte, len(keys))}
	for _, k := range keys {
		if k.mac == nil {
			return ErrClosed
		}
		env.MACs[hex.EncodeToString(k.id[:])] = p.stateMAC(k.mac, state)
	}
	b, err := json.Marshal(env)
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
