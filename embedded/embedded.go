// Package embedded wires keyforge for one host: a keyring file, a SQLite
// registry, the lifecycle jobs and, optionally, the HTTP control plane, all
// from a directory and a root key source.
//
// It is the setup most deployments start with, and it is a convenience over
// the same packages a larger deployment assembles itself: nothing here is
// reachable only through it. Open returns the pieces, so a host that outgrows
// the single-host layout keeps using the [keyforge.Client], the
// [rotate.Rotator] and the rest, and swaps the store or the provider.
//
// # Layout
//
// Everything lives in one directory, except the root key, which must not:
//
//	keyring.kf    the keyring, sealed under a key derived from the root key
//	registry.db   the registry (SQLite, with its -wal and -shm files)
//	runs/         the state of lifecycle jobs, so they resume after a restart
//
// # Backup
//
// A backup is the keyring and the registry together. Either alone is useless
// or dangerous: a registry without its keyring names keys that cannot be
// unwrapped, and a keyring without its registry cannot say which data keys it
// protects. Take them at the same time, acknowledge the keyring backup so
// rotation can rely on it, and keep the root key somewhere else again: it is
// the one secret that cannot be recovered from either. [System.BackupRegistry]
// writes a consistent registry copy while the system is running.
package embedded

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/jobs"
	"github.com/plexusone/keyforge/metrics"
	"github.com/plexusone/keyforge/policy"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/provider/local"
	"github.com/plexusone/keyforge/rotate"
	"github.com/plexusone/keyforge/service"
	"github.com/plexusone/keyforge/sqlstore"
	"github.com/plexusone/keyforge/status"
)

// File and directory names inside [Options.Dir].
const (
	KeyringFile  = "keyring.kf"
	RegistryFile = "registry.db"
	RunsDir      = "runs"
)

// ErrKeyringMissing is returned when the registry holds keys but the keyring
// file is gone. Creating a new keyring would not recover them: it would start
// an empty one beside a registry that names keys it does not hold, and every
// operation would fail, or worse, look like a fresh start. Restore the keyring
// from backup.
var ErrKeyringMissing = errors.New("embedded: the registry holds keys but the keyring file is missing; restore the keyring from backup")

// PurposeOptions configures one purpose.
type PurposeOptions struct {
	// Algorithms narrows the algorithms for the purpose. The zero value uses
	// the active profile's.
	Algorithms algorithm.Selection
	// PerSubject gives each subject its own data keys, so a subject can be
	// shredded. See [keyforge.PurposeConfig].
	PerSubject bool
}

// Options configures [Open].
type Options struct {
	// Dir holds the keyring, the registry and the job state. It is created if
	// it does not exist. Required.
	Dir string
	// Root supplies the root key that protects the keyring. It must not be a
	// file in Dir. Required.
	Root local.RootKeySource
	// Purposes lists the purposes to manage. Each gets a KEK on first start.
	// Required.
	Purposes map[keyforge.Purpose]PurposeOptions
	// Policy is the rotation and retirement policy. The zero value is the
	// default policy.
	Policy policy.Set
	// Selector chooses the algorithm profile. The zero value uses the default
	// profile.
	Selector *algorithm.Selector
	// Guard is consulted before a version is retired or destroyed. With none,
	// nothing is retired or destroyed.
	Guard guard.Guard
	// Audit receives lifecycle events. The default discards them.
	Audit audit.Sink
	// Metrics receives operation and rotation counts. The default discards them.
	Metrics metrics.Metrics
	// Clock defaults to the system clock.
	Clock keyforge.Clock
	// Authorizer is asked before every control-plane action. Without one the
	// system has no control plane and [System.Handler] returns an error: the
	// control plane is never open by default.
	Authorizer service.Authorizer
	// Jobs tunes the scheduler; its provider, rotator, store and purposes are
	// supplied here and ignored if set.
	Jobs jobs.SchedulerOptions
}

// System is a running single-host keyforge: the pieces, wired.
type System struct {
	// Client encrypts and decrypts.
	Client *keyforge.Client
	// Rotator performs rotation, re-wrapping, retirement and the emergency
	// procedures.
	Rotator *rotate.Rotator
	// Reporter builds the status report.
	Reporter *status.Reporter
	// Registry is the SQLite registry.
	Registry *sqlstore.Store
	// Keyring is the keyring-file provider.
	Keyring *local.Provider
	// Jobs runs the lifecycle jobs. [System.Run] starts it.
	Jobs *jobs.Embedded

	svc      *service.Service
	purposes []keyforge.Purpose
}

// Open opens the system in o.Dir, creating the keyring and the registry on
// first use and a KEK for each purpose that has none. It is idempotent: opening
// an existing directory changes nothing.
func Open(ctx context.Context, o Options) (*System, error) {
	switch {
	case o.Dir == "":
		return nil, errors.New("embedded: Options.Dir is required")
	case o.Root == nil:
		return nil, errors.New("embedded: Options.Root is required")
	case len(o.Purposes) == 0:
		return nil, errors.New("embedded: at least one purpose is required")
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("embedded: %w", err)
	}
	if err := os.Chmod(o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("embedded: %w", err)
	}

	reg, err := sqlstore.OpenSQLite(ctx, filepath.Join(o.Dir, RegistryFile))
	if err != nil {
		return nil, err
	}
	sys, err := open(ctx, o, reg)
	if err != nil {
		return nil, errors.Join(err, reg.Close())
	}
	return sys, nil
}

func open(ctx context.Context, o Options, reg *sqlstore.Store) (*System, error) {
	kr, err := openKeyring(ctx, o, reg)
	if err != nil {
		return nil, err
	}
	sys, err := wire(ctx, o, reg, kr)
	if err != nil {
		return nil, errors.Join(err, kr.Close())
	}
	return sys, nil
}

// openKeyring opens the keyring, or creates it if this is a first start. A
// missing keyring beside a registry that holds keys is an error, not a first
// start.
func openKeyring(ctx context.Context, o Options, reg *sqlstore.Store) (*local.Provider, error) {
	lo := local.Options{Path: filepath.Join(o.Dir, KeyringFile), Root: o.Root}
	kr, err := local.Open(ctx, lo)
	switch {
	case err == nil:
		return kr, nil
	case !errors.Is(err, local.ErrKeyringNotFound):
		return nil, err
	}
	keks, err := reg.ListKEKs(ctx)
	if err != nil {
		return nil, err
	}
	if len(keks) > 0 {
		return nil, ErrKeyringMissing
	}
	return local.Create(ctx, lo)
}

func wire(ctx context.Context, o Options, reg *sqlstore.Store, kr *local.Provider) (*System, error) {
	provs := []provider.Provider{kr}
	purposes := make([]keyforge.Purpose, 0, len(o.Purposes))
	selections := make(map[keyforge.Purpose]algorithm.Selection, len(o.Purposes))
	for p, po := range o.Purposes {
		purposes = append(purposes, p)
		selections[p] = po.Algorithms
	}
	configs := o.Policy.PurposeConfigs(selections)
	for p, po := range o.Purposes {
		cfg := configs[p]
		cfg.PerSubject = po.PerSubject
		configs[p] = cfg
	}

	client, err := keyforge.New(keyforge.Options{
		Store: reg, Providers: provs, Selector: o.Selector, Purposes: configs,
		Clock: o.Clock, Metrics: o.Metrics,
	})
	if err != nil {
		return nil, err
	}
	rot, err := rotate.New(rotate.Options{
		Store: reg, Providers: provs, Policy: o.Policy,
		Backups: map[string]rotate.Backup{kr.Name(): kr},
		Clock:   o.Clock, Audit: o.Audit, Guard: o.Guard, Metrics: o.Metrics, Epochs: client,
	})
	if err != nil {
		return nil, err
	}
	for _, p := range purposes {
		if _, err := rot.EnsureKEK(ctx, p, kr.Name()); err != nil && !errors.Is(err, audit.ErrNotRecorded) {
			return nil, fmt.Errorf("embedded: starting purpose %q: %w", string(p), err)
		}
	}

	jo := o.Jobs
	jo.Rotator, jo.Store, jo.Purposes = rot, reg, purposes
	jo.Clock, jo.Audit, jo.Metrics = o.Clock, o.Audit, o.Metrics
	runner, err := jobs.NewEmbedded(jobs.EmbeddedOptions{
		SchedulerOptions: jo,
		StateDir:         filepath.Join(o.Dir, RunsDir),
	})
	if err != nil {
		return nil, err
	}

	rep, err := status.New(status.Options{
		Store: reg, Rotator: rot, Providers: provs, Purposes: purposes, Policy: o.Policy,
		Selector: o.Selector, Scheduler: runner.Scheduler, Clock: o.Clock,
		Backups: map[string]status.BackupFunc{kr.Name(): status.LocalBackup(kr)},
	})
	if err != nil {
		return nil, err
	}

	sys := &System{
		Client: client, Rotator: rot, Reporter: rep, Registry: reg, Keyring: kr, Jobs: runner,
		purposes: purposes,
	}
	if o.Authorizer != nil {
		sys.svc, err = service.New(service.Options{
			Store: reg, Rotator: rot, Reporter: rep, Authorizer: o.Authorizer, Verifier: client,
			Backups: map[string]service.BackupAcker{kr.Name(): kr},
			Audit:   o.Audit, Clock: o.Clock,
		})
		if err != nil {
			return nil, err
		}
	}
	return sys, nil
}

// Handler returns the HTTP control plane. It is an error to ask for it when
// [Options.Authorizer] was not set.
func (s *System) Handler() (http.Handler, error) {
	if s.svc == nil {
		return nil, errors.New("embedded: no control plane: Options.Authorizer was not set")
	}
	return s.svc, nil
}

// Purposes returns the purposes the system manages.
func (s *System) Purposes() []keyforge.Purpose {
	return append([]keyforge.Purpose(nil), s.purposes...)
}

// Run runs the lifecycle jobs, resuming any a previous process left unfinished,
// until ctx is cancelled. A host that drives the scheduler from its own timer
// calls Jobs.Work and Jobs.Scheduler.Tick instead.
func (s *System) Run(ctx context.Context) error { return s.Jobs.Run(ctx) }

// BackupRegistry writes a consistent copy of the registry to path, which must
// not exist. The keyring is backed up by copying its file; acknowledge it with
// the keyring's AckBackup afterwards.
func (s *System) BackupRegistry(ctx context.Context, path string) error {
	return s.Registry.Backup(ctx, path)
}

// Close releases the registry and the keyring. Stop Run first.
func (s *System) Close() error {
	return errors.Join(s.Registry.Close(), s.Keyring.Close())
}

// Ready reports whether the system can serve: the registry answers and the
// keyring is healthy. It is for a liveness endpoint, and says nothing about
// whether anything is overdue; the status report does that.
func (s *System) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.Registry.Ping(ctx); err != nil {
		return fmt.Errorf("embedded: registry: %w", err)
	}
	if err := s.Keyring.Health(ctx); err != nil {
		return fmt.Errorf("embedded: keyring: %w", err)
	}
	return nil
}
