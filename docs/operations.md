# Operations

What to watch, what to do on a schedule, and what to do when something goes
wrong. Commands assume `KEYFORGE_SERVER` points at the control plane; see
[getting started](getting-started.md#expose-the-control-plane).

## What runs by itself

With the lifecycle jobs running, keyforge:

- **Rotates** a key-encryption key when its interval has passed (default 365
  days) and records a sentinel for the new version.
- **Re-wraps** the data keys under older versions to the active one, in
  batches, resuming after a crash. Stored data is never rewritten.
- **Advances** a data key to a new epoch at its encryption cap or maximum age
  (default 2³⁰ encryptions or 90 days), as writes happen.
- **Requests retirement** of versions outside the retained floor, which starts
  their delay, and **completes** it and **destroys** the material once the delay
  has passed and nothing references the version, each only where the guard
  allows.
- **Completes erasures** whose key versions have all been destroyed.

With no guard configured, nothing is retired or destroyed: the absence of a veto
is not consent. A version whose retirement was requested waits, and the guard
is asked again on each pass. Emergency procedures are never started by the
jobs; a person starts them.

Policy is set per purpose through `embedded.Options.Policy`:

| Setting | Default | Meaning |
|---|---|---|
| `KEKInterval` | 365 days | How long a version is active |
| `DEKMaxAge` | 90 days | How long a data key epoch takes writes |
| `DEKMaxEncryptions` | 2³⁰ | Encryptions per data key |
| `RetirementDelay` | 30 days | Wait between asking to retire a version and doing it |
| `RetainVersions` | 2 | Versions never retired: the active one and the newest decrypt-only |
| `RequireBackup` | off | Rotation waits for the keyring backup to be acknowledged |

The retirement delay must be at least ten times the client cache TTL, so that a
process holding a cached view cannot keep wrapping under a version already
eligible for retirement.

## Monitoring

`keyforge status` is the full picture: each purpose, its key versions and
states, what is overdue, backup state, provider health, jobs that failed and
erasures pending. `keyforge health` exits non-zero and lists the problems in
words, so a monitor can alert on it. `keyforge status --json` is for tooling.

Attention is needed when status reports:

| Report | Meaning | Do |
|---|---|---|
| A rotation overdue | The job did not run or keeps failing | Check the jobs section for the failure; fix the cause; or `keyforge rotate <purpose>` |
| Keyring ahead of its backup | A change is not in the backup you last acknowledged | Back up and acknowledge ([below](#backup-and-restore)) |
| A provider unhealthy | The keyring cannot be read or unlocked | Check the file, its mode and the root key source |
| A purpose with no usable key | Nothing can be written | Fix the provider; do not work around it |
| A job failed repeatedly | Backoff is lengthening | Read the failure; it names the step |

`keyforge verify` round-trips a test value through each purpose's keys from a
cold start. Run it after a deploy, a restore or a change to the root key
source. It checks that keys are usable, which `status` cannot.

## The root key

The root key seals the keyring. Everything else can be rebuilt from a keyring
and a registry; the root key cannot be rebuilt from anything. Lose it and every
key-encryption key in the keyring is gone, and with them everything wrapped
under them.

- **Generate** 32 random bytes: `keyforge rootkey generate`. keyforge does not
  stretch a passphrase, because a passphrase is not a key.
- **Keep it out of the state directory** and out of the keyring's backup. A
  backup that holds both the keyring and the root key is the keyring in the
  clear.
- **Hold two copies**: one in the secret manager the process reads it from, one
  offline (a sealed envelope in a safe, a hardware token, a second person's
  password manager). keyforge does not split or escrow it for you, because that
  would mean implementing a secret-sharing scheme; use one you already trust.
- **Test the second copy.** Restore into a scratch directory using only the
  offline copy and run `keyforge verify` against it. An escrow you have not
  read back is not one.
- **Rotate it** when someone who held it leaves or a copy may have been seen:
  `Keyring.RotateRootKey(ctx, next)` re-encrypts the keyring under the new
  root key in one atomic write. Update the source the process reads from, and
  both stored copies, before the next restart. This protects the keyring file
  from now on. It does not rotate any key-encryption key: a keyring copy taken
  earlier, together with the old root key, still yields live keys, so after a
  suspected exposure of the root key also rotate the key-encryption keys and
  retire the old versions.

A wrong root key is refused with `ErrWrongRootKey` before anything is
decrypted, so a mistake is reported as what it is and not as a corrupt file.

## Backup and restore

A backup has three parts, and they belong together:

1. **The keyring file** (`keyring.kf`).
2. **The registry**: it holds the wrapped data keys and the state of every key
   version. Without it the keyring cannot say which data keys it protects.
3. **The root key**, kept apart from both (see above).

### Taking a backup

```bash
keyforge keyring inspect /var/lib/myapp/keyforge/keyring.kf
# generation: 14   root key ID: 5f1c…
```

Copy the keyring file. Copy the registry with `System.BackupRegistry(ctx,
path)`, which writes a consistent snapshot of the SQLite registry while the
system is running (copying the database file on its own is not a backup,
because recent writes sit in the write-ahead log). For PostgreSQL use its own
tooling. Then tell keyforge which keyring generation the copy holds:

```bash
keyforge backup ack local --generation 14 --note "offsite bucket, daily"
```

With `RequireBackup` set, a rotation waits until the acknowledgement catches up.
What it guarantees is narrow: a rotation does not start while the previous
keyring generation is unbacked, so unbacked rotations cannot pile up. It does
not protect the new version itself. A disk lost right after a rotation loses
what was wrapped under the new version, whatever the setting, so take and
acknowledge a copy straight after every rotation.

### Restoring

**Stop the process first**, then restore the keyring and the registry from the
same backup, and open with `AcceptRollback: true`. A keyring file replaced
under a running process is refused at the next write, but the process keeps its
in-memory copy until it restarts. Without it, a keyring older than one this host has seen
is refused with `ErrKeyringRolledBack`, naming both generations, so that a stale
copy is never used by mistake.

The highest generation this host has seen is kept beside the keyring in
`keyring.kf.backup`, authenticated under a key derived from the root key, so it
cannot be edited or forged without the root key. Removing it does not switch
the check off: a keyring past generation 1 with no such file is refused with
`ErrBackupStateMissing`, and one that does not authenticate with
`ErrCorruptBackupState`. Moving a keyring to a new host without that file, or
replacing a damaged one, therefore also needs `AcceptRollback: true` once. The
check cannot tell an older keyring restored together with its own older state
file from the real thing; keep the keys directory writable only by the service.

**Upgrading from a version that did not authenticate the state file.** The
first open after the upgrade fails with `ErrUnauthenticatedBackupState`. Confirm
the keyring on disk is the one you expect (`keyforge keyring inspect`), then open
once with `AcceptRollback: true`; the existing high-water mark and backup
acknowledgement are kept and the file is rewritten authenticated.

**What a restore loses.** The registry holds data keys. Any data key created
after the registry backup is not in it, and data encrypted under such a key
cannot be decrypted. Back up the registry as often as you can afford to lose
data written between backups; on PostgreSQL, point-in-time recovery closes the
gap. A keyring copy is cheap and changes only on rotation, so acknowledge a fresh
one after every rotation.

**A restore can undo an erasure.** Shredded subjects, their tombstones and the
destroyed state of their data keys live in the registry, so restoring a
registry backup taken before a shred brings the subject's keys back and removes
the tombstone. Keep a record of requested erasures outside the registry, and
repeat them after any restore. keyforge does not replay them.

After a restore, run `keyforge verify`, then `keyforge status`.

A missing keyring beside a registry that holds keys is refused with
`ErrKeyringMissing` rather than recreated, because an empty keyring would make
every operation fail beside a registry that looks healthy.

## Manual rotation

```bash
keyforge rotate <purpose>      # activate the next version
keyforge rewrap <purpose>      # move data keys off every non-active version
keyforge rollback <purpose>    # reactivate the most recent decrypt-only version
```

Rolling back is for a version that turns out to be bad (a provider fault, a
configuration error): nothing needs recovering, because the earlier version was
kept. Data keys already wrapped under the demoted version still unwrap under it.

## Retiring and destroying a version

Retirement and destruction are separate steps, each asking the **guard**:

```bash
keyforge retire request <kek> <version>    # starts the delay
keyforge retire complete <kek> <version>   # after the delay, if no data key is under it and the guard allows
keyforge retire cancel   <kek> <version>   # back to decrypt-only
keyforge destroy <kek> <version>           # destroy the material, if the guard allows
```

A retired version is not usable even before its material is destroyed, so
retiring has an effect on its own, and data wrapped under it outside the
registry becomes unreadable at retirement, not at destruction. Destruction is
irreversible: after it, only a backup that holds the keyring can bring the
version back.

The guard is yours to write. It sees the action, the purpose, the version, how
many registry data keys still reference it, and who asked, and returns allow,
deny or pending. It exists to know what keyforge cannot: that an export, a
snapshot or a backup somewhere still needs the version, or that data is under a
legal hold. A deny at retirement returns the version to service with the denial recorded.
A deny at destruction leaves the version retired: it can no longer be used, and
only destruction remains for it, so the guard's useful veto is the one at
retirement. A guard that fails, or is absent, advances nothing.

## Data outside the registry

Inline envelopes carry their wrapped key with them, so the registry does not
know they exist and a re-wrap does not move them. Retiring a version while an
inline object is still wrapped under it makes the object unreadable once the
material is destroyed. Before retiring a version, find and re-encrypt inline
objects (`Reencrypt` brings an envelope up to the current key) or confirm they
are gone. The guard is where that check belongs.

## Emergencies

Emergency procedures differ from scheduled work in three ways: they do not wait
for a backup acknowledgement, they have no retirement delay, and the guard is
asked and its answer recorded, but it cannot block them. Exposure is not a time
to wait for an approval.

### A key-encryption key version is exposed

```bash
keyforge compromise <kek> <version>
```

This replaces the version if it is active (the demotion and the new activation
are one transaction, so there is never a moment with no active version), marks
it compromised, re-wraps every data key away from it, asks the guard and records
the answer, then retires and destroys it. It is idempotent and resumable: if
some data key cannot be moved, the version stays compromised and referenced, is
not destroyed, and the call reports what remains. Call it again.

`--keep-material` stops after retirement, leaving the material at the provider
so you can recover inline objects before destroying it through the usual path.

Re-wrapping protects data keys going forward. It cannot un-expose a key that was
read: data encrypted under a data key the attacker could unwrap must be treated
as exposed. For that, the data key's own procedure applies.

### A data key is exposed

```bash
keyforge datakey compromise <id>   # replaces it and marks it compromised
```

The key stays readable so that what it protects can be re-encrypted. The host
does that, as it meets each record or in a pass of its own, with `Reencrypt`;
keyforge cannot, because the data is the application's. The report gives an upper
bound on how much was encrypted under the key. When the host is done:

```bash
keyforge datakey destroy <id>
```

## Erasing a subject

For a per-subject purpose:

```bash
keyforge shred request <purpose> <subject>
keyforge shred status  <purpose> <subject>
```

Requesting destroys the subject's data keys at once, so its data is unrecoverable
from the live system wherever the ciphertext was copied. A new key for the
subject is then refused: an erasure that quietly re-enrolled the subject would
not be one.

The erasure is **not complete** until every key-encryption key version that ever
wrapped one of the subject's keys is destroyed, because a registry backup taken
earlier still holds them wrapped under one of those versions. "Complete" speaks
for the live system only: a keyring backup taken before the versions were
destroyed still holds their material, and together with a registry backup from
before the shred it recovers the subject. Expire keyring and registry backups
from before an erasure on the same schedule as the erasure. `shred status`
lists the versions outstanding and an expected date. With the defaults that is
more than two years for a version that is active today, plus your backup
retention. A purpose that needs faster erasure sets a shorter `KEKInterval`.

A client that has the subject's key cached keeps using it until the entry
expires or `Client.Purge` is called; purge the clients if the erasure must be
effective immediately. That covers writes as well as reads: a process holding
the key goes on writing under it, and nothing it writes can be read by another
process or after a restart. Shredding a purpose that is not per-subject erases
nothing, and a purpose with no key is refused.

## Limits to plan around

- The local provider is as safe as the host and its root key source. It is not a
  hardware module, and it is the wrong choice where managed keys are required.
- The durable job state is for one process. Several replicas sharing a registry
  need a shared job provider; the keyforge scheduler works with any OmniWorkflow
  provider.
- Inline-mode objects each wrap a fresh data key under the active key-encryption
  key version with a random nonce, and there is no count of wraps per version.
  Keep a version's inline writes well under 2³² by rotating on a schedule that
  fits your volume.
- Another process that destroys a key version does not take effect in a
  running provider that has already loaded its material until that provider
  reloads; destruction is not instant across processes.
- keyforge depends on the host clock for scheduling. A clock set far ahead
  makes rotations and retirement delays come due early.
- Go cannot lock or reliably zero memory: cached keys can appear in a memory
  dump or swap.
