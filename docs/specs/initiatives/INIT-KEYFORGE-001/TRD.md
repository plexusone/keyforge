# keyforge: Technical Requirements

**Initiative:** `INIT-KEYFORGE-001`
**Repository:** `github.com/plexusone/keyforge`

Implements the [PRD](PRD.md).

## Concepts

| Term | Meaning |
|---|---|
| **Purpose** | A named use of encryption (`session-secrets`, `hold-snapshots`). Keys are scoped to a purpose; the purpose is bound into every ciphertext |
| **KEK** | Key-encryption key. Held by a provider and never exposed. Has **versions** |
| **DEK** | Data-encryption key. Encrypts application data and is stored only wrapped by a KEK |
| **Epoch** | A DEK generation for a purpose (and optionally a subject): new writes use the current epoch, older epochs are decrypt-only |
| **Envelope** | The self-describing ciphertext: header, nonce, ciphertext and tag |
| **Context** | Caller-supplied bytes bound into the ciphertext (for example a record ID) |

## Architecture

```text
 application ──► keyforge (library) ──► provider (local | KMS)
                      │      ▲
                      ▼      │ wrapped DEKs, key states
                  registry store          control plane (service, CLI)
                      ▲                          │
                      └── scheduler, retire ◄────┘     guard, audit sink,
                                                       authorizer (host-supplied)
```

- The **library** is on the data path and runs in process. A data key is
  unwrapped once and cached; encrypt and decrypt make no network call.
- The **control plane** (service, scheduler, CLI) is off the data path. It
  reads and writes the registry, drives rotation and destruction, and reports
  status.
- The **host application** supplies a store, a provider, a guard, an audit
  sink and an authorizer. keyforge does not authenticate callers.

### Packages

| Package | Contents |
|---|---|
| `keyforge` | Core types: `Purpose`, `KeyRef`, `Envelope`, `Client` (`Encrypt`, `Decrypt`, `Reencrypt`), errors |
| `envelope` | The binary and text formats, versioning, parser |
| `provider` | `Provider` interface and the conformance suite |
| `provider/local` | The keyring-file provider |
| `registry` | `Store` interface, in-memory implementation, key state machine |
| `store/ent` | SQLite and PostgreSQL store (separate module so the core has no ORM dependency) |
| `policy` | Rotation, epoch and retirement policy per purpose |
| `rotate` | The scheduler and jobs |
| `guard` | `DestroyGuard` interface and helpers |
| `audit` | `Sink` interface and event types |
| `service` | HTTP control plane |
| `cmd/keyforge` | CLI (Cobra) |

The core module depends only on the standard library and
`golang.org/x/crypto`.

## Data model

### Key states

A key version moves through these states. A transition that removes key
material from use (into `retired` or `destroyed`) is one-way; the only other
backward moves are the two listed in the transition table.

```text
pending ─► active ⇄ decrypt-only ⇄ retire-requested ─► retired ─► destroyed
             │            │               │                ▲
             └────────────┴───────────────┴─► compromised ─┘
```

| State | Encrypt | Decrypt | Notes |
|---|---|---|---|
| `pending` | no | no | Created, not yet in use |
| `active` | yes | yes | Exactly one active version per KEK |
| `decrypt-only` | no | yes | Rotated out; kept until nothing references it |
| `retire-requested` | no | yes | Retirement asked for; delay running, guard consulted |
| `retired` | no | no | Key material removed from use, recoverable only from backups |
| `destroyed` | no | no | Key material destroyed at the provider |
| `compromised` | no | policy | Marked by an operator; leads to the emergency procedure |

### Transitions

These are the only permitted transitions. The store conformance suite checks
every one and checks that every pair not listed is refused with a typed error.

| From | To | Trigger | Audit event |
|---|---|---|---|
| `pending` | `active` | Activation; the previous `active` version moves to `decrypt-only` in the same transaction | `key.activated` |
| `active` | `decrypt-only` | Activation of another version, or rollback | `key.activated`, `key.rolled_back` |
| `decrypt-only` | `active` | **Rollback**: only the most recent `decrypt-only` version, and the current `active` version moves to `decrypt-only` in the same transaction | `key.rolled_back` |
| `decrypt-only` | `retire-requested` | Retirement requested; the delay starts | `key.retire_requested` |
| `retire-requested` | `decrypt-only` | **Cancellation**: the guard denies, or an operator cancels | `guard.denied`, `key.retire_cancelled` |
| `retire-requested` | `retired` | Delay passed and the guard allows | `key.retired` |
| `retired` | `destroyed` | The guard allows; the provider destroys the material | `key.destroyed` |
| `active`, `decrypt-only`, `retire-requested` | `compromised` | Operator marks it | `key.compromised` |
| `compromised` | `retired` | Emergency procedure, after re-wrap | `key.retired` |

- Exactly one version per KEK is `active` after every transaction.
- A rollback demotes the newer version to `decrypt-only`; it does not
  compromise it, so data written under it stays readable.
- Nothing leaves `retired`, `destroyed` or `compromised` except as listed.
  Material retired by mistake is recovered only through the restore
  procedure, never by a state change.

### Registry records

- **Key**: `id`, `purpose`, `kind` (`kek`), `provider`, `state`, `created_at`.
- **Key version**: `key_id`, `version`, `state`, `created_at`, `rotated_at`,
  `retire_after`, `provider_ref`.
- **DEK**: `id`, `purpose`, `subject` (optional), `epoch`, `kek_id`,
  `kek_version`, `wrapped`, `state`, `reserved` (encryption-count high-water
  mark, see [Encryption counter](#encryption-counter)), `created_at`.
- **Job**: `kind`, `cursor`, `state`, lease holder and expiry, for resumable
  rotation and re-wrapping.
- **Event**: the audit trail, also emitted to the sink.

## Envelope format

Two modes share one header.

| Mode | Holds | Use |
|---|---|---|
| **Reference** (default) | The DEK identifier; the wrapped DEK lives in the registry | Rows and values encrypted under a purpose or subject epoch. KEK rotation re-wraps registry records, so stored data is not touched |
| **Inline** | The wrapped DEK, KEK reference and version, beside the ciphertext | Standalone objects: exports, snapshots, files. A fresh DEK per object |

Layout (version 1, big-endian):

```text
magic "KF" | format u8 | mode u8 | algorithm u8 | flags u8
purpose  : len u8 + bytes
reference: dek_id 16 bytes                       (reference mode)
inline   : kek_id 16 bytes, kek_version u32, wrapped_len u16, wrapped
nonce    : 12 bytes
ciphertext || tag
```

- **Flags:** all eight bits are reserved and must be zero in format 1. A
  non-zero value fails with `ErrUnsupportedFlags`. Every bit assigned later is
  critical: a reader that does not know a set bit rejects the envelope, so no
  bit can be silently ignored. The flags byte is part of the AAD, so it
  cannot be changed or stripped without failing authentication. A
  known-answer vector covers the rejection.
- **Text form:** `kf1.` followed by unpadded base64url, for text columns and
  JSON.
- **AAD:** the header bytes up to the nonce, followed by the caller context.
  Changing the purpose, key, mode or context makes decryption fail.
- **Algorithm 1 (registry ID 1):** AES-256-GCM through `cipher.NewGCMWithRandomNonce`, the
  only GCM constructor permitted under `fips140=only`. Its output begins with
  the 12-byte random nonce, which the format stores in the header's nonce
  field and restores on open. Each encryption is counted against the DEK's
  cap (see [Encryption counter](#encryption-counter)), and a DEK reaching its
  cap is rotated to a new epoch before the NIST random-nonce limit of 2³²
  invocations. The default cap is 2³⁰.
- **Forward compatibility:** unknown `format` or `algorithm` values fail with
  a typed error rather than a guess. The parser is fuzzed.

### Encryption counter

The cap must hold across replicas and crashes without a registry call per
encryption, so encryptions are counted in blocks reserved from the registry:

- The DEK record holds `reserved`, a high-water mark. A process reserves a
  block of B encryptions (default 2¹⁶) by advancing `reserved` with one
  compare-and-set, and counts within the block in memory with an atomic
  counter. Each replica holds its own block.
- A block that is not fully used (the process exits or crashes) counts as
  used. `reserved` can therefore overstate the encryptions performed, never
  understate them.
- A reservation that would take `reserved` past the cap triggers a new epoch
  instead, and the write proceeds under the new epoch's DEK. If no new epoch
  can be created, the write fails closed.
- During a registry outage, writes continue until the current block is
  spent and then fail closed. Reads are unaffected.
- At the default cap and block size a DEK needs at most 2¹⁴ reservations in
  its life, one registry write per 65,536 encryptions.

## Providers

```go
type Provider interface {
    Name() string
    CreateKey(ctx context.Context, spec KeySpec) (KeyRef, error)
    Rotate(ctx context.Context, ref KeyRef) (version uint32, err error)
    Wrap(ctx context.Context, ref KeyRef, version uint32, dek, aad []byte) ([]byte, error)
    Unwrap(ctx context.Context, ref KeyRef, version uint32, wrapped, aad []byte) ([]byte, error)
    Destroy(ctx context.Context, ref KeyRef, version uint32) error
    Health(ctx context.Context) error
}
```

```go
// KeyRef identifies a KEK. ID is keyforge's identifier, the one written in
// envelopes; ProviderRef is the provider's own opaque identifier (a keyring
// entry, a KMS key ARN or resource name), stored in the registry.
type KeyRef struct {
    ID          [16]byte
    Provider    string
    ProviderRef string
}

// KeySpec describes a KEK to create.
type KeySpec struct {
    Purpose   Purpose
    Algorithm AlgorithmID // from the registry; AES-256-GCM in this initiative
}
```

- The envelope carries only `ID`, so it stays provider-neutral and a key can
  move between providers by updating the registry, not the data.
- A provider never returns KEK material. `Wrap` and `Unwrap` take the AAD
  (purpose and key identity) so the wrap is bound to its use; a KMS provider
  maps it to the service's encryption context.
- A provider that rotates natively (a managed KMS) reports the new version
  from `Rotate`; one that does not (the local keyring) generates it.
- Every provider passes the same conformance suite, which also runs against
  the local provider in CI.
- The test providers include one that versions natively, the way a managed
  KMS does, so the interface is exercised by both rotation styles before any
  cloud provider exists.

### Local provider

- A **keyring file** (mode 0600) holds KEK versions, encrypted under a
  **root key** obtained from a `RootKeySource` (an environment variable, a
  file, or a secret manager such as omnivault). The root key never touches
  disk beside the keyring.
- The keyring header carries a non-secret **root-key ID** assigned when the
  root key is created. Opening a keyring with a different root key fails with
  `ErrWrongRootKey` before decryption is attempted, so a wrong key is not
  reported as a corrupted file.
- **Root-key rotation** re-encrypts the keyring under a new root key in one
  atomic write and records the new root-key ID. The keyring is small, so this
  is a rewrite, not a job.
- **Escrow is the operator's.** keyforge does not split or escrow the root
  key; that would mean implementing a cryptographic scheme. The operations
  guide documents keeping the root key in a secret manager with a second,
  offline copy. The DR drill obtains the root key through a separately
  configured recovery `RootKeySource`, so the escrow path is tested rather
  than assumed.
- Writes are atomic: write to a temporary file, fsync, rename, fsync the
  directory, and take an advisory lock so concurrent processes do not
  interleave.
- A monotonically increasing **keyring generation** is stored in the file.
  `keyforge backup ack` records the generation of the copy the operator has
  safely stored; `status` reports a keyring whose generation is ahead of the
  acknowledged one, and rotation under a policy that requires a verified
  backup waits until the acknowledgement catches up (otherwise a restored
  backup that predates a rotation would lose data wrapped under the newer
  version).
- The provider is reported as `local` in status and in the startup log, so it
  is not mistaken for a managed one.

## Rotation

### KEK rotation (automatic, default 365 days)

1. Create the next version at the provider (`pending`).
2. Mark it `active` and the previous version `decrypt-only`, in one registry
   transaction.
3. A resumable job re-wraps DEK records still wrapped under the old version,
   in batches, recording a cursor. Each batch unwraps with the old version
   and wraps with the new one; it is idempotent.
4. When no DEK record references the old version, it becomes eligible for
   retirement, subject to the retained-versions rule below.

### Retained versions

- **Policy keeps the last two versions.** `retain_versions` defaults to 2: the
  active version and the most recent `decrypt-only` version are never
  retired, even when nothing references the latter. It stays usable for
  rollback: if the active version turns out to be bad (a provider fault, a
  wrong configuration), the previous one is reactivated (see
  [Transitions](#transitions)) and nothing needs recovering. Counting by state
  rather than by number keeps the rule well defined after a rollback.
- **Older versions (N-2 and below) become eligible for retirement only when
  all of these hold:** no DEK record or tracked object references them; the
  retirement delay has passed; no hold covers data they protect; and the
  guard allows it. The count is a floor on retention, never a trigger to
  delete.
- **Re-wrap promptly.** The re-wrap job starts as soon as a new version is
  active, so references to N-1 drain quickly and N-1 is held only as the
  rollback margin.
- **Data outside the registry is the limit.** An inline envelope, an export,
  a snapshot or a backup is not re-wrapped by the job. A version that
  protects such data stays until the host asserts, through the guard, that no
  such data remains or accepts its loss, and the backups' retention sets how
  long old versions must be kept to restore them.
- **Signing keys add a pre-publish step** (later release): version N+1 is
  published for verification before it signs anything, N signs, and N-1 stays
  verify-only for at least the longest token lifetime plus the longest cache
  time of a relying party's key set, and then is retired by the same rules.

Stored application data is unchanged throughout. In inline mode there are no
registry records to re-wrap: an old version stays `decrypt-only` until the
host asserts, through the guard, that nothing references it (for example
after a lazy `Reencrypt` pass or because the objects expired).

### Data-key rotation (automatic, default 90 days or volume cap)

A new epoch for a purpose (or subject) is created when the current one
reaches its age or its encryption cap. New writes use it; old epochs are
`decrypt-only`. `Decrypt` returns a `Stale` indication when the envelope's
epoch is no longer current, and `Reencrypt` produces a current envelope, so
hosts can rewrite data on its next write or in a throttled background pass.
No pass is required for correctness.

### Per-subject keys and crypto-shredding

A purpose can be declared **per-subject**: each subject (a user, a tenant)
gets its own DEK epochs, and `Encrypt` takes the subject with the purpose.
Shredding a subject destroys its DEKs, which makes its data unrecoverable
wherever the ciphertext was copied.

Destroying a DEK record does not complete the shred on its own. Registry
backups still hold the subject's DEK wrapped under the KEK versions that were
active while it existed, and while any of those versions survives, a restored
backup can unwrap it. So:

- **A shred is complete when every KEK version that ever wrapped the
  subject's DEKs is destroyed.** keyforge records those versions when the
  shred is requested and reports the shred as `pending` until the last one is
  destroyed, then as `complete`, with an audit event for each.
- With the defaults (KEK rotation yearly, two retained versions, the
  retirement delay) completion takes years, and backup retention can extend
  it, because a version is kept while backups that need it are retained.
- A purpose that needs a shorter erasure guarantee sets a shorter KEK
  interval. The time to complete is roughly the interval times the retained
  versions plus the retirement delay, and `status` reports the expected date
  per pending shred.
- Shredding is per-subject reference mode only. Inline envelopes carry their
  own DEK, wrapped under the KEK, and are shredded only by destroying the KEK
  versions or the objects.

### Retirement and destruction

- `retire-requested` starts a delay (default 30 days, per purpose).
- Before `retired` and again before `destroyed`, the **guard** is consulted.
  It may allow, deny with a reason, or answer `Pending` (an approval is
  outstanding). Only an allow advances the state.
- A denied request returns the key to `decrypt-only`, usable, with an audit
  event. A pending answer leaves it `retire-requested`, still decryptable,
  and the guard is asked again on the next scheduler pass.
- Destruction is irreversible at the provider; for providers with a
  deletion window it is scheduled and cancellable inside it.

### Emergency rotation

Separate from scheduled rotation, and audited as such:

- **KEK compromised:** mark the version `compromised`, create and activate a
  new version, re-wrap every DEK, then destroy the old version. The guard may
  not block the procedure but is consulted and its answer recorded.
- **DEK exposed:** create a new epoch, mark the old DEK `compromised`, and
  re-encrypt the data under it (the host drives this through `Reencrypt`;
  keyforge reports the progress and the remaining references).

## Rotation drill

Real keys rotate on their policy (KEK yearly, data keys quarterly or by
volume). A schedule that is that slow is also one that nobody exercises, so
the mechanism is exercised on a key that holds nothing:

- keyforge maintains a built-in **canary purpose**, enabled by default, that
  runs the full lifecycle on a weekly schedule: create a version, activate
  it, re-wrap, encrypt and decrypt across the old and new versions, roll back
  to the previous version and forward again, retire after a short delay, and
  destroy the retired version.
- Every step is the code path real keys use, against the configured provider
  and registry, so a provider credential that has expired or a job that stalls
  surfaces in the canary within a week and not at the first real rotation.
- A failed or overdue drill is an alert and appears in `status`; a successful
  one is an audit event with its duration.
- `keyforge verify` runs the same drill on demand and across every purpose's
  read path (decrypt a sample of stored envelopes without returning data).
- The drill's interval is configurable, and a deployment with a managed
  provider that charges per key version may lengthen it.

Real keys are not rotated weekly by default: more frequent rotation adds
versions, re-wrap work and audit volume without a matching security gain, and
for the local provider each rotation is another keyring that must be backed
up. Policy lets a deployment shorten the interval for a purpose.

## Disaster-recovery drill

The rotation drill proves the mechanism works. The DR drill proves the state
can be recovered: that a keyring and registry restored from backup can still
decrypt everything they are supposed to. It runs without a person, and every
judgment that is not mechanical is made by an analyst agent that writes the
report.

### Mechanical part (the drill engine)

1. **Provision an isolated environment** with no network path to production
   and no write access to production state, through a host-supplied
   `RestoreTarget`.
2. **Fetch the latest backups** of the registry and, for the local provider,
   the keyring, through a host-supplied `BackupSource`, and verify their
   digests.
3. **Check the recovery point.** Compare the restored keyring generation and
   registry state with the acknowledged and current ones. A restore that
   predates a rotation or a key version is a failure, not a warning.
4. **Start keyforge in recovery mode** against the restored state, with the
   same profile and provider configuration as production, and the root key
   obtained the way an operator would during a real recovery: through the
   recovery `RootKeySource` (the secret manager or the escrowed copy), not
   from the production process.
5. **Decrypt sentinels.** Keyforge writes a sentinel envelope per purpose
   and key version, whose plaintext is a fixed, non-secret marker, and keeps
   them with the registry. The drill decrypts every sentinel for every
   retained version. A version that cannot decrypt its sentinel is a
   critical failure.
6. **Sample real data.** Through a host-supplied `Sampler`, the drill
   decrypts a bounded sample of real envelopes per purpose, checking only
   that authentication and decryption succeed. Plaintext is discarded and
   never logged. The `Sampler` is optional: without one, the step is recorded
   as not run and appears among the drill's limits in the result and the
   report.
7. **Measure** time to first successful decrypt (the recovery time), the age
   of the backup and the generation gap (the recovery point), and the
   duration of each step.
8. **Run negative checks:** a deliberately stale keyring copy must be
   detected, and an envelope under a destroyed version must fail with the
   expected typed error, so the drill proves its own checks can fail.
9. **Destroy the environment** and verify that no key material or restored
   state remains.
10. **Emit the result:** a JSON document of steps, outcomes, metrics, versions
    and digests. It contains key identifiers and versions at most, never key
    material or plaintext.

Objective outcomes (each step passed or failed, whether the recovery time and
point are within configured limits) are decided by the engine and are final.

### Judgment part (the analyst and the report)

Some conclusions are not mechanical: how serious a result is, whether a
metric is trending toward a limit, what probably caused a failure, what to
change first. These are made by an **analyst**, an agent supplied by the host
through an `Analyst` interface. keyforge core has no dependency on any model
or agent framework.

- **Input:** the result document, the previous drills' results and reports,
  and sanitized logs. **The analyst never receives key material, plaintext, or
  access to the restored environment.**
- **Output:** a DR report in Markdown and JSON, with: the objective verdict;
  metrics and trends; each finding with severity, evidence and likely cause;
  prioritized recommendations; the limits of the drill (what it did not
  cover); and provenance (analyst identity, model, time, inputs by digest).
- **Standing:** the analyst's conclusions are advisory and cannot change
  policy, key state or the objective verdict. In the exported crypto
  specification the drill's objective results are `verified` evidence and the
  analyst's conclusions are `inferred` until a person attests them.
- **Escalation:** a failed drill or a critical finding raises an alert
  through the audit sink, whatever the report says.

### Schedule and triggers

The drill runs quarterly by default, and on demand (`keyforge drill`), and
after a change to the provider, the backup configuration or the registry's
location. A drill that is overdue is reported in `status` and alerts, like an
overdue rotation. The report is stored with the audit trail and is evidence
for the recovery claims in the crypto specification.

### Interfaces the host supplies

| Interface | Purpose |
|---|---|
| `BackupSource` | Fetch the latest registry and keyring backups and their digests |
| `RestoreTarget` | Provision and destroy the isolated environment |
| `Sampler` | Return a bounded sample of real envelopes per purpose (optional) |
| `Analyst` | Turn the result document into the report |
| `ReportSink` | Store the report and result with the audit trail |

All five interfaces are defined in keyforge, because the drill engine calls
them; hosts implement them. keyforge ships local-filesystem implementations
of `BackupSource`, `RestoreTarget` and `ReportSink`, so the engine is tested
end to end and a single-host deployment can drill without writing any.

## Scheduling

- A scheduler runs in the control-plane process. Policy is declared per
  purpose.
- **Leader election** is a lease row in the registry, so several replicas
  never run the same job. Jobs are resumable from their cursor after a crash
  or lease loss.
- The scheduler reports overdue keys, failed jobs and a stale backup
  acknowledgement as metrics and audit events. A key past its period is
  reported, never silently kept.

## Caching and availability

- Unwrapped DEKs are cached in process with a TTL (default 5 minutes) and a
  size bound, and are zeroed on eviction on a best-effort basis (Go gives no
  guarantee).
- Reads and writes for cached DEKs continue during a registry or provider
  outage. A key not in the cache fails closed.
- A cache hit after a KEK rotation is still correct: the unwrapped DEK did
  not change.

## Audit

Events carry an ID, time, actor (supplied by the host), action, purpose,
key and version, outcome, and a reason, and never key material. Actions
include `key.created`, `key.rotated`, `key.activated`, `key.rolled_back`,
`key.retire_requested`, `key.retire_cancelled`, `key.retired`, `key.destroyed`, `key.compromised`, `wrap.failed`,
`subject.shred_requested`, `subject.shred_completed`, `admin.read`,
`guard.denied`, `guard.pending`, `job.failed`, `backup.stale`.
Ordinary encrypt and decrypt are not logged individually; their rates and
failures are metered.

Metrics go through a small `Metrics` interface in the core (counters and
gauges for operation rates, failures, cache hits, overdue keys and drill
outcomes), with a no-op default. An OpenTelemetry adapter, if added, lives in
a separate module so the core keeps its dependency rule.

## Control plane

- **Service:** HTTP handlers for key listing, status, rotate, request
  retire, destroy, and backup acknowledgement, each behind a host-supplied
  `Authorizer` (`Authorize(ctx, action, purpose) error`). Mounting and
  authentication are the host's.
- **CLI:** `keyforge status`, `rotate`, `retire`, `destroy`, `backup ack`,
  `verify` (round-trips a test value through every purpose), and, with the
  drills, `drill` (runs the DR drill on demand). The CLI is a
  client of the library and the store, with no separate logic.

## Algorithms and profiles

### Rules

- **Everything goes through keyforge.** Every protection of stored data and
  keys that keyforge's callers perform uses an algorithm from keyforge's
  registry. Callers do not select or call primitives for that purpose.
- **Algorithms are named exactly:** mode and size, always ("AES-256-GCM", never
  "AES-256"). The registry's names are the names used in the envelope, in
  configuration, in logs and in status.
- **The floor is an authenticated mode.** AES-256-GCM is the minimum. No ECB,
  CBC, CTR or unauthenticated construction is registered.
- **Standard library first.** Primitives come from the Go standard library
  and, where it has none, `golang.org/x/crypto`. No third-party primitive or
  post-quantum implementation is used.
- **The sets are code.** Registry entries and profile membership are
  compiled in and reviewed. Configuration can narrow a profile and cannot add
  an algorithm. Adding one is a release with an envelope identifier and
  known-answer vectors.

### Registry

| ID | Algorithm | Use | `fips` | `standard` |
|---|---|---|---|---|
| 1 | AES-256-GCM (`cipher.NewGCMWithRandomNonce`) | Data encryption; DEK wrapping in the local provider | yes | yes |
| 2 | ChaCha20-Poly1305 | Data encryption | no | reserved |
| 16 | HPKE, DHKEM P-256 / HKDF-SHA-256 / AES-256-GCM | Asymmetric KEK | reserved | reserved |
| 17 | HPKE, MLKEM768P256 / HKDF-SHA-256 / AES-256-GCM | Hybrid post-quantum asymmetric KEK | reserved | reserved |
| 18 | HPKE, MLKEM768X25519 / HKDF-SHA-256 / AES-256-GCM | Hybrid post-quantum asymmetric KEK | no | reserved |
| 32 | Ed25519 | Signing | reserved | reserved |
| 33 | ECDSA P-256 / SHA-256 | Signing | reserved | reserved |
| 34 | ML-DSA-65 | Signing | reserved, needs a module version that includes it | reserved |

"Reserved" entries are identifiers set aside so the format does not change
when they are added; none is implemented or in scope for this initiative. The
registry contains ID 1 only, and the only algorithm in either profile is
AES-256-GCM, which both profiles approve.

### Profiles

- `Profile` is `Standard` or `FIPS`. A client's profile defaults to `FIPS` when
  the process runs in FIPS mode (`crypto/fips140.Enabled()`) and to
  `Standard` otherwise. Configuration may deny algorithms in either profile
  or select `FIPS` outside FIPS mode, which uses only the approved set
  without module validation.
- Each purpose declares an optional **pinned profile** and an
  **allowed-algorithm list** that must be a subset of its profile. Startup
  validates every configured purpose and fails fast on a violation.
- **Writes** choose the first algorithm of the purpose's list that the active
  profile permits. **Reads** follow the profile: an envelope that names an
  algorithm outside it fails with `ErrAlgorithmNotPermitted`, which reports
  the algorithm and the profile, and does not fall back. Migration is a
  `Reencrypt` in a process whose profile permits the old algorithm.
- `status` reports the profile, the module version and whether the process
  is in FIPS mode.

### Starting point, FIPS 140-3 and post-quantum

- **The selector is the deliverable; the non-approved algorithms are not.**
  keyforge starts in the `standard` profile and does not require FIPS mode.
  What this initiative builds is the generic algorithm selector, so that
  adding the first non-approved algorithm, or requiring FIPS-only operation,
  is a registry entry and a configuration change and not a redesign. No
  non-approved algorithm is implemented or in scope.
- **FIPS-clean by construction.** Because the one algorithm is approved
  (AES-256-GCM through `NewGCMWithRandomNonce`), the code stays valid under
  `GODEBUG=fips140=only`. A CI job runs the tests under
  `GODEBUG=fips140=only` from the first phase so the property is checked
  rather than assumed. It is non-gating until FIPS operation is first
  required, and gating from then on.
- Symmetric wrapping needs no post-quantum change. Asymmetric KEKs, when
  added, are hybrid KEMs through `crypto/hpke`, `MLKEM768X25519` in
  the `standard` profile and `MLKEM768P256` in `fips`. Signing keys move to
  ML-DSA (`crypto/mldsa`) or a hybrid when the formats and relying parties
  that carry them support it.

## Inventory and the crypto specification

keyforge is the system of record for the cryptography the platform selects
and enforces, and the one place to register the cryptography it relies on but
does not control, so that the system's crypto specification has a single
source.

### Three kinds of fact

| Kind | Examples | Authority | Verification state in the export |
|---|---|---|---|
| **Enforced** | Registry algorithms and profiles, purposes, key classes and rotation policy, a dated summary of key state, providers, FIPS mode | keyforge | `verified`, with configuration and runtime evidence from keyforge |
| **Declared** | Edge TLS at a CDN, service-to-service TLS, database TLS: the expectation (minimum version, suites, key exchange groups, certificate key strength) | The system that configures it; keyforge holds the expectation | `attested`, or `review-required` once its review date passes (derived when read, not stored) |
| **Observed** | A scan's handshake results, a dependency analysis | The scanner | `discovered`, promoted to `verified` when it matches the expectation |

### External boundaries

An external boundary record holds an identifier, a kind (`tls-edge`,
`tls-internal`, `tls-database`, `storage-at-rest`, and so on), the
**expectation**, an owner, a pointer to where the real configuration lives
(an IaC path, a cloud console resource, a vendor document), and a review
date. keyforge does not enforce it.

- **Policy is the floor; the expectation is at or above it.** The floor is
  the platform's cryptographic policy (a minimum TLS version, a minimum key
  size, an allow-set of suites). A boundary with no expectation is held to
  the floor directly. An expectation may be stricter without justification.
- **An expectation below the floor is a waiver.** It carries a reason and an
  owner, and it needs a review date. It is reported as a conditional pass
  until that date and as a failure after it.
- **Three results are kept distinct:** an observation below the floor is a
  violation; an observation below the expectation but above the floor is
  drift; an expectation below the floor is an exception.
- **The review date belongs to the claim that covers the record.** The export
  states each boundary's expectation as a claim with `reviewBy`, `reviewedAt`
  and `reviewedBy`. A declaration past its review date is read as
  `review-required`; the stored status is not rewritten, so stale assertions
  cannot be read as current fact and the export does not change meaning with
  the clock.

### Export

- `keyforge spec export` (and the library function behind it) produces a
  `systemspec-crypto` document: implementations (keyforge, the Go
  cryptographic module with its version and FIPS mode, each provider),
  algorithms from the registry, uses per purpose with their configuration
  (rotation intervals, profile), claims with verification states, and
  evidence pointing to keyforge configuration and the external boundary
  records.
- The export is derived and reproducible. It is never edited by hand, and
  it contains key identifiers at most, never key material. Key state is a
  dated summary claim ("all versions within policy as of T; current version
  N") backed by `verified` evidence; the export has no row per key version,
  which would change with every rotation and with the weekly canary.
- Where the specification does not yet model a detail, the export uses the
  objects it has and leaves the rest undocumented rather than inventing it.
  Key classes, certificates and protocol detail arrive in the
  specification's later phases, and the review, expectation, operating-mode
  and algorithm-profile fields in the phase after them. The export gains each
  as it ships, and the first export is limited to the v0.1 objects.

### Verification

Verification is outside keyforge, and the verifier itself is not part of this
initiative: test applications and scanners will be built later, against the
export format defined here. A test application or scanner will take the
exported specification and the registered expectations, observe the deployed
system (TLS handshakes, certificate chains, key exchange groups including
hybrid post-quantum ones), and attach its results as evidence. A mismatch
between an expectation and an observation is a finding (drift when the
observation is still above the policy floor, a violation when it is below).
Results flow back as evidence on claims and do not edit the inventory.

### What keyforge does not do here

- It does not scan networks or services.
- It does not replace the configuration of an external system; the
  expectation points at it.
- It does not assert that every service uses keyforge. Direct use of a
  primitive for data or key protection elsewhere is found by source and
  dependency analysis.

## Threat model

| Asset | Threat | Mitigation |
|---|---|---|
| KEK material | Read from disk or backup | Root key held apart from the keyring; managed providers keep material in the service; file mode and lock |
| DEK material | Process memory read | Bounded cache and TTL; best-effort zeroing; not defended against a host-level attacker |
| Ciphertext | Moved or replayed between purposes or records | AAD binds purpose, key identity and caller context |
| Ciphertext | Tampering | AEAD authentication |
| Key availability | Provider or registry outage | Cache; fail closed beyond it; status and health reporting |
| Data under retention | Premature destruction | Guard, delay and audit on every retire and destroy |
| Rotation | Restoring a stale backup loses data | Keyring generation and backup acknowledgement |
| Control plane | Unauthorized rotation or destruction | Host-supplied authorizer on every action; audit |

### Known limitations

- The local provider is as safe as the host and its root-key source. It is
  not an HSM and is documented as unsuitable where managed keys are required.
- Go cannot lock or reliably zero memory; cached keys can appear in memory
  dumps and swap.
- An attacker who controls the host process can use keys it can use; keyforge
  limits blast radius by purpose and subject, not by defeating that attacker.
- Scheduling depends on the host clock.
- Inline-mode retirement relies on the host's statement that nothing
  references a version.
- A subject shred is complete only when every KEK version that wrapped the
  subject's DEKs is destroyed; until then a restored registry backup can
  recover the data.

## Testing

- **Provider conformance suite**, run against every provider.
- **Store conformance suite**, run against the in-memory and SQL stores.
- **Known-answer vectors** for the envelope format, published in
  `testdata`.
- **Fuzzing** of the envelope parser.
- **Property tests:** encrypt, rotate any number of times, decrypt.
- **Crash tests:** killing the process during a keyring write and during a
  re-wrap batch leaves a consistent, resumable state.
- **Race detector** on the cache, scheduler and store.
- **Injected time and randomness.** The `Client`, policy, scheduler and drill
  take a clock, and DEK and key generation take an entropy reader, so tests
  are deterministic. GCM nonces come from `NewGCMWithRandomNonce` and cannot
  be injected; the known-answer vectors therefore fix the open path (decrypt
  a published envelope), and the seal path is tested by round trip.
- **Scale benchmark** for success criterion 2: a KEK rotation over a store
  holding a million wrapped DEKs completes, and concurrent reads succeed
  throughout.
- **FIPS-only run** of the test suite under `GODEBUG=fips140=only` in CI.

## Integration

keyforge is generic. A host application adopts it by supplying a store, a
provider, a guard that consults its retention and approval policy, an audit
sink, and an authorizer.
[systemforge](https://github.com/plexusone/systemforge) is the first host;
its adoption decisions are in its architecture decision records.
