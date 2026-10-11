# keyforge: Technical Requirements

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

A key version moves through these states and never backwards:

```text
pending ─► active ─► decrypt-only ─► retire-requested ─► retired ─► destroyed
                          │                                  ▲
                          └────────── compromised ───────────┘
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

### Registry records

- **Key**: `id`, `purpose`, `kind` (`kek`), `provider`, `state`, `created_at`.
- **Key version**: `key_id`, `version`, `state`, `created_at`, `rotated_at`,
  `retire_after`, `provider_ref`.
- **DEK**: `id`, `purpose`, `subject` (optional), `epoch`, `kek_id`,
  `kek_version`, `wrapped`, `state`, `encryptions` (counter), `created_at`.
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

- **Text form:** `kf1.` followed by unpadded base64url, for text columns and
  JSON.
- **AAD:** the header bytes up to the nonce, followed by the caller context.
  Changing the purpose, key, mode or context makes decryption fail.
- **Algorithm 1:** AES-256-GCM with a random 96-bit nonce. The DEK's
  `encryptions` counter is incremented per encryption, and a DEK reaching its
  cap is rotated to a new epoch before the NIST random-nonce limit of 2³²
  invocations. The default cap is 2³⁰.
- **Forward compatibility:** unknown `format` or `algorithm` values fail with
  a typed error rather than a guess. The parser is fuzzed.

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

- A provider never returns KEK material. `Wrap` and `Unwrap` take the AAD
  (purpose and key identity) so the wrap is bound to its use; a KMS provider
  maps it to the service's encryption context.
- A provider that rotates natively (a managed KMS) reports the new version
  from `Rotate`; one that does not (the local keyring) generates it.
- Every provider passes the same conformance suite, which also runs against
  the local provider in CI.

### Local provider

- A **keyring file** (mode 0600) holds KEK versions, encrypted under a
  **root key** obtained from a `RootKeySource` (an environment variable, a
  file, or a secret manager such as omnivault). The root key never touches
  disk beside the keyring.
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
   retirement.

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

### Retirement and destruction

- `retire-requested` starts a delay (default 30 days, per purpose).
- Before `retired` and again before `destroyed`, the **guard** is consulted.
  It may allow, deny with a reason, or answer `Pending` (an approval is
  outstanding). Only an allow advances the state.
- A denied or pending request leaves the key `decrypt-only`, usable, with an
  audit event.
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
include `key.created`, `key.rotated`, `key.activated`, `key.retire_requested`,
`key.retired`, `key.destroyed`, `key.compromised`, `wrap.failed`,
`admin.read`, `guard.denied`, `guard.pending`, `job.failed`, `backup.stale`.
Ordinary encrypt and decrypt are not logged individually; their rates and
failures are metered.

## Control plane

- **Service:** HTTP handlers for key listing, status, rotate, request
  retire, destroy, and backup acknowledgement, each behind a host-supplied
  `Authorizer` (`Authorize(ctx, action, purpose) error`). Mounting and
  authentication are the host's.
- **CLI:** `keyforge status`, `rotate`, `retire`, `destroy`, `backup ack`,
  `verify` (round-trips a test value through every purpose). The CLI is a
  client of the library and the store, with no separate logic.

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

## Integration

keyforge is generic. A host application adopts it by supplying a store, a
provider, a guard that consults its retention and approval policy, an audit
sink, and an authorizer.
[systemforge](https://github.com/plexusone/systemforge) is the first host;
its adoption decisions are in its architecture decision records.
