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
| `keyforge` | Core types: `Purpose`, `KeyRef`, `Envelope`, `Store` (what the client needs from the registry), `Client` (`Encrypt`, `EncryptInline`, `Decrypt`, `Reencrypt`), errors |
| `algorithm` | The algorithm registry: identifiers, exact names, and construction of the AEAD for each (profiles and selection are added with the selector) |
| `envelope` | The binary and text formats, header validation, versioning, parser, and sealing and opening of the payload |
| `provider` | `Provider` interface, `KeyRef` and `KeySpec` (the root package re-exports them) |
| `provider/providertest` | The conformance suite every provider runs |
| `provider/local` | The keyring-file provider |
| `registry` | `Store` (the client's `keyforge.Store` plus key and version administration), record types, the key-version and data-key transition tables |
| `registry/memory` | In-memory store, the reference the SQL store is compared against |
| `registry/storetest` | The store conformance suite |
| `sqlstore` | The Ent-backed `registry.Store` for SQLite and PostgreSQL, with versioned schema and retry of engine contention |
| `sqlstore/ent` | The Ent schema and generated code |
| `embedded` | The single-host setup: keyring, SQLite registry, jobs and service wired from a directory and a root key source |
| `policy` | Rotation, epoch and retirement policy per purpose |
| `rotate` | KEK rotation, re-wrapping, rollback, retirement, destruction and the emergency procedures (the scheduler arrives with the control plane) |
| `guard` | The `Guard` interface, its decisions and combinators |
| `audit` | Lifecycle events, the `Sink` interface, a recorder, and the actor context |
| `service` | HTTP control plane |
| `cli` | The Cobra commands, over the control plane's HTTP API |
| `cmd/keyforge` | The standalone binary |

The module is one module. What keeps it reviewable is its import graph: the
packages that touch key material (`algorithm`, `envelope`, `provider`,
`provider/local`, the root package, and `metrics`, which holds only counters and
bounded labels) import only the standard library, and a test enforces it. The store holds wrapped keys and never a plaintext one, so
reading or editing the database yields no key and cannot move a ciphertext to
another record. Ent and the database drivers are imported by `sqlstore` only,
OmniWorkflow by `jobs` only, and Cobra by `cli` and `cmd/keyforge` only.

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

- At most one version per KEK is `active`, and exactly one once the first has
  been activated. A KEK whose only active version is marked `compromised` has
  none until another is activated, and wrapping fails closed meanwhile.
- A rollback demotes the newer version to `decrypt-only`; it does not
  compromise it, so data written under it stays readable.
- Nothing leaves `retired`, `destroyed` or `compromised` except as listed.
  Material retired by mistake is recovered only through the restore
  procedure, never by a state change.

### What the store enforces

The registry enforces what can be enforced structurally and atomically, so no
caller can violate it by mistake. Policy lives above it.

- **The transition table**, for key versions and for data keys. A refused
  transition changes nothing and is `ErrInvalidTransition`.
- **One active version.** Activating a version demotes the previous one in the
  same transaction. Demoting the active version directly is refused: a version
  stops being active by another being activated.
- **Rollback only to the most recent `decrypt-only` version**
  (`ErrNoRollbackTarget`).
- **Retirement needs its delay and no references.** `retire-requested` records
  a `retire_after` later than the request; completing before it is
  `ErrRetireDelay`; retiring or destroying while any data key is still wrapped
  under the version is `ErrVersionReferenced`. An emergency retirement of a
  `compromised` version skips the delay and not the reference check.
- **A data key is wrapped under a usable version.** Advancing an epoch
  requires a version that is `active`, or `decrypt-only` (a client holding a
  cached view may wrap under a version that has just been rotated out, and the
  re-wrap job moves it). Re-wrapping targets only an `active` version.
- **Advancing and re-wrapping are compare-and-set.** Concurrent writers
  converge on one key, and repeating a completed re-wrap succeeds, so a
  resumed job is safe.
- **The cap is exact.** Reservations are granted up to the limit and never past
  it, to a current `active` key only, however many callers race.

Not enforced by the store, because they are policy: how many versions to
retain, when to rotate, and whether a guard allows a destruction.

### The SQL store

`sqlstore` implements the registry over Ent for SQLite and PostgreSQL, and the
conformance suite runs against both. The memory store remains the reference
for behaviour.

- **Uniqueness is in the database.** Partial unique indexes allow one active
  KEK per purpose, one active version per KEK, and one current data key per
  purpose and subject, so a race that the transaction logic missed fails
  instead of corrupting the registry. Each is also a lookup the operations
  rely on.
- **Transactions.** Every operation that changes state is one transaction. On
  PostgreSQL it runs at the serializable level; on SQLite it begins
  immediately, so writers queue, and the pool is held to one connection. A
  serialization failure, a deadlock, a busy database or a unique violation from
  a lost race is retried a bounded number of times, and the retry re-reads, so
  a loser converges on the winner's record.
- **Stored forms.** Identifiers are their 16 raw bytes, which both engines
  order as `bytes.Compare` does, so a cursor over data keys means the same
  thing everywhere. States are the small integers of the Go constants, and
  changing one is a stored-format change. An absent time is `NULL`, never the
  zero time. Times are read back in UTC.
- **A destroyed key keeps its record and loses its wrapped value**, in the same
  statement that changes its state, so there is no moment with a destroyed key
  that still holds a wrapped one. The wrapping history (`wrapped_under`) is
  kept, because it decides when a shred is complete.
- **The schema** is created by an automatic migration when the store is
  opened. Versioned migrations are a follow-up, and until then a schema change
  is additive only.
- **Scale.** The encryption counter takes a transaction per block reservation,
  not per encryption, which is what keeps the data path off the database.

### Data key states

| State | Write | Read | Notes |
|---|---|---|---|
| `active` | yes | yes | The current epoch for a purpose and subject |
| `decrypt-only` | no | yes | A superseded epoch |
| `compromised` | no | yes | Marked by an operator; readable so what it protects can be re-encrypted. A compromised current key is replaced on the next write after a client's cached view of it expires (at most the cache TTL), and data under it is reported stale |
| `destroyed` | no | no | No usable wrapped key |

A current key is demoted only by advancing the epoch, never by marking it
directly. `active` to `compromised` and `decrypt-only` or `compromised` to
`destroyed` are the only direct changes; a `compromised` key stays
`compromised` when the epoch advances.

### Registry records

- **Key**: `id`, `purpose`, `kind` (`kek`), `provider`, `state`, `created_at`.
- **Key version**: `key_id`, `version`, `state`, `created_at`, `rotated_at`,
  `retire_after`, `provider_ref`.
- **DEK**: `id`, `purpose`, `subject` (optional), `epoch`, `kek_id`,
  `kek_version`, `wrapped`, `state`, `reserved` (encryption-count high-water
  mark, see [Encryption counter](#encryption-counter)), `created_at`.
- **Jobs** are not a registry record: their identity, state and resumption
  belong to the OmniWorkflow provider that runs them (see Scheduling).
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
- **Purpose names:** 1 to 255 bytes of lowercase ASCII letters, digits, `.`,
  `_` and `-`, beginning with a letter or digit. The restriction keeps a
  purpose unambiguous in logs, configuration and the header; anything else is
  `ErrInvalidPurpose`.
- **Field consistency:** reference mode requires a non-zero data key ID and
  no inline fields; inline mode requires a non-zero key-encryption key ID, a
  wrapped key of 1 to 65535 bytes, and no data key ID. An inconsistent header
  is `ErrInvalidHeader` on write and on parse.
- **Text form:** `kf1.` followed by unpadded base64url, for text columns and
  JSON. It has one spelling: padding, line breaks, the standard alphabet and
  non-canonical trailing bits are rejected with `ErrBadTextForm`. A
  well-formed prefix for another version is `ErrUnsupportedFormat`.
- **AAD:** the header bytes up to the nonce, followed by the caller context.
  Changing the purpose, key, mode or context makes decryption fail.
- **Algorithm 1 (registry ID 1):** AES-256-GCM through `cipher.NewGCMWithRandomNonce`, the
  only GCM constructor permitted under `fips140=only`. Its output begins with
  the 12-byte random nonce, which the format stores in the header's nonce
  field and restores on open. Each encryption is counted against the DEK's
  cap (see [Encryption counter](#encryption-counter)), and a DEK reaching its
  cap is rotated to a new epoch before the NIST random-nonce limit of 2³²
  invocations. The default cap is 2³⁰.
- **Forward compatibility:** unknown `format`, `mode`, `algorithm` or `flags`
  values fail with a typed error rather than a guess. The parser is fuzzed.
- **Typed errors:** `ErrBadMagic`, `ErrTruncated`, `ErrUnsupportedFormat`,
  `ErrUnknownMode`, `ErrUnknownAlgorithm`, `ErrUnsupportedFlags`,
  `ErrInvalidPurpose`, `ErrInvalidHeader`, `ErrBadTextForm`, and
  `ErrAuthentication`. The ones that report a value carry it in a
  `ValueError`. `ErrAuthentication` carries no detail: a wrong key, a changed
  header or context and a modified ciphertext are not distinguished.
- **Sealing and opening:** the payload is sealed with an AEAD that generates
  its own random nonce, which is split off the output and stored in the
  header's nonce field, and reassembled on open. An AEAD that takes an
  explicit nonce is refused (`ErrNotRandomNonce`), so a nonce can never be
  chosen by a caller.

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
- A reservation is granted up to the cap and never past it, so the last block
  of a key is partial. When nothing is left, or the key is no longer the
  current epoch, the registry grants zero and the writer advances to a new
  epoch; the write then proceeds under the new epoch's DEK. If no new epoch
  can be created, the write fails closed.
- The cap should be far larger than the block size times the number of
  concurrent writers. A write retries a bounded number of times when other
  writers use up a key's capacity first, and fails closed with
  `ErrKeyUnavailable` if it cannot get a key with capacity.
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
    ID          envelope.ID // [16]byte
    Provider    string
    ProviderRef string
}

// KeySpec describes a KEK to create.
type KeySpec struct {
    Purpose   string       // a valid purpose name; the provider may label with it
    Algorithm algorithm.ID // from the registry
    ID        envelope.ID  // optional: a key moved from another provider keeps its ID
}
```

- The envelope carries only `ID`, so it stays provider-neutral and a key can
  move between providers by updating the registry, not the data.
- A provider never returns KEK material. `Wrap` and `Unwrap` take the AAD
  (purpose and key identity) so the wrap is bound to its use; a KMS provider
  maps it to the service's encryption context.
- **Versions** are numbered from 1 and increase. `CreateKey` makes version 1;
  `Rotate` adds the next and returns its number, leaving earlier versions
  usable for `Unwrap`. Which version is active is the registry's decision.
- **Errors are typed and carry no detail that helps an attacker:**
  `ErrKeyNotFound`, `ErrVersionNotFound`, `ErrVersionDestroyed`,
  `ErrUnsupportedAlgorithm`, `ErrInvalidArgument`, and `ErrUnwrapFailed`,
  which is the same for a wrong AAD, a wrong version or key, and a modified or
  truncated wrapped key.
- `Destroy` is irreversible and idempotent, so a retried job is safe. After it
  `Wrap` and `Unwrap` for that version fail with `ErrVersionDestroyed`.
- Every method honors the context: with a cancelled context it returns an
  error wrapping `ctx.Err()` and changes nothing. Providers neither retain nor
  modify their inputs, return slices the caller owns, and are safe for
  concurrent use.
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
- **The root key is 32 random bytes**, supplied as base64 or hex by an
  environment variable, a file, or code. keyforge does not stretch a
  passphrase: a passphrase is not a key. A file source must not be readable by
  group or others, and a root key file in the keyring's directory is refused.
- The keyring is sealed with AES-256-GCM under a key derived from the root key
  with HKDF-SHA-256 (the standard library's `crypto/hkdf`). A **root-key ID**
  is derived from the same root key under a different context string, so it
  identifies the key without revealing it or the encryption key. It is stored
  in the file's header, which is authenticated but not encrypted. Opening a
  keyring with a different root key fails with `ErrWrongRootKey` before
  decryption is attempted, so a wrong key is not reported as a corrupted file.
- **File format** (frozen once a keyring exists): a fixed 32-byte header,
  authenticated as the additional data, then the sealed payload.

  ```text
  magic "KFKR" | format u8 | reserved u8 | algorithm u8 | reserved u8
  root key ID : 16 bytes
  generation  : u64, big-endian
  sealed      : nonce (12) || ciphertext || tag
  ```

  The payload is JSON: for each KEK its identifier, purpose, algorithm, latest
  version, and each version's key material or a destroyed marker. Reserved
  bytes must be zero, and anything unrecognized is `ErrCorruptKeyring`.
- **Root-key rotation** re-encrypts the keyring under a new root key in one
  atomic write and records the new root-key ID. The keyring is small, so this
  is a rewrite, not a job.
- **Escrow is the operator's.** keyforge does not split or escrow the root
  key; that would mean implementing a cryptographic scheme. The operations
  guide documents keeping the root key in a secret manager with a second,
  offline copy. The DR drill obtains the root key through a separately
  configured recovery `RootKeySource`, so the escrow path is tested rather
  than assumed.
- Writes are atomic: take an advisory lock, re-read the file, apply the
  change, write a temporary file in the same directory, fsync it, rename it
  over the keyring, and fsync the directory (a no-op on Windows, where the
  rename is itself atomic). A change is made against a fresh read under the
  lock, so concurrent processes do not interleave and none loses another's
  version. A crash leaves the previous keyring or the new one; temporary files
  left behind are removed by the next writer.
- The file is created with mode 0600, and a keyring that group or others can
  read is refused. Opening a provider zeroes the root key after deriving from
  it, and `Close` zeroes the key material the provider holds.
- A monotonically increasing **keyring generation** is stored in the file's
  authenticated header, where it can be read without the root key. Every
  change, including a root key rotation, increases it, and a write is always
  above every generation the host has seen, so generations are never reused.
- **Backup state** is kept in a small file beside the keyring
  (`<keyring>.backup`), not inside it: recording an acknowledgement in the
  keyring would itself change its generation and leave it permanently one ahead
  of its acknowledgement. It holds the highest generation seen and the last
  acknowledged one with its time and a note. It is not authenticated: it
  catches mistakes, not an attacker who can already replace the keyring.
- `keyforge backup ack` records the generation of the copy the operator has
  safely stored. It cannot acknowledge a generation the keyring has not
  reached, or one older than the last acknowledgement. `status` reports a
  keyring whose generation is ahead of the acknowledged one, and rotation under
  a policy that requires a verified backup waits until the acknowledgement
  catches up (otherwise a restored backup that predates a rotation would lose
  data wrapped under the newer version).
- **Restoring an older copy is detected** when the keyring is opened: a
  generation below the highest this host has seen is `ErrKeyringRolledBack`,
  naming both. An operator who intended the restore opens with the rollback
  accepted, which clamps the acknowledgement to the restored generation and
  continues numbering above everything seen. A copy can be compared with the
  live keyring without the root key by reading its generation and root key
  identifier from the header.
- The provider is reported as `local` in status and in the startup log, so it
  is not mistaken for a managed one.

## Client

```go
func (c *Client) Encrypt(ctx, purpose, plaintext, context) (*Envelope, error)
func (c *Client) EncryptInline(ctx, purpose, plaintext, context) (*Envelope, error)
func (c *Client) Decrypt(ctx, purpose, e *Envelope, context) (plaintext []byte, info Info, err error)
func (c *Client) Reencrypt(ctx, purpose, e *Envelope, context) (*Envelope, error)
```

- **Purposes are configured.** A purpose the client was not given fails with
  `ErrUnknownPurpose`. `New` validates every purpose against the algorithm
  selector, so a configuration that widens the profile or leaves a purpose with
  nothing to write with fails at startup.
- **Decrypt names the purpose** it expects. An envelope for another purpose is
  `ErrPurposeMismatch` before any key work, and the purpose is authenticated
  in any case.
- **Reference mode** (`Encrypt`) uses the purpose's current data key. **Inline
  mode** (`EncryptInline`) generates a fresh data key per object and wraps it
  under the purpose's active KEK version, so it contacts the provider once per
  object to wrap, and once to unwrap an object the process has not seen. It is
  for standalone objects, and not for a hot path against a managed key
  service.
- **Reads** are allowed under `active`, `decrypt-only` and `compromised` data
  keys, so data can be re-encrypted away from a compromised one; a `destroyed`
  key fails with `ErrKeyUnusable`. **Writes** use only the `active` key.
- **`Info.Stale`** is true when the envelope's data key is not the current
  epoch (reference mode) or its KEK version is older than the active one
  (inline mode). `Reencrypt` decrypts and writes again under the current key in
  the same mode; it always produces a new envelope, and callers use `Stale` to
  skip current ones.
- **Time and randomness are injected:** a clock and an entropy reader supply
  cache expiry, data keys and identifiers. Nonces come from the AEAD's own
  generator and are not drawn from the entropy reader.
- **Fail closed:** when a key cannot be obtained (registry or provider down and
  nothing cached, entropy failure), the operation returns `ErrKeyUnavailable`;
  it never falls back to a weaker path.

### Wrapping data keys

A data key is wrapped by the provider with additional data that binds it to its
record. The layout is part of the stored format, and changing it makes existing
wrapped keys unreadable:

```text
reference: "keyforge/dek/v1\x00" | lp(purpose) | lp(subject) | dek_id (16) | kek_id (16)
inline:    "keyforge/inline/v1\x00" | lp(purpose) | kek_id (16)
```

`lp` is a u32 big-endian length followed by the bytes. The subject is empty for
a purpose-wide key. A wrapped key therefore cannot be moved to another purpose,
subject or record, and the re-wrap job recomputes the same additional data when
it moves a key to a new KEK version.

## Policy

Policy is declared per purpose and is data: the `policy` package holds it and
the rotation and retirement code acts on it. A deployment has a default and
per-purpose overrides; a field a purpose leaves unset inherits.

| Field | Default | Meaning |
|---|---|---|
| `kekInterval` | 365 days | How long a KEK version is active before rotation |
| `dekMaxAge` | 90 days | How long a data key epoch is current |
| `dekMaxEncryptions` | 2³⁰ | Cap on encryptions per data key |
| `retirementDelay` | 30 days | Wait between a request to retire a version and its retirement |
| `retainVersions` | 2 | Floor on versions kept: the active one and the most recent decrypt-only ones |
| `requireBackup` | false | Rotation waits until the keyring backup is acknowledged as current |

- **A purpose can only tighten `requireBackup`**: it can ask for a backup the
  default does not require, and cannot waive one the default does.
- **The retirement delay must far exceed the cache TTL** (at least ten times),
  so that no data key can appear under a version that is already eligible for
  retirement. A set that violates this fails validation.
- The encryption cap must not exceed 2³¹, well below the 2³² random-nonce
  limit.
- Durations are written with a day suffix in configuration (`365d`, `36h`), and
  an unknown field is an error so a misspelled setting is not ignored.

## Rotation

### KEK rotation (automatic, default 365 days)

1. Create the next version at the provider and register it as `pending`.
2. Mark it `active` and the previous version `decrypt-only`, in one registry
   transaction.
3. Record a **sentinel** for the new version: a fixed, non-secret marker sealed
   as an inline envelope under a fresh data key wrapped by that version. The
   recovery drill decrypts it to prove a restored registry and keyring can still
   use the version.
4. A resumable job re-wraps DEK records still wrapped under the old version,
   in batches, recording a cursor. Each batch unwraps with the old version
   and wraps with the new one using the same additional data, then replaces the
   record with a compare-and-set on the version it read; it is idempotent.
5. When no DEK record references the old version, it becomes eligible for
   retirement, subject to the retained-versions rule below.

- **The interval is measured from activation**, recorded as `ActivatedAt` on
  every activation including a rollback, and not from creation.
- **Rotation resumes.** A version left `pending` by an interrupted rotation is
  activated instead of creating another at the provider. The provider call and
  the registration are not one transaction, so a crash between them leaves at
  worst an unused version at the provider.
- **The re-wrap does not stop at a bad key.** A data key that cannot be moved
  is counted and reported, the rest are moved, and the run is not `done`, so a
  version that is still referenced is not retired. Overlapping runs are safe:
  the compare-and-set makes one the winner and the other count the key as
  already moved.
- **Rollback** reactivates the most recent decrypt-only version and demotes the
  active one in the same transaction. Data keys wrapped under the demoted
  version still unwrap under it.
- **A backup requirement waits.** Where policy requires a verified backup and
  the keyring's backup is not acknowledged as current, rotation is refused with
  `ErrBackupStale`, and is refused with `ErrBackupUnknown` if the provider
  cannot say. It fails closed.

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

- **Age is measured from the record's creation time**, which comes from the
  registry, so every replica agrees on it. A write that finds the current epoch
  at or past its maximum age creates the next one; replicas racing to do so
  converge on one through the registry's compare-and-set. An epoch is used for
  less than its lifetime, never up to and past it.
- Age and volume are independent triggers: whichever is reached first rolls the
  epoch. The client's per-purpose configuration takes both from policy.
- An old epoch is not stranded: it keeps decrypting, reports `Stale`, and its
  data moves to the current epoch on the host's next write or by `Reencrypt`.

### Per-subject keys and crypto-shredding

A purpose can be declared **per-subject**: each subject (a user, a tenant) gets
its own DEK epochs, written with `EncryptFor(purpose, subject, ...)`. The
subject is not in the envelope: the envelope names its data key, and the
registry knows whose key that is. A subject is 1 to 255 bytes of valid UTF-8
with no control characters, and it is part of the additional data the key is
wrapped with, so a wrapped key cannot be moved to another subject. A per-subject
purpose rejects a write without a subject, and any other purpose rejects one
with a subject.

Shredding a subject destroys its DEKs, which makes its data unrecoverable
wherever the ciphertext was copied.

Destroying a DEK record does not complete the shred on its own. Registry
backups still hold the subject's DEK wrapped under the KEK versions that were
active while it existed, and while any of those versions survives, a restored
backup can unwrap it. So:

- **Every data key keeps a history** of the KEK versions it has been wrapped
  under, in order. A re-wrap moves a key to a newer version but an older backup
  still holds it under the previous one, so the history is what decides which
  versions matter.
- **Requesting a shred** destroys every data key of the subject under the
  purpose, in every state, removes their wrapped values, clears the current key,
  and records the union of their histories. It is atomic and idempotent, and
  leaves a **tombstone**: a new key for the subject is refused with
  `ErrSubjectShredded`, because an erasure that quietly re-enrolled the subject
  would not be one.
- **A shred is complete when every KEK version in that record is destroyed.**
  It is reported as `pending`, with the outstanding versions and an expected
  date, until then. Completing is checked by the registry, not asserted.
- **The expected date follows from policy:** a version leaves the retained
  floor after that many further rotations, one KEK interval apart, and then
  waits out the retirement delay. With the defaults (365 days, two retained
  versions, 30 days) that is more than two years for a version that is active
  today, plus backup retention. A purpose that needs a faster erasure guarantee
  sets a shorter KEK interval.
- A subject with no keys completes at once, and is still tombstoned.
- **Caches.** A client that has the subject's key cached keeps using it until
  the entry expires or `Purge` is called, so the live registry stops serving the
  key at once and a process may serve it for up to the cache TTL. A host that
  needs the erasure effective at once purges its clients.
- Shredding is per-subject reference mode only. Inline envelopes carry their
  own wrapped key and are shredded only by destroying the KEK versions or the
  objects.

### Retirement and destruction

Retirement and destruction are separate steps, each consulting the **guard**,
because the facts can change between them.

1. **Request.** A decrypt-only version outside the retained-versions floor moves
   to `retire-requested` and the delay starts (default 30 days, per purpose).
   References do not stop the request: the re-wrap can finish during the delay.
2. **Complete.** After the delay, with no data key in the registry wrapped under
   the version, the guard is asked. Only an **allow** moves it to `retired`.
   **Deny** returns it to `decrypt-only`, usable, with the denial recorded, and it
   can be requested again. **Pending** (an approval is outstanding) leaves it
   `retire-requested` and the guard is asked again on the next pass. A guard
   that **fails**, or is **absent**, advances nothing: the absence of a veto is
   not consent, and a zero decision is not an allow.
3. **Destroy.** A `retired` version's material is destroyed at the provider,
   after the guard is asked again. The order is guard, then provider, then
   registry. Destroying at the provider is idempotent, so a crash between the
   last two is repaired by calling again; the reverse order could record a
   destruction that did not happen.

- **A retired version is not usable**, even though the provider still holds its
  material until step 3: the client asks the registry whether a version may be
  unwrapped, on the first unwrap and then from its cache, and refuses
  `retired`, `destroyed` and `pending`. Retiring therefore has an effect on its
  own, and not only at destruction.
- Destruction is irreversible at the provider. Where a provider offers a
  deletion window, it can be used to schedule the destruction and cancel it
  inside the window; the provider interface does not yet expose one.
- The guard sees the action, the purpose, the KEK version, how many registry
  data keys still reference it (zero at completion), who asked, and whether the
  procedure is an emergency. It cannot see data outside the registry, which is
  why the host supplies it: an inline envelope, an export, a snapshot or a
  backup that needs the version is the host's to know.
- Every outcome is an audit event: `key.retire_requested`, `key.retired`,
  `key.retire_cancelled`, `key.destroyed`, `guard.denied`, `guard.pending`.

### Emergency rotation

Separate from scheduled rotation, and audited as such. It differs in three
ways: it does not wait for a backup to be acknowledged, it has no retirement
delay, and the guard is **asked and its answer recorded, but it cannot block**.
A guard that denies, is pending, fails or is absent is on the trail and does not
stop the procedure.

**KEK compromised.** For a version that is known or suspected to be exposed:

1. If it is active, replace it: the activation demotes it in the same
   transaction, so there is no moment without an active version and nothing new
   is wrapped under it afterwards. (A client holding a cached view can wrap
   under it until its entry expires; the re-wrap covers those, and a repeat call
   picks up stragglers.) A version that is not active needs no replacement.
2. Mark it `compromised`.
3. Re-wrap every data key away from it.
4. Ask the guard and record the answer.
5. Retire it, then destroy it at the provider, unless asked to keep the
   material.

- It is **idempotent and resumable**. If any data key cannot be moved the
  version stays `compromised` and referenced, is not retired or destroyed, and
  the call reports it as incomplete with the progress; calling again continues
  without repeating the replacement or the marking.
- **Data outside the registry** (inline envelopes, exports, snapshots) wrapped
  under the version is not covered by the re-wrap and is lost when it is
  destroyed. `KeepMaterial` stops after retirement so the host can recover what
  it needs before destroying through the usual guarded path.

**DEK exposed.** For a data key known or suspected to be exposed:

1. If it is the current epoch, create the next epoch first, so writes move off
   it at once.
2. Mark it `compromised`. It stays readable.
3. The **host re-encrypts** what it protects, with `Reencrypt` as it meets each
   record or in a pass of its own: the data is the application's, and keyforge
   cannot do it. The report gives an **upper bound** on how much was encrypted
   under the key, the registry's reserved high-water mark, which can overstate;
   which records are affected is found by the data key identifier their
   envelopes carry.
4. When the host is done it destroys the key through the guard. Destroying
   removes the wrapped value and keeps the record as the trail.

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

Lifecycle work runs as jobs on [OmniWorkflow](https://github.com/plexusone/omniworkflow),
through its provider-neutral `WorkflowProvider`. The `jobs` package supplies the
scheduler that notices what is due and the executor that does each step; any
OmniWorkflow provider runs them: in-memory, the durable embedded provider,
Temporal, or Step Functions.

- **Operations are idempotent and resumable by construction**, which is what
  makes at-least-once step delivery safe: a rotation re-checks that it is due,
  a re-wrap moves only what has not moved, and the guarded steps ask the guard
  again.
- **Exactly one execution without leader election.** Every job has a
  deterministic run ID built from what it does and to what (for example
  `keyforge/rotate-kek/<kek>/<version>#<attempt>`). OmniWorkflow's `Start` is
  idempotent by run ID, so several replicas that find the same work due start
  the same run and one execution results. keyforge keeps no lease.
- **Time is the scheduler's.** A plan has no timers, so a tick evaluates the
  registry and starts short jobs: a rotation when a version is past its
  interval, a drain of any non-active version still holding data keys, a
  retirement request for a version outside the floor, a completion once the
  delay has passed, a destruction once retired, and the recording of finished
  erasures. A retirement delay, or a guard that is still pending, is a
  condition the next tick finds still true.
- **Attempts.** A finished run is terminal, and `Start` on its ID returns it
  without running again, so each new attempt has a new number. A run that
  succeeded while its condition still holds (a pending approval) is followed by
  another only after a recheck interval; one that failed is followed by one
  after a backoff that doubles up to a ceiling. A failure is reported once, with
  a `job.failed` event, and stays in the tick result while it is the latest word.
- **Overdue work is reported, not silently kept**: a rotation past its date is
  listed in every tick's result, whether or not a job is running for it.
- **Resumption.** With the durable provider a run left unfinished by a crash
  resumes under the same run ID when the worker starts. The durable provider is
  single-process; a deployment with several replicas gives the scheduler and
  worker a shared provider such as Temporal.
- **Guard approvals** are the host's callback. A `Pending` answer leaves the
  version where it is and the next tick asks again, so a long wait for an
  approval costs one short job per recheck interval and not a held run.

## Caching and availability

- Unwrapped DEKs are cached in process with a TTL (default 5 minutes) and a
  size bound with least-recently-used eviction. The raw key is zeroed as soon
  as the cipher has been constructed, and only the cipher is cached; Go gives
  no guarantee about the cipher's expanded key schedule.
- The client also caches the current data key record per purpose and subject,
  the active KEK version per purpose, and KEK references, under the same TTL.
  `Stale` is computed from the cached current record, so it is advisory: an
  outage can hide it, and it never fails a read.
- A key destroyed or retired in the registry can still be used from a cache
  until its entry expires. `Purge` drops every cached key at once for a host
  that needs immediacy.
- A client that cached the active KEK version keeps wrapping new data keys
  under it until the entry expires, so a data key can be created under a
  version that has just stopped being active. The re-wrap job covers those
  records, and the retirement delay (30 days by default) must be far longer
  than the cache TTL (5 minutes by default) so that no such record can appear
  after a version is eligible for retirement.
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

Metrics go through a small `Metrics` interface in the core (counters, gauges and
duration observations), with a no-op default. An adapter to Prometheus or
OpenTelemetry is a few lines over it and lives in the host or a separate module,
so the core keeps its dependency rule.

| Metric | Type | Labels |
|---|---|---|
| `keyforge_operations_total` | counter | `op`, `purpose`, `outcome` |
| `keyforge_operation_duration` | observation | `op`, `purpose` |
| `keyforge_cache_lookups_total` | counter | `cache` (dek, inline, current), `result` |
| `keyforge_epoch_advances_total` | counter | `purpose`, `reason` (first, cap, age, not_active, manual) |
| `keyforge_kek_rotations_total` | counter | `purpose`, `outcome` |
| `keyforge_rewrapped_keys_total` | counter | `outcome` (moved, skipped, failed) |
| `keyforge_kek_rotation_overdue_seconds` | gauge | `purpose` |
| `keyforge_jobs_started_total`, `keyforge_jobs_failed_total` | counter | `kind` |
| `keyforge_jobs_waiting`, `keyforge_jobs_in_flight` | gauge | none |

- **Labels are bounded by construction.** The purpose is a configured name, and
  one the client is not configured for is reported as `unknown`; an outcome is
  one of a small fixed set (`ok`, `unavailable`, `unusable`, `authentication`,
  `invalid`, `refused`, `shredded`, `error`). A subject, a key identifier, a
  context or an error message is never a label.
- **The overdue gauge is reported as zero when nothing is late**, for every
  configured purpose, so a recovered rotation clears an alert instead of leaving
  a stale value.

## Status

`status.Reporter.Report` assembles one point-in-time view for an operator, a
service endpoint or a ticket. It holds identifiers, states, counts and times,
and never key material, wrapped keys or plaintext.

| Section | Content |
|---|---|
| Crypto | The active algorithm profile and its exact algorithm names, whether the process is in FIPS mode and whether non-approved algorithms are refused outright, and the Go cryptographic module version |
| Providers | Each provider's name and health, and for a provider with a keyring its backup state: generation, acknowledged generation, how far behind, and the note |
| Purposes | Per purpose: the KEK and provider, every version with its state, activation, rotation and retirement times, how many data keys still reference it, whether it may be retired and why not; the next rotation and how overdue; data keys by state; and the policy in force |
| Erasures | Each pending subject erasure with how many KEK versions remain and when it is expected to finish |
| Jobs | The scheduler's latest tick: work in flight, work held back, and jobs whose latest attempt failed with their consecutive failures |

- **`Healthy` is false when anything needs an operator**, and `Problems` says in
  plain words what: an unhealthy provider, an overdue rotation, a keyring ahead
  of its acknowledged backup, a purpose with no active version (writes fail
  closed), compromised data keys not yet destroyed, or a failing job.
- **A part that cannot be read is reported as such and does not hide the rest.**
  An outage of one provider is what the report is for.
- The provider is reported by its name, `local` for the keyring provider, so it
  is not mistaken for a managed one.

## Control plane

- **Service:** an `http.Handler` (package `service`) over the library, with no
  logic of its own. Mounting, TLS and authentication are the host's: it
  authenticates in its own middleware, names the caller with `audit.WithActor`
  so the events a request causes are attributed, and supplies an `Authorizer`
  (`Authorize(ctx, action, purpose) error`) that is asked before every action.
  There is no default: a service with no authorizer cannot be constructed.
- **CLI:** `keyforge status`, `health`, `purposes`, `rotate`, `rollback`,
  `rewrap`, `retire request|complete|cancel`, `destroy`, `compromise`,
  `datakey compromise|destroy`, `backup ack`, `shred request|status`, `verify`,
  and, with the drills, `drill`. The CLI is a client of the control plane's HTTP
  API and holds no logic of its own, so the command line cannot do what the
  service would refuse. It has two transports: a remote server (`--server` or
  `KEYFORGE_SERVER`, with a bearer token from `--token-file` or
  `KEYFORGE_TOKEN`), and an in-process handler for a host binary that embeds the
  commands, where no network is involved and the host's own authorizer applies.
  `keyring inspect` (a keyring file's generation and root key identifier,
  without the root key) and `rootkey generate` (32 random bytes as base64) need
  no server. `--json` prints the response unchanged. Commands exit non-zero on an
  error and on a guard's denial, and a denial's body is still shown. Cobra is
  imported only by the `cli` and `cmd/keyforge` packages.

### Endpoints

| Method and path | Action | Notes |
|---|---|---|
| `GET /v1/status` | `status.read` | The full report; always 200 |
| `GET /v1/health` | `status.read` | 200 when healthy, 503 with the problems otherwise |
| `GET /v1/purposes`, `GET /v1/purposes/{purpose}` | `keys.list` | |
| `POST /v1/purposes/{purpose}/rotate` | `keys.rotate` | Rotation only; the drain is the scheduler's or `rewrap` |
| `POST /v1/purposes/{purpose}/rollback` | `keys.rollback` | |
| `POST /v1/purposes/{purpose}/rewrap` | `keys.rewrap` | Synchronous, bounded by the request |
| `POST /v1/keks/{kek}/versions/{v}/retire` | `keys.retire.request` | Starts the delay |
| `POST .../retire/complete`, `.../retire/cancel` | `keys.retire.complete`, `keys.retire.cancel` | |
| `POST .../destroy` | `keys.destroy` | |
| `POST .../compromise` | `keys.compromise` | Emergency; body `{"keepMaterial": bool}` |
| `POST /v1/datakeys/{id}/compromise`, `/destroy` | `datakeys.compromise`, `datakeys.destroy` | |
| `POST /v1/backups/{provider}/ack` | `backup.ack` | Body `{"generation", "note"}` |
| `POST`, `GET /v1/purposes/{purpose}/subjects/{subject}/shred` | `shred.request`, `shred.read` | 202 until complete |

- **Authorization comes first.** The action is authorized before the resource is
  looked up, and a key path is authorized against the purpose the key belongs to
  once resolved, so a caller who may not act cannot learn from the response
  whether a key exists. An unknown resource is a 404 only for a caller who is
  permitted the action. No body is read before authorization.
- **Status codes.** `401` for no identity, `403` for any other refusal, with no
  reason echoed; `404` unknown resource; `409` for a state or policy conflict
  (a denial by the guard, a delay not yet run, a version still referenced, a
  stale backup); `202` for an approval still outstanding or an erasure not yet
  complete; `503` when a key or provider is unavailable.
- **Errors carry a stable code and a message that names no detail.** An
  unexpected failure is `500 internal` with a generic message; the detail is the
  host's to log.
- **An audit gap is a warning, not a failure.** When the change was made and its
  event could not be recorded, the response is `200` with a `warnings` entry, and
  the caller is not told the operation failed.
- Request bodies are JSON, at most 1 MiB, with unknown fields refused.
- Administrative reads are themselves audited (`admin.read`).

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
  without module validation. A denial can only narrow the profile.
- Each purpose declares an optional **pinned profile** and an
  **allowed-algorithm list**. A pinned profile must be no wider than the
  active one, and the list must be a subset of the profile in force, without
  repeats. Startup validates every configured purpose and fails fast, reporting
  every violation, including a purpose left with no algorithm to write with.
- **Writes** choose the first algorithm of the purpose's list that the profile
  in force permits, or the profile's first algorithm when the list is empty;
  with none, the write fails closed (`ErrNoPermitted`). **Reads** follow the
  profile in force and not the write list, so narrowing a list does not strand
  data already written: an envelope that names an algorithm outside the
  profile fails with `ErrNotPermitted`, which reports the algorithm and the
  profile, and does not fall back. Migration is a `Reencrypt` in a process
  whose profile permits the old algorithm.
- `status` reports the profile, the module version (`crypto/fips140.Version`)
  and whether the process is in FIPS mode.

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
- A shred is complete for the live system only. Shreds and tombstones live in
  the registry, so restoring an older registry resurrects the subject's keys,
  and a keyring backup taken before the versions were destroyed still holds
  their material. Operators expire such backups on the erasure's schedule and
  keep a record of requested erasures outside the registry.
- A client holding a cached key for a shredded subject goes on writing under it
  until the entry expires or `Purge` is called, and what it writes cannot be
  read elsewhere. `Purge` covers reads and writes, and in-flight operations do
  not repopulate the caches afterwards.
- A keyring copied over the file under a running provider is refused at the
  next write and at the next open, but the provider keeps its in-memory copy
  until restarted; restores are done with the process stopped.
- Inline wraps are not counted per KEK version; the nonce bound for one
  key-encryption key version is the operator's to respect by rotating on a
  schedule that fits the inline volume.
- Unauthenticated inline envelopes cost a registry call and a provider unwrap
  and can evict cache entries; they cannot disclose a key.
- A guard's denial at destruction leaves a version retired, not in service; the
  veto that returns a version to service is the one at retirement.
- A retained-backup requirement gates the previous keyring generation, not the
  new version: a disk lost straight after a rotation loses what was wrapped
  under the new version.
- Rotating the root key re-encrypts the keyring and rotates no
  key-encryption key.
- A provider process keeps the material of a version another process has
  destroyed until it reloads the keyring.

## Testing

- **Provider conformance suite**, run against every provider.
- **Store conformance suite**, run against the in-memory and SQL stores.
- **Known-answer vectors** for the envelope format, published in
  `testdata`.
- **Fuzzing** of the envelope parser.
- **Property tests:** encrypt, rotate any number of times, decrypt.
- **Crash tests:** killing the process during a keyring write and during a
  re-wrap batch leaves a consistent, resumable state. For the keyring this is
  tested two ways: a write is stopped at each stage (temporary file created,
  written, flushed, renamed, directory flushed) and the file left behind is
  opened, and a helper process rotating in a loop is killed at random moments
  and the keyring checked for a torn or mixed state each time, with the dead
  process's lock required not to block the next writer. These show that no
  crash point leaves a keyring that fails to open or mixes two states. They
  cannot show that the operating system and storage honor `fsync` ordering
  through a power loss; that rests on the platform.
- **Race detector** on the cache, scheduler and store.
- **Injected time and randomness.** The `Client`, policy, scheduler and drill
  take a clock, and DEK and key generation take an entropy reader, so tests
  are deterministic. GCM nonces come from `NewGCMWithRandomNonce` and cannot
  be injected; the known-answer vectors therefore fix the open path (decrypt
  a published envelope), and the seal path is tested by round trip.
- **Scale benchmark** for success criterion 2: a KEK rotation over a store
  holding a million wrapped DEKs completes, and concurrent reads succeed
  throughout. `BenchmarkRotateAndRewrap` (in memory, so it measures keyforge's
  own work) and `BenchmarkRotateAndRewrapSQLite` (a transaction per key) take
  `KEYFORGE_BENCH_KEYS`; one million keys is a few seconds in memory and a few
  minutes on SQLite with full synchronous writes. Batching several keys to a
  transaction is the known way to speed the SQL case up. Concurrent reads
  during a rotation and re-wrap are a test, run with the race detector.
- **Lifecycle tests on the whole stack** (`embedded`): a seeded random
  sequence of writes, rotations, re-wraps, the passage of time and restarts
  after which every envelope written still decrypts; and a re-wrap interrupted
  after each possible number of keys, then resumed by a restarted system.
- **FIPS-only run** of the test suite under `GODEBUG=fips140=only` in CI.

## Integration

keyforge is generic. A host application adopts it by supplying a store, a
provider, a guard that consults its retention and approval policy, an audit
sink, and an authorizer.
[systemforge](https://github.com/plexusone/systemforge) is the first host;
its adoption decisions are in its architecture decision records.

### Single-host setup

`embedded.Open` wires one host from a directory and a root key source, and
returns the pieces (client, rotator, reporter, registry, keyring, jobs) so a
host that outgrows it keeps the same objects and swaps the store or the
provider. It is a convenience over public packages, not a second code path.

- **Layout.** `keyring.kf`, `registry.db` and `runs/` in one directory,
  created `0700`. The root key is never in it: the keyring provider refuses a
  root key file beside the keyring.
- **Start is idempotent.** On a first start it creates the keyring, then a KEK
  for each configured purpose with its first version active and a sentinel
  recorded (`Rotator.EnsureKEK`). On later starts it changes nothing. A start
  interrupted part-way resumes: a KEK without an active version is completed,
  not replaced.
- **A missing keyring is not a first start.** If the registry holds keys and
  the keyring file is gone, `Open` fails with `ErrKeyringMissing` rather than
  creating an empty keyring, which would leave every operation failing beside
  a registry that names keys it cannot unwrap. A wrong root key is refused and
  changes nothing.
- **No control plane by default.** The HTTP handler exists only when an
  authorizer is supplied.
- **Backup is two files and a secret.** The keyring and the registry are backed
  up together, the keyring backup is acknowledged so rotation can rely on it,
  and the root key is kept elsewhere, because it cannot be recovered from
  either. `BackupRegistry` writes a consistent copy of the registry while the
  system runs, which copying the database file does not.
