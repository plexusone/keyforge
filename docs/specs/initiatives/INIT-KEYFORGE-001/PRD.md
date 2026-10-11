# keyforge: Product Requirements

**Initiative:** `INIT-KEYFORGE-001`
**Repository:** `github.com/plexusone/keyforge`

## Problem

Applications that encrypt data end up with a private, ad hoc key mechanism
per feature: a key in an environment variable for sessions, another for
backups, a signing key on disk. Each has the same gaps:

- **Rotation is a project.** Changing a key means re-encrypting everything it
  protects, so keys are never rotated, or are rotated rarely and with
  downtime.
- **No record of which key protects what.** When a key is suspected
  compromised there is no inventory of the data it covers.
- **No safe way to destroy.** Privacy erasure has to reach backups and
  replicas, and retention duties (legal hold) can forbid destroying a key at
  all. Nothing in the key mechanism knows either.
- **Single-host and cloud deployments differ.** A solo developer starts with
  a file; a production system uses a managed key service. Moving between them
  should not rewrite stored data.

Managed cloud services solve rotation well (a key keeps its identifier,
gains new key material, and old material stays available for decryption),
but applications still have to model purposes, per-subject keys, destruction
policy and audit around them, and cannot rely on a managed service when
running locally.

## Goals

1. **One interface for all application encryption**, independent of where
   the root keys live.
2. **Rotation without re-encrypting stored data** and without downtime, done
   automatically on a schedule.
3. **A versioned, self-describing ciphertext format**, so any record can be
   decrypted, rotated or destroyed knowing only what is stored beside it.
4. **Destruction as a controlled, audited operation** that a caller can veto,
   including crypto-shredding of per-subject data.
5. **Works from a single file key to a managed KMS** by configuration.
6. **Reviewable.** Small surface, standard primitives, public, with a stated
   threat model.

## Non-goals

- Implementing cryptographic primitives. keyforge composes the Go standard
  library and `golang.org/x/crypto`.
- Replacing a KMS or HSM. Root keys stay in the provider.
- Storing application secrets, passwords or API keys. That is a secret
  manager's job.
- TLS certificate lifecycle in v1. Certificates and other key types may be
  added later through the same registry.
- Building the verifier. Test applications and scanners that check a
  deployed system against the exported crypto specification are a later,
  separate effort; keyforge's part is to produce the specification and the
  expectations they will consume.
- Authenticating callers of the control plane. The control plane takes an
  authorizer from the host application.

## Users

| User | Needs |
|---|---|
| Application developer | Encrypt and decrypt a value with a purpose and a context; never see key material |
| Operator | See key state, rotate or retire a key, know when a key is overdue or not backed up |
| Security reviewer | Read the format, the threat model and the audit trail |
| Platform integrator | Plug in retention and approval policy before destruction; supply provider and storage |

## Requirements

### Functional

| ID | Requirement |
|---|---|
| FR1 | Encrypt and decrypt byte strings with envelope encryption under a named **purpose**, bound to caller-supplied context so a ciphertext cannot be moved to another purpose or record |
| FR2 | A versioned, self-describing envelope format that identifies the purpose, key and key version, algorithm and nonce |
| FR3 | A provider interface that wraps and unwraps data keys without exposing the KEK; a local keyring provider; a documented path to cloud KMS providers |
| FR4 | A registry of keys, key versions and their states, with a store interface |
| FR5 | Automatic KEK rotation by policy per purpose, re-wrapping data keys with no change to stored data |
| FR6 | Data-key epochs: a new data key per purpose per period or per volume of encryptions; old epochs decrypt-only |
| FR7 | Lazy re-encryption: decrypting reports a stale envelope so callers can rewrite it on the next write |
| FR8 | Retirement and destruction as separate steps with a delay, a caller-supplied guard that can refuse, and an audit event |
| FR9 | Per-subject data keys, so destroying one key makes one subject's data unrecoverable everywhere it was copied |
| FR10 | Emergency rotation: destroy a compromised version and re-encrypt, as a separate audited procedure |
| FR10a | A retained-versions floor (default two: the active and previous versions) with rollback to the previous version; older versions retire only when unreferenced, past the delay, outside any hold, and allowed by the guard |
| FR10b | A built-in canary purpose that runs the full key lifecycle weekly on a key holding no data, with `keyforge verify` on demand and an alert when a drill fails or is overdue |
| FR10c | A fully automated disaster-recovery drill that restores keyforge's state from backup into an isolated environment, proves every retained key version can decrypt, measures recovery time and recovery point, destroys the environment, and emits a machine-readable result containing no key material |
| FR10d | A DR report written from the drill result by an analyst (an agent supplied by the host), covering the judgments that are not mechanical: severity, trends against earlier drills, likely causes and recommendations, with the analyst's conclusions marked as inferred and the objective results as verified |
| FR11 | Audit events for creation, rotation, wrap failures, administrative access, retirement and destruction, with no key material |
| FR12 | Status reporting: key states, next rotation, overdue keys, keyring backup status, provider health |
| FR13 | A CLI for status, rotation, retirement and backup acknowledgement, and an embeddable control-plane service |
| FR14 | Asymmetric KEKs used as hybrid encryption (later release) |
| FR15 | Signing-key management with published overlap on rotation (later release) |
| FR16 | An algorithm registry with exact names (mode and size), a `fips` and a `standard` profile fixed in code, per-purpose narrowing, and typed refusal of an algorithm outside the active profile |
| FR17 | An inventory of the cryptography keyforge governs (algorithms, profiles, purposes, key versions, providers, rotation state), and of **external boundaries** (edge TLS, service-to-service TLS, database TLS) with an expectation, an owner, a source of truth, and a review date |
| FR18 | Export of the inventory as a `systemspec-crypto` document, with enforced facts, declared external facts and their verification states kept distinct, containing no key material |

### Non-functional

| ID | Requirement |
|---|---|
| NFR1 | **No network call per operation.** Data keys are unwrapped once and cached in process; a control-plane or provider outage does not stop cached reads |
| NFR2 | Fail closed: with no usable key, operations fail rather than weaken |
| NFR3 | Rotation is online and resumable; it never requires a maintenance window |
| NFR4 | Key material is never logged, returned in errors or written to audit events |
| NFR5 | Standard primitives only, with published test vectors and fuzzing of the envelope parser |
| NFR6 | Library-first: the library is the product; the CLI and service are thin adapters over it |
| NFR7 | Works on a single host with SQLite or with PostgreSQL, without code changes |
| NFR8 | Public-ready repository and history from the first commit |
| NFR9 | Algorithm choice is a generic selector with `fips` and `standard` profiles; the first release runs in the `standard` profile with AES-256-GCM only, and non-approved algorithms are out of scope. Post-quantum algorithms are adopted from the Go standard library, hybrid first, when they are scoped |

## Success criteria

1. An application can encrypt and decrypt through keyforge using only the
   local provider, with no configuration beyond a key file path.
2. A KEK rotation on a store holding a million wrapped keys completes online
   with no change to application data, and reads during the rotation succeed.
3. A KEK that has been rotated out can be retired only through the guarded,
   delayed path, and a guard that refuses leaves the key usable.
4. Restoring the keyring from a backup that predates a rotation is detected
   and reported before it can lose data.
5. An external reviewer can reconstruct, from the format specification alone,
   how any ciphertext was produced.
6. A disaster-recovery drill runs with no person involved, restores the
   registry and keyring from backup in an isolated environment, decrypts a
   sentinel for every retained key version, reports its recovery time and
   recovery point against configured limits, and produces a report whose
   conclusions are marked as inferred and whose objective results are marked
   as verified.

## Out of scope for v0.1.0

Cloud KMS providers, asymmetric KEKs, signing-key management, a remote
service mode and certificate lifecycle. The interfaces are designed so each
fits without changing stored data.

## Open questions

- The default cap on encryptions per data key, and the default delay before a
  retired key version is destroyed.
- Whether the registry stores wrapped data keys itself or only metadata, with
  wrapped keys stored beside each record by the application.
- Which managed KMS provider to implement first.
- Escrow and recovery of the local provider's root key.
