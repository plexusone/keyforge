# ROADMAP — keyforge: Encryption and Signing Key Lifecycle

**Initiative:** `INIT-KEYFORGE-001`
**Repository:** `github.com/plexusone/keyforge`

Specs: [PRD](PRD.md), [TRD](TRD.md), [PLAN](PLAN.md). Work items carry
stable IDs (`RMI-KEYFORGE-NNN`), are reviewed and executed by phase, and commits
implementing one carry the trailer `Refs: RMI-KEYFORGE-<NNN>`.

Later, not scheduled: cloud KMS providers, asymmetric KEKs as hybrid encryption,
signing-key management with published overlap, a remote service mode, and
certificate lifecycle through the same registry.

## Phase 1 — Envelope and core library

**Theme:** The format is specified, vectored and fuzzed, and a client encrypts and decrypts over an in-memory registry and a test provider.

- [ ] `RMI-KEYFORGE-001` Envelope format v1: header, reference and inline modes, reserved flags byte, text form, AAD binding, typed errors; known-answer vectors in `testdata`; non-gating `fips140=only` CI run
- [ ] `RMI-KEYFORGE-032` Algorithm registry and profile selector: exact names, `fips` and `standard` profiles fixed in code, per-purpose pinned profile and allowed list (narrow only), typed refusal outside the profile; registry holds AES-256-GCM only
  - Depends on: `RMI-KEYFORGE-001`
- [ ] `RMI-KEYFORGE-002` Envelope parser fuzzing and boundary tests (truncation, unknown format and algorithm, oversize fields)
  - Depends on: `RMI-KEYFORGE-001`
- [ ] `RMI-KEYFORGE-003` `Provider` interface, `KeyRef` and `KeySpec`, and provider conformance suite
- [ ] `RMI-KEYFORGE-004` `Client`: `Encrypt`, `Decrypt`, `Reencrypt` with purposes, context binding, injected clock and entropy, DEK cache with TTL and bounds, encryption counter by reserved blocks and cap
  - Depends on: `RMI-KEYFORGE-001`, `RMI-KEYFORGE-003`, `RMI-KEYFORGE-032`
- [ ] `RMI-KEYFORGE-005` Test providers (keyring-style and natively versioning) and in-memory registry sufficient to exercise the client end to end
  - Depends on: `RMI-KEYFORGE-003`, `RMI-KEYFORGE-004`

## Phase 2 — Local provider and registry

**Theme:** A real keyring provider with safe writes, and a store interface with a conformance suite.

- [ ] `RMI-KEYFORGE-006` `registry.Store` interface, key and version state machine with its transition table, and store conformance suite
  - Depends on: `RMI-KEYFORGE-004`
- [ ] `RMI-KEYFORGE-007` In-memory store implementing the interface and passing the suite
  - Depends on: `RMI-KEYFORGE-006`
- [ ] `RMI-KEYFORGE-008` Local provider: encrypted keyring file, `RootKeySource` (environment, file), root-key ID and rotation, atomic writes with directory fsync and advisory lock
  - Depends on: `RMI-KEYFORGE-003`
- [ ] `RMI-KEYFORGE-009` Keyring generation counter, `backup ack`, and stale-backup detection
  - Depends on: `RMI-KEYFORGE-008`
- [ ] `RMI-KEYFORGE-010` Crash-safety tests for keyring writes; local provider passes the conformance suite
  - Depends on: `RMI-KEYFORGE-008`, `RMI-KEYFORGE-009`

## Phase 3 — Rotation, policy and retirement

**Theme:** Keys rotate automatically and resumably, and destruction is delayed, guarded and audited.

- [ ] `RMI-KEYFORGE-011` Policy per purpose: KEK interval, DEK age and volume cap, retirement delay, backup requirement
  - Depends on: `RMI-KEYFORGE-006`
- [ ] `RMI-KEYFORGE-012` KEK rotation: create, activate, rollback to the previous version, resumable re-wrap job with cursor, a sentinel per version, reference-count check for retirement eligibility
  - Depends on: `RMI-KEYFORGE-007`, `RMI-KEYFORGE-011`
- [ ] `RMI-KEYFORGE-013` Data-key epochs: automatic new epoch by age or cap, `Stale` reporting on decrypt
  - Depends on: `RMI-KEYFORGE-004`, `RMI-KEYFORGE-011`
- [ ] `RMI-KEYFORGE-014` Retirement and destruction: delay, `DestroyGuard` (allow, deny, pending), provider destroy, audit events
  - Depends on: `RMI-KEYFORGE-012`
- [ ] `RMI-KEYFORGE-015` Emergency rotation procedures for a compromised KEK and an exposed DEK
  - Depends on: `RMI-KEYFORGE-012`, `RMI-KEYFORGE-013`, `RMI-KEYFORGE-014`
- [ ] `RMI-KEYFORGE-033` Per-subject DEKs and crypto-shredding: subject epochs, shred request, tracking of the KEK versions that wrapped the subject's keys, pending-until-destroyed status with expected completion, audit events
  - Depends on: `RMI-KEYFORGE-013`, `RMI-KEYFORGE-014`

## Phase 4 — Control plane

**Theme:** A scheduler, audit, status, an HTTP service and a CLI over the library.

> Release gate: the scheduler depends on OmniWorkflow, developed here against a local `replace`. keyforge is not pushed or tagged until OmniWorkflow has a release without that `replace` and this repository's `go.mod` points at it.

- [ ] `RMI-KEYFORGE-016` Scheduler and executor over OmniWorkflow: deterministic run IDs in place of leader election, durable resumption, retry with backoff, overdue and failure reporting
  - Depends on: `RMI-KEYFORGE-012`, `RMI-KEYFORGE-013`
- [ ] `RMI-KEYFORGE-017` Audit `Sink` interface, event types, and a core `Metrics` interface for rates, failures and overdue keys
  - Depends on: `RMI-KEYFORGE-014`
- [ ] `RMI-KEYFORGE-018` Status model: key states, next rotation, overdue keys, backup status, provider health
  - Depends on: `RMI-KEYFORGE-009`, `RMI-KEYFORGE-016`
- [ ] `RMI-KEYFORGE-019` HTTP control-plane service with a host-supplied `Authorizer`
  - Depends on: `RMI-KEYFORGE-017`, `RMI-KEYFORGE-018`
- [ ] `RMI-KEYFORGE-020` CLI (`status`, `rotate`, `retire`, `destroy`, `backup ack`, `verify`)
  - Depends on: `RMI-KEYFORGE-018`

## Phase 5 — Hardening and v0.1.0

**Theme:** A SQL store, crash and property tests, documentation, review and the release.

- [ ] `RMI-KEYFORGE-021` Ent-backed SQL store for SQLite and PostgreSQL (pgx), passing the store conformance suite on both
  - Depends on: `RMI-KEYFORGE-006`
- [ ] `RMI-KEYFORGE-035` Embedded single-host helper: keyring, SQLite registry, jobs and service wired from a directory and a root key source
  - Depends on: `RMI-KEYFORGE-021`, `RMI-KEYFORGE-008`, `RMI-KEYFORGE-016`, `RMI-KEYFORGE-019`
- [ ] `RMI-KEYFORGE-036` Crypto-path import boundary: algorithm, envelope, provider, local provider and the client import only the standard library, enforced by a test
  - Depends on: `RMI-KEYFORGE-021`
- [ ] `RMI-KEYFORGE-022` Property tests (rotate N times, decrypt), crash tests for re-wrap batches, and a million-key rotation benchmark; race detector clean
  - Depends on: `RMI-KEYFORGE-015`, `RMI-KEYFORGE-016`
- [ ] `RMI-KEYFORGE-023` Documentation: getting started, format specification, operations guide (rotation, backup, root-key escrow, emergency), threat model
  - Depends on: `RMI-KEYFORGE-020`
- [ ] `RMI-KEYFORGE-024` Internal review of format and rotation; fix findings; record known limitations
  - Depends on: `RMI-KEYFORGE-022`, `RMI-KEYFORGE-023`
- [ ] `RMI-KEYFORGE-025` v0.1.0 release: changelog, release notes, signed tag after CI on all platforms
  - Depends on: `RMI-KEYFORGE-021`, `RMI-KEYFORGE-024`, `RMI-KEYFORGE-035`, `RMI-KEYFORGE-036`

## Phase 6 — Rotation and disaster-recovery drills

**Theme:** The rotation mechanism is exercised weekly on a canary, and recovery from backup is proven by an unattended drill with an analyst-written report, released as v0.2.0.

- [ ] `RMI-KEYFORGE-029` Canary purpose and rotation drill: weekly full-lifecycle run on a key that holds no data, `keyforge verify` on demand, alert and status on failure or overdue
  - Depends on: `RMI-KEYFORGE-014`, `RMI-KEYFORGE-016`, `RMI-KEYFORGE-018`
- [ ] `RMI-KEYFORGE-030` DR drill engine: isolated restore, sentinel decryption per purpose and version, optional `Sampler`, recovery point and time, negative checks, teardown, key-free result; local-filesystem host implementations; `keyforge drill`, quarterly schedule
  - Depends on: `RMI-KEYFORGE-009`, `RMI-KEYFORGE-012`, `RMI-KEYFORGE-018`, `RMI-KEYFORGE-029`
- [ ] `RMI-KEYFORGE-031` DR report: `Analyst` interface, report format (Markdown and JSON) with provenance and inferred-versus-verified standing, trend comparison with earlier drills, escalation of failed drills
  - Depends on: `RMI-KEYFORGE-030`
- [ ] `RMI-KEYFORGE-034` v0.2.0 release: changelog, release notes, signed tag after CI on all platforms
  - Depends on: `RMI-KEYFORGE-025`, `RMI-KEYFORGE-029`, `RMI-KEYFORGE-031`

## Phase 7 — Inventory and crypto specification

**Theme:** keyforge is the single system of record for the platform's cryptographic choices and generates the system's crypto specification for verification.

- [ ] `RMI-KEYFORGE-026` Inventory model and store: external boundary records (kind, expectation at or above the policy floor or a waiver, owner, source pointer, review date) with expiry derived at read time
  - Depends on: `RMI-KEYFORGE-018`, `RMI-KEYFORGE-025`
- [ ] `RMI-KEYFORGE-027` `systemspec-crypto` export: implementations, registry algorithms, uses per purpose, claims with verification states, and evidence, with no key material; `keyforge spec export`
  - Depends on: `RMI-KEYFORGE-026`
- [ ] `RMI-KEYFORGE-028` Profile and FIPS-mode reporting in the export, and a conformance check that the export validates against the specification's schema
  - Depends on: `RMI-KEYFORGE-027`
