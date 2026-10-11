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

- [ ] `RMI-KEYFORGE-001` Envelope format v1: header, reference and inline modes, text form, AAD binding, typed errors; known-answer vectors in `testdata`
- [ ] `RMI-KEYFORGE-002` Envelope parser fuzzing and boundary tests (truncation, unknown format and algorithm, oversize fields)
  - Depends on: `RMI-KEYFORGE-001`
- [ ] `RMI-KEYFORGE-003` `Provider` interface and provider conformance suite
- [ ] `RMI-KEYFORGE-004` `Client`: `Encrypt`, `Decrypt`, `Reencrypt` with purposes, context binding, DEK cache with TTL and bounds, per-DEK encryption counter and cap
  - Depends on: `RMI-KEYFORGE-001`, `RMI-KEYFORGE-003`
- [ ] `RMI-KEYFORGE-005` Test provider and in-memory registry sufficient to exercise the client end to end
  - Depends on: `RMI-KEYFORGE-003`, `RMI-KEYFORGE-004`

## Phase 2 — Local provider and registry

**Theme:** A real keyring provider with safe writes, and a store interface with a conformance suite.

- [ ] `RMI-KEYFORGE-006` `registry.Store` interface, key and version state machine, and store conformance suite
  - Depends on: `RMI-KEYFORGE-004`
- [ ] `RMI-KEYFORGE-007` In-memory store implementing the interface and passing the suite
  - Depends on: `RMI-KEYFORGE-006`
- [ ] `RMI-KEYFORGE-008` Local provider: encrypted keyring file, `RootKeySource` (environment, file), atomic writes with directory fsync and advisory lock
  - Depends on: `RMI-KEYFORGE-003`
- [ ] `RMI-KEYFORGE-009` Keyring generation counter, `backup ack`, and stale-backup detection
  - Depends on: `RMI-KEYFORGE-008`
- [ ] `RMI-KEYFORGE-010` Crash-safety tests for keyring writes; local provider passes the conformance suite
  - Depends on: `RMI-KEYFORGE-008`, `RMI-KEYFORGE-009`

## Phase 3 — Rotation, policy and retirement

**Theme:** Keys rotate automatically and resumably, and destruction is delayed, guarded and audited.

- [ ] `RMI-KEYFORGE-011` Policy per purpose: KEK interval, DEK age and volume cap, retirement delay, backup requirement
  - Depends on: `RMI-KEYFORGE-006`
- [ ] `RMI-KEYFORGE-012` KEK rotation: create, activate, resumable re-wrap job with cursor, reference-count check for retirement eligibility
  - Depends on: `RMI-KEYFORGE-007`, `RMI-KEYFORGE-011`
- [ ] `RMI-KEYFORGE-013` Data-key epochs: automatic new epoch by age or cap, `Stale` reporting on decrypt
  - Depends on: `RMI-KEYFORGE-004`, `RMI-KEYFORGE-011`
- [ ] `RMI-KEYFORGE-014` Retirement and destruction: delay, `DestroyGuard` (allow, deny, pending), provider destroy, audit events
  - Depends on: `RMI-KEYFORGE-012`
- [ ] `RMI-KEYFORGE-015` Emergency rotation procedures for a compromised KEK and an exposed DEK
  - Depends on: `RMI-KEYFORGE-012`, `RMI-KEYFORGE-013`, `RMI-KEYFORGE-014`

## Phase 4 — Control plane

**Theme:** A scheduler, audit, status, an HTTP service and a CLI over the library.

- [ ] `RMI-KEYFORGE-016` Scheduler with registry lease for leader election, job resumption, overdue and failure reporting
  - Depends on: `RMI-KEYFORGE-012`, `RMI-KEYFORGE-013`
- [ ] `RMI-KEYFORGE-017` Audit `Sink` interface, event types, and metrics for rates, failures and overdue keys
  - Depends on: `RMI-KEYFORGE-014`
- [ ] `RMI-KEYFORGE-018` Status model: key states, next rotation, overdue keys, backup status, provider health
  - Depends on: `RMI-KEYFORGE-009`, `RMI-KEYFORGE-016`
- [ ] `RMI-KEYFORGE-019` HTTP control-plane service with a host-supplied `Authorizer`
  - Depends on: `RMI-KEYFORGE-017`, `RMI-KEYFORGE-018`
- [ ] `RMI-KEYFORGE-020` CLI (`status`, `rotate`, `retire`, `destroy`, `backup ack`, `verify`)
  - Depends on: `RMI-KEYFORGE-018`
- [ ] `RMI-KEYFORGE-029` Canary purpose and rotation drill: weekly full-lifecycle run on a key that holds no data, `keyforge verify` on demand, alert and status on failure or overdue
  - Depends on: `RMI-KEYFORGE-014`, `RMI-KEYFORGE-016`

## Phase 5 — Hardening and v0.1.0

**Theme:** A SQL store, crash and property tests, documentation, review and the release.

- [ ] `RMI-KEYFORGE-021` SQL store (SQLite and PostgreSQL) in its own module, passing the store conformance suite
  - Depends on: `RMI-KEYFORGE-006`
- [ ] `RMI-KEYFORGE-022` Property tests (rotate N times, decrypt) and crash tests for re-wrap batches; race detector clean
  - Depends on: `RMI-KEYFORGE-015`, `RMI-KEYFORGE-016`
- [ ] `RMI-KEYFORGE-023` Documentation: getting started, format specification, operations guide (rotation, backup, emergency), threat model
  - Depends on: `RMI-KEYFORGE-020`
- [ ] `RMI-KEYFORGE-024` Internal review of format and rotation; fix findings; record known limitations
  - Depends on: `RMI-KEYFORGE-022`, `RMI-KEYFORGE-023`
- [ ] `RMI-KEYFORGE-025` v0.1.0 release: changelog, release notes, signed tag after CI on all platforms
  - Depends on: `RMI-KEYFORGE-021`, `RMI-KEYFORGE-024`

## Phase 6 — Inventory and crypto specification

**Theme:** keyforge is the single system of record for the platform's cryptographic choices and generates the system's crypto specification for verification.

- [ ] `RMI-KEYFORGE-026` Inventory model and store: external boundary records (kind, expectation, owner, source pointer, review date) with review-date expiry
  - Depends on: `RMI-KEYFORGE-018`, `RMI-KEYFORGE-025`
- [ ] `RMI-KEYFORGE-027` `systemspec-crypto` export: implementations, registry algorithms, uses per purpose, claims with verification states, and evidence, with no key material; `keyforge spec export`
  - Depends on: `RMI-KEYFORGE-026`
- [ ] `RMI-KEYFORGE-028` Profile and FIPS-mode reporting in the export, and a conformance check that the export validates against the specification's schema
  - Depends on: `RMI-KEYFORGE-027`
