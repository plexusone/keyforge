# keyforge: Roadmap

Work items carry stable IDs (`RMI-KEYFORGE-NNN`) and are reviewed and
executed by phase. A phase's status is derived from its items. Commits
implementing an item carry the trailer `Refs: RMI-KEYFORGE-<NNN>`.

Specs: [PRD](PRD.md), [TRD](TRD.md), [PLAN](PLAN.md).

## Phase 1: Envelope and core library

- [ ] `RMI-KEYFORGE-001` Envelope format v1: header, reference and inline modes, text form, AAD binding, typed errors; known-answer vectors in `testdata`
- [ ] `RMI-KEYFORGE-002` Envelope parser fuzzing and boundary tests (truncation, unknown format and algorithm, oversize fields)
- [ ] `RMI-KEYFORGE-003` `Provider` interface and provider conformance suite
- [ ] `RMI-KEYFORGE-004` `Client`: `Encrypt`, `Decrypt`, `Reencrypt` with purposes, context binding, DEK cache with TTL and bounds, per-DEK encryption counter and cap
- [ ] `RMI-KEYFORGE-005` Test provider and in-memory registry sufficient to exercise the client end to end

## Phase 2: Local provider and registry

- [ ] `RMI-KEYFORGE-006` `registry.Store` interface, key and version state machine, and store conformance suite
- [ ] `RMI-KEYFORGE-007` In-memory store implementing the interface and passing the suite
- [ ] `RMI-KEYFORGE-008` Local provider: encrypted keyring file, `RootKeySource` (environment, file), atomic writes with directory fsync and advisory lock
- [ ] `RMI-KEYFORGE-009` Keyring generation counter, `backup ack`, and stale-backup detection
- [ ] `RMI-KEYFORGE-010` Crash-safety tests for keyring writes; local provider passes the conformance suite

## Phase 3: Rotation, policy and retirement

- [ ] `RMI-KEYFORGE-011` Policy per purpose: KEK interval, DEK age and volume cap, retirement delay, backup requirement
- [ ] `RMI-KEYFORGE-012` KEK rotation: create, activate, resumable re-wrap job with cursor, reference-count check for retirement eligibility
- [ ] `RMI-KEYFORGE-013` Data-key epochs: automatic new epoch by age or cap, `Stale` reporting on decrypt
- [ ] `RMI-KEYFORGE-014` Retirement and destruction: delay, `DestroyGuard` (allow, deny, pending), provider destroy, audit events
- [ ] `RMI-KEYFORGE-015` Emergency rotation procedures for a compromised KEK and an exposed DEK

## Phase 4: Control plane

- [ ] `RMI-KEYFORGE-016` Scheduler with registry lease for leader election, job resumption, overdue and failure reporting
- [ ] `RMI-KEYFORGE-017` Audit `Sink` interface, event types, and metrics for rates, failures and overdue keys
- [ ] `RMI-KEYFORGE-018` Status model: key states, next rotation, overdue keys, backup status, provider health
- [ ] `RMI-KEYFORGE-019` HTTP control-plane service with a host-supplied `Authorizer`
- [ ] `RMI-KEYFORGE-020` CLI (`status`, `rotate`, `retire`, `destroy`, `backup ack`, `verify`)

## Phase 5: Hardening and v0.1.0

- [ ] `RMI-KEYFORGE-021` SQL store (SQLite and PostgreSQL) in its own module, passing the store conformance suite
- [ ] `RMI-KEYFORGE-022` Property tests (rotate N times, decrypt) and crash tests for re-wrap batches; race detector clean
- [ ] `RMI-KEYFORGE-023` Documentation: getting started, format specification, operations guide (rotation, backup, emergency), threat model
- [ ] `RMI-KEYFORGE-024` Internal review of format and rotation; fix findings; record known limitations
- [ ] `RMI-KEYFORGE-025` v0.1.0 release: changelog, release notes, signed tag after CI on all platforms

## Later

- Cloud KMS providers (first provider chosen after v0.1.0).
- Asymmetric KEKs as hybrid encryption.
- Signing-key management with published overlap.
- A remote service mode.
- Certificate lifecycle through the same registry.
