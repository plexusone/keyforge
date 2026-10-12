# keyforge: Plan

**Initiative:** `INIT-KEYFORGE-001`
**Repository:** `github.com/plexusone/keyforge`

Implements the [PRD](PRD.md) and [TRD](TRD.md). The [roadmap](ROADMAP.md)
holds the work items and their status.

## Approach

- **Format first.** The envelope format is the one thing that cannot change
  after data exists, so it is specified, vectored and fuzzed before any
  provider or scheduler is built on it.
- **Library before control plane.** The data path (encrypt, decrypt, cache)
  is complete and tested with the in-memory store and the local provider
  before the scheduler, service and CLI exist.
- **Conformance suites with the interfaces.** The provider and store
  conformance suites are written with the interfaces, so each later
  implementation inherits them.
- **Public-ready from the first commit.** Specs, history and docs carry no
  internal facts; the security policy and threat model exist before the first
  release.

## Phases

| Phase | Theme | Outcome |
|---|---|---|
| 1 | Envelope and core library | A tested format and `Client` over an in-memory registry and a test provider |
| 2 | Local provider and registry | A real keyring provider with safe writes, and the store interface with an in-memory implementation and conformance suite |
| 3 | Rotation, policy and retirement | Automatic KEK and DEK rotation, resumable jobs, the guard, and the delay |
| 4 | Control plane | Scheduler with leader lease, audit sink, status, the service and the CLI |
| 5 | Hardening and v0.1.0 | SQL store, crash and fuzz tests, documentation, security review, release |
| 6 | Inventory and crypto specification | External boundary inventory and export of the system's crypto specification for verification (after v0.1.0) |

## Dependencies and sequencing

- Phase 2's provider conformance suite depends on the `Provider` interface
  fixed in phase 1.
- Phase 3 depends on the registry state machine from phase 2.
- Phase 4's scheduler depends on phase 3's jobs; the SQL store in phase 5
  depends on the store conformance suite from phase 2.
- systemforge integration (guard, audit sink, catalog granularity, and a
  `Sampler` implementation that reads sample envelopes from the encrypted
  columns of registered entities) follows v0.1.0 and is tracked in
  systemforge. The `Sampler` interface is defined in keyforge, which calls
  it, and is optional, so the drill runs before the integration exists.

## Risks

| Risk | Mitigation |
|---|---|
| Format mistakes found after release | Vectors and fuzzing before phase 2; a format version byte and typed errors for unknown values |
| Keyring corruption or loss | Atomic writes, generation counter, backup acknowledgement, crash tests |
| Rotation job leaves a mixed state | Idempotent batches with a cursor; both versions stay readable throughout |
| Scope creep into a KMS or secret store | The non-goals in the PRD; providers and omnivault cover those |
| Perceived rolling of own crypto | Standard primitives only; the format reviewed before release |

## Release

v0.1.0 when phase 5 completes and CI is green on all platforms. The release
notes state the maturity (pre-1.0, not externally audited), the threat model
and the known limitations.
