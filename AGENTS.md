# AGENTS.md — keyforge

Guidance for coding agents working in this repository. The organization-wide
guidelines in `plexusone/.github` also apply.

## What this is

keyforge manages encryption and signing key lifecycle: envelope encryption,
rotation without re-encrypting stored data, and guarded retirement and
destruction. The design is the source of truth:

- `docs/specs/initiatives/INIT-KEYFORGE-001/PRD.md` — what and why
- `docs/specs/initiatives/INIT-KEYFORGE-001/TRD.md` — format, interfaces,
  state machine, threat model
- `docs/specs/initiatives/INIT-KEYFORGE-001/ROADMAP.md` — phases and work
  items (`RMI-KEYFORGE-NNN`)

Read the TRD before changing a format, an interface or a state transition.
If the code and the TRD disagree, resolve it in the TRD in the same change.

## Rules specific to this repository

- **Standard primitives only.** Use the Go standard library and
  `golang.org/x/crypto`. Never implement a cipher, a mode, a KDF or a MAC.
- **Key material never leaves its owner.** Never log it, put it in an error
  or an audit event, or return it from a provider. Zero buffers you own when
  done, on a best-effort basis.
- **The envelope format is frozen once data exists.** Any change to it needs
  a version bump, new known-answer vectors in `testdata`, and a fuzz run.
  Unknown versions and algorithms fail with typed errors.
- **Algorithms come from the registry and are named exactly.** Never write a
  bare "AES-256"; say "AES-256-GCM". Do not call a primitive for data or key
  protection outside the registry, and do not add configuration that widens a
  profile. The `fips` and `standard` sets are code.
- **Keep the code valid under `GODEBUG=fips140=only`.** Use
  `cipher.NewGCMWithRandomNonce`, never `NewGCM`. Non-approved algorithms are
  not implemented in this initiative; when one is added it goes behind the
  `standard` profile only. Post-quantum algorithms come from the
  standard library (`crypto/mlkem`, `crypto/hpke`, `crypto/mldsa`), hybrid
  first, and never from a third-party package.
- **Agents never see key material.** An analyst or any other agent that
  works with drill results, logs or exports receives metadata only, with no
  keys, plaintext or access to a restored environment, and its conclusions are
  advisory and marked as inferred.
- **Fail closed.** With no usable key, an operation fails; it never falls back
  to a weaker path.
- **No network call per encrypt or decrypt.** The data path is in process.
- **Core stays dependency-light.** The core module depends on the standard
  library and `golang.org/x/crypto`. ORM and cloud SDK code lives in separate
  packages or modules.
- **Time and randomness are injected** (a clock, an entropy reader) so tests
  are deterministic.
- **Public-ready.** This repository is public: write code, comments, docs and
  commit messages that are fit for it from the first commit.

## Workflow

- Work by phase from the roadmap, and carry `Refs: RMI-KEYFORGE-<NNN>` on
  commits that implement an item.
- Each phase ends with tests, `golangci-lint run` and `go vet` clean, and the
  race detector clean on packages with concurrency.
- Prefer unit tests; the provider and store conformance suites are the
  contract for every implementation.
- Commits are conventional, topical and signed, and build and pass tests on
  their own.

## Commands

```bash
go build ./...
go test -race -count=1 ./...
golangci-lint run
```
