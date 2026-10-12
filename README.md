# KeyForge

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![PostgreSQL][pg-svg]][pg-url]
![coverage](https://img.shields.io/badge/coverage-73.0%25-yellowgreen)
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Docs][docs-mkdoc-svg]][docs-mkdoc-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/plexusone/keyforge/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/plexusone/keyforge/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/plexusone/keyforge/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/plexusone/keyforge/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/plexusone/keyforge/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/plexusone/keyforge/actions/workflows/go-sast-codeql.yaml
 [pg-svg]: https://github.com/plexusone/keyforge/actions/workflows/go-postgres.yaml/badge.svg?branch=main
 [pg-url]: https://github.com/plexusone/keyforge/actions/workflows/go-postgres.yaml
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/plexusone/keyforge
 [docs-godoc-url]: https://pkg.go.dev/github.com/plexusone/keyforge
 [docs-mkdoc-svg]: https://img.shields.io/badge/Go-dev%20guide-blue.svg
 [docs-mkdoc-url]: https://plexusone.dev/keyforge
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/plexusone/keyforge/blob/main/LICENSE

Encryption and signing key lifecycle for Go applications: envelope
encryption, automatic rotation without re-encrypting stored data, and
controlled retirement and destruction.

> **Status:** pre-release (v0.1.0 in preparation), not externally audited, and
> not ready for production use. The envelope format is not frozen until v0.1.0.
> See the [threat model](docs/threat-model.md) for what it defends and where it
> stops.

## What it does

- **Envelope encryption.** Data is encrypted with a data key (DEK); data keys
  are wrapped by a key-encryption key (KEK) that a provider holds. Every
  ciphertext records which key version wrapped it.
- **Rotation without re-encryption.** Rotating a KEK re-wraps data keys; the
  stored data is not rewritten. Old key versions stay readable until nothing
  references them.
- **Pluggable providers.** A local keyring for development and single-host
  deployments, and a cloud KMS interface for managed key services.
- **Controlled destruction.** Retiring or destroying a key is a separate,
  audited step that a caller-supplied guard can veto, so data under a legal
  hold or other retention is never made unrecoverable by accident.
- **Crypto-shredding.** Per-subject keys make erasure a key destruction that
  also covers backups.

## What it is not

- Not a secret store. Use a secret manager such as
  [omnivault](https://github.com/plexusone/omnivault) to hold secrets and to
  supply the local provider's root key.
- Not a KMS. keyforge wraps and manages keys through providers; it does not
  replace a managed key service or a hardware module.
- Not a cryptography library. It composes standard primitives (AES-256-GCM,
  HKDF-SHA-256) from the Go standard library and `golang.org/x/crypto`.

## Quick start

```go
sys, err := embedded.Open(ctx, embedded.Options{
	Dir:  "/var/lib/myapp/keyforge",
	Root: local.FileSource("/etc/keyforge/root.key"),
	Purposes: map[keyforge.Purpose]embedded.PurposeOptions{"session-secrets": {}},
})
if err != nil {
	return err
}
defer sys.Close()

sealed, err := sys.Client.Encrypt(ctx, "session-secrets", []byte("token-value"), []byte("user:42"))
plaintext, _, err := sys.Client.Decrypt(ctx, "session-secrets", sealed, []byte("user:42"))
```

[Getting started](docs/getting-started.md) covers the root key, running the
lifecycle jobs and the control plane.

## Packages

| Package | Role |
|---|---|
| `keyforge` (root) | The client: `Encrypt`, `EncryptFor`, `EncryptInline`, `Decrypt`, `Reencrypt` |
| `embedded` | Single-host setup from a directory and a root key |
| `envelope`, `algorithm` | The ciphertext format and the algorithm registry |
| `provider`, `provider/local` | Key holders, and the keyring-file provider |
| `registry`, `sqlstore` | The record of keys, and its SQLite and PostgreSQL store (Ent) |
| `rotate`, `jobs` | Rotation, re-wrapping, retirement, emergencies and erasure, and their scheduler |
| `service`, `cli`, `cmd/keyforge` | The HTTP control plane and the command line over it |

The packages that touch key material import only the standard library and
[oscompat](https://github.com/grokify/oscompat), a dependency-free module for
operating-system differences, and a test enforces it.

## Documentation

- [Getting started](docs/getting-started.md)
- [Operations](docs/operations.md): rotation, backup, root-key escrow,
  retirement, emergencies and erasure
- [Envelope format](docs/format.md)
- [Threat model](docs/threat-model.md)
- [Product requirements](docs/specs/initiatives/INIT-KEYFORGE-001/PRD.md)
- [Technical requirements](docs/specs/initiatives/INIT-KEYFORGE-001/TRD.md)
- [Plan](docs/specs/initiatives/INIT-KEYFORGE-001/PLAN.md) and [roadmap](docs/specs/initiatives/INIT-KEYFORGE-001/ROADMAP.md)
- [Release notes](docs/releases/v0.1.0.md) and [changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## License

MIT.
