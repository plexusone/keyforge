# keyforge

Encryption and signing key lifecycle for Go applications: envelope
encryption, automatic rotation without re-encrypting stored data, and
controlled retirement and destruction.

> **Status:** design phase. The API is not yet defined and nothing here is
> ready for production use. See the [product requirements](docs/specs/initiatives/INIT-KEYFORGE-001/PRD.md).

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
- Not a cryptography library. It composes standard primitives (AES-GCM,
  HPKE) from the Go standard library and `golang.org/x/crypto`.

## Documentation

- [Product requirements](docs/specs/initiatives/INIT-KEYFORGE-001/PRD.md)
- [Technical requirements](docs/specs/initiatives/INIT-KEYFORGE-001/TRD.md)
- [Plan](docs/specs/initiatives/INIT-KEYFORGE-001/PLAN.md) and [roadmap](docs/specs/initiatives/INIT-KEYFORGE-001/ROADMAP.md)
- [Security policy](SECURITY.md)

## License

MIT.
