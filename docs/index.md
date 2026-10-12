# keyforge

Encryption and signing key lifecycle for Go applications: envelope encryption,
automatic rotation without re-encrypting stored data, and controlled retirement
and destruction.

!!! warning "Pre-release"
    keyforge has not been externally audited and is not yet recommended for
    production use. Read the [threat model](threat-model.md) first.

## What it does

| | |
|---|---|
| **Envelope encryption** | Data is encrypted with a data key; data keys are wrapped by a key-encryption key that a provider holds. Every ciphertext records which key version wrapped it. |
| **Rotation without re-encryption** | Rotating a key-encryption key re-wraps data keys. Stored data is not rewritten, and old versions stay readable until nothing references them. |
| **Controlled destruction** | Retiring or destroying a key is a separate, audited step that a caller-supplied guard can veto, so data under a legal hold is never made unrecoverable by accident. |
| **Crypto-shredding** | Per-subject keys make erasure a key destruction, tracked until every key version that wrapped the subject's keys is gone. |
| **Single host or shared** | A keyring file and a SQLite registry from one directory, or PostgreSQL for several replicas. |

## What it is not

- **Not a secret store.** Use a secret manager such as
  [omnivault](https://github.com/plexusone/omnivault) to hold secrets and to
  supply the local provider's root key.
- **Not a KMS.** keyforge manages keys through providers; it does not replace a
  managed key service or a hardware module.
- **Not a cryptography library.** It composes AES-256-GCM and HKDF-SHA-256 from
  the Go standard library and `golang.org/x/crypto`.

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

Continue with [Getting started](getting-started.md).

## Where to go next

| If you want to | Read |
|---|---|
| Run keyforge on one host | [Getting started](getting-started.md) |
| Operate it: rotation, backup, the root key, emergencies | [Operations](operations.md) |
| Know what is stored and what is authenticated | [Envelope format](format.md) |
| Judge what it defends against | [Threat model](threat-model.md) |
| See the design | [Technical requirements](specs/initiatives/INIT-KEYFORGE-001/TRD.md) |

## Packages

| Package | Role |
|---|---|
| `keyforge` | The client: `Encrypt`, `EncryptFor`, `EncryptInline`, `Decrypt`, `Reencrypt` |
| `embedded` | Single-host setup from a directory and a root key |
| `envelope`, `algorithm` | The ciphertext format and the algorithm registry |
| `provider`, `provider/local` | Key holders, and the keyring-file provider |
| `registry`, `sqlstore` | The record of keys, and its SQLite and PostgreSQL store |
| `rotate`, `jobs` | Rotation, re-wrapping, retirement, emergencies and erasure, and their scheduler |
| `service`, `cli` | The HTTP control plane and the command line over it |

The packages that touch key material import only the standard library, and a
test enforces it.
