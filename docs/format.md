# Envelope format

This describes format version 1, the ciphertext keyforge writes. The format is
frozen once data exists under it: a change needs a version bump, new
known-answer vectors in `envelope/testdata/vectors.json`, and a fuzz run. Readers reject
versions, modes, algorithms and flags they do not know, with typed errors,
rather than guessing.

## Modes

| Mode | Holds | Use |
|---|---|---|
| **Reference** (default) | The data key's identifier; the wrapped key lives in the registry | Rows and values under a purpose or subject. Rotating a key-encryption key re-wraps registry records, so stored data is never rewritten |
| **Inline** | The wrapped data key, the key-encryption key's identifier and the version, beside the ciphertext | Standalone objects: exports, snapshots, files. A fresh data key per object |

## Layout

Big-endian.

```text
magic "KF" | format u8 | mode u8 | algorithm u8 | flags u8
purpose   : len u8 + bytes
reference : dek_id 16 bytes                          (reference mode)
inline    : kek_id 16 bytes, kek_version u32,
            wrapped_len u16, wrapped                 (inline mode)
nonce     : 12 bytes
ciphertext || tag
```

| Field | Rule |
|---|---|
| `format` | `1`. Anything else is `ErrUnsupportedFormat`. |
| `mode` | `1` reference, `2` inline. Anything else is `ErrUnknownMode`. |
| `algorithm` | `1` is AES-256-GCM. Anything else is `ErrUnknownAlgorithm`. |
| `flags` | All eight bits are reserved and must be zero. A non-zero value is `ErrUnsupportedFlags`. |
| `purpose` | 1 to 255 bytes of lowercase ASCII letters, digits, `.`, `_` and `-`, beginning with a letter or digit. |
| reference | A non-zero data key identifier and no inline fields. |
| inline | A non-zero key-encryption key identifier, a wrapped key of 1 to 65535 bytes, and no data key identifier. |

An inconsistent header is `ErrInvalidHeader`, on write and on parse.

## What is authenticated

The AAD is the header bytes up to the nonce, followed by the caller's context.
Changing the purpose, the key, the mode, the flags or the context makes
decryption fail with `ErrAuthentication`. That error carries no detail: a wrong
key, a changed header, a changed context and a modified ciphertext are not
distinguished.

A data key is wrapped with its own AAD, which is also stored format:

| Wrapped key | AAD, in order |
|---|---|
| Reference mode | `"keyforge/dek/v1\0"`, purpose, subject, data key identifier, key-encryption key identifier |
| Inline mode | `"keyforge/inline/v1\0"`, purpose, key-encryption key identifier |

The purpose and the subject are each length-prefixed with a big-endian `u32`.
A wrapped key therefore cannot be moved to another purpose or subject, or
presented under another identity.

## Text form

`kf1.` followed by unpadded base64url of the binary form, for text columns and
JSON. There is one spelling: padding, line breaks, the standard alphabet and
non-canonical trailing bits are rejected with `ErrBadTextForm`. A well-formed
prefix for another version is `ErrUnsupportedFormat`.

## Algorithm 1: AES-256-GCM

AES-256-GCM through `cipher.NewGCMWithRandomNonce`, the only GCM constructor
permitted under `GODEBUG=fips140=only`. The AEAD generates its own random nonce;
the format stores it in the header's nonce field and restores it on open. An
AEAD that takes an explicit nonce is refused (`ErrNotRandomNonce`), so a nonce
can never be chosen by a caller.

Random 96-bit nonces limit one key to far fewer than 2³² encryptions. keyforge
counts encryptions per data key, in blocks reserved from the registry, and moves
to a new data key epoch at the cap (default 2³⁰) or at the maximum age
(default 90 days), whichever comes first. The cap holds across replicas and
crashes: an unused part of a reserved block counts as used, so the count can
overstate and never understate.

## Typed errors

`ErrBadMagic`, `ErrTruncated`, `ErrUnsupportedFormat`, `ErrUnknownMode`,
`ErrUnknownAlgorithm`, `ErrUnsupportedFlags`, `ErrInvalidPurpose`,
`ErrInvalidHeader`, `ErrBadTextForm` and `ErrAuthentication`. Those that report
a value carry it in a `ValueError`.

## The keyring file

The local provider's keyring has its own format, also frozen once a keyring
exists: a fixed 32-byte header, authenticated as additional data, then the
sealed payload.

```text
magic "KFKR" | format u8 | reserved u8 | algorithm u8 | reserved u8
root key ID : 16 bytes
generation  : u64, big-endian
sealed      : nonce (12) || ciphertext || tag
```

The payload is sealed with AES-256-GCM under a key derived from the root key
with HKDF-SHA-256. The root-key identifier is derived from the same root key
under a different context, so it identifies the key without revealing it. The
generation increases with every change and can be read without the root key,
which is how a restored older copy is detected. Reserved bytes must be zero,
and anything unrecognized is `ErrCorruptKeyring`.
