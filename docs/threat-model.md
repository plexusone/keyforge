# Threat model

What keyforge defends, against whom, and where it stops. The design is in the
[technical requirements](specs/initiatives/INIT-KEYFORGE-001/TRD.md); this is
the part a reviewer reads first.

keyforge has **not been externally audited**. It composes standard primitives
from the Go standard library and `golang.org/x/crypto` and implements none of
its own; the risk it adds is in how they are combined and in key lifecycle.

## Assets and attackers

The assets are key-encryption key material, data key material, the plaintext
the data keys protect, and the ability to destroy keys.

| Attacker | Has | What keyforge offers |
|---|---|---|
| Reads the database | The registry: wrapped data keys, key states | The registry holds wrapped keys and never a plaintext one. It yields no key and cannot move a ciphertext to another record. |
| Reads a backup | The keyring and the registry | The keyring is sealed under the root key, which is held apart. A backup without the root key is ciphertext. |
| Reads the ciphertext store | Envelopes | AEAD authentication; the AAD binds purpose, mode, key identity and caller context. |
| Modifies stored data | Write access to rows | Tampering fails authentication. Moving an envelope to another record fails if the caller binds a context. |
| Reaches the control plane | Network access | The authorizer is asked before every action and there is no default allow. |
| Compromises the host process | Code execution as the application | **Not defended.** See below. |

## Mitigations

| Asset | Threat | Mitigation |
|---|---|---|
| Key-encryption key material | Read from disk or backup | Sealed under a root key held apart from the keyring; keyring mode 0600, group- or other-readable refused; a root key file beside the keyring refused |
| Key-encryption key material | Wrong or stale keyring used | A wrong root key is refused before decryption; a keyring older than one seen is refused unless the restore is accepted |
| Data key material | Memory read | Bounded cache with a TTL; best-effort zeroing |
| Ciphertext | Moved between purposes, subjects or records | AAD binds the purpose and the caller's context; the wrapped key is bound to its purpose, subject and identity |
| Ciphertext | Tampering | AES-256-GCM authentication |
| Nonce reuse | Random-nonce collision | One counted cap per data key, enforced across replicas and crashes in blocks; epochs advance before the limit |
| Availability | Provider or registry outage | A cache; beyond it, operations fail closed and say so; reads are unaffected by a write-side outage |
| Data under retention | Premature destruction | A separate guard consulted at retirement and again at destruction; a delay; every outcome audited |
| Rotation | A restored stale backup loses data | Keyring generation and backup acknowledgement; rotation can wait on it |
| Erasure | A backup restores a shredded key | A shred is complete only when every key version that ever wrapped the subject's keys is destroyed in the live keyring. Backups are the operator's: see the limitations |
| Control plane | Unauthorized rotation or destruction | Host-supplied authorizer on every action; audit of administrative reads |
| Logs | Key material in an error or event | Key material never leaves its owner: it is not logged, not in errors and not in audit events |

## Fail closed

With no usable key, an operation fails; it never falls back to a weaker path.
There is no network call per encrypt or decrypt: the data path is in process.
An algorithm outside the active profile is refused, and the profile can narrow
the set and never widen it. The code stays valid under
`GODEBUG=fips140=only`.

## Known limitations

- **The local provider is as safe as the host and its root key source.** It is
  not a hardware module and is unsuitable where managed keys are required.
- **Memory.** Go cannot lock or reliably zero memory. Cached keys can appear in
  memory dumps and swap.
- **A compromised process can use the keys it can use.** keyforge limits the
  blast radius by purpose and subject; it does not defeat an attacker who
  controls the process.
- **The root key is not recoverable.** Its loss is the loss of the keyring.
  keyforge does not escrow it.
- **Backups of the registry lose recent data keys.** Data written under a data
  key created after the last registry backup is unreadable after a restore.
- **Scheduling depends on the host clock.**
- **Inline objects are invisible to the registry.** Retiring a version relies on
  the host's statement that nothing outside the registry needs it.
- **A restore can undo an erasure.** Shreds and tombstones live in the registry;
  restoring an older registry resurrects the subject's keys, and a keyring
  backup holds destroyed versions' material. Erasure is complete for the live
  system only.
- **A restore under a running process.** An older keyring copy put in place
  while the process runs is refused at the next write and at the next open, but
  the process keeps using its in-memory copy until restarted. Stop the process
  before restoring.
- **Unauthenticated envelopes cost work.** A parsed inline envelope with an
  unseen key reference makes a registry call and a provider unwrap, and bogus
  versions can evict cache entries. This cannot disclose a key.
- **Inline wraps are not counted** against the key-encryption key version they
  are wrapped under.
- **Erasure takes as long as key retirement.** A shred is complete only when the
  key versions that wrapped the subject's keys are destroyed; until then a
  restored registry backup can recover the data.
- **Cached keys outlive a shred or a retirement** for up to the cache TTL, or
  until `Purge`.
- **Not externally audited.**

## Reporting

Report a suspected vulnerability privately; see [SECURITY.md](../SECURITY.md).
