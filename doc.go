// Package keyforge manages the lifecycle of encryption and signing keys:
// envelope encryption with versioned key-encryption keys, automatic
// rotation without re-encrypting stored data, and controlled retirement
// and destruction.
//
// The design is in docs/specs/initiatives/INIT-KEYFORGE-001.
//
// # Model
//
// Data is encrypted with a data-encryption key (DEK) under a named purpose.
// DEKs are stored only wrapped by a key-encryption key (KEK) that a
// [provider.Provider] holds. A [Client] encrypts and decrypts; the registry
// ([Store]) records which DEK and which KEK version protect what.
//
// Data keys are unwrapped once and cached in process, so encrypting and
// decrypting make no network call.
package keyforge
