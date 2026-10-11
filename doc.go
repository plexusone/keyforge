// Package keyforge manages the lifecycle of encryption and signing keys:
// envelope encryption with versioned key-encryption keys, automatic
// rotation without re-encrypting stored data, and controlled retirement
// and destruction.
//
// The design is in docs/specs. The package is a scaffold; the API is not
// yet defined.
package keyforge
