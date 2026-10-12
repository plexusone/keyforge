# Getting started

This guide takes a single host from nothing to encrypted data with rotation
running. It uses the `embedded` package, which wires a keyring file, a SQLite
registry, the lifecycle jobs and the control plane from a directory and a root
key. Larger deployments assemble the same pieces themselves; the
[technical requirements](specs/initiatives/INIT-KEYFORGE-001/TRD.md) describe
each.

## The root key

The keyring file holds your key-encryption keys, sealed under a **root key**.
The root key is 32 random bytes, and it is the one secret keyforge cannot
recover for you. Generate it once and keep it somewhere other than the state
directory:

```bash
keyforge rootkey generate > /etc/keyforge/root.key
chmod 600 /etc/keyforge/root.key
```

Put a copy in a secret manager or an offline store as well. See
[operations](operations.md#the-root-key) for what to do and why.

A root key file in the keyring's directory is refused, and so is one readable
by group or others.

## Open the system

```go
sys, err := embedded.Open(ctx, embedded.Options{
	Dir:  "/var/lib/myapp/keyforge",
	Root: local.FileSource("/etc/keyforge/root.key"),
	Purposes: map[keyforge.Purpose]embedded.PurposeOptions{
		"session-secrets": {},
		"customer-notes":  {PerSubject: true},
	},
})
if err != nil {
	return err
}
defer sys.Close()
```

On the first start this creates the directory, the keyring and the registry,
and a key-encryption key with its first version active for each purpose. On
every later start it changes nothing. A **purpose** is a name for what the data
is for; it is part of what a ciphertext is bound to, so a value encrypted for
one purpose cannot be opened as another.

Purpose names are 1 to 255 bytes of lowercase letters, digits, `.`, `_` and
`-`, beginning with a letter or digit.

`PerSubject: true` gives each subject (a user, a tenant) data keys of its own,
which is what makes erasing one subject possible. See
[operations](operations.md#erasing-a-subject).

## Encrypt and decrypt

```go
sealed, err := sys.Client.Encrypt(ctx, "session-secrets", []byte("token-value"), []byte("user:42"))
if err != nil {
	return err
}
text := sealed.String() // "kf1." and base64url: safe for a text column or JSON

plaintext, info, err := sys.Client.Decrypt(ctx, "session-secrets", sealed, []byte("user:42"))
```

The last argument is a **context**: bytes that are authenticated but not
stored, such as the row's key. Decryption fails unless the same bytes are
supplied, so a ciphertext copied to another row does not open there. Use
something your application can always reconstruct.

For a per-subject purpose, write with `EncryptFor`:

```go
sealed, err := sys.Client.EncryptFor(ctx, "customer-notes", "customer-17", note, []byte("note:9"))
```

`Decrypt` needs no subject: the envelope names its data key and the registry
knows whose it is. Parse a stored envelope with `envelope.ParseText`.

`Decrypt` reports whether the envelope is **stale** (written under a data key
that is no longer current). Rewriting stale values as you meet them is optional;
nothing breaks if you never do, because rotation does not depend on it.

For a standalone object such as a file or an export, `EncryptInline` carries
the wrapped key with the ciphertext instead of recording it in the registry.
Inline objects are not found by a re-wrap; see
[operations](operations.md#data-outside-the-registry).

## Run the lifecycle jobs

```go
go func() {
	if err := sys.Run(ctx); err != nil {
		log.Print(err)
	}
}()
```

`Run` rotates keys when they are due, moves data keys off old versions, and
completes retirements and erasures that are ready. It resumes any work a
previous process left unfinished. Defaults: a key-encryption key rotates every
365 days, a data key epoch ends after 90 days or 2³⁰ encryptions, and a rotated
version is kept for at least 30 days before it can be retired. Set `Policy` in
the options to change them per purpose.

Nothing is retired or destroyed unless you supply a `Guard`, because the
absence of a veto is not consent. Rotation and re-wrapping, which lose nothing,
run without one.

## Expose the control plane

The HTTP control plane exists only when you supply an authorizer, and it asks
before every action:

```go
opts.Authorizer = service.AuthorizerFunc(func(ctx context.Context, a service.Action, purpose string) error {
	// Return nil to allow, service.ErrUnauthenticated if there is no identity,
	// or any other error to forbid. The identity is whatever your middleware
	// put on ctx.
	return checkAdmin(ctx, a, purpose)
})

h, err := sys.Handler()
if err != nil {
	return err
}
go http.ListenAndServe("127.0.0.1:8480", h)
```

There is no default allow. Actions include `status.read`, `keys.rotate`,
`keys.retire.request`, `keys.destroy` and `shred.request`; give each caller only
the ones it needs.

Then use the command line:

```bash
export KEYFORGE_SERVER=http://127.0.0.1:8480
keyforge status
keyforge verify
```

`keyforge status` shows every key, what is overdue, backups and provider
health. `keyforge health` exits non-zero and lists the problems, for a monitor.
`keyforge verify` round-trips a test value through each purpose's keys from a
cold start, which is the quickest way to learn that a key is usable.

## Back it up

A backup is the keyring and the registry together, taken at the same time, plus
the root key kept apart. Read [operations](operations.md#backup-and-restore)
before relying on a deployment: a backup you have not restored from is a hope.

## Next

- [Operations](operations.md): rotation, backup, root-key escrow, retirement,
  emergencies and erasure.
- [Envelope format](format.md): what is stored and what is bound to it.
- [Threat model](threat-model.md): what keyforge defends against, and what it
  does not.
