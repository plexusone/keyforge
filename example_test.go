package keyforge_test

import (
	"context"
	"fmt"
	"log"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/provider"
	providermemory "github.com/plexusone/keyforge/provider/memory"
	registrymemory "github.com/plexusone/keyforge/registry/memory"
)

// A client needs a provider that holds key-encryption keys, a registry that
// records which keys protect what, and the purposes it may use. The in-memory
// provider and registry used here are for tests and examples only.
func Example() {
	ctx := context.Background()

	prov := providermemory.NewKeyring()
	reg := registrymemory.NewStore()

	// Create a key-encryption key and make it the active one for a purpose.
	kek, err := prov.CreateKey(ctx, provider.KeySpec{Purpose: "session-secrets", Algorithm: algorithm.AES256GCM})
	if err != nil {
		log.Fatal(err)
	}
	if err := reg.PutKEK(kek); err != nil {
		log.Fatal(err)
	}
	if err := reg.SetActiveKEK("session-secrets", keyforge.KEKVersion{Ref: kek, Version: 1}); err != nil {
		log.Fatal(err)
	}

	client, err := keyforge.New(keyforge.Options{
		Store:     reg,
		Providers: []provider.Provider{prov},
		Purposes:  map[keyforge.Purpose]keyforge.PurposeConfig{"session-secrets": {}},
	})
	if err != nil {
		log.Fatal(err)
	}

	// The context binds the ciphertext to a record: it cannot be moved.
	sealed, err := client.Encrypt(ctx, "session-secrets", []byte("token-value"), []byte("user:42"))
	if err != nil {
		log.Fatal(err)
	}
	text := sealed.String() // "kf1." followed by base64url, safe for a text column

	plaintext, info, err := client.Decrypt(ctx, "session-secrets", sealed, []byte("user:42"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s (stale: %v)\n", plaintext, info.Stale)
	fmt.Println(text[:4])

	// Output:
	// token-value (stale: false)
	// kf1.
}
