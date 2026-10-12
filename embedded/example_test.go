package embedded_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/embedded"
	"github.com/plexusone/keyforge/provider/local"
)

// A single host needs a directory for its state and a root key held somewhere
// else. Open creates the keyring, the registry and a key for each purpose on
// the first start, and finds them again on every start after.
func Example() {
	ctx := context.Background()

	tmp, err := os.MkdirTemp("", "keyforge-example-")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			log.Print(err)
		}
	}()

	// In a deployment the root key comes from a secret manager or a file
	// outside the state directory: local.EnvSource("KEYFORGE_ROOT_KEY") or
	// local.FileSource("/etc/keyforge/root.key"). It is 32 random bytes, which
	// `keyforge rootkey generate` prints.
	root := make([]byte, local.RootKeySize)
	if _, err := rand.Read(root); err != nil {
		log.Fatal(err)
	}

	sys, err := embedded.Open(ctx, embedded.Options{
		Dir:  filepath.Join(tmp, "keyforge"),
		Root: local.StaticSource(root),
		Purposes: map[keyforge.Purpose]embedded.PurposeOptions{
			"session-secrets": {},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := sys.Close(); err != nil {
			log.Print(err)
		}
	}()

	// The context binds the ciphertext to a record: it cannot be moved.
	sealed, err := sys.Client.Encrypt(ctx, "session-secrets", []byte("token-value"), []byte("user:42"))
	if err != nil {
		log.Fatal(err)
	}
	plaintext, _, err := sys.Client.Decrypt(ctx, "session-secrets", sealed, []byte("user:42"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(plaintext))

	// Output: token-value
}
