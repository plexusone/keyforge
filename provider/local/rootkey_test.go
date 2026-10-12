package local

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grokify/oscompat/fs"
)

func key32(b byte) []byte { return bytes.Repeat([]byte{b}, RootKeySize) }

func TestDecodeRootKey(t *testing.T) {
	k := key32(0xAB)
	std := base64.StdEncoding.EncodeToString(k)
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"base64", std, true},
		{"base64 with newline", std + "\n", true},
		{"base64 with surrounding space", "  " + std + "  ", true},
		{"hex", hex.EncodeToString(k), true},
		{"uppercase hex", strings.ToUpper(hex.EncodeToString(k)), true},
		{"empty", "", false},
		{"whitespace only", " \n", false},
		{"too short", base64.StdEncoding.EncodeToString(k[:16]), false},
		{"too long", base64.StdEncoding.EncodeToString(append(k, 0)), false},
		{"hex of 31 bytes", hex.EncodeToString(k[:31]), false},
		{"not encoded", "correct horse battery staple", false},
		{"url alphabet", strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xFB}, 32))), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeRootKey([]byte(tt.in))
			if tt.ok {
				if err != nil || len(got) != RootKeySize {
					t.Fatalf("decodeRootKey = %d bytes, %v", len(got), err)
				}
				return
			}
			if !errors.Is(err, ErrBadRootKey) {
				t.Fatalf("decodeRootKey = %v, want ErrBadRootKey", err)
			}
			if trimmed := strings.TrimSpace(tt.in); trimmed != "" && strings.Contains(err.Error(), trimmed) {
				t.Fatalf("the error repeats the rejected input: %v", err)
			}
		})
	}
}

func TestEnvSource(t *testing.T) {
	const name = "KEYFORGE_TEST_ROOT_KEY"
	t.Setenv(name, base64.StdEncoding.EncodeToString(key32(5)))
	got, err := EnvSource(name).RootKey(bg)
	if err != nil || !bytes.Equal(got, key32(5)) {
		t.Fatalf("RootKey = %x, %v", got, err)
	}
	if _, err := EnvSource("KEYFORGE_TEST_UNSET_VARIABLE").RootKey(bg); !errors.Is(err, ErrRootKeyUnavailable) {
		t.Fatalf("unset variable: %v, want ErrRootKeyUnavailable", err)
	}
	t.Setenv(name, "not a key")
	if _, err := EnvSource(name).RootKey(bg); !errors.Is(err, ErrBadRootKey) {
		t.Fatalf("malformed variable: %v, want ErrBadRootKey", err)
	}
}

func TestFileSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key32(9))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := FileSource(path).RootKey(bg)
	if err != nil || !bytes.Equal(got, key32(9)) {
		t.Fatalf("RootKey = %x, %v", got, err)
	}
	if _, err := FileSource(filepath.Join(dir, "missing")).RootKey(bg); !errors.Is(err, ErrRootKeyUnavailable) {
		t.Fatalf("missing file: %v, want ErrRootKeyUnavailable", err)
	}
	if fs.PermissionsEnforced() {
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := FileSource(path).RootKey(bg); !errors.Is(err, ErrInsecureRootKeyFile) {
			t.Fatalf("group-readable file: %v, want ErrInsecureRootKeyFile", err)
		}
	}
}

func TestStaticSourceCopies(t *testing.T) {
	k := key32(1)
	src := StaticSource(k)
	k[0] = 0xFF
	got, err := src.RootKey(bg)
	if err != nil || got[0] != 1 {
		t.Fatalf("the source shares the caller's slice: %x, %v", got[:1], err)
	}
	got[0] = 0xEE
	again, _ := src.RootKey(bg)
	if again[0] != 1 {
		t.Fatal("a returned key shares the source's storage")
	}
	if _, err := StaticSource([]byte{1, 2}).RootKey(bg); !errors.Is(err, ErrBadRootKey) {
		t.Fatalf("short static key: %v", err)
	}
}

func TestDerivedKeysAreSeparated(t *testing.T) {
	enc1, id1, err := deriveKeys(key32(1))
	if err != nil {
		t.Fatal(err)
	}
	enc2, id2, err := deriveKeys(key32(2))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc1, enc2) || id1 == id2 {
		t.Fatal("different root keys derived the same material")
	}
	if bytes.Contains(enc1, id1[:]) || bytes.Equal(enc1[:rootKeyIDSize], id1[:]) {
		t.Fatal("the root key identifier is derived from the same output as the encryption key")
	}
	again, idAgain, err := deriveKeys(key32(1))
	if err != nil || !bytes.Equal(again, enc1) || idAgain != id1 {
		t.Fatal("derivation is not deterministic")
	}
	if _, _, err := deriveKeys(key32(1)[:16]); !errors.Is(err, ErrBadRootKey) {
		t.Fatalf("short root key: %v", err)
	}
}
