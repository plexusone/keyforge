package envelope_test

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
)

const vectorsPath = "testdata/vectors.json"

// vectorKey is a fixed, non-secret key that exists only for these vectors.
func vectorKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(0xA0 + i)
	}
	return k
}

type validVector struct {
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	Algorithm string `json:"algorithm"`
	Purpose   string `json:"purpose"`
	Context   string `json:"context"`   // hex
	Plaintext string `json:"plaintext"` // hex
	Envelope  string `json:"envelope"`  // hex, binary form
	Text      string `json:"text"`
}

type invalidVector struct {
	Name     string `json:"name"`
	Envelope string `json:"envelope"` // hex, binary form
	Error    string `json:"error"`
}

type vectorFile struct {
	Description string          `json:"description"`
	Key         string          `json:"key"` // hex; non-secret, used only for these vectors
	Valid       []validVector   `json:"valid"`
	Invalid     []invalidVector `json:"invalid"`
}

var vectorErrors = map[string]error{
	"ErrBadMagic":          envelope.ErrBadMagic,
	"ErrTruncated":         envelope.ErrTruncated,
	"ErrUnsupportedFormat": envelope.ErrUnsupportedFormat,
	"ErrUnknownMode":       envelope.ErrUnknownMode,
	"ErrUnknownAlgorithm":  envelope.ErrUnknownAlgorithm,
	"ErrUnsupportedFlags":  envelope.ErrUnsupportedFlags,
	"ErrInvalidPurpose":    envelope.ErrInvalidPurpose,
	"ErrAuthentication":    envelope.ErrAuthentication,
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVectors opens published envelopes. They were produced once by the seal
// path and are frozen, so a change to the format or to the AAD construction
// breaks them.
func TestVectors(t *testing.T) {
	f := loadVectors(t)
	key := mustHex(t, f.Key)
	aead, err := algorithm.New(algorithm.AES256GCM, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Valid) == 0 {
		t.Fatal("no valid vectors")
	}
	for _, v := range f.Valid {
		t.Run(v.Name, func(t *testing.T) {
			bin := mustHex(t, v.Envelope)
			e, err := envelope.Parse(bin)
			if err != nil {
				t.Fatal(err)
			}
			if e.Mode.String() != v.Mode || e.Algorithm.String() != v.Algorithm || e.Purpose != v.Purpose {
				t.Fatalf("header = %v %v %q, want %v %v %q", e.Mode, e.Algorithm, e.Purpose, v.Mode, v.Algorithm, v.Purpose)
			}
			got, err := e.Open(aead, mustHex(t, v.Context))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, mustHex(t, v.Plaintext)) {
				t.Fatalf("plaintext = %x, want %s", got, v.Plaintext)
			}

			// The encoding is canonical: parsing and re-marshalling gives back
			// the same bytes, and the text form is the one that was published.
			again, err := e.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, bin) {
				t.Fatal("re-marshalled binary form differs from the vector")
			}
			if e.String() != v.Text {
				t.Fatalf("text form = %q, want %q", e.String(), v.Text)
			}
			fromText, err := envelope.ParseText(v.Text)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(mustMarshal(t, fromText), bin) {
				t.Fatal("text form parses to a different envelope")
			}
		})
	}
}

// TestVectorsIndependentOpen opens the same vectors with plain AES-GCM and
// an explicit nonce, so a mistake in how the random-nonce constructor's
// output is split and re-assembled cannot hide behind a round trip.
func TestVectorsIndependentOpen(t *testing.T) {
	f := loadVectors(t)
	block, err := aes.NewCipher(mustHex(t, f.Key))
	if err != nil {
		t.Fatal(err)
	}
	gcm := newExplicitNonceAEAD(t, block)
	for _, v := range f.Valid {
		t.Run(v.Name, func(t *testing.T) {
			e, err := envelope.Parse(mustHex(t, v.Envelope))
			if err != nil {
				t.Fatal(err)
			}
			aad, err := e.Header.AAD(mustHex(t, v.Context))
			if err != nil {
				t.Fatal(err)
			}
			got, err := gcm.Open(nil, e.Nonce[:], e.Ciphertext, aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, mustHex(t, v.Plaintext)) {
				t.Fatalf("plaintext = %x, want %s", got, v.Plaintext)
			}
		})
	}
}

func TestInvalidVectors(t *testing.T) {
	f := loadVectors(t)
	if len(f.Invalid) == 0 {
		t.Fatal("no invalid vectors")
	}
	aead, err := algorithm.New(algorithm.AES256GCM, mustHex(t, f.Key))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Invalid {
		t.Run(v.Name, func(t *testing.T) {
			want, ok := vectorErrors[v.Error]
			if !ok {
				t.Fatalf("vector names an unknown error %q", v.Error)
			}
			e, err := envelope.Parse(mustHex(t, v.Envelope))
			if err == nil {
				// Parsing may succeed for an input that fails to authenticate.
				_, err = e.Open(aead, nil)
			}
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}
}

func mustMarshal(t *testing.T, e *envelope.Envelope) []byte {
	t.Helper()
	b, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestGenerateVectors rewrites testdata/vectors.json. It runs only when
// KEYFORGE_UPDATE_VECTORS=1 and exists to document how the file was made.
// Regenerating draws new random nonces, so it changes every envelope, and the
// result must be reviewed as a format change.
func TestGenerateVectors(t *testing.T) {
	if os.Getenv("KEYFORGE_UPDATE_VECTORS") != "1" {
		t.Skip("set KEYFORGE_UPDATE_VECTORS=1 to regenerate testdata/vectors.json")
	}
	key := vectorKey()
	aead, err := algorithm.New(algorithm.AES256GCM, key)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		header    envelope.Header
		context   []byte
		plaintext []byte
	}{
		{"reference-basic", envelope.Header{Mode: envelope.ModeReference, Algorithm: algorithm.AES256GCM, Purpose: "session-secrets", DEKID: testID(0x10)}, []byte("record:42"), []byte("hello keyforge")},
		{"reference-empty-context", envelope.Header{Mode: envelope.ModeReference, Algorithm: algorithm.AES256GCM, Purpose: "session-secrets", DEKID: testID(0x30)}, nil, []byte("no context")},
		{"reference-empty-plaintext", envelope.Header{Mode: envelope.ModeReference, Algorithm: algorithm.AES256GCM, Purpose: "audit-log", DEKID: testID(0x50)}, []byte("seq:1"), nil},
		{"reference-longest-purpose", envelope.Header{Mode: envelope.ModeReference, Algorithm: algorithm.AES256GCM, Purpose: strings.Repeat("a", 255), DEKID: testID(0x70)}, nil, []byte("long purpose")},
		{"inline-basic", envelope.Header{Mode: envelope.ModeInline, Algorithm: algorithm.AES256GCM, Purpose: "hold-snapshots", KEKID: testID(0x20), KEKVersion: 7, Wrapped: bytes.Repeat([]byte{0xAB}, 60)}, []byte("object:9"), []byte("standalone object")},
		{"inline-large-wrapped", envelope.Header{Mode: envelope.ModeInline, Algorithm: algorithm.AES256GCM, Purpose: "exports", KEKID: testID(0x40), KEKVersion: 4294967295, Wrapped: bytes.Repeat([]byte{0xCD}, 1000)}, nil, []byte("big wrapped key")},
	}

	out := vectorFile{
		Description: "Known-answer vectors for envelope format 1. Produced once by the seal path and frozen; the key is a fixed non-secret test key. Regenerating changes every envelope and is a format change.",
		Key:         hex.EncodeToString(key),
	}
	var first []byte
	for _, c := range cases {
		e, err := envelope.Seal(aead, c.header, c.plaintext, c.context)
		if err != nil {
			t.Fatal(err)
		}
		bin := mustMarshal(t, e)
		if first == nil {
			first = bin
		}
		out.Valid = append(out.Valid, validVector{
			Name:      c.name,
			Mode:      c.header.Mode.String(),
			Algorithm: c.header.Algorithm.String(),
			Purpose:   c.header.Purpose,
			Context:   hex.EncodeToString(c.context),
			Plaintext: hex.EncodeToString(c.plaintext),
			Envelope:  hex.EncodeToString(bin),
			Text:      e.String(),
		})
	}

	mutate := func(name, errName string, fn func(b []byte) []byte) {
		b := fn(append([]byte(nil), first...))
		out.Invalid = append(out.Invalid, invalidVector{Name: name, Envelope: hex.EncodeToString(b), Error: errName})
	}
	mutate("bad-magic", "ErrBadMagic", func(b []byte) []byte { b[0] = 'X'; return b })
	mutate("unsupported-format-2", "ErrUnsupportedFormat", func(b []byte) []byte { b[2] = 2; return b })
	mutate("unknown-mode-3", "ErrUnknownMode", func(b []byte) []byte { b[3] = 3; return b })
	mutate("unknown-algorithm-2", "ErrUnknownAlgorithm", func(b []byte) []byte { b[4] = 2; return b })
	mutate("flags-set", "ErrUnsupportedFlags", func(b []byte) []byte { b[5] = 0x01; return b })
	mutate("empty-purpose", "ErrInvalidPurpose", func(b []byte) []byte { b[6] = 0; return b })
	mutate("truncated-in-header", "ErrTruncated", func(b []byte) []byte { return b[:10] })
	mutate("truncated-before-tag", "ErrTruncated", func(b []byte) []byte { return b[:len(b)-len("hello keyforge")-16+15] })
	mutate("flipped-ciphertext-bit", "ErrAuthentication", func(b []byte) []byte { b[len(b)-1] ^= 1; return b })

	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsPath, append(enc, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
