package algorithm_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/plexusone/keyforge/algorithm"
)

func TestAES256GCMProperties(t *testing.T) {
	id := algorithm.AES256GCM
	if !id.Valid() {
		t.Fatal("AES-256-GCM is not valid")
	}
	if got := id.String(); got != "AES-256-GCM" {
		t.Fatalf("String = %q, want the exact mode-and-size name", got)
	}
	if id.KeySize() != 32 || id.NonceSize() != 12 || id.TagSize() != 16 {
		t.Fatalf("sizes = key %d nonce %d tag %d, want 32, 12, 16", id.KeySize(), id.NonceSize(), id.TagSize())
	}
	if uint8(id) != 1 {
		t.Fatalf("identifier = %d, want 1: the value is frozen in the envelope format", uint8(id))
	}
}

func TestUnknownIdentifiers(t *testing.T) {
	for _, id := range []algorithm.ID{0, 2, 16, 17, 18, 32, 33, 34, 255} {
		if id.Valid() {
			t.Errorf("%d is valid; only identifier 1 is in the registry", uint8(id))
		}
		if id.KeySize() != 0 || id.NonceSize() != 0 || id.TagSize() != 0 {
			t.Errorf("%d reports sizes for an unknown algorithm", uint8(id))
		}
		if _, err := algorithm.New(id, make([]byte, 32)); !errors.Is(err, algorithm.ErrUnknown) {
			t.Errorf("New(%d) = %v, want ErrUnknown", uint8(id), err)
		}
	}
}

func TestNewChecksKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33, 64} {
		if _, err := algorithm.New(algorithm.AES256GCM, make([]byte, n)); !errors.Is(err, algorithm.ErrKeySize) {
			t.Errorf("New with a %d-byte key = %v, want ErrKeySize", n, err)
		}
	}
}

func TestNewReturnsRandomNonceAEAD(t *testing.T) {
	aead, err := algorithm.New(algorithm.AES256GCM, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if aead.NonceSize() != 0 {
		t.Fatalf("NonceSize = %d, want 0: the AEAD must generate its own nonce", aead.NonceSize())
	}
	// A nil nonce is the API of a random-nonce AEAD: it generates the nonce.
	a := aead.Seal(nil, nil, []byte("m"), nil) //nolint:gosec // G407: see above
	b := aead.Seal(nil, nil, []byte("m"), nil) //nolint:gosec // G407: see above
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same message are identical")
	}
	got, err := aead.Open(nil, nil, a, nil)
	if err != nil || string(got) != "m" {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestErrorsNameNoKeyBytes(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 31)
	_, err := algorithm.New(algorithm.AES256GCM, key)
	if err == nil {
		t.Fatal("expected an error")
	}
	if bytes.Contains([]byte(err.Error()), key[:4]) {
		t.Fatalf("error %q contains key bytes", err)
	}
}
