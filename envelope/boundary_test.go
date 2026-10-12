package envelope_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
)

// inlinePrefix builds the bytes of an inline-mode header up to and including
// the wrapped length field, with whatever wrapped length is claimed.
func inlinePrefix(purpose string, claimed uint16) []byte {
	b := []byte{'K', 'F', 1, byte(envelope.ModeInline), byte(algorithm.AES256GCM), 0, byte(len(purpose))} //nolint:gosec // G115: test input; the callers pass short constant purposes
	b = append(b, purpose...)
	b = append(b, bytes.Repeat([]byte{0x22}, 16)...)
	b = binary.BigEndian.AppendUint32(b, 1)
	return binary.BigEndian.AppendUint16(b, claimed)
}

func TestBoundaryPurposeLengths(t *testing.T) {
	aead := newAEAD(t)
	for _, n := range []int{1, 2, 254, 255} {
		h := referenceHeader()
		h.Purpose = strings.Repeat("a", n)
		e, err := envelope.Seal(aead, h, []byte("x"), nil)
		if err != nil {
			t.Fatalf("purpose of %d bytes: %v", n, err)
		}
		p, err := envelope.Parse(mustMarshal(t, e))
		if err != nil || p.Purpose != h.Purpose {
			t.Fatalf("purpose of %d bytes did not round-trip: %v", n, err)
		}
	}
	for _, n := range []int{0, 256, 1000} {
		h := referenceHeader()
		h.Purpose = strings.Repeat("a", n)
		if _, err := envelope.Seal(aead, h, []byte("x"), nil); !errors.Is(err, envelope.ErrInvalidPurpose) {
			t.Fatalf("purpose of %d bytes: Seal = %v, want ErrInvalidPurpose", n, err)
		}
	}
}

func TestBoundaryWrappedKeyLengths(t *testing.T) {
	aead := newAEAD(t)
	for _, n := range []int{1, 255, 256, 65534, 65535} {
		h := inlineHeader()
		h.Wrapped = bytes.Repeat([]byte{0x5C}, n)
		e, err := envelope.Seal(aead, h, []byte("x"), nil)
		if err != nil {
			t.Fatalf("wrapped key of %d bytes: %v", n, err)
		}
		p, err := envelope.Parse(mustMarshal(t, e))
		if err != nil || len(p.Wrapped) != n {
			t.Fatalf("wrapped key of %d bytes did not round-trip: %v", n, err)
		}
	}
	for _, n := range []int{0, 65536} {
		h := inlineHeader()
		h.Wrapped = make([]byte, n)
		if _, err := envelope.Seal(aead, h, []byte("x"), nil); !errors.Is(err, envelope.ErrInvalidHeader) {
			t.Fatalf("wrapped key of %d bytes: Seal = %v, want ErrInvalidHeader", n, err)
		}
	}
}

// TestClaimedLengthsPastTheInput gives the parser lengths that promise far more
// data than exist. It must report truncation, not read past the slice or
// allocate what the field claims.
func TestClaimedLengthsPastTheInput(t *testing.T) {
	for _, claimed := range []uint16{1, 100, 65535} {
		in := append(inlinePrefix("exports", claimed), bytes.Repeat([]byte{1}, 10)...)
		if _, err := envelope.Parse(in); !errors.Is(err, envelope.ErrTruncated) {
			t.Fatalf("claimed wrapped length %d: Parse = %v, want ErrTruncated", claimed, err)
		}
	}
	// A claimed wrapped length of zero is a header inconsistency, not a read.
	if _, err := envelope.Parse(append(inlinePrefix("exports", 0), make([]byte, 40)...)); !errors.Is(err, envelope.ErrInvalidHeader) {
		t.Fatalf("zero wrapped length: want ErrInvalidHeader")
	}
}

func TestBoundaryCiphertextSizes(t *testing.T) {
	aead := newAEAD(t)
	for _, n := range []int{0, 1, 15, 16, 17, 4096, 1 << 20} {
		pt := bytes.Repeat([]byte{0x7E}, n)
		e, err := envelope.Seal(aead, referenceHeader(), pt, []byte("c"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := envelope.Parse(mustMarshal(t, e))
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.Open(aead, []byte("c"))
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("plaintext of %d bytes did not round-trip: %v", n, err)
		}
	}
}

func TestBoundaryContextSizes(t *testing.T) {
	aead := newAEAD(t)
	for _, n := range []int{0, 1, 65535, 1 << 20} {
		ctx := bytes.Repeat([]byte{0x31}, n)
		e, err := envelope.Seal(aead, referenceHeader(), []byte("x"), ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Open(aead, ctx); err != nil {
			t.Fatalf("context of %d bytes: %v", n, err)
		}
		if n > 0 {
			if _, err := e.Open(aead, ctx[:n-1]); !errors.Is(err, envelope.ErrAuthentication) {
				t.Fatalf("context of %d bytes cut by one: Open = %v, want ErrAuthentication", n, err)
			}
		}
	}
}

// TestContextCannotBeShiftedIntoTheHeader checks that moving bytes between the
// end of the header and the start of the context does not produce the same
// authenticated data. The header is self-delimiting, so it cannot.
func TestContextCannotBeShiftedIntoTheHeader(t *testing.T) {
	aead := newAEAD(t)
	a := envelope.Header{Mode: envelope.ModeInline, Algorithm: algorithm.AES256GCM, Purpose: "p", KEKID: testID(1), KEKVersion: 1, Wrapped: []byte{1, 2, 3, 4}}
	b := a
	b.Wrapped = []byte{1, 2, 3}

	ea, err := envelope.Seal(aead, a, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Same total bytes as header a, with the last wrapped byte moved into the
	// context.
	eb := *ea
	eb.Header = b
	if _, err := eb.Open(aead, []byte{4}); !errors.Is(err, envelope.ErrAuthentication) {
		t.Fatalf("Open = %v, want ErrAuthentication", err)
	}
}
