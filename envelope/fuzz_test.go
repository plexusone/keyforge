package envelope_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
)

// typedParseErrors is every error Parse and ParseText may return. An error
// outside this set is a bug: the parser reports only what it can name.
var typedParseErrors = []error{
	envelope.ErrBadMagic,
	envelope.ErrTruncated,
	envelope.ErrUnsupportedFormat,
	envelope.ErrUnknownMode,
	envelope.ErrUnknownAlgorithm,
	envelope.ErrUnsupportedFlags,
	envelope.ErrInvalidPurpose,
	envelope.ErrInvalidHeader,
	envelope.ErrBadTextForm,
}

func isTyped(err error) bool {
	for _, t := range typedParseErrors {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

func seedFromVectors(f *testing.F) {
	f.Helper()
	b, err := readVectorFile()
	if err != nil {
		f.Fatal(err)
	}
	for _, v := range b.Valid {
		f.Add(mustDecodeHex(f, v.Envelope))
	}
	for _, v := range b.Invalid {
		f.Add(mustDecodeHex(f, v.Envelope))
	}
	f.Add([]byte{})
	f.Add([]byte("KF"))
	f.Add([]byte("KF\x01\x01\x01\x00"))
}

// FuzzParse feeds arbitrary bytes to the binary parser. It must never panic,
// must fail only with a typed error, and anything it accepts must be in
// canonical form: re-marshalling gives back exactly the input.
func FuzzParse(f *testing.F) {
	seedFromVectors(f)
	aead, err := algorithm.New(algorithm.AES256GCM, vectorKey())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		e, err := envelope.Parse(in)
		if err != nil {
			if !isTyped(err) {
				t.Fatalf("Parse returned an untyped error: %v", err)
			}
			return
		}
		out, err := e.MarshalBinary()
		if err != nil {
			t.Fatalf("a parsed envelope does not marshal: %v", err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("parse then marshal changed the bytes:\n in  %x\n out %x", in, out)
		}
		// Opening arbitrary parsed input must fail cleanly, never panic.
		if _, err := e.Open(aead, nil); err != nil && !errors.Is(err, envelope.ErrAuthentication) {
			t.Fatalf("Open returned an unexpected error: %v", err)
		}
	})
}

// FuzzParseText does the same for the text form, and additionally requires
// that the text form has a single spelling: an accepted string is exactly the
// string the envelope marshals back to.
func FuzzParseText(f *testing.F) {
	b, err := readVectorFile()
	if err != nil {
		f.Fatal(err)
	}
	for _, v := range b.Valid {
		f.Add(v.Text)
	}
	f.Add("")
	f.Add("kf1.")
	f.Add("kf2.AAAA")
	f.Add("kf1.AAAA=")
	f.Fuzz(func(t *testing.T, in string) {
		e, err := envelope.ParseText(in)
		if err != nil {
			if !isTyped(err) {
				t.Fatalf("ParseText returned an untyped error: %v", err)
			}
			return
		}
		if got := e.String(); got != in {
			t.Fatalf("parse then marshal changed the text:\n in  %q\n out %q", in, got)
		}
	})
}
