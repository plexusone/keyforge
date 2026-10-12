package envelope_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func testID(seed byte) envelope.ID {
	var id envelope.ID
	for i := range id {
		id[i] = seed + byte(i)
	}
	return id
}

func newAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	aead, err := algorithm.New(algorithm.AES256GCM, testKey())
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func referenceHeader() envelope.Header {
	return envelope.Header{
		Mode:      envelope.ModeReference,
		Algorithm: algorithm.AES256GCM,
		Purpose:   "session-secrets",
		DEKID:     testID(0x10),
	}
}

func inlineHeader() envelope.Header {
	return envelope.Header{
		Mode:       envelope.ModeInline,
		Algorithm:  algorithm.AES256GCM,
		Purpose:    "hold-snapshots",
		KEKID:      testID(0x20),
		KEKVersion: 7,
		Wrapped:    bytes.Repeat([]byte{0xAB}, 60),
	}
}

func TestRoundTrip(t *testing.T) {
	aead := newAEAD(t)
	for name, h := range map[string]envelope.Header{"reference": referenceHeader(), "inline": inlineHeader()} {
		t.Run(name, func(t *testing.T) {
			plaintext := []byte("the quick brown fox")
			context := []byte("record:42")

			e, err := envelope.Seal(aead, h, plaintext, context)
			if err != nil {
				t.Fatal(err)
			}
			bin, err := e.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := envelope.Parse(bin)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parsed.Open(aead, context)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("plaintext = %q, want %q", got, plaintext)
			}

			text := e.String()
			if !strings.HasPrefix(text, "kf1.") {
				t.Fatalf("text form %q lacks the kf1. prefix", text)
			}
			fromText, err := envelope.ParseText(text)
			if err != nil {
				t.Fatal(err)
			}
			again, err := fromText.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, bin) {
				t.Fatal("text form does not round-trip to the same binary form")
			}
		})
	}
}

func TestSealUsesFreshNonces(t *testing.T) {
	aead := newAEAD(t)
	a, err := envelope.Seal(aead, referenceHeader(), []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := envelope.Seal(aead, referenceHeader(), []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Nonce == b.Nonce {
		t.Fatal("two seals produced the same nonce")
	}
}

func TestEmptyPlaintext(t *testing.T) {
	aead := newAEAD(t)
	e, err := envelope.Seal(aead, referenceHeader(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Ciphertext) != algorithm.AES256GCM.TagSize() {
		t.Fatalf("ciphertext length = %d, want the tag alone", len(e.Ciphertext))
	}
	got, err := e.Open(aead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("plaintext = %q, want empty", got)
	}
}

// TestAADBinding changes each authenticated input in turn and requires that
// opening fails, so a ciphertext cannot be moved to another purpose, key or
// record.
func TestAADBinding(t *testing.T) {
	aead := newAEAD(t)
	context := []byte("record:42")

	reference, err := envelope.Seal(aead, referenceHeader(), []byte("secret"), context)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := envelope.Seal(aead, inlineHeader(), []byte("secret"), context)
	if err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name   string
		base   *envelope.Envelope
		mutate func(e *envelope.Envelope)
		ctx    []byte
	}{
		{"context", reference, func(*envelope.Envelope) {}, []byte("record:43")},
		{"empty context", reference, func(*envelope.Envelope) {}, nil},
		{"purpose", reference, func(e *envelope.Envelope) { e.Purpose = "backup-keys" }, context},
		{"data key id", reference, func(e *envelope.Envelope) { e.DEKID[0] ^= 1 }, context},
		{"inline purpose", inline, func(e *envelope.Envelope) { e.Purpose = "backup-keys" }, context},
		{"kek id", inline, func(e *envelope.Envelope) { e.KEKID[0] ^= 1 }, context},
		{"kek version", inline, func(e *envelope.Envelope) { e.KEKVersion++ }, context},
		{"wrapped key", inline, func(e *envelope.Envelope) {
			e.Wrapped = append([]byte(nil), e.Wrapped...)
			e.Wrapped[0] ^= 1
		}, context},
		{"nonce", reference, func(e *envelope.Envelope) { e.Nonce[0] ^= 1 }, context},
		{"ciphertext", reference, func(e *envelope.Envelope) {
			e.Ciphertext = append([]byte(nil), e.Ciphertext...)
			e.Ciphertext[0] ^= 1
		}, context},
		{"tag", reference, func(e *envelope.Envelope) {
			e.Ciphertext = append([]byte(nil), e.Ciphertext...)
			e.Ciphertext[len(e.Ciphertext)-1] ^= 1
		}, context},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			e := *m.base
			m.mutate(&e)
			if _, err := e.Open(aead, m.ctx); !errors.Is(err, envelope.ErrAuthentication) {
				t.Fatalf("Open = %v, want ErrAuthentication", err)
			}
		})
	}

	t.Run("wrong key", func(t *testing.T) {
		other := testKey()
		other[0] ^= 1
		wrong, err := algorithm.New(algorithm.AES256GCM, other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reference.Open(wrong, context); !errors.Is(err, envelope.ErrAuthentication) {
			t.Fatalf("Open = %v, want ErrAuthentication", err)
		}
	})

	t.Run("header bytes differ between modes", func(t *testing.T) {
		ref := envelope.Header{Mode: envelope.ModeReference, Algorithm: algorithm.AES256GCM, Purpose: "p", DEKID: testID(1)}
		inl := envelope.Header{Mode: envelope.ModeInline, Algorithm: algorithm.AES256GCM, Purpose: "p", KEKID: testID(1), Wrapped: []byte{1}}
		refAAD, err := ref.AAD(nil)
		if err != nil {
			t.Fatal(err)
		}
		inlAAD, err := inl.AAD(nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(refAAD, inlAAD) {
			t.Fatal("reference and inline headers produce the same AAD")
		}
	})
}

func TestSealRefusesExplicitNonceAEAD(t *testing.T) {
	block, err := aes.NewCipher(testKey())
	if err != nil {
		t.Fatal(err)
	}
	aead := newExplicitNonceAEAD(t, block)
	if _, err := envelope.Seal(aead, referenceHeader(), []byte("x"), nil); !errors.Is(err, envelope.ErrNotRandomNonce) {
		t.Fatalf("Seal = %v, want ErrNotRandomNonce", err)
	}
	e, err := envelope.Seal(newAEAD(t), referenceHeader(), []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Open(aead, nil); !errors.Is(err, envelope.ErrNotRandomNonce) {
		t.Fatalf("Open = %v, want ErrNotRandomNonce", err)
	}
}

func TestHeaderValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(h *envelope.Header)
		base   func() envelope.Header
		want   error
	}{
		{"valid reference", func(*envelope.Header) {}, referenceHeader, nil},
		{"valid inline", func(*envelope.Header) {}, inlineHeader, nil},
		{"unknown mode", func(h *envelope.Header) { h.Mode = 9 }, referenceHeader, envelope.ErrUnknownMode},
		{"zero mode", func(h *envelope.Header) { h.Mode = 0 }, referenceHeader, envelope.ErrUnknownMode},
		{"unknown algorithm", func(h *envelope.Header) { h.Algorithm = 99 }, referenceHeader, envelope.ErrUnknownAlgorithm},
		{"empty purpose", func(h *envelope.Header) { h.Purpose = "" }, referenceHeader, envelope.ErrInvalidPurpose},
		{"uppercase purpose", func(h *envelope.Header) { h.Purpose = "Session" }, referenceHeader, envelope.ErrInvalidPurpose},
		{"purpose with space", func(h *envelope.Header) { h.Purpose = "a b" }, referenceHeader, envelope.ErrInvalidPurpose},
		{"purpose starting with dash", func(h *envelope.Header) { h.Purpose = "-a" }, referenceHeader, envelope.ErrInvalidPurpose},
		{"purpose too long", func(h *envelope.Header) { h.Purpose = strings.Repeat("a", 256) }, referenceHeader, envelope.ErrInvalidPurpose},
		{"longest purpose", func(h *envelope.Header) { h.Purpose = strings.Repeat("a", 255) }, referenceHeader, nil},
		{"reference without dek id", func(h *envelope.Header) { h.DEKID = envelope.ID{} }, referenceHeader, envelope.ErrInvalidHeader},
		{"reference with inline fields", func(h *envelope.Header) { h.KEKVersion = 1 }, referenceHeader, envelope.ErrInvalidHeader},
		{"inline without kek id", func(h *envelope.Header) { h.KEKID = envelope.ID{} }, inlineHeader, envelope.ErrInvalidHeader},
		{"inline without wrapped key", func(h *envelope.Header) { h.Wrapped = nil }, inlineHeader, envelope.ErrInvalidHeader},
		{"inline wrapped key too long", func(h *envelope.Header) { h.Wrapped = make([]byte, 65536) }, inlineHeader, envelope.ErrInvalidHeader},
		{"inline largest wrapped key", func(h *envelope.Header) { h.Wrapped = make([]byte, 65535) }, inlineHeader, nil},
		{"inline with dek id", func(h *envelope.Header) { h.DEKID = testID(1) }, inlineHeader, envelope.ErrInvalidHeader},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.base()
			tt.mutate(&h)
			err := h.Validate()
			if tt.want == nil {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestValueErrorCarriesValue(t *testing.T) {
	b := mustBinary(t, referenceHeader())
	b[2] = 9 // format version

	_, err := envelope.Parse(b)
	if !errors.Is(err, envelope.ErrUnsupportedFormat) {
		t.Fatalf("Parse = %v, want ErrUnsupportedFormat", err)
	}
	var ve *envelope.ValueError
	if !errors.As(err, &ve) || ve.Value != 9 {
		t.Fatalf("errors.As = %v, value %v, want 9", errors.As(err, &ve), ve)
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	valid := mustBinary(t, referenceHeader())
	tests := []struct {
		name   string
		mutate func(b []byte) []byte
		want   error
	}{
		{"empty", func([]byte) []byte { return nil }, envelope.ErrTruncated},
		{"one byte", func(b []byte) []byte { return b[:1] }, envelope.ErrTruncated},
		{"bad magic", func(b []byte) []byte { b[0] = 'X'; return b }, envelope.ErrBadMagic},
		{"lowercase magic", func(b []byte) []byte { b[0], b[1] = 'k', 'f'; return b }, envelope.ErrBadMagic},
		{"format 0", func(b []byte) []byte { b[2] = 0; return b }, envelope.ErrUnsupportedFormat},
		{"format 2", func(b []byte) []byte { b[2] = 2; return b }, envelope.ErrUnsupportedFormat},
		{"mode 0", func(b []byte) []byte { b[3] = 0; return b }, envelope.ErrUnknownMode},
		{"mode 3", func(b []byte) []byte { b[3] = 3; return b }, envelope.ErrUnknownMode},
		{"algorithm 0", func(b []byte) []byte { b[4] = 0; return b }, envelope.ErrUnknownAlgorithm},
		{"algorithm 2", func(b []byte) []byte { b[4] = 2; return b }, envelope.ErrUnknownAlgorithm},
		{"algorithm 255", func(b []byte) []byte { b[4] = 255; return b }, envelope.ErrUnknownAlgorithm},
		{"flag bit 0", func(b []byte) []byte { b[5] = 0x01; return b }, envelope.ErrUnsupportedFlags},
		{"flag bit 7", func(b []byte) []byte { b[5] = 0x80; return b }, envelope.ErrUnsupportedFlags},
		{"empty purpose", func(b []byte) []byte { b[6] = 0; return b }, envelope.ErrInvalidPurpose},
		{"purpose length past end", func(b []byte) []byte { b[6] = 255; return b }, envelope.ErrTruncated},
		{"purpose with uppercase", func(b []byte) []byte { b[7] = 'S'; return b }, envelope.ErrInvalidPurpose},
		{"missing tag", func(b []byte) []byte { return b[:6+1+len("session-secrets")+16+12+15] }, envelope.ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := tt.mutate(append([]byte(nil), valid...))
			if _, err := envelope.Parse(in); !errors.Is(err, tt.want) {
				t.Fatalf("Parse = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestTruncationNeverSucceeds cuts a valid envelope at every length. Each cut
// must either fail to parse with an error or parse into an envelope that does
// not authenticate, and nothing may panic.
func TestTruncationNeverSucceeds(t *testing.T) {
	aead := newAEAD(t)
	for name, h := range map[string]envelope.Header{"reference": referenceHeader(), "inline": inlineHeader()} {
		t.Run(name, func(t *testing.T) {
			e, err := envelope.Seal(aead, h, []byte("some plaintext to cut"), []byte("ctx"))
			if err != nil {
				t.Fatal(err)
			}
			full, err := e.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			for n := range full {
				p, err := envelope.Parse(full[:n])
				if err != nil {
					continue
				}
				if _, err := p.Open(aead, []byte("ctx")); !errors.Is(err, envelope.ErrAuthentication) {
					t.Fatalf("cut at %d of %d: Open = %v, want ErrAuthentication", n, len(full), err)
				}
			}
		})
	}
}

func TestTextForm(t *testing.T) {
	aead := newAEAD(t)
	e, err := envelope.Seal(aead, referenceHeader(), []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	good := e.String()
	body := strings.TrimPrefix(good, "kf1.")

	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", envelope.ErrBadTextForm},
		{"no prefix", body, envelope.ErrBadTextForm},
		{"uppercase prefix", "KF1." + body, envelope.ErrBadTextForm},
		{"no dot", "kf1" + body, envelope.ErrBadTextForm},
		{"other version", "kf2." + body, envelope.ErrUnsupportedFormat},
		{"version 0", "kf0." + body, envelope.ErrUnsupportedFormat},
		{"leading zero version", "kf01." + body, envelope.ErrBadTextForm},
		{"non-numeric version", "kfx." + body, envelope.ErrBadTextForm},
		{"huge version", "kf9999." + body, envelope.ErrBadTextForm},
		{"padded", good + "=", envelope.ErrBadTextForm},
		{"standard alphabet", "kf1.+" + body[1:], envelope.ErrBadTextForm},
		{"whitespace", good + "\n", envelope.ErrBadTextForm},
		{"empty body", "kf1.", envelope.ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := envelope.ParseText(tt.in); !errors.Is(err, tt.want) {
				t.Fatalf("ParseText = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestJSON(t *testing.T) {
	aead := newAEAD(t)
	e, err := envelope.Seal(aead, inlineHeader(), []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		Value *envelope.Envelope `json:"value"`
	}
	b, err := json.Marshal(row{Value: e})
	if err != nil {
		t.Fatal(err)
	}
	var back row
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Value.String() != e.String() {
		t.Fatal("JSON round trip changed the envelope")
	}
	if !strings.Contains(string(b), `"kf1.`) {
		t.Fatalf("JSON %s does not hold the text form", b)
	}
}

func TestErrorsCarryNoKeyMaterial(t *testing.T) {
	aead := newAEAD(t)
	e, err := envelope.Seal(aead, referenceHeader(), []byte("plaintext-marker"), []byte("context-marker"))
	if err != nil {
		t.Fatal(err)
	}
	e.Ciphertext[0] ^= 1
	_, err = e.Open(aead, []byte("context-marker"))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, leak := range []string{"plaintext-marker", "context-marker", string(testKey())} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error %q leaks %q", err, leak)
		}
	}
}

func mustBinary(t *testing.T, h envelope.Header) []byte {
	t.Helper()
	e, err := envelope.Seal(newAEAD(t), h, []byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIDIsStoredAsRawBytes(t *testing.T) {
	id := testID(0x30)
	v, err := id.Value()
	if err != nil {
		t.Fatal(err)
	}
	b, ok := v.([]byte)
	if !ok || !bytes.Equal(b, id[:]) {
		t.Fatalf("Value = %T %x, want the 16 raw bytes", v, v)
	}
	var back envelope.ID
	if err := back.Scan(b); err != nil || back != id {
		t.Fatalf("Scan = %v, %v", back, err)
	}
	for name, in := range map[string]any{"string": "abc", "short": []byte{1, 2}, "nil": nil, "long": make([]byte, 17)} {
		var x envelope.ID
		if err := x.Scan(in); err == nil {
			t.Errorf("Scan accepted %s", name)
		}
	}
}

func TestIDTextAndJSONForm(t *testing.T) {
	id := envelope.ID{0xde, 0xad, 0xbe, 0xef, 15: 0x01}
	b, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if want := `"` + id.String() + `"`; string(b) != want {
		t.Fatalf("got %s, want %s", b, want)
	}
	var back envelope.ID
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != id {
		t.Fatalf("round trip: got %v", back)
	}
	for _, bad := range []string{`"abc"`, `"zz` + strings.Repeat("0", 30) + `"`, `[1,2]`} {
		if err := json.Unmarshal([]byte(bad), &back); err == nil {
			t.Fatalf("%s: expected an error", bad)
		}
	}
}
