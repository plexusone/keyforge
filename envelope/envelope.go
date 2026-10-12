package envelope

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/plexusone/keyforge/algorithm"
)

const (
	// FormatVersion is the only format version this build writes and reads.
	FormatVersion uint8 = 1

	// NonceSize is the size of the nonce field in format 1.
	NonceSize = 12

	// MaxPurposeLen is the longest purpose name, bounded by its u8 length.
	MaxPurposeLen = 255
	// MaxWrappedLen is the longest wrapped data key in inline mode, bounded
	// by its u16 length.
	MaxWrappedLen = 65535

	textPrefix = "kf1."
	magic0     = 'K'
	magic1     = 'F'
)

// Mode says where the wrapped data key lives.
type Mode uint8

const (
	// ModeReference names the data key by identifier. The wrapped key is held
	// by the registry, so rotating the key-encryption key re-wraps registry
	// records and stored data is not touched.
	ModeReference Mode = 1
	// ModeInline carries the wrapped data key, its key-encryption key and
	// version beside the ciphertext, for standalone objects.
	ModeInline Mode = 2
)

// String returns the mode's name.
func (m Mode) String() string {
	switch m {
	case ModeReference:
		return "reference"
	case ModeInline:
		return "inline"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(m))
	}
}

// ID is a 16-byte key identifier.
type ID [16]byte

// String returns the identifier as lowercase hex.
func (id ID) String() string { return hex.EncodeToString(id[:]) }

// IsZero reports whether the identifier is all zero bytes.
func (id ID) IsZero() bool { return id == ID{} }

// Header is the authenticated, self-describing part of an envelope.
//
// Which fields are used depends on Mode. In reference mode DEKID names the
// data key and the inline fields must be zero. In inline mode KEKID,
// KEKVersion and Wrapped describe the wrapped data key and DEKID must be zero.
type Header struct {
	Mode      Mode
	Algorithm algorithm.ID
	Purpose   string

	DEKID ID // reference mode

	KEKID      ID     // inline mode
	KEKVersion uint32 // inline mode
	Wrapped    []byte // inline mode
}

// Envelope is a parsed or sealed ciphertext: the header, the nonce and the
// ciphertext with its authentication tag.
type Envelope struct {
	Header
	Nonce      [NonceSize]byte
	Ciphertext []byte // ciphertext || tag
}

// validPurpose reports whether p is a legal purpose name: 1 to 255 bytes of
// lowercase ASCII letters, digits, '.', '_' and '-', beginning with a letter
// or digit. The restriction keeps purposes unambiguous in logs, configuration
// and the header.
func validPurpose(p string) bool {
	if len(p) == 0 || len(p) > MaxPurposeLen {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// Validate checks that the header is one this build can write: a known mode
// and algorithm, a legal purpose, and fields consistent with the mode.
func (h *Header) Validate() error {
	switch h.Mode {
	case ModeReference, ModeInline:
	default:
		return &ValueError{Kind: ErrUnknownMode, Value: uint8(h.Mode)}
	}
	if !h.Algorithm.Valid() {
		return &ValueError{Kind: ErrUnknownAlgorithm, Value: uint8(h.Algorithm)}
	}
	if !validPurpose(h.Purpose) {
		return ErrInvalidPurpose
	}
	switch h.Mode {
	case ModeReference:
		if h.DEKID.IsZero() {
			return fmt.Errorf("%w: reference mode needs a data key ID", ErrInvalidHeader)
		}
		if !h.KEKID.IsZero() || h.KEKVersion != 0 || len(h.Wrapped) != 0 {
			return fmt.Errorf("%w: reference mode carries inline fields", ErrInvalidHeader)
		}
	case ModeInline:
		if h.KEKID.IsZero() {
			return fmt.Errorf("%w: inline mode needs a key-encryption key ID", ErrInvalidHeader)
		}
		if len(h.Wrapped) == 0 || len(h.Wrapped) > MaxWrappedLen {
			return fmt.Errorf("%w: wrapped key length %d out of range", ErrInvalidHeader, len(h.Wrapped))
		}
		if !h.DEKID.IsZero() {
			return fmt.Errorf("%w: inline mode carries a data key ID", ErrInvalidHeader)
		}
	}
	return nil
}

// appendHeader appends the header bytes up to, and excluding, the nonce.
// The header must already be valid.
func (h *Header) appendHeader(b []byte) []byte {
	b = append(b, magic0, magic1, FormatVersion, byte(h.Mode), byte(h.Algorithm), 0)
	b = append(b, byte(len(h.Purpose))) //nolint:gosec // G115: Validate bounds the purpose to 255 bytes, and appendHeader requires a valid header
	b = append(b, h.Purpose...)
	switch h.Mode {
	case ModeReference:
		b = append(b, h.DEKID[:]...)
	case ModeInline:
		b = append(b, h.KEKID[:]...)
		b = binary.BigEndian.AppendUint32(b, h.KEKVersion)
		b = binary.BigEndian.AppendUint16(b, uint16(len(h.Wrapped))) //nolint:gosec // G115: Validate bounds the wrapped key to 65535 bytes, and appendHeader requires a valid header
		b = append(b, h.Wrapped...)
	}
	return b
}

// AAD returns the additional authenticated data for the header and the
// caller's context: the header bytes up to the nonce, followed by the
// context. The header is self-delimiting, so the concatenation is
// unambiguous.
func (h *Header) AAD(context []byte) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	b := h.appendHeader(make([]byte, 0, 64+len(h.Wrapped)+len(context)))
	return append(b, context...), nil
}

// MarshalBinary returns the binary form of the envelope.
func (e *Envelope) MarshalBinary() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if len(e.Ciphertext) < e.Algorithm.TagSize() {
		return nil, fmt.Errorf("%w: ciphertext shorter than the authentication tag", ErrInvalidHeader)
	}
	b := make([]byte, 0, 64+len(e.Wrapped)+NonceSize+len(e.Ciphertext))
	b = e.appendHeader(b)
	b = append(b, e.Nonce[:]...)
	return append(b, e.Ciphertext...), nil
}

// Parse decodes the binary form. It fails with a typed error for any input it
// does not fully understand: it never guesses and never reads past the input.
func Parse(b []byte) (*Envelope, error) {
	r := reader{b: b}
	m, ok := r.take(2)
	if !ok {
		return nil, ErrTruncated
	}
	if m[0] != magic0 || m[1] != magic1 {
		return nil, ErrBadMagic
	}
	fixed, ok := r.take(4)
	if !ok {
		return nil, ErrTruncated
	}
	format, mode, alg, flags := fixed[0], fixed[1], fixed[2], fixed[3]
	if format != FormatVersion {
		return nil, &ValueError{Kind: ErrUnsupportedFormat, Value: format}
	}
	if flags != 0 {
		return nil, &ValueError{Kind: ErrUnsupportedFlags, Value: flags}
	}
	e := &Envelope{}
	e.Mode = Mode(mode)
	e.Algorithm = algorithm.ID(alg)
	switch e.Mode {
	case ModeReference, ModeInline:
	default:
		return nil, &ValueError{Kind: ErrUnknownMode, Value: mode}
	}
	if !e.Algorithm.Valid() {
		return nil, &ValueError{Kind: ErrUnknownAlgorithm, Value: alg}
	}

	plen, ok := r.take(1)
	if !ok {
		return nil, ErrTruncated
	}
	purpose, ok := r.take(int(plen[0]))
	if !ok {
		return nil, ErrTruncated
	}
	e.Purpose = string(purpose)
	if !validPurpose(e.Purpose) {
		return nil, ErrInvalidPurpose
	}

	switch e.Mode {
	case ModeReference:
		id, ok := r.take(len(e.DEKID))
		if !ok {
			return nil, ErrTruncated
		}
		copy(e.DEKID[:], id)
	case ModeInline:
		id, ok := r.take(len(e.KEKID))
		if !ok {
			return nil, ErrTruncated
		}
		copy(e.KEKID[:], id)
		v, ok := r.take(4)
		if !ok {
			return nil, ErrTruncated
		}
		e.KEKVersion = binary.BigEndian.Uint32(v)
		l, ok := r.take(2)
		if !ok {
			return nil, ErrTruncated
		}
		wrapped, ok := r.take(int(binary.BigEndian.Uint16(l)))
		if !ok {
			return nil, ErrTruncated
		}
		e.Wrapped = append([]byte(nil), wrapped...)
	}
	if err := e.Header.Validate(); err != nil {
		return nil, err
	}

	nonce, ok := r.take(NonceSize)
	if !ok {
		return nil, ErrTruncated
	}
	copy(e.Nonce[:], nonce)

	rest := r.rest()
	if len(rest) < e.Algorithm.TagSize() {
		return nil, ErrTruncated
	}
	e.Ciphertext = append([]byte(nil), rest...)
	return e, nil
}

// MarshalText returns the text form: "kf1." followed by unpadded base64url
// of the binary form. It implements [encoding.TextMarshaler], so an Envelope
// is a string in JSON.
func (e *Envelope) MarshalText() ([]byte, error) {
	b, err := e.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(textPrefix)+base64.RawURLEncoding.EncodedLen(len(b)))
	out = append(out, textPrefix...)
	return base64.RawURLEncoding.AppendEncode(out, b), nil
}

// String returns the text form, or an empty string if the envelope is not
// valid.
func (e *Envelope) String() string {
	b, err := e.MarshalText()
	if err != nil {
		return ""
	}
	return string(b)
}

// UnmarshalText parses the text form. It implements
// [encoding.TextUnmarshaler].
func (e *Envelope) UnmarshalText(text []byte) error {
	p, err := ParseText(string(text))
	if err != nil {
		return err
	}
	*e = *p
	return nil
}

// ParseText decodes the text form. The prefix must be exactly "kf1."; a
// well-formed prefix for another version fails with ErrUnsupportedFormat.
// Padding, line breaks and non-canonical base64url are rejected.
func ParseText(s string) (*Envelope, error) {
	// The base64 decoder skips CR and LF; the text form has one spelling.
	if !strings.HasPrefix(s, "kf") || strings.ContainsAny(s, "\r\n") {
		return nil, ErrBadTextForm
	}
	dot := strings.IndexByte(s, '.')
	if dot < 3 {
		return nil, ErrBadTextForm
	}
	if version := s[2:dot]; version != "1" {
		n, err := strconv.ParseUint(version, 10, 8)
		if err != nil || (len(version) > 1 && version[0] == '0') {
			return nil, ErrBadTextForm
		}
		return nil, &ValueError{Kind: ErrUnsupportedFormat, Value: uint8(n)}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s[dot+1:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadTextForm, err)
	}
	return Parse(b)
}

// Seal encrypts plaintext under aead and returns the envelope for header h.
// The header and context are authenticated: opening needs the same header and
// the same context.
//
// aead must generate its own nonce, as the AEAD returned by
// [algorithm.New] does; anything that takes an explicit nonce is refused so
// that a nonce can never be chosen by a caller.
func Seal(aead cipher.AEAD, h Header, plaintext, context []byte) (*Envelope, error) {
	if aead.NonceSize() != 0 {
		return nil, ErrNotRandomNonce
	}
	aad, err := h.AAD(context)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nil, plaintext, aad) //nolint:gosec // G407: a nil nonce is the API of a random-nonce AEAD, which generates the nonce itself; NonceSize()==0 was checked above
	if len(sealed) < NonceSize+h.Algorithm.TagSize() {
		return nil, fmt.Errorf("%w: sealed output too short", ErrInvalidHeader)
	}
	e := &Envelope{Header: h}
	e.Wrapped = append([]byte(nil), h.Wrapped...)
	copy(e.Nonce[:], sealed[:NonceSize])
	e.Ciphertext = sealed[NonceSize:]
	return e, nil
}

// Open authenticates and decrypts the envelope under aead with the same
// context that was given to Seal. Any failure to authenticate, whether a
// wrong key, a changed header or context, or a modified ciphertext, is
// ErrAuthentication with no further detail.
func (e *Envelope) Open(aead cipher.AEAD, context []byte) ([]byte, error) {
	if aead.NonceSize() != 0 {
		return nil, ErrNotRandomNonce
	}
	aad, err := e.Header.AAD(context)
	if err != nil {
		return nil, err
	}
	if len(e.Ciphertext) < e.Algorithm.TagSize() {
		return nil, ErrTruncated
	}
	in := make([]byte, 0, NonceSize+len(e.Ciphertext))
	in = append(in, e.Nonce[:]...)
	in = append(in, e.Ciphertext...)
	pt, err := aead.Open(nil, nil, in, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return pt, nil
}

// reader is a bounds-checked cursor over a byte slice.
type reader struct {
	b   []byte
	off int
}

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || len(r.b)-r.off < n {
		return nil, false
	}
	s := r.b[r.off : r.off+n]
	r.off += n
	return s, true
}

func (r *reader) rest() []byte { return r.b[r.off:] }
