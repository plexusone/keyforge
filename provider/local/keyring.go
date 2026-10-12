package local

import (
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
)

// The keyring file is a fixed 32-byte header followed by the sealed payload.
//
//	magic "KFKR" | format u8 | reserved u8 | algorithm u8 | reserved u8
//	root key ID  : 16 bytes
//	generation   : u64, big-endian
//	sealed       : nonce (12) || ciphertext || tag
//
// The header is the additional authenticated data, so the root key ID and the
// generation cannot be changed without failing authentication, and both can be
// read without decrypting: a wrong root key is reported as one, and a backup's
// generation can be compared with the current one without the key.
//
// The format is frozen once a keyring exists. A change needs a new format
// version.
const (
	fileMagic        = "KFKR"
	fileFormat       = 1
	headerSize       = 32
	payloadFormat    = 1
	keyringAlgorithm = algorithm.AES256GCM
)

// Typed errors for the keyring file.
var (
	// ErrKeyringNotFound is returned when the keyring file does not exist.
	ErrKeyringNotFound = errors.New("local: keyring not found")
	// ErrKeyringExists is returned when creating a keyring over an existing one.
	ErrKeyringExists = errors.New("local: keyring already exists")
	// ErrWrongRootKey is returned when the root key is not the one the keyring
	// was written under. It is reported before decryption is attempted, so a
	// wrong key is not mistaken for a corrupted file.
	ErrWrongRootKey = errors.New("local: wrong root key for this keyring")
	// ErrCorruptKeyring is returned for a file that is not a keyring this
	// build understands, or that fails authentication: truncated, modified, or
	// not written by keyforge.
	ErrCorruptKeyring = errors.New("local: corrupt keyring")
	// ErrInsecurePermissions is returned for a keyring that other users can
	// read.
	ErrInsecurePermissions = errors.New("local: keyring is readable by others")
)

// header is the parsed fixed part of the file.
type header struct {
	rootKeyID  [rootKeyIDSize]byte
	generation uint64
}

func (h header) encode() []byte {
	b := make([]byte, 0, headerSize)
	b = append(b, fileMagic...)
	b = append(b, fileFormat, 0, byte(keyringAlgorithm), 0)
	b = append(b, h.rootKeyID[:]...)
	return binary.BigEndian.AppendUint64(b, h.generation)
}

// parseHeader reads the fixed header. It fails with ErrCorruptKeyring for
// anything it does not fully understand.
func parseHeader(b []byte) (header, error) {
	if len(b) < headerSize {
		return header{}, fmt.Errorf("%w: %d bytes is shorter than the header", ErrCorruptKeyring, len(b))
	}
	if string(b[:4]) != fileMagic {
		return header{}, fmt.Errorf("%w: not a keyring", ErrCorruptKeyring)
	}
	if b[4] != fileFormat {
		return header{}, fmt.Errorf("%w: unsupported format %d", ErrCorruptKeyring, b[4])
	}
	if b[5] != 0 || b[7] != 0 {
		return header{}, fmt.Errorf("%w: reserved bytes are set", ErrCorruptKeyring)
	}
	if algorithm.ID(b[6]) != keyringAlgorithm {
		return header{}, fmt.Errorf("%w: unsupported algorithm %d", ErrCorruptKeyring, b[6])
	}
	var h header
	copy(h.rootKeyID[:], b[8:24])
	h.generation = binary.BigEndian.Uint64(b[24:32])
	return h, nil
}

// peek returns the header of a keyring file without decrypting it.
func peek(file []byte) (header, error) { return parseHeader(file) }

// seal encodes a payload under the derived key with the header as AAD.
func seal(aead cipher.AEAD, h header, payload []byte) []byte {
	hb := h.encode()
	sealed := aead.Seal(nil, nil, payload, hb) //nolint:gosec // G407: a nil nonce is the API of the registry's random-nonce AEAD
	return append(hb, sealed...)
}

// open authenticates and decrypts a keyring file. The caller has already
// compared the root key ID, so a failure here is corruption or tampering.
func open(aead cipher.AEAD, file []byte) (header, []byte, error) {
	h, err := parseHeader(file)
	if err != nil {
		return header{}, nil, err
	}
	pt, err := aead.Open(nil, nil, file[headerSize:], file[:headerSize])
	if err != nil {
		return header{}, nil, fmt.Errorf("%w: authentication failed", ErrCorruptKeyring)
	}
	return h, pt, nil
}

// The payload is JSON inside the authenticated envelope. Its schema is part of
// the stored format.
type payloadDTO struct {
	Format int      `json:"format"`
	Keys   []keyDTO `json:"keys"`
}

type keyDTO struct {
	ID        string       `json:"id"`
	Purpose   string       `json:"purpose"`
	Algorithm uint8        `json:"algorithm"`
	Latest    uint32       `json:"latest"`
	Versions  []versionDTO `json:"versions"`
}

type versionDTO struct {
	Version   uint32 `json:"version"`
	Material  []byte `json:"material,omitempty"`
	Destroyed bool   `json:"destroyed,omitempty"`
}

// state is the in-memory keyring.
type state struct {
	keys map[envelope.ID]*keyState
}

type keyState struct {
	id       envelope.ID
	purpose  string
	alg      algorithm.ID
	latest   uint32
	versions map[uint32]*versionState
}

type versionState struct {
	material  []byte
	destroyed bool
	aead      cipher.AEAD // built lazily from material
}

func newState() *state { return &state{keys: map[envelope.ID]*keyState{}} }

// wipe zeroes the key material the state holds.
func (s *state) wipe() {
	for _, k := range s.keys {
		for _, v := range k.versions {
			clear(v.material)
			v.aead = nil
		}
	}
}

// marshal encodes the state. The result holds key material; the caller zeroes it.
func (s *state) marshal() ([]byte, error) {
	dto := payloadDTO{Format: payloadFormat}
	ids := make([]envelope.ID, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b envelope.ID) int { return slices.Compare(a[:], b[:]) })
	for _, id := range ids {
		k := s.keys[id]
		kd := keyDTO{ID: hex.EncodeToString(id[:]), Purpose: k.purpose, Algorithm: uint8(k.alg), Latest: k.latest}
		nums := make([]uint32, 0, len(k.versions))
		for n := range k.versions {
			nums = append(nums, n)
		}
		slices.Sort(nums)
		for _, n := range nums {
			v := k.versions[n]
			kd.Versions = append(kd.Versions, versionDTO{Version: n, Material: v.material, Destroyed: v.destroyed})
		}
		dto.Keys = append(dto.Keys, kd)
	}
	return json.Marshal(dto)
}

// unmarshalState decodes and validates a payload.
func unmarshalState(b []byte) (*state, error) {
	var dto payloadDTO
	if err := json.Unmarshal(b, &dto); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrCorruptKeyring, err)
	}
	if dto.Format != payloadFormat {
		return nil, fmt.Errorf("%w: unsupported payload format %d", ErrCorruptKeyring, dto.Format)
	}
	s := newState()
	for _, kd := range dto.Keys {
		raw, err := hex.DecodeString(kd.ID)
		if err != nil || len(raw) != len(envelope.ID{}) {
			return nil, fmt.Errorf("%w: malformed key identifier", ErrCorruptKeyring)
		}
		var id envelope.ID
		copy(id[:], raw)
		alg := algorithm.ID(kd.Algorithm)
		if !alg.Valid() || id.IsZero() || !envelope.ValidPurpose(kd.Purpose) {
			return nil, fmt.Errorf("%w: malformed key record", ErrCorruptKeyring)
		}
		if _, dup := s.keys[id]; dup {
			return nil, fmt.Errorf("%w: duplicate key", ErrCorruptKeyring)
		}
		k := &keyState{id: id, purpose: kd.Purpose, alg: alg, latest: kd.Latest, versions: map[uint32]*versionState{}}
		for _, vd := range kd.Versions {
			if vd.Version == 0 || vd.Version > kd.Latest {
				return nil, fmt.Errorf("%w: malformed version", ErrCorruptKeyring)
			}
			if _, dup := k.versions[vd.Version]; dup {
				return nil, fmt.Errorf("%w: duplicate version", ErrCorruptKeyring)
			}
			if vd.Destroyed != (len(vd.Material) == 0) || (!vd.Destroyed && len(vd.Material) != alg.KeySize()) {
				return nil, fmt.Errorf("%w: malformed key material", ErrCorruptKeyring)
			}
			k.versions[vd.Version] = &versionState{material: slices.Clone(vd.Material), destroyed: vd.Destroyed}
		}
		s.keys[id] = k
	}
	return s, nil
}
