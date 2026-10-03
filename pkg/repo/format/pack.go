package format

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// A pack is one object in the bucket holding many sealed blobs of one type:
//
//	offset  size   field
//	0       4      magic "SGPK"
//	4       1      version = 1
//	5       3      reserved, zero
//	8       4      W = length of the wrapped key
//	12      W      wrapped key: an Age file whose plaintext is the 32-byte pack key
//	12+W    …      blob records, back to back
//	…       …      trailer record
//	end-8   4      T = length of the trailer record
//	end-4   4      magic "SGPK"
//
// A blob record is a 24-byte random nonce followed by the XChaCha20-Poly1305
// ciphertext of the payload under the pack key, with the blob id (32 bytes)
// and the type byte (1 byte) as additional data. The record does not carry the
// type byte: the trailer and the index do, and a wrong one fails
// authentication.

// PackMagic opens and closes every pack.
var PackMagic = [4]byte{'S', 'G', 'P', 'K'}

const (
	// PackHeaderFixed is the length of the header before the wrapped key.
	PackHeaderFixed = 12
	// PackFooterLen is the length of the footer: T and the closing magic.
	PackFooterLen = 8
	// MaxWrappedKey bounds W, so a corrupt header cannot ask for gigabytes.
	MaxWrappedKey = 64 << 10
	// NonceLen is the XChaCha20-Poly1305 nonce length.
	NonceLen = 24
	// TagLen is the Poly1305 tag length.
	TagLen = 16
	// RecordOverhead is what sealing adds to a payload.
	RecordOverhead = NonceLen + TagLen
	// PackHeaderProbe is how much of a pack a reader fetches first: enough
	// for any wrapped key an Age X25519 recipient produces.
	PackHeaderProbe = 4096
)

// Blob types, in bits 0–6 of the type byte. Bit 7 marks a zstd payload.
const (
	BlobData    byte = 0
	BlobTree    byte = 1
	BlobTrailer byte = 127
	// Compressed is bit 7 of the type byte.
	Compressed byte = 0x80
)

// ValidTypeByte reports whether b is a type byte a blob record may carry:
// data or tree, raw or compressed. The trailer's type is never in an index.
func ValidTypeByte(b byte) bool {
	t := b &^ Compressed
	return t == BlobData || t == BlobTree
}

// BlobKind is a type byte without the compression bit.
func BlobKind(b byte) byte { return b &^ Compressed }

// BlobAD is the additional data a blob record is sealed under.
func BlobAD(id ID, typeByte byte) []byte {
	ad := make([]byte, 0, 33)
	ad = append(ad, id[:]...)
	return append(ad, typeByte)
}

// TrailerAD is the additional data of a pack's trailer record:
// "SGPK-trailer" followed by the 16 bytes of the pack id.
func TrailerAD(packID string) ([]byte, error) {
	raw, err := PackIDBytes(packID)
	if err != nil {
		return nil, err
	}
	return append([]byte("SGPK-trailer"), raw...), nil
}

// EncodePackHeader returns the bytes before the first blob record.
func EncodePackHeader(wrappedKey []byte) ([]byte, error) {
	if len(wrappedKey) == 0 || len(wrappedKey) > MaxWrappedKey {
		return nil, fmt.Errorf("pack header: a wrapped key of %d bytes is out of range", len(wrappedKey))
	}
	h := make([]byte, PackHeaderFixed, PackHeaderFixed+len(wrappedKey))
	copy(h[0:4], PackMagic[:])
	h[4] = Version
	binary.LittleEndian.PutUint32(h[8:12], uint32(len(wrappedKey)))
	return append(h, wrappedKey...), nil
}

// PackHeaderLen reads W from the first 12 bytes of a pack and returns the
// whole header's length, 12+W.
func PackHeaderLen(prefix []byte) (int, error) {
	if len(prefix) < PackHeaderFixed {
		return 0, fmt.Errorf("pack header: %d bytes is shorter than the 12-byte fixed header", len(prefix))
	}
	if !bytes.Equal(prefix[0:4], PackMagic[:]) {
		return 0, fmt.Errorf("pack header: the magic is %q, not SGPK", prefix[0:4])
	}
	if prefix[4] != Version {
		return 0, fmt.Errorf("pack header: format version %d is not one this reader knows (it reads version %d)", prefix[4], Version)
	}
	if prefix[5] != 0 || prefix[6] != 0 || prefix[7] != 0 {
		return 0, fmt.Errorf("pack header: the reserved bytes are not zero")
	}
	w := binary.LittleEndian.Uint32(prefix[8:12])
	if w == 0 || w > MaxWrappedKey {
		return 0, fmt.Errorf("pack header: a wrapped key of %d bytes is out of range", w)
	}
	return PackHeaderFixed + int(w), nil
}

// ParsePackHeader returns the wrapped key from a pack's first bytes, which
// must hold the whole header.
func ParsePackHeader(prefix []byte) (wrappedKey []byte, headerLen int, err error) {
	n, err := PackHeaderLen(prefix)
	if err != nil {
		return nil, 0, err
	}
	if len(prefix) < n {
		return nil, n, fmt.Errorf("pack header: need %d bytes, have %d", n, len(prefix))
	}
	return prefix[PackHeaderFixed:n], n, nil
}

// EncodePackFooter returns the last 8 bytes of a pack whose trailer record is
// trailerLen bytes long.
func EncodePackFooter(trailerLen int) []byte {
	f := make([]byte, PackFooterLen)
	binary.LittleEndian.PutUint32(f[0:4], uint32(trailerLen))
	copy(f[4:8], PackMagic[:])
	return f
}

// ParsePackFooter reads T from a pack's last 8 bytes and checks it fits in a
// pack of packLen bytes with a header of headerLen.
func ParsePackFooter(footer []byte, packLen int64, headerLen int) (trailerLen int, err error) {
	if len(footer) != PackFooterLen {
		return 0, fmt.Errorf("pack footer: %d bytes, not 8", len(footer))
	}
	if !bytes.Equal(footer[4:8], PackMagic[:]) {
		return 0, fmt.Errorf("pack footer: the closing magic is %q, not SGPK", footer[4:8])
	}
	t := int64(binary.LittleEndian.Uint32(footer[0:4]))
	if t < RecordOverhead || int64(headerLen)+t+PackFooterLen > packLen {
		return 0, fmt.Errorf("pack footer: a trailer of %d bytes does not fit a %d-byte pack", t, packLen)
	}
	return int(t), nil
}

// BlobEntry locates one blob record inside a pack. Offset and Length cover
// the whole record, nonce included, from the start of the pack.
type BlobEntry struct {
	ID        string `json:"id"`
	Type      byte   `json:"type"`
	Offset    int64  `json:"offset"`
	Length    int64  `json:"length"`
	RawLength int64  `json:"raw_length"`
}

// Validate checks one entry on its own. Whether it fits its pack is checked
// against the pack's real length, by ValidateIn.
func (e BlobEntry) Validate() error {
	if _, err := ParseID(e.ID); err != nil {
		return err
	}
	if !ValidTypeByte(e.Type) {
		return fmt.Errorf("blob %s: type byte %d is not data or tree", short(e.ID), e.Type)
	}
	if e.Offset < PackHeaderFixed+1 {
		return fmt.Errorf("blob %s: offset %d is inside the pack header", short(e.ID), e.Offset)
	}
	if e.Length < RecordOverhead {
		return fmt.Errorf("blob %s: a record of %d bytes is shorter than the nonce and tag", short(e.ID), e.Length)
	}
	if e.RawLength < 0 || e.RawLength > MaxBlobRaw {
		return fmt.Errorf("blob %s: raw length %d is out of range", short(e.ID), e.RawLength)
	}
	if e.Type&Compressed == 0 && e.Length-RecordOverhead != e.RawLength {
		return fmt.Errorf("blob %s: an uncompressed record of %d bytes cannot hold %d raw bytes", short(e.ID), e.Length, e.RawLength)
	}
	return nil
}

// ValidateIn checks the entry lies between the header and the trailer of a
// pack of packLen bytes.
func (e BlobEntry) ValidateIn(headerLen int, packLen int64, trailerLen int) error {
	end := packLen - PackFooterLen - int64(trailerLen)
	if e.Offset < int64(headerLen) || e.Offset+e.Length > end || e.Offset+e.Length < e.Offset {
		return fmt.Errorf("blob %s: bytes %d+%d fall outside the pack's records (%d to %d)", short(e.ID), e.Offset, e.Length, headerLen, end)
	}
	return nil
}

// MaxBlobRaw bounds a blob's plaintext. Data blobs are at most one chunk
// (8 MiB); a tree blob for a directory of a million entries is about 200 MiB.
const MaxBlobRaw = 1 << 30

// Trailer lists every blob record in a pack, so a pack can be read without
// its index.
type Trailer struct {
	Blobs []BlobEntry `json:"blobs"`
}

// EncodeTrailer returns the trailer's plaintext JSON.
func EncodeTrailer(t Trailer) ([]byte, error) {
	if t.Blobs == nil {
		t.Blobs = []BlobEntry{}
	}
	return Marshal(t)
}

// DecodeTrailer parses and validates a trailer's plaintext.
func DecodeTrailer(b []byte) (Trailer, error) {
	var t Trailer
	if err := Unmarshal(b, &t); err != nil {
		return t, fmt.Errorf("pack trailer: %w", err)
	}
	if t.Blobs == nil {
		return t, fmt.Errorf("pack trailer: no blobs list")
	}
	var prevEnd int64
	for i, e := range t.Blobs {
		if err := e.Validate(); err != nil {
			return t, fmt.Errorf("pack trailer: %w", err)
		}
		if e.Offset < prevEnd {
			return t, fmt.Errorf("pack trailer: blob %d overlaps the one before it", i)
		}
		prevEnd = e.Offset + e.Length
	}
	return t, nil
}
