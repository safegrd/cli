// Package seal is the writing half of the repository's encryption. It holds
// only what a host that backs up needs: a recipient, never an identity. The
// reading half is package unseal, which the writer does not import, so a host
// that writes a repository has no code path that could read it back.
package seal

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
	"github.com/safegrd/cli/pkg/repo/format"
	"golang.org/x/crypto/chacha20poly1305"
)

// KeyLen is a pack key's length.
const KeyLen = chacha20poly1305.KeySize

// Key is one pack's key. Each pack has its own, and the writer forgets it once
// the pack is written.
type Key [KeyLen]byte

// NewKey returns a random pack key.
func NewKey() (Key, error) {
	var k Key
	_, err := rand.Read(k[:])
	return k, err
}

// Recipient parses an Age X25519 recipient (age1…).
func Recipient(publicKey string) (age.Recipient, error) {
	r, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("the recipient %q is not an age X25519 public key: %w", publicKey, err)
	}
	return r, nil
}

// WrapKey seals a pack key to the recipient: an Age file whose plaintext is
// the 32 key bytes.
func WrapKey(k Key, r age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(k[:]); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Sealer seals blob records under one pack key.
type Sealer struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
	}
	rand io.Reader
}

// NewSealer returns a sealer for k. Nonces come from crypto/rand.
func NewSealer(k Key) (*Sealer, error) { return newSealer(k, rand.Reader) }

// NewSealerWithNonces is NewSealer with the nonce source given, for tests
// that need fixed bytes.
func NewSealerWithNonces(k Key, nonces io.Reader) (*Sealer, error) { return newSealer(k, nonces) }

func newSealer(k Key, nonces io.Reader) (*Sealer, error) {
	a, err := chacha20poly1305.NewX(k[:])
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: a, rand: nonces}, nil
}

// Record seals payload as one blob record: nonce, then ciphertext, with the
// blob id and type byte bound in as additional data.
func (s *Sealer) Record(id format.ID, typeByte byte, payload []byte) ([]byte, error) {
	return s.seal(payload, format.BlobAD(id, typeByte))
}

// Trailer seals a pack's trailer plaintext.
func (s *Sealer) Trailer(packID string, plaintext []byte) ([]byte, error) {
	ad, err := format.TrailerAD(packID)
	if err != nil {
		return nil, err
	}
	return s.seal(plaintext, ad)
}

func (s *Sealer) seal(plaintext, ad []byte) ([]byte, error) {
	out := make([]byte, format.NonceLen, format.NonceLen+len(plaintext)+format.TagLen)
	if _, err := io.ReadFull(s.rand, out); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return s.aead.Seal(out, out[:format.NonceLen], plaintext, ad), nil
}

var encoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))

// Payload returns the bytes a blob record seals and its type byte: the
// plaintext compressed with zstd when that is smaller, otherwise as it is.
func Payload(kind byte, plaintext []byte) ([]byte, byte) {
	c := encoder.EncodeAll(plaintext, make([]byte, 0, len(plaintext)/2))
	if len(c) < len(plaintext) {
		return c, kind | format.Compressed
	}
	return plaintext, kind
}

// Object encrypts v to the recipient as an Age file whose plaintext is the
// zstd-compressed JSON of v. Index, catalog and snapshot objects are written
// this way.
func Object(v any, r age.Recipient) ([]byte, error) {
	js, err := format.Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	z, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, err
	}
	if _, err := z.Write(js); err != nil {
		return nil, err
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
