// Package unseal is the reading half of the repository's encryption, and the
// only one that takes an identity. Restore, check, find and the drill use it;
// the writer never imports it.
package unseal

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
	"github.com/safegrd/cli/pkg/repo/format"
	"golang.org/x/crypto/chacha20poly1305"
)

// Identities parses one or more Age identities, one per line.
func Identities(privateKey string) ([]age.Identity, error) {
	ids, err := age.ParseIdentities(strings.NewReader(privateKey))
	if err != nil {
		return nil, fmt.Errorf("the private key is not an age identity: %w", err)
	}
	return ids, nil
}

// UnwrapKey opens a pack's wrapped key.
func UnwrapKey(wrapped []byte, ids []age.Identity) ([32]byte, error) {
	var k [32]byte
	r, err := age.Decrypt(bytes.NewReader(wrapped), ids...)
	if err != nil {
		return k, fmt.Errorf("the pack key does not open with this identity: %w", err)
	}
	b, err := io.ReadAll(io.LimitReader(r, 64))
	if err != nil {
		return k, fmt.Errorf("the pack key: %w", err)
	}
	if len(b) != 32 {
		return k, fmt.Errorf("the pack key is %d bytes, not 32", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// Opener opens the blob records of one pack.
type Opener struct {
	aead interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
}

// NewOpener returns an opener for a pack key.
func NewOpener(k [32]byte) (*Opener, error) {
	a, err := chacha20poly1305.NewX(k[:])
	if err != nil {
		return nil, err
	}
	return &Opener{aead: a}, nil
}

func (o *Opener) open(record, ad []byte) ([]byte, error) {
	if len(record) < format.RecordOverhead {
		return nil, fmt.Errorf("a record of %d bytes is shorter than the nonce and tag", len(record))
	}
	return o.aead.Open(nil, record[:format.NonceLen], record[format.NonceLen:], ad)
}

var decoders = func() *zstd.Decoder {
	d, _ := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(format.MaxBlobRaw))
	return d
}()

// Blob opens one blob record, decompresses it and checks that the plaintext
// hashes to its id. Passing authentication is not enough: the id check is what
// proves these are the bytes the tree names.
func (o *Opener) Blob(record []byte, e format.BlobEntry) ([]byte, error) {
	id, err := format.ParseID(e.ID)
	if err != nil {
		return nil, err
	}
	payload, err := o.open(record, format.BlobAD(id, e.Type))
	if err != nil {
		return nil, fmt.Errorf("blob %s does not authenticate: it was altered, or it is not the blob its index names", e.ID)
	}
	plain := payload
	if e.Type&format.Compressed != 0 {
		plain, err = decoders.DecodeAll(payload, make([]byte, 0, e.RawLength))
		if err != nil {
			return nil, fmt.Errorf("blob %s does not decompress: %w", e.ID, err)
		}
	}
	if int64(len(plain)) != e.RawLength {
		return nil, fmt.Errorf("blob %s is %d bytes, its index says %d", e.ID, len(plain), e.RawLength)
	}
	sum := format.Hash(plain)
	if subtle.ConstantTimeCompare(sum[:], id[:]) != 1 {
		return nil, fmt.Errorf("blob %s hashes to %s", e.ID, hex.EncodeToString(sum[:]))
	}
	return plain, nil
}

// Trailer opens a pack's trailer record and parses it.
func (o *Opener) Trailer(packID string, record []byte) (format.Trailer, error) {
	ad, err := format.TrailerAD(packID)
	if err != nil {
		return format.Trailer{}, err
	}
	plain, err := o.open(record, ad)
	if err != nil {
		return format.Trailer{}, fmt.Errorf("pack %s: the trailer does not authenticate", packID)
	}
	return format.DecodeTrailer(plain)
}

// Object decrypts an Age-encrypted object and decodes its JSON into v.
func Object(b []byte, ids []age.Identity, v any) error {
	r, err := age.Decrypt(bytes.NewReader(b), ids...)
	if err != nil {
		return fmt.Errorf("does not open with this identity: %w", err)
	}
	z, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(format.MaxBlobRaw))
	if err != nil {
		return err
	}
	defer z.Close()
	js, err := io.ReadAll(io.LimitReader(z, format.MaxBlobRaw))
	if err != nil {
		return fmt.Errorf("does not decompress: %w", err)
	}
	return format.Unmarshal(js, v)
}
