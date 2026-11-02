package unseal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/seal"
)

func keyPair(t *testing.T) (age.Recipient, []age.Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient(), []age.Identity{id}
}

// refused reports whether err is a refusal that says words: an error for
// another reason (a bad fixture, a panic turned into an error) is not the one
// the test is about.
func refused(err error, words string) bool {
	return err != nil && strings.Contains(err.Error(), words)
}

func newKey(t *testing.T) seal.Key {
	k, err := seal.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The record bytes for fixed key, nonce and payload are frozen.
func TestBlobRecordBytesAreFrozen(t *testing.T) {
	var k seal.Key
	for i := range k {
		k[i] = byte(i)
	}
	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	s, err := seal.NewSealerWithNonces(k, bytes.NewReader(nonce))
	if err != nil {
		t.Fatal(err)
	}
	id := format.Hash([]byte("hello"))
	rec, err := s.Record(id, format.BlobData, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "404142434445464748494a4b4c4d4e4f5051525354555657bc5c691cbf978b3c49a6667b763424484bdfd042d9"
	if hex.EncodeToString(rec) != want {
		t.Fatalf("record %x\nwant   %s", rec, want)
	}
	o, err := NewOpener(k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := o.Blob(rec, format.BlobEntry{ID: id.String(), Type: 0, RawLength: 5})
	if err != nil || string(got) != "hello" {
		t.Fatalf("open: %q %v", got, err)
	}
}

func sealed(t *testing.T, k seal.Key, plain []byte, kind byte) ([]byte, format.BlobEntry) {
	t.Helper()
	s, err := seal.NewSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	payload, tb := seal.Payload(kind, plain)
	id := format.Hash(plain)
	rec, err := s.Record(id, tb, payload)
	if err != nil {
		t.Fatal(err)
	}
	return rec, format.BlobEntry{ID: id.String(), Type: tb, Offset: 100, Length: int64(len(rec)), RawLength: int64(len(plain))}
}

func TestEveryTamperedFieldIsRefused(t *testing.T) {
	k := newKey(t)
	plain := []byte(strings.Repeat("compressible ", 200))
	rec, e := sealed(t, k, plain, format.BlobData)
	if e.Type&format.Compressed == 0 {
		t.Fatal("compressible plaintext was stored raw")
	}
	o, _ := NewOpener(k)
	if got, err := o.Blob(rec, e); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v", err)
	}
	flip := func(i int) []byte {
		b := append([]byte{}, rec...)
		b[i] ^= 1
		return b
	}
	if _, err := o.Blob(flip(0), e); !refused(err, "does not authenticate") {
		t.Errorf("a changed nonce opened: %v", err)
	}
	if _, err := o.Blob(flip(len(rec)/2), e); !refused(err, "does not authenticate") {
		t.Errorf("a changed ciphertext opened: %v", err)
	}
	if _, err := o.Blob(flip(len(rec)-1), e); !refused(err, "does not authenticate") {
		t.Errorf("a changed tag opened: %v", err)
	}
	wrongType := e
	wrongType.Type = format.BlobTree | format.Compressed
	if _, err := o.Blob(rec, wrongType); !refused(err, "does not authenticate") {
		t.Errorf("the record opened under another type byte: %v", err)
	}
	rawFlag := e
	rawFlag.Type = format.BlobData
	if _, err := o.Blob(rec, rawFlag); !refused(err, "does not authenticate") {
		t.Errorf("the record opened with its compression bit cleared: %v", err)
	}
	other := e
	other.ID = format.Hash([]byte("other")).String()
	if _, err := o.Blob(rec, other); !refused(err, "does not authenticate") {
		t.Errorf("the record opened under another id: %v", err)
	}
	// A blob moved into another pack is under another key.
	o2, _ := NewOpener(newKey(t))
	if _, err := o2.Blob(rec, e); !refused(err, "does not authenticate") {
		t.Errorf("a record opened under another pack's key: %v", err)
	}
}

// Authentication alone is not enough: a writer that sealed bytes under the
// wrong id produces a record that authenticates and must still be refused.
func TestTheIDIsCheckedAfterAuthentication(t *testing.T) {
	k := newKey(t)
	s, _ := seal.NewSealer(k)
	claimed := format.Hash([]byte("what the tree names"))
	rec, err := s.Record(claimed, format.BlobData, []byte("other bytes"))
	if err != nil {
		t.Fatal(err)
	}
	o, _ := NewOpener(k)
	_, err = o.Blob(rec, format.BlobEntry{ID: claimed.String(), Type: 0, Length: int64(len(rec)), RawLength: 11})
	if err == nil || !strings.Contains(err.Error(), "hashes to") {
		t.Fatalf("a record whose plaintext does not hash to its id was accepted: %v", err)
	}
}

func TestWrappedKeyOpensOnlyWithTheIdentity(t *testing.T) {
	r, ids := keyPair(t)
	_, otherIDs := keyPair(t)
	k := newKey(t)
	w, err := seal.WrapKey(k, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapKey(w, ids)
	if err != nil || got != [32]byte(k) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := UnwrapKey(w, otherIDs); !refused(err, "does not open with this identity") {
		t.Fatalf("another identity opened the pack key: %v", err)
	}
	w[len(w)-1] ^= 1
	if _, err := UnwrapKey(w, ids); !refused(err, "failed to decrypt and authenticate") {
		t.Fatalf("a changed wrapped key opened: %v", err)
	}
}

func TestTrailerIsBoundToItsPack(t *testing.T) {
	k := newKey(t)
	s, _ := seal.NewSealer(k)
	pack := format.NewRandomID()
	plain, _ := format.EncodeTrailer(format.Trailer{})
	rec, err := s.Trailer(pack, plain)
	if err != nil {
		t.Fatal(err)
	}
	o, _ := NewOpener(k)
	if _, err := o.Trailer(pack, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Trailer(format.NewRandomID(), rec); !refused(err, "the trailer does not authenticate") {
		t.Fatalf("a trailer opened as another pack's: %v", err)
	}
}

func TestObjectsRoundTrip(t *testing.T) {
	r, ids := keyPair(t)
	in := format.Catalog{Version: 1, EpochID: "e202610-3fa94c1d", RunID: format.NewRandomID(), Complete: true,
		Entries: []format.CatalogEntry{{Path: "etc/hosts", Event: format.EventPresent, Type: "f"}}}
	b, err := seal.Object(in, r)
	if err != nil {
		t.Fatal(err)
	}
	var out format.Catalog
	if err := Object(b, ids, &out); err != nil {
		t.Fatal(err)
	}
	if out.Entries[0].Path != "etc/hosts" {
		t.Fatalf("%+v", out)
	}
	_, other := keyPair(t)
	if err := Object(b, other, &out); !refused(err, "does not open with this identity") {
		t.Fatalf("another identity opened the object: %v", err)
	}
}

func TestIncompressibleBlobsAreStoredRaw(t *testing.T) {
	plain := make([]byte, 4096)
	_, _ = rand.Read(plain)
	payload, tb := seal.Payload(format.BlobData, plain)
	if tb != format.BlobData || !bytes.Equal(payload, plain) {
		t.Fatal("random bytes were stored compressed")
	}
}
