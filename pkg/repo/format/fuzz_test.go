package format

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// Decoders must never panic, and must refuse rather than guess: whatever one
// accepts is a value its encoder writes back and the decoder reads again as
// the same value. Under plain go test these run on their seeds only; run one
// with -fuzz to search further.

func FuzzDecodeTree(f *testing.F) {
	f.Add([]byte(`{"entries":[]}`))
	f.Add([]byte(`{"entries":[{"name":"a","type":"symlink","mode":511,"mtime":"2026-01-01T00:00:00Z","target":"b"}]}`))
	f.Add([]byte(`{"entries":[{"name_b64":"/w==","type":"file","mode":420,"mtime":"2026-01-01T00:00:00Z","size":0,"sha256":"` + strings.Repeat("0", 64) + `","content":[]}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		tr, err := DecodeTree(b)
		if err != nil {
			return // a refusal is a correct answer to arbitrary bytes
		}
		enc, err := EncodeTree(tr)
		if err != nil {
			t.Fatalf("decoded a tree the encoder refuses: %v", err)
		}
		back, err := DecodeTree(enc)
		if err != nil {
			t.Fatalf("the encoder wrote a tree the decoder refuses: %v\n%s", err, enc)
		}
		again, err := EncodeTree(back)
		if err != nil || !bytes.Equal(again, enc) {
			t.Fatalf("a tree does not survive a second round trip: %v\n%s\n%s", err, enc, again)
		}
	})
}

func FuzzDecodeTrailer(f *testing.F) {
	f.Add([]byte(`{"blobs":[]}`))
	f.Add([]byte(`{"blobs":[{"id":"` + strings.Repeat("0", 64) + `","type":128,"offset":300,"length":100,"raw_length":500}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		tr, err := DecodeTrailer(b)
		if err != nil {
			return // a refusal is a correct answer to arbitrary bytes
		}
		enc, err := EncodeTrailer(tr)
		if err != nil {
			t.Fatalf("decoded a trailer the encoder refuses: %v", err)
		}
		back, err := DecodeTrailer(enc)
		if err != nil || !reflect.DeepEqual(back, tr) {
			t.Fatalf("a trailer does not survive a round trip: %v\n%+v\n%+v", err, tr, back)
		}
	})
}

func FuzzParsePack(f *testing.F) {
	h, _ := EncodePackHeader([]byte("wrapped-key"))
	f.Add(append(append(h, make([]byte, 60)...), EncodePackFooter(40)...))
	f.Add([]byte("SGPK"))
	f.Fuzz(func(t *testing.T, b []byte) {
		wrapped, n, err := ParsePackHeader(b)
		if err != nil {
			return // a refusal is a correct answer to arbitrary bytes
		}
		if n > len(b) || !bytes.Equal(b[n-len(wrapped):n], wrapped) {
			t.Fatalf("the header claims %d bytes of %d, its wrapped key not among them", n, len(b))
		}
		if h, err := EncodePackHeader(wrapped); err != nil || !bytes.Equal(h, b[:n]) {
			t.Fatalf("a parsed header does not encode back to its bytes: %v", err)
		}
		if len(b) < n+PackFooterLen {
			return
		}
		tl, err := ParsePackFooter(b[len(b)-PackFooterLen:], int64(len(b)), n)
		if err == nil && (tl < 0 || n+tl+PackFooterLen > len(b)) {
			t.Fatalf("a footer accepted a trailer of %d bytes in a %d-byte pack with a %d-byte header", tl, len(b), n)
		}
	})
}

func FuzzDecodeIndex(f *testing.F) {
	f.Add([]byte(`{"version":1,"epoch_id":"e202610-3fa94c1d","run_id":"` + strings.Repeat("a", 32) + `","packs":[]}`))
	withPack, err := Marshal(Index{Version: 1, EpochID: "e202610-3fa94c1d", RunID: strings.Repeat("a", 32), Packs: []IndexPack{
		{PackID: strings.Repeat("b", 32), Bytes: 1000, Blobs: []BlobEntry{{ID: Hash([]byte("x")).String(), Type: 1, Offset: 300, Length: 100, RawLength: 60}}},
	}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(withPack)
	f.Fuzz(func(t *testing.T, b []byte) {
		var x Index
		if Unmarshal(b, &x) != nil || x.Validate() != nil {
			return // a refusal is a correct answer to arbitrary bytes
		}
		enc, err := Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		var back Index
		if err := Unmarshal(enc, &back); err != nil || back.Validate() != nil || !reflect.DeepEqual(back, x) {
			t.Fatalf("a valid index does not survive a round trip: %v\n%s", err, enc)
		}
	})
}
