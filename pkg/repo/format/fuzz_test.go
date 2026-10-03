package format

import (
	"strings"
	"testing"
)

// Decoders must never panic, and must refuse rather than guess.

func FuzzDecodeTree(f *testing.F) {
	f.Add([]byte(`{"entries":[]}`))
	f.Add([]byte(`{"entries":[{"name":"a","type":"symlink","mode":511,"mtime":"2026-01-01T00:00:00Z","target":"b"}]}`))
	f.Add([]byte(`{"entries":[{"name_b64":"/w==","type":"file","mode":420,"mtime":"2026-01-01T00:00:00Z","size":0,"sha256":"` + strings.Repeat("0", 64) + `","content":[]}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		tr, err := DecodeTree(b)
		if err != nil {
			return
		}
		if _, err := EncodeTree(tr); err != nil {
			t.Fatalf("decoded a tree the encoder refuses: %v", err)
		}
	})
}

func FuzzDecodeTrailer(f *testing.F) {
	f.Add([]byte(`{"blobs":[]}`))
	f.Add([]byte(`{"blobs":[{"id":"` + strings.Repeat("0", 64) + `","type":128,"offset":300,"length":100,"raw_length":500}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		tr, err := DecodeTrailer(b)
		if err != nil {
			return
		}
		for _, e := range tr.Blobs {
			if e.Validate() != nil {
				t.Fatal("decoded an invalid entry")
			}
		}
	})
}

func FuzzParsePack(f *testing.F) {
	h, _ := EncodePackHeader([]byte("wrapped-key"))
	f.Add(append(append(h, make([]byte, 60)...), EncodePackFooter(40)...))
	f.Add([]byte("SGPK"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, n, err := ParsePackHeader(b)
		if err != nil || len(b) < n+PackFooterLen {
			return
		}
		_, _ = ParsePackFooter(b[len(b)-PackFooterLen:], int64(len(b)), n)
	})
}

func FuzzDecodeIndex(f *testing.F) {
	f.Add([]byte(`{"version":1,"epoch_id":"e202610-3fa94c1d","run_id":"` + strings.Repeat("a", 32) + `","packs":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var x Index
		if Unmarshal(b, &x) != nil {
			return
		}
		_ = x.Validate()
	})
}
