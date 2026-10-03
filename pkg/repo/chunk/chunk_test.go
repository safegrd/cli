package chunk

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math/rand"
	"testing"

	"github.com/safegrd/cli/pkg/repo/format"
)

// A fixed irreducible polynomial, so the cuts are reproducible.
const testPol = Pol(0x3DA3358B4DC173)

func cut(t *testing.T, c *Chunker, data []byte) [][]byte {
	t.Helper()
	c.Reset(bytes.NewReader(data))
	var out [][]byte
	for {
		b, err := c.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, append([]byte{}, b...))
	}
}

func randomBytes(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func TestBoundarySizes(t *testing.T) {
	p := format.DefaultChunker
	c, err := New(testPol, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, p.Min - 1, p.Min, p.Avg, p.Max, p.Max + 1, 3*p.Max + 17} {
		data := randomBytes(int64(n), n)
		chunks := cut(t, c, data)
		if n == 0 && len(chunks) != 0 {
			t.Fatalf("an empty file gave %d chunks", len(chunks))
		}
		joined := bytes.Join(chunks, nil)
		if !bytes.Equal(joined, data) {
			t.Fatalf("%d bytes: chunks do not reassemble the input", n)
		}
		for i, ch := range chunks {
			if len(ch) > p.Max {
				t.Fatalf("%d bytes: chunk %d is %d bytes, over the maximum", n, i, len(ch))
			}
			if i < len(chunks)-1 && len(ch) < p.Min {
				t.Fatalf("%d bytes: chunk %d is %d bytes, under the minimum", n, i, len(ch))
			}
		}
		again := cut(t, c, data)
		if len(again) != len(chunks) {
			t.Fatalf("%d bytes: the same input cut differently", n)
		}
	}
}

func TestAnInsertReAlignsWithinTwoChunks(t *testing.T) {
	c, err := New(testPol, format.DefaultChunker)
	if err != nil {
		t.Fatal(err)
	}
	data := randomBytes(7, 24<<20)
	before := map[[32]byte]bool{}
	for _, ch := range cut(t, c, data) {
		before[sha256.Sum256(ch)] = true
	}
	edited := append([]byte("inserted at the very start"), data...)
	after := cut(t, c, edited)
	var fresh int
	for _, ch := range after {
		if !before[sha256.Sum256(ch)] {
			fresh++
		}
	}
	if fresh > 2 {
		t.Fatalf("an insert at offset 0 changed %d of %d chunks", fresh, len(after))
	}
}

func TestRefusesOtherParameters(t *testing.T) {
	if _, err := New(testPol, format.ChunkerParams{Algorithm: "fastcdc", Min: 1, Avg: 2, Max: 4}); err == nil {
		t.Fatal("another algorithm accepted")
	}
	p := format.DefaultChunker
	p.Avg = 1000
	if _, err := New(testPol, p); err == nil {
		t.Fatal("an average that is not a power of two accepted")
	}
	if _, err := New(Pol(4), format.DefaultChunker); err == nil {
		t.Fatal("a reducible polynomial accepted")
	}
	pol, err := RandomPolynomial()
	if err != nil || !pol.Irreducible() {
		t.Fatalf("random polynomial %v %v", pol, err)
	}
}
