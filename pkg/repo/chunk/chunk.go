// Package chunk cuts file contents into content-defined chunks. A one-byte
// edit changes one chunk, and an insert re-aligns within a chunk or two
// instead of shifting every block after it. Each epoch has its own random
// polynomial, kept only by the writer.
package chunk

import (
	"fmt"
	"io"
	"math/bits"

	"github.com/restic/chunker"
	"github.com/safegrd/cli/pkg/repo/format"
)

// Pol is a chunker polynomial.
type Pol = chunker.Pol

// RandomPolynomial returns a fresh random irreducible polynomial.
func RandomPolynomial() (Pol, error) { return chunker.RandomPolynomial() }

// Chunker cuts one stream at a time.
type Chunker struct {
	c   *chunker.Chunker
	pol Pol
	p   format.ChunkerParams
	buf []byte
}

// New returns a chunker for the polynomial and size bounds of an epoch.
func New(pol Pol, p format.ChunkerParams) (*Chunker, error) {
	if p.Algorithm != format.ChunkerAlgorithm {
		return nil, fmt.Errorf("chunker %q is not %s", p.Algorithm, format.ChunkerAlgorithm)
	}
	if p.Avg <= 0 || p.Avg&(p.Avg-1) != 0 {
		return nil, fmt.Errorf("chunker average %d is not a power of two", p.Avg)
	}
	if !pol.Irreducible() {
		return nil, fmt.Errorf("chunker polynomial %v is not irreducible", pol)
	}
	return &Chunker{pol: pol, p: p, buf: make([]byte, p.Max)}, nil
}

// Reset starts cutting r.
func (c *Chunker) Reset(r io.Reader) {
	avgBits := bits.TrailingZeros(uint(c.p.Avg))
	if c.c == nil {
		c.c = chunker.New(r, c.pol, chunker.WithBoundaries(uint(c.p.Min), uint(c.p.Max)), chunker.WithAverageBits(avgBits))
		return
	}
	c.c.Reset(r, c.pol, chunker.WithBoundaries(uint(c.p.Min), uint(c.p.Max)), chunker.WithAverageBits(avgBits))
}

// Next returns the next chunk's bytes, valid until the next call, or io.EOF.
func (c *Chunker) Next() ([]byte, error) {
	ch, err := c.c.Next(c.buf)
	if err != nil {
		return nil, err
	}
	return ch.Data, nil
}
