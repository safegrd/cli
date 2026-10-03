package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
)

// The content root is the digest a snapshot is attested by. It is the
// SHA-256 of one line per entry reachable from the root tree, the root itself
// excluded, sorted by the raw bytes of the path before any escaping:
//
//	<type> SP <value> SP <path> LF
//
// type is d, f or l; value is the file's SHA-256 in hex for f, the hex of
// the link target's bytes for l, and "-" for d; path is the entry's path from
// the root, "/"-separated, with every byte outside 0x21–0x7e and every "%"
// written as %XX in uppercase hex. Modes, owners and times are left out, so a
// restore by a user who cannot set them still reproduces the root.

// ContentType letters.
const (
	ContentDir     = 'd'
	ContentFile    = 'f'
	ContentSymlink = 'l'
)

// EscapePath writes path as it appears in a content-root line.
func EscapePath(path string) string {
	var b bytes.Buffer
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c < 0x21 || c > 0x7e || c == '%' {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ContentLine is one line of the content root, newline included.
func ContentLine(typ byte, value, path string) []byte {
	line := make([]byte, 0, len(value)+len(path)+8)
	line = append(line, typ, ' ')
	line = append(line, value...)
	line = append(line, ' ')
	line = append(line, EscapePath(path)...)
	return append(line, '\n')
}

// ContentValue is the value field for an entry: the file's SHA-256, the hex
// of a link's target, or "-" for a directory.
func ContentValue(typ byte, fileSHA256, linkTarget string) string {
	switch typ {
	case ContentFile:
		return fileSHA256
	case ContentSymlink:
		return hex.EncodeToString([]byte(linkTarget))
	default:
		return "-"
	}
}

// ContentRoot hashes lines that arrive already sorted by raw path. It refuses
// a path out of order, so a caller that forgot to sort learns it here rather
// than from a drill that disagrees.
type ContentRoot struct {
	h    hash.Hash
	last []byte
	n    int64
	err  error
}

// NewContentRoot starts an empty content root.
func NewContentRoot() *ContentRoot { return &ContentRoot{h: sha256.New()} }

// Add appends one entry. Paths must arrive in strictly increasing byte order.
func (c *ContentRoot) Add(typ byte, value, path string) {
	if c.err != nil {
		return
	}
	if c.n > 0 && bytes.Compare(c.last, []byte(path)) >= 0 {
		c.err = fmt.Errorf("content root: path %q arrived after %q", path, c.last)
		return
	}
	c.last = append(c.last[:0], path...)
	c.n++
	c.h.Write(ContentLine(typ, value, path))
}

// Sum returns the root in hex, or the ordering error.
func (c *ContentRoot) Sum() (string, error) {
	if c.err != nil {
		return "", c.err
	}
	return hex.EncodeToString(c.h.Sum(nil)), nil
}

// Count is how many entries were added.
func (c *ContentRoot) Count() int64 { return c.n }
