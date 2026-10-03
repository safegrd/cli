// Package format holds the byte encodings of an incremental file repository:
// packs, blob records, trailers, trees, indexes, snapshots, catalog deltas and
// the content root. Everything here is a pure function with no I/O, so the
// writer, the reader and the independent checker share exactly these and
// nothing else.
//
// A repository is cut into epochs. An epoch is self-contained: nothing in it
// refers to anything outside it. Every object is written once and never
// rewritten, which is what lets each one carry a storage lock fixed when it
// is written.
package format

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

// Version is the repository format version this package reads and writes.
// A reader meeting any other version refuses by name.
const Version = 1

// FormatName is the "format" value of an epoch descriptor.
const FormatName = "safegrd-repo"

// SidecarFormat is the "format" value a repository snapshot's metadata
// sidecar carries, so a reader can dispatch before touching ciphertext.
const SidecarFormat = "repo-v1"

// ID is a blob id: the SHA-256 of the blob's plaintext.
type ID [32]byte

// Hash returns the id of plaintext.
func Hash(plaintext []byte) ID { return sha256.Sum256(plaintext) }

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// IsZero reports whether id is all zero bytes, which no real blob has.
func (id ID) IsZero() bool { return id == ID{} }

// ParseID decodes 64 lowercase hex characters.
func ParseID(s string) (ID, error) {
	var id ID
	if len(s) != 64 || !lowerHex.MatchString(s) {
		return id, fmt.Errorf("blob id %q is not 64 lowercase hex characters", short(s))
	}
	_, err := hex.Decode(id[:], []byte(s))
	return id, err
}

var (
	lowerHex  = regexp.MustCompile(`^[0-9a-f]+$`)
	hex32     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	epochIDRe = regexp.MustCompile(`^e[0-9]{6}-[0-9a-f]{8}$`)
)

// NewRandomID returns 32 lowercase hex characters from a CSPRNG: a run id or
// a pack id.
func NewRandomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("format: the system random source failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// ValidRandomID reports whether s is a run id or pack id: 32 lowercase hex.
func ValidRandomID(s string) bool { return hex32.MatchString(s) }

// ValidEpochID reports whether s is e<YYYYMM>-<8 lowercase hex>.
func ValidEpochID(s string) bool { return epochIDRe.MatchString(s) }

// PackIDBytes returns the 16 bytes a pack id's hex encodes.
func PackIDBytes(packID string) ([]byte, error) {
	if !ValidRandomID(packID) {
		return nil, fmt.Errorf("pack id %q is not 32 lowercase hex characters", short(packID))
	}
	return hex.DecodeString(packID)
}

func short(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
