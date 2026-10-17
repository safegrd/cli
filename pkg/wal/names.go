// Package wal archives a PostgreSQL cluster's write-ahead log next to its
// backups, so it can be restored to any moment the archive covers.
//
// Each WAL file is compressed and encrypted on the host and written unlocked.
// Once a day the unlocked files are joined, still encrypted, into one locked
// bundle and deleted, so the job never needs the private key. Base backups
// are pg_basebackup's tar, written as one locked object.
//
//	wal/<surface-id>/<system-id>/
//	  base/<base-id>/base.tar.zst.age
//	  base/<base-id>/base.json
//	  segments/<name>-<unix>-<sha16>.zst.age
//	  bundles/<bundle-id>.bundle
//	  bundles/<bundle-id>.json
//	  points/<restore-point>.json
package wal

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	segmentRe = regexp.MustCompile(`^[0-9A-F]{24}$`)
	historyRe = regexp.MustCompile(`^[0-9A-F]{8}\.history$`)
	backupRe  = regexp.MustCompile(`^[0-9A-F]{24}\.[0-9A-F]{8}\.backup$`)
	partialRe = regexp.MustCompile(`^[0-9A-F]{24}\.partial$`)
	baseIDRe  = regexp.MustCompile(`^b-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)
	bundleRe  = regexp.MustCompile(`^w-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)
	pointRe   = regexp.MustCompile(`^r-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)
)

// ValidName refuses anything PostgreSQL would not archive: a segment, a
// timeline history, a backup history or a segment left partial by a
// promotion.
func ValidName(name string) error {
	if segmentRe.MatchString(name) || historyRe.MatchString(name) || backupRe.MatchString(name) || partialRe.MatchString(name) || sqliteSegRe.MatchString(name) {
		return nil
	}
	return fmt.Errorf("%q is not a WAL file name PostgreSQL archives (a segment, a .history, a .backup or a .partial), nor a SQLite segment", name)
}

// IsSegment says whether name is a whole WAL segment.
func IsSegment(name string) bool { return segmentRe.MatchString(name) }

// ValidSystemID refuses a system identifier that is not a cluster's.
func ValidSystemID(id string) error {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil || id == "0" || strings.HasPrefix(id, "0") {
		return fmt.Errorf("%q is not a PostgreSQL system identifier", id)
	}
	return nil
}

// Prefix is the key prefix of one cluster's archive under a store's root.
func Prefix(root, surfaceID, systemID string) string {
	return path.Join(root, "wal", surfaceID, systemID)
}

// Systems lists the clusters a surface's archive holds, by system
// identifier.
func Systems(ctx context.Context, st Store, surfaceID string) ([]string, error) {
	names, err := st.Children(ctx, path.Join(st.Root(), "wal", surfaceID))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		if ValidSystemID(n) == nil {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Pushed is one WAL file as it sits unlocked in the archive.
type Pushed struct {
	Name     string
	PushedAt time.Time
	// Sha16 is the first 16 hex digits of the SHA-256 of the uncompressed
	// file.
	Sha16 string
	Key   string
	Size  int64
}

// segmentKey is where a pushed WAL file goes.
func segmentKey(prefix, name string, at time.Time, sha256hex string) string {
	return path.Join(prefix, "segments", fmt.Sprintf("%s-%d-%s.zst.age", name, at.Unix(), sha256hex[:16]))
}

// parseSegmentKey reads a pushed WAL file's key back. ok is false for a key
// that is not one.
func parseSegmentKey(key string) (Pushed, bool) {
	base := strings.TrimSuffix(path.Base(key), ".zst.age")
	if base == path.Base(key) {
		return Pushed{}, false
	}
	i := strings.LastIndexByte(base, '-')
	if i < 0 {
		return Pushed{}, false
	}
	sha := base[i+1:]
	rest := base[:i]
	j := strings.LastIndexByte(rest, '-')
	if j < 0 || len(sha) != 16 {
		return Pushed{}, false
	}
	unix, err := strconv.ParseInt(rest[j+1:], 10, 64)
	if err != nil {
		return Pushed{}, false
	}
	name := rest[:j]
	if ValidName(name) != nil {
		return Pushed{}, false
	}
	return Pushed{Name: name, PushedAt: time.Unix(unix, 0).UTC(), Sha16: sha, Key: key}, true
}

// newID is a base or bundle id: a kind letter, the time and 32 random bits.
func newID(kind string, at time.Time, rnd string) string {
	return fmt.Sprintf("%s-%s-%s", kind, at.UTC().Format("20060102T150405Z"), rnd)
}
