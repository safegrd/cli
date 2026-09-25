package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/safegrd/cli/pkg/storage"
)

// A bucket for runPrune: versions, their locks, and a clock of its own that
// is deliberately not this host's.
type fakePruneBucket struct {
	now      time.Time
	versions []storage.VersionInfo
	locks    map[string]time.Time
	holds    map[string]bool
	deleted  []string
	noLock   bool
	denied   bool
}

func (b *fakePruneBucket) SnapshotVersions(context.Context) ([]storage.VersionInfo, error) {
	return b.versions, nil
}
func (b *fakePruneBucket) VersionLock(_ context.Context, key, v string) (time.Time, bool, error) {
	return b.locks[key+"|"+v], b.holds[key+"|"+v], nil
}
func (b *fakePruneBucket) DeleteVersion(_ context.Context, key, v string) error {
	if b.denied {
		return &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
	}
	b.deleted = append(b.deleted, key+"|"+v)
	return nil
}
func (b *fakePruneBucket) BucketNow(context.Context) (time.Time, error) { return b.now, nil }
func (b *fakePruneBucket) Prefix() string                               { return "safegrd/snapshots" }
func (b *fakePruneBucket) LockDisabled() bool                           { return b.noLock }

func (b *fakePruneBucket) put(node, id string, modified, lockedUntil time.Time) {
	for _, ext := range []string{".safegrd", ".meta.json"} {
		key := "safegrd/snapshots/" + node + "/" + id + ext
		v := id + ext
		b.versions = append(b.versions, storage.VersionInfo{Key: key, VersionID: v, LastModified: modified})
		b.locks[key+"|"+v] = lockedUntil
	}
}

func (b *fakePruneBucket) gone(node, id string) bool {
	n := 0
	for _, d := range b.deleted {
		if d == "safegrd/snapshots/"+node+"/"+id+".safegrd|"+id+".safegrd" || d == "safegrd/snapshots/"+node+"/"+id+".meta.json|"+id+".meta.json" {
			n++
		}
	}
	return n == 2
}

func TestPruneDeletesOnlyWhatTheBucketSaysHasExpired(t *testing.T) {
	// The host's clock is irrelevant: the bucket's says it is 2027.
	now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	b := &fakePruneBucket{now: now, locks: map[string]time.Time{}, holds: map[string]bool{}}
	b.put("db", "old", now.AddDate(0, 0, -40), now.AddDate(0, 0, -10))
	b.put("db", "graced", now.AddDate(0, 0, -20), now.Add(-12*time.Hour))
	b.put("db", "locked", now.AddDate(0, 0, -10), now.AddDate(0, 0, 5))
	b.put("db", "frozen", now.AddDate(0, 0, -30), now.AddDate(0, 0, -9))
	b.put("db", "newest", now.AddDate(0, 0, -1), now.AddDate(0, 0, -1)) // expired, but the newest
	b.put("db", "held", now.AddDate(0, 0, -35), now.AddDate(0, 0, -8))
	b.holds["safegrd/snapshots/db/held.safegrd|held.safegrd"] = true
	keep := func(string) (map[string]bool, error) { return map[string]bool{"frozen": true}, nil }
	var out bytes.Buffer
	r, err := runPrune(context.Background(), b, keep, nil, false, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !b.gone("db", "old") {
		t.Errorf("the expired snapshot and its metadata were not deleted: %v", b.deleted)
	}
	for _, id := range []string{"graced", "locked", "frozen", "newest", "held"} {
		for _, d := range b.deleted {
			if d == "safegrd/snapshots/db/"+id+".safegrd|"+id+".safegrd" {
				t.Errorf("%s was deleted", id)
			}
		}
	}
	if r.Deleted != 1 || r.Kept != 2 || r.Held != 1 || r.Locked != 2 {
		t.Errorf("report = %v", r)
	}
	// Metadata goes after its snapshot, never before.
	if len(b.deleted) == 2 && b.deleted[0] != "safegrd/snapshots/db/old.safegrd|old.safegrd" {
		t.Errorf("delete order = %v, want the snapshot before its metadata", b.deleted)
	}
}

func TestPruneWithoutTheServersKeepListPrunesNothing(t *testing.T) {
	now := time.Now()
	b := &fakePruneBucket{now: now, locks: map[string]time.Time{}, holds: map[string]bool{}}
	b.put("db", "old", now.AddDate(0, 0, -40), now.AddDate(0, 0, -10))
	b.put("db", "newest", now.AddDate(0, 0, -1), now.AddDate(0, 0, 1))
	var out bytes.Buffer
	r, _ := runPrune(context.Background(), b, func(string) (map[string]bool, error) { return nil, errors.New("offline") }, nil, false, &out)
	if len(b.deleted) != 0 || r.Failed != 1 {
		t.Errorf("pruned without knowing what the server keeps: deleted %v, report %v", b.deleted, r)
	}
}

func TestPruneDryRunDeletesNothingAndRefusalsAreSaid(t *testing.T) {
	now := time.Now()
	b := &fakePruneBucket{now: now, locks: map[string]time.Time{}, holds: map[string]bool{}}
	b.put("db", "old", now.AddDate(0, 0, -40), now.AddDate(0, 0, -10))
	b.put("db", "newest", now.AddDate(0, 0, -1), now.AddDate(0, 0, 1))
	none := func(string) (map[string]bool, error) { return nil, nil }
	var out bytes.Buffer
	if r, _ := runPrune(context.Background(), b, none, nil, true, &out); len(b.deleted) != 0 || r.WouldDelete != 1 {
		t.Errorf("dry run: deleted %v, report %v", b.deleted, r)
	}
	b.denied = true
	out.Reset()
	if r, _ := runPrune(context.Background(), b, none, nil, false, &out); r.Failed == 0 || !bytes.Contains(out.Bytes(), []byte("s3:DeleteObjectVersion")) {
		t.Errorf("a refused delete was not said with the permission it needs: %v\n%s", r, out.String())
	}
}

func TestPruneUnderWORMModeNoneReadsTheRecordedDate(t *testing.T) {
	now := time.Now()
	b := &fakePruneBucket{now: now, noLock: true, locks: map[string]time.Time{}, holds: map[string]bool{}}
	b.put("db", "old", now.AddDate(0, 0, -40), time.Time{})
	b.put("db", "recent", now.AddDate(0, 0, -5), time.Time{})
	b.put("db", "newest", now.AddDate(0, 0, -1), time.Time{})
	until := map[string]time.Time{"old": now.AddDate(0, 0, -10), "recent": now.AddDate(0, 0, 3)}
	// Keyed by where the metadata is listed, which is the surface's own node.
	retain := func(key string) (time.Time, error) {
		return until[strings.TrimSuffix(strings.TrimPrefix(key, "safegrd/snapshots/db/"), ".meta.json")], nil
	}
	var out bytes.Buffer
	runPrune(context.Background(), b, func(string) (map[string]bool, error) { return nil, nil }, retain, false, &out)
	if !b.gone("db", "old") || len(b.deleted) != 2 {
		t.Errorf("under NONE, deleted %v; want only the snapshot whose kept-until date has passed", b.deleted)
	}
}
