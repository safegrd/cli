package cli

import (
	"bytes"
	"context"
	"errors"
	"github.com/safegrd/cli/pkg/config"
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

// A short retention never empties a surface: with every lock long over, the
// newest --min-keep snapshots of each surface stay and only the older go.
func TestPruneKeepsTheNewestFewWhateverTheLocksSay(t *testing.T) {
	now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	b := &fakePruneBucket{now: now, locks: map[string]time.Time{}, holds: map[string]bool{}}
	for i, id := range []string{"d1", "d2", "d3", "d4", "d5"} {
		b.put("db", id, now.AddDate(0, 0, -10*(i+1)), now.AddDate(0, 0, -9*(i+1)))
	}
	b.put("web", "w1", now.AddDate(0, 0, -30), now.AddDate(0, 0, -20))
	var out bytes.Buffer
	r, err := runPruneWithGrace(context.Background(), b, func(string) (map[string]bool, error) { return nil, nil },
		nil, pruneGrace, 3, false, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"d1", "d2", "d3"} {
		if b.gone("db", id) {
			t.Errorf("%s is one of the three newest and was deleted", id)
		}
	}
	for _, id := range []string{"d4", "d5"} {
		if !b.gone("db", id) {
			t.Errorf("%s is past its lock and older than the three newest, and was kept", id)
		}
	}
	if b.gone("web", "w1") {
		t.Error("a surface's only snapshot was deleted")
	}
	if r.Deleted != 2 || r.Kept != 4 {
		t.Errorf("report: %s", r)
	}
}

// A host that was never enrolled has no remote server to hold a snapshot,
// so prune runs on its own rules. It used to refuse every incremental
// repository on such a host, so its bucket only grew. An enrolled host
// whose server cannot answer still prunes nothing.
func TestAStandaloneHostPrunesWithoutAServer(t *testing.T) {
	keep, err := serverKeepList(context.Background(), &config.CLIConfig{}, "node-x")
	if err != nil || keep == nil || len(keep) != 0 {
		t.Fatalf("standalone keep list: %v, %v; want an empty list and no error", keep, err)
	}
	enrolled := &config.CLIConfig{ServerURL: "http://127.0.0.1:1", ServerToken: "sg_tok_x", NodeID: "node-x"}
	if _, err := serverKeepList(context.Background(), enrolled, ""); err == nil {
		t.Fatal("an enrolled host whose server is unreachable got a keep list")
	}
}
