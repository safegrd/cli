package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/write"
)

// memBucket is a versioned bucket that remembers each object's lock.
type memBucket struct {
	mu   sync.Mutex
	objs map[string]memObj
	root string
	// noLocks is a bucket without Object Lock (worm_mode NONE).
	noLocks bool
}

type memObj struct {
	body []byte
	lock time.Time
}

func (m *memBucket) Root() string     { return m.root }
func (m *memBucket) Describe() string { return "mem" }
func (m *memBucket) Put(_ context.Context, key string, body []byte, _ [16]byte, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.noLocks {
		until = time.Time{}
	}
	m.objs[key] = memObj{append([]byte{}, body...), until}
	return nil
}
func (m *memBucket) Get(_ context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objs[key]
	if !ok {
		return nil, sink.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(o.body)), nil
}
func (m *memBucket) GetRange(_ context.Context, key string, off, n int64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.objs[key]
	end := off + n
	if end > int64(len(o.body)) {
		end = int64(len(o.body))
	}
	return o.body[off:end], nil
}
func (m *memBucket) List(_ context.Context, prefix string) ([]sink.ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []sink.ObjectInfo
	for k, o := range m.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, sink.ObjectInfo{Key: k, Size: int64(len(o.body))})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
func (m *memBucket) Children(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	seen := map[string]bool{}
	var out []string
	for k := range m.objs {
		if rest, ok := strings.CutPrefix(k, prefix); ok {
			if i := strings.Index(rest, "/"); i > 0 && !seen[rest[:i]] {
				seen[rest[:i]] = true
				out = append(out, rest[:i])
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
func (m *memBucket) Versions(ctx context.Context, prefix string) ([]sink.Version, error) {
	objs, _ := m.List(ctx, prefix)
	var out []sink.Version
	for _, o := range objs {
		out = append(out, sink.Version{Key: o.Key, VersionID: "v1", Size: o.Size})
	}
	return out, nil
}
func (m *memBucket) Retention(_ context.Context, key, _ string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.objs[key].lock, nil
}
func (m *memBucket) DeleteVersion(_ context.Context, key, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objs, key)
	return nil
}

func (m *memBucket) count(sub string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k := range m.objs {
		if strings.Contains(k, sub) {
			n++
		}
	}
	return n
}

// The worked example's shape on a short clock: later objects go once every
// later snapshot of the epoch has expired, the opening run's objects stay
// while the opening snapshot is kept, and an epoch that holds the newest
// snapshot keeps everything.
func TestRepoPruneDeletesByClass(t *testing.T) {
	t.Run("locked", func(t *testing.T) { testRepoPrune(t, false) })
	// Without locks the class cannot be read from the bucket, so every
	// object is treated as opening: kept until every snapshot has expired.
	t.Run("no lock", func(t *testing.T) { testRepoPrune(t, true) })
}

func testRepoPrune(t *testing.T, noLocks bool) {
	id, _ := age.GenerateX25519Identity()
	src := t.TempDir()
	mb := &memBucket{objs: map[string]memObj{}, root: "safegrd/snapshots", noLocks: noLocks}
	node := &rootedStore{repoPruneStore: mb, root: "safegrd/snapshots/node-1"}
	b := sink.NewDirect(node)
	state := t.TempDir()
	retain := policy.Retention{Days: 7, KeepMonthly: 12}
	run := func(at time.Time, body string, tier string, planned time.Time) *write.Result {
		if err := os.WriteFile(filepath.Join(src, "f"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		snap := "snap-" + at.Format("0102-1504")
		res, err := write.Run(context.Background(), b, write.Options{
			SurfaceID: "s", Roots: []string{src}, StateDir: state, Recipient: id.Recipient().String(), Retention: retain,
			Tier: tier, Planned: planned, SnapshotID: snap, Now: func() time.Time { return at },
			Sidecar: func(r *write.Result) ([]byte, error) {
				return json.Marshal(model.SnapshotMetadata{SnapshotID: snap, CreatedAt: at, ObjectClass: r.Class, Format: model.SnapshotFormatRepo,
					EpochID: r.Epoch.EpochID, WORMRetentionUntil: r.Snapshot.RetainUntil, Sha256Checksum: r.Snapshot.ContentRoot})
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	oct1 := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	opening := run(oct1, "a", format.TierMonthly, oct1.AddDate(1, 0, 0))
	run(oct1.AddDate(0, 0, 10), "b", format.TierBase, oct1.AddDate(0, 0, 17))
	run(oct1.AddDate(0, 0, 20), "c", format.TierBase, oct1.AddDate(0, 0, 27))
	nov1 := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	run(nov1, "d", format.TierMonthly, nov1.AddDate(1, 0, 0)) // the newest, in November's epoch

	e := opening.Epoch
	keep := func(string) (map[string]bool, error) { return map[string]bool{}, nil }
	prune := func(now time.Time) pruneReport {
		var r pruneReport
		if err := pruneRepos(context.Background(), mb, keep, now, time.Hour, false, io.Discard, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	octPrefix := "repo/s/" + e.EpochID + "/"
	all := mb.count(octPrefix)

	// Before the later lock ends nothing goes.
	prune(e.LaterRetainUntil.Add(-time.Hour))
	if got := mb.count(octPrefix); got != all {
		t.Fatalf("%d of %d objects left before the later lock ended", got, all)
	}
	// After it, the later runs' objects go (where the bucket says which they
	// are); the opening snapshot stays whole either way.
	prune(e.LaterRetainUntil.Add(2 * time.Hour))
	left := mb.count(octPrefix)
	if mb.count(octPrefix+"snapshots/snap-"+oct1.Format("0102-1504")) != 2 {
		t.Fatalf("after the later lock the opening snapshot has %d of its 2 objects", mb.count(octPrefix+"snapshots/snap-"+oct1.Format("0102-1504")))
	}
	if noLocks {
		if left != all {
			t.Fatalf("without locks, %d of %d objects left before every snapshot expired", left, all)
		}
	} else {
		if left >= all {
			t.Fatalf("after the later lock: %d of %d left", left, all)
		}
		for k, o := range mb.objs {
			if strings.HasPrefix(k, "safegrd/snapshots/node-1/"+octPrefix) && !o.lock.Equal(e.OpeningRetainUntil) {
				t.Fatalf("a later object survived: %s locked to %s", k, o.lock)
			}
		}
	}
	// The opening snapshot is still restorable from what is left.
	es, _ := b.Epochs(context.Background(), "s")
	if len(es) != 2 {
		t.Fatalf("%d epochs", len(es))
	}
	// After the opening lock, October's epoch goes entirely; November's,
	// which holds the newest snapshot, stays.
	prune(e.OpeningRetainUntil.Add(2 * time.Hour))
	if got := mb.count(octPrefix); got != 0 {
		t.Fatalf("%d objects of October's epoch left after every lock ended", got)
	}
	if mb.count("repo/s/e202611") == 0 {
		t.Fatal("the epoch holding the newest snapshot was pruned")
	}
}
