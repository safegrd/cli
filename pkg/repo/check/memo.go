package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
)

// Memo holds what checks of one epoch share, so that checking n snapshots
// reads each object once rather than n times: the pack listing, every
// snapshot with its catalog in snapshot order, the index of each run, the
// result of each pack's trailer check, and one reader, which keeps pack
// headers and trees. The catalog is replayed forward from the last snapshot
// checked, so checking an epoch's snapshots in order replays each delta once.
//
// A Memo is for one epoch and one set of identities, and for one goroutine.
type Memo struct {
	b   sink.Backend
	e   sink.EpochInfo
	ids []age.Identity
	r   *read.Repo

	sizes    map[string]int64           // pack name to size; nil until listed
	snaps    map[string]format.Snapshot // snapshot id to its object
	runs     []memoRun                  // every snapshot, oldest first; nil until listed
	indexes  map[string]format.Index    // run id to its index
	trailers map[string]error           // pack name to its trailer check
	state    map[string][2]string       // the catalog replayed to runs[stateAt]
	stateAt  int
}

type memoRun struct {
	snap format.Snapshot
	cat  *format.Catalog // nil until read
}

// NewMemo returns an empty memo for the epoch.
func NewMemo(b sink.Backend, e sink.EpochInfo, ids []age.Identity) *Memo {
	return &Memo{b: b, e: e, ids: ids, r: read.Open(b, e, ids), snaps: map[string]format.Snapshot{},
		indexes: map[string]format.Index{}, trailers: map[string]error{}, stateAt: -1}
}

// snapshot reads a snapshot object once.
func (m *Memo) snapshot(ctx context.Context, id string) (format.Snapshot, error) {
	if s, ok := m.snaps[id]; ok {
		return s, nil
	}
	s, err := m.r.Snapshot(ctx, id)
	if err != nil {
		return s, err
	}
	m.snaps[id] = s
	return s, nil
}

// packSizes lists the epoch's packs once.
func (m *Memo) packSizes(ctx context.Context) (map[string]int64, error) {
	if m.sizes != nil {
		return m.sizes, nil
	}
	listed, err := m.b.List(ctx, m.e, "packs")
	if err != nil {
		return nil, err
	}
	sizes := make(map[string]int64, len(listed))
	for _, ob := range listed {
		sizes[ob.Key[strings.LastIndex(ob.Key, "/")+1:]] = ob.Size
	}
	m.sizes = sizes
	return sizes, nil
}

// index is the snapshot's effective index, from each run's index read once.
func (m *Memo) index(ctx context.Context, snap format.Snapshot) (read.Index, error) {
	idx := read.Index{}
	for _, run := range snap.Runs {
		x, ok := m.indexes[run]
		if !ok {
			var err error
			if x, err = m.r.RunIndex(ctx, snap, run); err != nil {
				return nil, err
			}
			m.indexes[run] = x
		}
		m.r.AddRunIndex(idx, x)
	}
	return idx, nil
}

// trailer checks a pack's trailer against the index entries that place blobs
// in it, once per pack: a pack is indexed by the one run that wrote it, so
// every snapshot expects the same entries.
func (m *Memo) trailer(ctx context.Context, pack string, size int64, want []format.BlobEntry) error {
	if err, ok := m.trailers[pack]; ok {
		return err
	}
	err := checkTrailer(ctx, m.b, m.e, pack, size, want, m.ids)
	m.trailers[pack] = err
	return err
}

// loadRuns lists the epoch's snapshots and reads each snapshot object once.
func (m *Memo) loadRuns(ctx context.Context) error {
	if m.runs != nil {
		return nil
	}
	ids, err := Snapshots(ctx, m.b, m.e)
	if err != nil {
		return err
	}
	runs := make([]memoRun, 0, len(ids))
	for _, id := range ids {
		s, err := m.snapshot(ctx, id)
		if err != nil {
			return err
		}
		runs = append(runs, memoRun{snap: s})
	}
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].snap.CreatedAt.Before(runs[j].snap.CreatedAt) })
	m.runs = runs
	return nil
}

// catalog reads the catalog of the i'th run once.
func (m *Memo) catalog(ctx context.Context, i int) (*format.Catalog, error) {
	if c := m.runs[i].cat; c != nil {
		return c, nil
	}
	s := m.runs[i].snap
	key, _ := sink.ObjectKey(m.e.Prefix, sink.KindCatalog, s.RunID)
	body, err := m.b.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("the catalog of run %s: %w", s.RunID, err)
	}
	var c format.Catalog
	if err := unseal.Object(body, m.ids, &c); err != nil {
		return nil, fmt.Errorf("the catalog of run %s: %w", s.RunID, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	m.runs[i].cat = &c
	return &c, nil
}

// catalogState is the catalog replayed to the snapshot: every path it holds
// with its type and, for a file, its SHA-256. A complete catalog resets the
// state, so the replay starts at the nearest complete catalog at or before
// the snapshot, or continues from the last snapshot asked for when that is
// earlier. The map is the memo's own and is valid until the next call.
func (m *Memo) catalogState(ctx context.Context, snapshotID string) (map[string][2]string, error) {
	if err := m.loadRuns(ctx); err != nil {
		return nil, err
	}
	at := -1
	for i, r := range m.runs {
		if r.snap.SnapshotID == snapshotID {
			at = i
			break
		}
	}
	if at < 0 {
		return nil, fmt.Errorf("no catalog leads to snapshot %s", snapshotID)
	}
	if at == m.stateAt {
		return m.state, nil
	}
	from := m.stateAt + 1
	if m.stateAt < 0 || at < m.stateAt {
		from = 0
		for i := at; i >= 0; i-- {
			c, err := m.catalog(ctx, i)
			if err != nil {
				return nil, err
			}
			if c.Complete {
				from = i
				break
			}
		}
		m.state = map[string][2]string{}
	}
	for i := from; i <= at; i++ {
		c, err := m.catalog(ctx, i)
		if err != nil {
			return nil, err
		}
		if c.Complete {
			m.state = map[string][2]string{}
		}
		for _, en := range c.Entries {
			switch en.Event {
			case format.EventDeleted:
				delete(m.state, en.Path)
			default:
				v := en.SHA256
				if en.Type != "f" {
					v = ""
				}
				m.state[en.Path] = [2]string{en.Type, v}
			}
		}
	}
	m.stateAt = at
	return m.state, nil
}
