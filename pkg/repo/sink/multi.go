package sink

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/repo/format"
)

// Named is a bucket a run is written to beside the surface's own store: its
// name in the config, the backend over it, and how many days it keeps a run
// past its epoch's end.
type Named struct {
	Name          string
	D             *Direct
	RetentionDays int
}

// CopyResult is what one copy of one run came to.
type CopyResult struct {
	Name string
	// Prefix is the epoch's key prefix in the copy.
	Prefix string
	// RetainUntil is the lock the copy's objects carry, zero for a store
	// that locks nothing.
	RetainUntil time.Time
	// Held is true when the copy holds the run and every object it reads.
	Held bool
	// Behind is true when the copy took what it was given but lacks objects
	// of earlier runs, or the epoch itself; the run is not published there
	// and a catch-up copies what is missing.
	Behind bool
	Err    error
}

// Multi writes a run to the surface's own store and to each copy as it goes,
// so a copy costs no read back out of the first store. The first store
// decides the run: its failure fails the run, a copy's drops that copy for
// the rest of the run and is kept in its result. Every read goes to the
// first store.
//
// A copy publishes the run only at Commit, after the first store committed
// and once the copy is checked to hold every object the run reads: the
// sidecar and the recovery document are held back until then. A copy that
// misses anything is left without them, so no reader of the copy finds a
// snapshot whose objects are not all there.
type Multi struct {
	First  *Direct
	copies []*multiCopy

	mu    sync.Mutex
	epoch format.Epoch
}

type multiCopy struct {
	Named
	until     time.Time
	slots     map[string]Slot
	held      []heldPut
	err       error
	behind    bool
	published bool
}

type heldPut struct {
	slot Slot
	body []byte
}

// NewMulti returns a backend that writes to first and to each copy.
func NewMulti(first *Direct, copies ...Named) *Multi {
	m := &Multi{First: first}
	for _, c := range copies {
		m.copies = append(m.copies, &multiCopy{Named: c, slots: map[string]Slot{}})
	}
	return m
}

// Primary is the store every read goes to.
func (m *Multi) Primary() *Direct { return m.First }

// Results are the copies of the run, in the order they were given.
func (m *Multi) Results() []CopyResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CopyResult
	for _, c := range m.copies {
		r := CopyResult{Name: c.Name, Prefix: EpochPrefix(c.D.S.Root(), m.epoch.SurfaceID, m.epoch.EpochID),
			Held: c.published, Behind: c.behind, Err: c.err}
		if s, ok := c.D.S.(*S3); ok && s.Mode != "" {
			r.RetainUntil = c.until
		}
		out = append(out, r)
	}
	return out
}

func (m *Multi) live() []*multiCopy {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*multiCopy
	for _, c := range m.copies {
		if c.err == nil && !c.behind {
			out = append(out, c)
		}
	}
	return out
}

func (m *Multi) drop(c *multiCopy, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
}

func (m *Multi) setBehind(c *multiCopy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c.behind = true
}

// copyUntil is a copy's lock for the epoch: its own retention past the
// epoch's planned end, never shorter than the first store's lock on the
// epoch's opening run, and at least a day off.
func copyUntil(e format.Epoch, days int) time.Time {
	until := e.PlannedEnd.AddDate(0, 0, days)
	if until.Before(e.OpeningRetainUntil) {
		until = e.OpeningRetainUntil
	}
	if min := time.Now().Add(24 * time.Hour); until.Before(min) {
		until = min
	}
	return until
}

func (m *Multi) Describe() string { return m.First.Describe() }

// OpenEpoch opens the epoch in the first store, then writes its descriptor,
// byte for byte, to each copy. A copy that already holds a different
// descriptor is not overwritten; one that holds none of an epoch opened by
// an earlier run is behind, and the catch-up copies the epoch whole.
func (m *Multi) OpenEpoch(ctx context.Context, req OpenRequest) (Opened, error) {
	opened, err := m.First.OpenEpoch(ctx, req)
	if err != nil {
		return opened, err
	}
	e := opened.Epoch
	m.mu.Lock()
	m.epoch = e
	m.mu.Unlock()
	firstKey, _ := ObjectKey(EpochPrefix(m.First.S.Root(), e.SurfaceID, e.EpochID), KindEpoch, "")
	desc, err := m.First.Get(ctx, firstKey)
	if err != nil {
		for _, c := range m.live() {
			m.drop(c, fmt.Errorf("reading the epoch's descriptor to copy it: %w", err))
		}
		return opened, nil
	}
	for _, c := range m.live() {
		c.until = copyUntil(e, c.RetentionDays)
		key, _ := ObjectKey(EpochPrefix(c.D.S.Root(), e.SurfaceID, e.EpochID), KindEpoch, "")
		have, gerr := c.D.Get(ctx, key)
		switch {
		case gerr == nil:
			if string(have) != string(desc) {
				m.drop(c, fmt.Errorf("its %s differs from the surface's own and is not overwritten", key))
			}
		case !errors.Is(gerr, ErrNotFound):
			m.drop(c, fmt.Errorf("reading %s: %w", key, gerr))
		case !opened.New:
			m.setBehind(c)
		default:
			if perr := c.D.S.Put(ctx, key, desc, md5.Sum(desc), c.until); perr != nil {
				m.drop(c, perr)
			}
		}
	}
	return opened, nil
}

// StartRun is the first store's decision.
func (m *Multi) StartRun(ctx context.Context, e format.Epoch, runID string) (RunDecision, error) {
	return m.First.StartRun(ctx, e, runID)
}

// Reserve reserves in the first store, and the same objects under each
// copy's own root, locked for the copy's retention or the first store's
// lock, whichever is later.
func (m *Multi) Reserve(ctx context.Context, e format.Epoch, class string, objs []ObjectSpec) ([]Slot, error) {
	slots, err := m.First.Reserve(ctx, e, class, objs)
	if err != nil {
		return nil, err
	}
	for _, c := range m.live() {
		cs, err := c.D.Reserve(ctx, e, class, objs)
		if err != nil {
			m.drop(c, err)
			continue
		}
		m.mu.Lock()
		for i := range cs {
			cs[i].RetainUntil, cs[i].Unlocked = c.until, false
			if !slots[i].Unlocked && slots[i].RetainUntil.After(cs[i].RetainUntil) {
				cs[i].RetainUntil = slots[i].RetainUntil
			}
			c.slots[slots[i].Key] = cs[i]
		}
		m.mu.Unlock()
	}
	return slots, nil
}

// Put writes to the first store and every copy at once. The sidecar and the
// recovery document are held for the copies until Commit.
func (m *Multi) Put(ctx context.Context, slot Slot, body []byte) error {
	copies := m.live()
	var wg sync.WaitGroup
	for _, c := range copies {
		m.mu.Lock()
		cs, ok := c.slots[slot.Key]
		m.mu.Unlock()
		if !ok {
			m.drop(c, fmt.Errorf("%s was not reserved in this bucket", slot.Key))
			continue
		}
		if slot.Kind == KindMeta || slot.Kind == KindRecovery || slot.Kind == KindRecoverySealed {
			m.mu.Lock()
			c.held = append(c.held, heldPut{slot: cs, body: append([]byte(nil), body...)})
			m.mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(c *multiCopy, cs Slot) {
			defer wg.Done()
			if err := c.D.Put(ctx, cs, body); err != nil {
				m.drop(c, err)
			}
		}(c, cs)
	}
	err := m.First.Put(ctx, slot, body)
	wg.Wait()
	return err
}

func (m *Multi) Uploaded(ctx context.Context, e format.Epoch, keys []string) error {
	return m.First.Uploaded(ctx, e, keys)
}

// Commit commits the run in the first store, then publishes it in each copy
// that holds every object the run wrote and reads.
func (m *Multi) Commit(ctx context.Context, e format.Epoch, c RunCommit) error {
	if err := m.First.Commit(ctx, e, c); err != nil {
		return err
	}
	firstPrefix := EpochPrefix(m.First.S.Root(), e.SurfaceID, e.EpochID)
	for _, cp := range m.live() {
		prefix := EpochPrefix(cp.D.S.Root(), e.SurfaceID, e.EpochID)
		heldKeys := map[string]bool{}
		for _, h := range cp.held {
			heldKeys[h.slot.Key] = true
		}
		objs, err := cp.D.S.List(ctx, prefix+"/")
		if err != nil {
			m.drop(cp, fmt.Errorf("listing what it holds: %w", err))
			continue
		}
		have := map[string]bool{}
		for _, o := range objs {
			have[o.Key] = true
		}
		missing := false
		for _, k := range append(append([]string(nil), c.Keys...), c.Refs...) {
			if !strings.HasPrefix(k, firstPrefix+"/") {
				continue
			}
			ck := prefix + strings.TrimPrefix(k, firstPrefix)
			if !heldKeys[ck] && !have[ck] {
				missing = true
				break
			}
		}
		if missing {
			m.setBehind(cp)
			continue
		}
		var perr error
		for _, h := range cp.held {
			if perr = cp.D.Put(ctx, h.slot, h.body); perr != nil {
				break
			}
		}
		if perr != nil {
			m.drop(cp, perr)
			continue
		}
		m.mu.Lock()
		cp.published = true
		m.mu.Unlock()
	}
	return nil
}

func (m *Multi) Epochs(ctx context.Context, surfaceID string) ([]EpochInfo, error) {
	return m.First.Epochs(ctx, surfaceID)
}

func (m *Multi) List(ctx context.Context, e EpochInfo, sub string) ([]ObjectInfo, error) {
	return m.First.List(ctx, e, sub)
}

func (m *Multi) Get(ctx context.Context, key string) ([]byte, error) { return m.First.Get(ctx, key) }

func (m *Multi) GetRange(ctx context.Context, key string, off, n int64) ([]byte, error) {
	return m.First.GetRange(ctx, key, off, n)
}
