package wal

import (
	"context"
	"sort"
	"time"
)

// Gap is a run of WAL segments missing from the archive.
type Gap struct {
	Timeline uint32
	// First and Last are the first and last missing segment.
	First, Last string
	// Breaks are the base backups whose replay stops at this gap.
	Breaks []string
	// Before is when the last segment a replay reads before the gap was
	// pushed: the last moment a restore from the bases it breaks can reach.
	Before time.Time
}

// Status is what an archive holds and how far back it can restore.
type Status struct {
	Bases      []BaseInfo
	Incomplete []string
	// Files counts WAL files by name, unlocked or bundled.
	Files         int
	Unlocked      int
	UnlockedBytes int64
	Bundles       int
	BundledBytes  int64
	// LockedTo is when the newest bundled WAL file was pushed: everything
	// up to it is locked. Zero with no bundle.
	LockedTo time.Time
	// NewestPush is when the newest WAL file was pushed.
	NewestPush time.Time
	Gaps       []Gap
	// WindowFrom to WindowTo is the span a restore can reach; HasWindow is
	// false when no base backup has unbroken WAL after it.
	HasWindow            bool
	WindowFrom, WindowTo time.Time
	// Conflicts are names archived twice with different contents.
	Conflicts []string
}

// Status reads the whole archive and works out its window.
func (a *Archive) Status(ctx context.Context) (Status, error) {
	var st Status
	var err error
	if st.Bases, st.Incomplete, err = a.Bases(ctx); err != nil {
		return st, err
	}
	pushed, err := a.Pushed(ctx)
	if err != nil {
		return st, err
	}
	bundles, err := a.Bundles(ctx)
	if err != nil {
		return st, err
	}
	when := map[string]time.Time{}
	shas := map[string]map[string]bool{}
	note := func(name, sha string, at time.Time) {
		if t, ok := when[name]; !ok || at.Before(t) {
			when[name] = at
		}
		if shas[name] == nil {
			shas[name] = map[string]bool{}
		}
		shas[name][sha] = true
		if at.After(st.NewestPush) {
			st.NewestPush = at
		}
	}
	for _, p := range pushed {
		st.Unlocked++
		st.UnlockedBytes += p.Size
		note(p.Name, p.Sha16, p.PushedAt)
	}
	for _, b := range bundles {
		st.Bundles++
		st.BundledBytes += b.Bytes
		for _, f := range b.Files {
			note(f.Name, f.PlainSha16, f.PushedAt)
			if f.PushedAt.After(st.LockedTo) {
				st.LockedTo = f.PushedAt
			}
		}
	}
	st.Files = len(when)
	for n, s := range shas {
		if len(s) > 1 {
			st.Conflicts = append(st.Conflicts, n)
		}
	}
	sort.Strings(st.Conflicts)
	if len(st.Bases) == 0 {
		return st, nil
	}

	segSize := st.Bases[len(st.Bases)-1].SegmentSize
	// Per timeline, the archived segment numbers, and where each timeline
	// begins: its first archived segment. After a promotion PostgreSQL
	// writes the new timeline from the segment holding the switch, and a
	// replay reads each segment from the newest timeline that has begun by
	// then, as restore_command's recovery_target_timeline = 'latest' does.
	// That is read from the names alone, so it needs no key; a timeline that
	// forked from an older one than its predecessor is read as linear.
	byTLI := map[uint32]map[uint64]time.Time{}
	begin := map[uint32]uint64{}
	var top uint64
	for n, t := range when {
		tli, seg, err := parseSegName(n, segSize)
		if err != nil {
			continue
		}
		if byTLI[tli] == nil {
			byTLI[tli] = map[uint64]time.Time{}
		}
		byTLI[tli][seg] = t
		if b, ok := begin[tli]; !ok || seg < b {
			begin[tli] = seg
		}
		if seg > top {
			top = seg
		}
	}
	var tlis []uint32
	for t := range begin {
		tlis = append(tlis, t)
	}
	sort.Slice(tlis, func(i, j int) bool { return tlis[i] > tlis[j] })
	// expected is the timeline a replay that started on from reads seg on.
	expected := func(seg uint64, from uint32) uint32 {
		for _, t := range tlis {
			if t >= from && begin[t] <= seg {
				return t
			}
		}
		return from
	}

	// Each base replays from its first segment until the first one missing.
	// The window ends where the longest replay ends, and starts at the end
	// of the oldest base that replays that far.
	gaps := map[string]*Gap{}
	for _, b := range st.Bases {
		tli, seg, err := parseSegName(b.StartWAL, segSize)
		if err != nil {
			continue
		}
		_, endSeg, _ := parseSegName(b.EndWAL, segSize)
		var to time.Time
		reached := false
		for s := seg; s <= top; s++ {
			t := expected(s, tli)
			if at, have := byTLI[t][s]; have {
				to, reached = at, s >= endSeg
				continue
			}
			// The replay stops here. A gap another base met first is
			// reported once, with every base it breaks.
			name := segName(t, s, segSize)
			if g, ok := gaps[name]; ok {
				g.Breaks = append(g.Breaks, b.BaseID)
				break
			}
			g := &Gap{Timeline: t, First: name, Last: name, Breaks: []string{b.BaseID}, Before: to}
			for s2 := s + 1; s2 <= top; s2++ {
				t2 := expected(s2, tli)
				if _, ok := byTLI[t2][s2]; ok {
					break
				}
				g.Last = segName(t2, s2, segSize)
			}
			gaps[name] = g
			break
		}
		if !reached {
			continue // the base never becomes consistent
		}
		if !st.HasWindow || to.After(st.WindowTo) {
			st.HasWindow, st.WindowFrom, st.WindowTo = true, b.EndedAt, to
		} else if to.Equal(st.WindowTo) && b.EndedAt.Before(st.WindowFrom) {
			st.WindowFrom = b.EndedAt
		}
	}
	// Each gap is the first a replay meets; one after it, with no base in
	// between, shows once the first is filled.
	for _, g := range gaps {
		st.Gaps = append(st.Gaps, *g)
	}
	sort.Slice(st.Gaps, func(i, j int) bool { return st.Gaps[i].First < st.Gaps[j].First })
	return st, nil
}
