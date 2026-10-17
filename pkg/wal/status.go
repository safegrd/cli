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
	// Per timeline, the archived segment numbers.
	byTLI := map[uint32]map[uint64]time.Time{}
	for n, t := range when {
		tli, seg, err := parseSegName(n, segSize)
		if err != nil {
			continue
		}
		if byTLI[tli] == nil {
			byTLI[tli] = map[uint64]time.Time{}
		}
		byTLI[tli][seg] = t
	}
	// From each timeline's oldest base start to its newest segment, every
	// missing run is a gap.
	starts := map[uint32]uint64{}
	for _, b := range st.Bases {
		tli, seg, err := parseSegName(b.StartWAL, segSize)
		if err != nil {
			continue
		}
		if s, ok := starts[tli]; !ok || seg < s {
			starts[tli] = seg
		}
	}
	for tli, from := range starts {
		segs := byTLI[tli]
		var top uint64
		for s := range segs {
			if s > top {
				top = s
			}
		}
		var gap *Gap
		for s := from; s <= top; s++ {
			if _, ok := segs[s]; ok {
				if gap != nil {
					st.Gaps = append(st.Gaps, *gap)
					gap = nil
				}
				continue
			}
			if gap == nil {
				gap = &Gap{Timeline: tli, First: segName(tli, s, segSize)}
			}
			gap.Last = segName(tli, s, segSize)
		}
	}
	sort.Slice(st.Gaps, func(i, j int) bool { return st.Gaps[i].First < st.Gaps[j].First })

	// Each base replays from its first segment until the first one missing.
	// The window ends where the longest replay ends, and starts at the end
	// of the oldest base that replays that far.
	for _, b := range st.Bases {
		tli, seg, err := parseSegName(b.StartWAL, segSize)
		if err != nil {
			continue
		}
		_, endSeg, _ := parseSegName(b.EndWAL, segSize)
		segs := byTLI[tli]
		last, ok := uint64(0), false
		for s := seg; ; s++ {
			if _, have := segs[s]; !have {
				break
			}
			last, ok = s, true
		}
		for i := range st.Gaps {
			g := st.Gaps[i]
			_, gs, _ := parseSegName(g.First, segSize)
			if g.Timeline == tli && ((ok && gs == last+1) || (!ok && gs == seg)) {
				st.Gaps[i].Breaks = append(st.Gaps[i].Breaks, b.BaseID)
			}
		}
		if !ok || last < endSeg {
			continue // the base never becomes consistent
		}
		to := segs[last]
		if !st.HasWindow || to.After(st.WindowTo) {
			st.HasWindow, st.WindowFrom, st.WindowTo = true, b.EndedAt, to
		} else if to.Equal(st.WindowTo) && b.EndedAt.Before(st.WindowFrom) {
			st.WindowFrom = b.EndedAt
		}
	}
	return st, nil
}
