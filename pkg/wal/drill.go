package wal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// DrillPlan is what a point-in-time drill restores: the newest restore point
// the archive can reach and the base backup before it, and the newest base
// for a replay to the end of the archive, with every WAL file each needs.
type DrillPlan struct {
	// Point is nil when no recorded restore point can be reached; then only
	// the replay to the end is drilled.
	Point     *RestorePoint
	PointBase BaseInfo
	EndBase   BaseInfo
	// PointFiles and EndFiles are the archived WAL files each replay reads.
	PointFiles []string
	EndFiles   []string
	// LastSegment is the newest archived segment: the replay to the end has
	// to reach it.
	LastSegment string
	SegSize     uint64
}

// ReachedEnd says a replay that ended at lsn read the newest archived
// segment.
func (p DrillPlan) ReachedEnd(lsn LSN) bool {
	_, last, err := parseSegName(p.LastSegment, p.SegSize)
	return err == nil && uint64(lsn)/p.SegSize >= last
}

// PlanDrill works out a drill from what the archive holds.
func (a *Archive) PlanDrill(ctx context.Context) (DrillPlan, error) {
	var p DrillPlan
	bases, _, err := a.Bases(ctx)
	if err != nil {
		return p, err
	}
	if len(bases) == 0 {
		return p, errors.New("the archive holds no complete base backup")
	}
	have, err := a.archivedNames(ctx)
	if err != nil {
		return p, err
	}
	segSize := bases[len(bases)-1].SegmentSize
	p.SegSize = segSize
	var top uint64
	for n := range have {
		_, seg, err := parseSegName(n, segSize)
		if err != nil {
			continue
		}
		if seg > top || (seg == top && n > p.LastSegment) {
			top, p.LastSegment = seg, n
		}
	}
	p.EndBase = bases[len(bases)-1]
	points, err := a.RestorePoints(ctx)
	if err != nil {
		return p, err
	}
	for i := len(points) - 1; i >= 0 && p.Point == nil; i-- {
		rp := points[i]
		lsn, err := ParseLSN(rp.LSN)
		if err != nil || uint64(lsn)/segSize > top {
			continue // its WAL is not archived yet
		}
		for j := len(bases) - 1; j >= 0; j-- {
			end, err := ParseLSN(bases[j].EndLSN)
			if err == nil && bases[j].EndedAt.Before(rp.At) && end <= lsn {
				p.Point, p.PointBase = &points[i], bases[j]
				break
			}
		}
	}
	p.EndFiles = filesFrom(have, p.EndBase, segSize, top)
	if p.Point != nil {
		lsn, _ := ParseLSN(p.Point.LSN)
		p.PointFiles = filesFrom(have, p.PointBase, segSize, uint64(lsn)/segSize)
	}
	return p, nil
}

// filesFrom lists the archived WAL files a replay from base up to segment
// last reads: every timeline's segments in that range, and every timeline
// history.
func filesFrom(have map[string]time.Time, base BaseInfo, segSize, last uint64) []string {
	_, first, err := parseSegName(base.StartWAL, segSize)
	if err != nil {
		return nil
	}
	var out []string
	for n := range have {
		if historyRe.MatchString(n) {
			out = append(out, n)
			continue
		}
		if _, seg, err := parseSegName(n, segSize); err == nil && seg >= first && seg <= last {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// StageWAL fetches each named WAL file into dir, for a restore_command that
// copies from there.
func (a *Archive) StageWAL(ctx context.Context, names []string, dir string) (int64, error) {
	var total int64
	for _, n := range names {
		f, err := os.OpenFile(filepath.Join(dir, n), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return total, err
		}
		cw := &countWriter{w: f}
		ferr := a.Fetch(ctx, n, cw)
		if cerr := f.Close(); ferr == nil {
			ferr = cerr
		}
		if ferr != nil {
			return total, fmt.Errorf("fetching %s for the drill: %w", n, ferr)
		}
		total += cw.n
	}
	return total, nil
}
