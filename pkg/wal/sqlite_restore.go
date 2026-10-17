package wal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/safegrd/cli/pkg/crypto"
)

// sqliteEntry is one SQLite segment the archive holds, unlocked or bundled.
type sqliteEntry struct {
	SQLiteSegment
	Name     string
	PushedAt time.Time
	// Key is the unlocked object, or Bundle and the place in it.
	Key           string
	Bundle        string
	Offset, Len   int64
	Sha16, Cipher string
}

// sqliteCatalog lists every SQLite segment once, so a restore reads each by
// its key instead of searching for it.
func (a *Archive) sqliteCatalog(ctx context.Context) (map[string][]sqliteEntry, error) {
	out := map[string][]sqliteEntry{}
	seen := map[string]bool{}
	bundles, err := a.Bundles(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range bundles {
		for _, f := range b.Files {
			seg, ok := ParseSQLiteSegment(f.Name)
			if !ok || seen[f.Name] {
				continue
			}
			seen[f.Name] = true
			out[seg.Generation] = append(out[seg.Generation], sqliteEntry{SQLiteSegment: seg, Name: f.Name, PushedAt: f.PushedAt,
				Bundle: b.BundleID, Offset: f.Offset, Len: f.Length, Sha16: f.PlainSha16, Cipher: f.CipherSha256})
		}
	}
	pushed, err := a.Pushed(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pushed {
		seg, ok := ParseSQLiteSegment(p.Name)
		if !ok || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		out[seg.Generation] = append(out[seg.Generation], sqliteEntry{SQLiteSegment: seg, Name: p.Name, PushedAt: p.PushedAt, Key: p.Key, Sha16: p.Sha16})
	}
	for g := range out {
		es := out[g]
		sort.Slice(es, func(i, j int) bool {
			if es[i].Salt1 != es[j].Salt1 {
				return es[i].Salt1 < es[j].Salt1
			}
			return es[i].Start < es[j].Start
		})
	}
	return out, nil
}

// sqliteRun is the unbroken run of a generation's segments from its base:
// each starts where the one before ended, or at the first frame of the next
// WAL. gap names the first segment out of place, if any.
func sqliteRun(base BaseInfo, es []sqliteEntry) (run []sqliteEntry, gap string) {
	salt, at := base.WALSalt1, int64(sqliteWALHeader)
	for _, e := range es {
		switch {
		case e.Salt1 == salt && e.Start == at:
		case e.Salt1 == salt+1 && e.Start == sqliteWALHeader:
		default:
			return run, e.Name
		}
		run = append(run, e)
		salt, at = e.Salt1, e.End
	}
	return run, ""
}

func (a *Archive) readSegment(ctx context.Context, e sqliteEntry) ([]byte, error) {
	var body []byte
	var err error
	if e.Bundle != "" {
		body, err = a.Store.GetRange(ctx, a.bundleKey(e.Bundle), e.Offset, e.Len)
		if err == nil {
			if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != e.Cipher {
				return nil, fmt.Errorf("%s in bundle %s does not match its index", e.Name, e.Bundle)
			}
		}
	} else {
		body, err = a.readCurrent(ctx, e.Key)
	}
	if err != nil {
		return nil, err
	}
	var plain bytes.Buffer
	if err := a.decryptTo(e.Name, body, e.Sha16, &plain); err != nil {
		return nil, err
	}
	return plain.Bytes(), nil
}

// SQLiteRestoreOptions is one SQLite restore.
type SQLiteRestoreOptions struct {
	// Target is the moment to restore to; zero restores everything.
	Target time.Time
	// Point restores to a recorded restore point instead.
	Point *RestorePoint
	// Out is the database file to write; it must not exist.
	Out string
}

// SQLiteRestoreResult is what a SQLite restore did.
type SQLiteRestoreResult struct {
	Base     BaseInfo
	Segments int
	// ReachedAt is when the last segment applied was pushed: the restore
	// holds every transaction committed by then, to within the follower's
	// interval.
	ReachedAt time.Time
}

// RestoreSQLite writes the database as it was at the target: the newest
// generation's base from before it, then every segment of the generation
// pushed by then, applied in order, whole transactions only. The result
// passes PRAGMA integrity_check or is removed.
func (a *Archive) RestoreSQLite(ctx context.Context, o SQLiteRestoreOptions) (SQLiteRestoreResult, error) {
	var res SQLiteRestoreResult
	if _, err := os.Stat(o.Out); err == nil {
		return res, fmt.Errorf("%s exists; a restore writes a new file", o.Out)
	}
	bases, _, err := a.Bases(ctx)
	if err != nil {
		return res, err
	}
	cat, err := a.sqliteCatalog(ctx)
	if err != nil {
		return res, err
	}
	var pick *BaseInfo
	for i := range bases {
		b := bases[i]
		switch {
		case b.Kind != "sqlite":
		case o.Point != nil:
			if b.Generation == o.Point.Generation {
				pick = &bases[i]
			}
		case o.Target.IsZero() || !b.EndedAt.After(o.Target):
			pick = &bases[i]
		}
	}
	if pick == nil {
		if o.Point != nil {
			return res, fmt.Errorf("the archive holds no base for generation %s of restore point %s", o.Point.Generation, o.Point.Name)
		}
		return res, errors.New("the archive holds no SQLite base from before that moment")
	}
	run, gap := sqliteRun(*pick, cat[pick.Generation])
	var apply []sqliteEntry
	for _, e := range run {
		switch {
		case o.Point != nil:
			if e.Salt1 > o.Point.WALSalt1 || (e.Salt1 == o.Point.WALSalt1 && e.End > o.Point.WALOffset) {
				continue
			}
		case !o.Target.IsZero() && e.PushedAt.After(o.Target):
			continue
		}
		apply = append(apply, e)
	}
	if o.Point != nil {
		last := SQLiteSegment{Salt1: pick.WALSalt1, End: sqliteWALHeader}
		if n := len(apply); n > 0 {
			last = apply[n-1].SQLiteSegment
		}
		if last.Salt1 != o.Point.WALSalt1 || last.End != o.Point.WALOffset {
			if gap != "" {
				return res, fmt.Errorf("the archive is missing WAL before restore point %s (first out of place: %s)", o.Point.Name, gap)
			}
			return res, fmt.Errorf("the archive's WAL does not reach restore point %s", o.Point.Name)
		}
	} else if !o.Target.IsZero() && gap != "" && (len(run) == 0 || run[len(run)-1].PushedAt.Before(o.Target)) {
		return res, fmt.Errorf("the archive is missing WAL after %s (first out of place: %s), before the moment asked for", timeOr(run), gap)
	}

	tmp := o.Out + ".restoring"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return res, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	rc, err := a.Store.Get(ctx, a.baseKey(pick.BaseID, "base.db.zst.age"))
	if err != nil {
		return res, fmt.Errorf("reading base %s: %w", pick.BaseID, err)
	}
	m, err := crypto.DecryptStream(rc, f, a.Identity)
	rc.Close()
	if err != nil {
		return res, fmt.Errorf("decrypting base %s: %w", pick.BaseID, err)
	}
	if m.RawSha256 != pick.TarSha256 {
		return res, fmt.Errorf("base %s decrypts to other bytes than were written", pick.BaseID)
	}
	var size uint32
	for _, e := range apply {
		frames, err := a.readSegment(ctx, e)
		if err != nil {
			return res, err
		}
		n, err := applyFrames(f, frames, pick.PageSize)
		if err != nil {
			return res, fmt.Errorf("%s: %w", e.Name, err)
		}
		if n != 0 {
			size = n
		}
		res.ReachedAt = e.PushedAt
	}
	if size != 0 {
		if err := f.Truncate(int64(size) * int64(pick.PageSize)); err != nil {
			return res, err
		}
	}
	if err := f.Sync(); err != nil {
		return res, err
	}
	if err := f.Close(); err != nil {
		return res, err
	}
	if err := sqliteIntegrity(ctx, tmp); err != nil {
		return res, err
	}
	if err := os.Rename(tmp, o.Out); err != nil {
		return res, err
	}
	ok = true
	res.Base, res.Segments = *pick, len(apply)
	if res.ReachedAt.IsZero() {
		res.ReachedAt = pick.EndedAt
	}
	return res, nil
}

func timeOr(run []sqliteEntry) string {
	if len(run) == 0 {
		return "the base"
	}
	return run[len(run)-1].PushedAt.UTC().Format("2006-01-02 15:04:05 UTC")
}

// sqliteIntegrity opens a restored file, read-only and with no WAL beside it,
// and runs PRAGMA integrity_check.
func sqliteIntegrity(ctx context.Context, path string) error {
	for _, side := range []string{"-wal", "-shm"} {
		_ = os.Remove(path + side)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return err
	}
	defer db.Close()
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&res); err != nil {
		return fmt.Errorf("integrity_check on the restored database: %w", err)
	}
	if res != "ok" {
		return fmt.Errorf("the restored database fails PRAGMA integrity_check: %s", res)
	}
	return nil
}

// SQLiteCounts counts every table of a restored database.
func SQLiteCounts(ctx context.Context, path string) (map[string]int64, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	out := map[string]int64{}
	for _, n := range names {
		var c int64
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+quoteSQLite(n)).Scan(&c); err != nil {
			return nil, err
		}
		out[n] = c
	}
	return out, nil
}

// SQLiteStatus is the window a SQLite archive restores: from the oldest base
// whose generation runs unbroken, to the newest segment of the generation
// that runs furthest.
func (a *Archive) SQLiteStatus(ctx context.Context) (Status, error) {
	var st Status
	bases, inc, err := a.Bases(ctx)
	if err != nil {
		return st, err
	}
	st.Incomplete = inc
	cat, err := a.sqliteCatalog(ctx)
	if err != nil {
		return st, err
	}
	pushed, err := a.Pushed(ctx)
	if err != nil {
		return st, err
	}
	for _, p := range pushed {
		st.Unlocked++
		st.UnlockedBytes += p.Size
		if p.PushedAt.After(st.NewestPush) {
			st.NewestPush = p.PushedAt
		}
	}
	bundles, err := a.Bundles(ctx)
	if err != nil {
		return st, err
	}
	for _, b := range bundles {
		st.Bundles++
		st.BundledBytes += b.Bytes
		for _, f := range b.Files {
			if f.PushedAt.After(st.LockedTo) {
				st.LockedTo = f.PushedAt
			}
			if f.PushedAt.After(st.NewestPush) {
				st.NewestPush = f.PushedAt
			}
		}
	}
	for _, es := range cat {
		st.Files += len(es)
	}
	// Each generation restores from its base's end to its last segment in
	// an unbroken run. The window is the newest generation's span, reaching
	// back through each earlier one whose run lasted until the next base.
	type span struct{ from, to time.Time }
	var spans []span
	for _, b := range bases {
		if b.Kind != "sqlite" {
			continue
		}
		st.Bases = append(st.Bases, b)
		run, gap := sqliteRun(b, cat[b.Generation])
		if gap != "" {
			st.Gaps = append(st.Gaps, Gap{First: gap, Last: gap, Breaks: []string{b.BaseID}})
		}
		to := b.EndedAt
		if n := len(run); n > 0 {
			to = run[n-1].PushedAt
		}
		spans = append(spans, span{b.EndedAt, to})
	}
	if n := len(spans); n > 0 {
		st.HasWindow, st.WindowFrom, st.WindowTo = true, spans[n-1].from, spans[n-1].to
		for i := n - 2; i >= 0 && !spans[i].to.Before(spans[i+1].from.Add(-time.Minute)); i-- {
			st.WindowFrom = spans[i].from
		}
	}
	return st, nil
}
