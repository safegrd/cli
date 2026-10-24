package wal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/dump"
)

// MySQLBase dumps the surface's database with the binary log position its
// snapshot sits at, into the archive as one locked object. A dump the tool
// wrote no position into fails and stores nothing.
func (a *Archive) MySQLBase(ctx context.Context, databaseURL string) (BaseInfo, error) {
	srv, err := InspectMySQL(ctx, databaseURL)
	if err != nil {
		return BaseInfo{}, err
	}
	a.SystemID = srv.SystemID
	ci, err := dump.MySQLConnectionInfo(databaseURL)
	if err != nil {
		return BaseInfo{}, err
	}
	d := dump.NewMySQLDumper(databaseURL)
	d.WithPosition = true
	info := BaseInfo{Kind: StreamMySQL, Source: ci.Addr}
	return a.putStreamBase(ctx, info, func(w io.Writer) (*StreamPos, error) {
		if _, err := d.Dump(ctx, ci.Database, w); err != nil {
			return nil, err
		}
		num, err := binlogFileNumber(d.Position.File)
		if err != nil {
			return nil, err
		}
		return &StreamPos{Engine: StreamMySQL, Database: ci.Database, MariaDB: srv.MariaDB, File: d.Position.File, FileNum: num,
			Pos: d.Position.Pos, GTIDs: d.Position.GTIDs}, nil
	})
}

// MySQLRestorePoint records the binary log position and every table's row
// count, read in one snapshot the position belongs to: on MySQL under FLUSH
// TABLES WITH READ LOCK for the moment the snapshot opens, on MariaDB from
// the snapshot's own binlog_snapshot_file and binlog_snapshot_position.
func (a *Archive) MySQLRestorePoint(ctx context.Context, databaseURL string) (RestorePoint, error) {
	var rp RestorePoint
	srv, err := InspectMySQL(ctx, databaseURL)
	if err != nil {
		return rp, err
	}
	a.SystemID = srv.SystemID
	db, err := dump.OpenMySQL(databaseURL)
	if err != nil {
		return rp, err
	}
	defer db.Close()
	reader, err := db.Conn(ctx)
	if err != nil {
		return rp, err
	}
	defer reader.Close()
	var file string
	var pos uint64
	if srv.MariaDB {
		if _, err := reader.ExecContext(ctx, "START TRANSACTION WITH CONSISTENT SNAPSHOT"); err != nil {
			return rp, err
		}
		for _, v := range []struct {
			name string
			dst  any
		}{{"binlog_snapshot_file", &file}, {"binlog_snapshot_position", &pos}} {
			var n string
			if err := reader.QueryRowContext(ctx, "SHOW STATUS LIKE '"+v.name+"'").Scan(&n, v.dst); err != nil {
				return rp, fmt.Errorf("reading %s: %w", v.name, err)
			}
		}
	} else {
		lock, err := db.Conn(ctx)
		if err != nil {
			return rp, err
		}
		defer lock.Close()
		if _, err := lock.ExecContext(ctx, "SET SESSION lock_wait_timeout = 5"); err != nil {
			return rp, err
		}
		if _, err := lock.ExecContext(ctx, "FLUSH TABLES WITH READ LOCK"); err != nil {
			return rp, fmt.Errorf("holding writes for the moment the point's snapshot opens: %w. Grant FLUSH_TABLES ON *.* (RELOAD before MySQL 8.0.23)", err)
		}
		_, err = reader.ExecContext(ctx, "START TRANSACTION WITH CONSISTENT SNAPSHOT")
		if err == nil {
			var rows *sql.Rows
			rows, err = lock.QueryContext(ctx, "SHOW BINARY LOG STATUS")
			if err != nil {
				rows, err = lock.QueryContext(ctx, "SHOW MASTER STATUS")
			}
			if err == nil {
				err = scanFirstTwo(rows, &file, &pos)
			}
		}
		_, _ = lock.ExecContext(context.Background(), "UNLOCK TABLES")
		if err != nil {
			return rp, err
		}
	}
	defer reader.ExecContext(context.Background(), "ROLLBACK") //nolint:errcheck // a read-only snapshot
	if file == "" {
		return rp, errors.New("the server gave no binary log position for the snapshot")
	}
	num, err := binlogFileNumber(file)
	if err != nil {
		return rp, err
	}
	ci, _ := dump.MySQLConnectionInfo(databaseURL)
	now := a.now()
	rp = RestorePoint{Version: 1, Name: newID("r", now, randomHex()), SurfaceID: a.SurfaceID, SystemID: a.SystemID, At: now,
		LSN:    fmt.Sprintf("%s:%d", file, pos),
		Stream: &StreamPos{Engine: StreamMySQL, Database: ci.Database, MariaDB: srv.MariaDB, File: file, FileNum: num, Pos: pos}}
	rows, err := reader.QueryContext(ctx, `SELECT table_name, COALESCE(table_rows, 0) FROM information_schema.tables
		WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name`)
	if err != nil {
		return rp, err
	}
	var names []string
	for rows.Next() {
		var n string
		var est int64
		if err := rows.Scan(&n, &est); err != nil {
			rows.Close()
			return rp, err
		}
		if est > pointCountCap {
			rp.Skipped = append(rp.Skipped, n)
			continue
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		var c int64
		if err := reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+strings.ReplaceAll(n, "`", "``")+"`").Scan(&c); err != nil {
			return rp, fmt.Errorf("counting %s: %w", n, err)
		}
		rp.Tables = append(rp.Tables, TableCount{Table: n, Before: c, After: c})
	}
	if err := a.recordStreamPoint(ctx, rp); err != nil {
		return rp, fmt.Errorf("recording restore point %s: %w", rp.Name, err)
	}
	return rp, nil
}

// StreamRestoreOptions is one restore of a MySQL or MongoDB archive.
type StreamRestoreOptions struct {
	// Target is the moment to restore to; zero restores everything.
	Target time.Time
	// Point restores to a recorded restore point instead.
	Point *RestorePoint
	// TargetURL is the empty database the restore writes.
	TargetURL string
	// WorkDir holds the log files a replay reads; it is created under it
	// and removed after.
	WorkDir string
}

// StreamRestoreResult is what a restore did.
type StreamRestoreResult struct {
	Base BaseInfo
	// Transactions is how many transactions (MySQL) or oplog entries
	// (MongoDB) of the surface's database were replayed.
	Transactions int
	// ReachedAt is when the last one replayed committed, or the base's
	// end when none was.
	ReachedAt time.Time
	// ArchiveEnd is when the newest segment of the run was pushed.
	ArchiveEnd time.Time
}

// planStream picks the base and the run of segments a restore reads, and
// refuses one that would stop short of what was asked without saying so.
func (a *Archive) planStream(ctx context.Context, engine string, o StreamRestoreOptions) (*BaseInfo, []streamEntry, error) {
	bases, _, err := a.Bases(ctx)
	if err != nil {
		return nil, nil, err
	}
	cat, err := a.streamCatalog(ctx, engine)
	if err != nil {
		return nil, nil, err
	}
	pick := pickStreamBase(bases, engine, o.Target, o.Point)
	if pick == nil {
		if o.Point != nil {
			return nil, nil, fmt.Errorf("the archive holds no base from before restore point %s", o.Point.Name)
		}
		if o.Target.IsZero() {
			return nil, nil, errors.New("the archive holds no base backup yet. Take one with 'safegrd wal base'")
		}
		return nil, nil, fmt.Errorf("the archive holds no base backup that ended by %s", o.Target.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	run, gap := streamRun(cat, pick.Stream.FileNum, pick.Stream.Pos)
	if len(run) == 0 {
		return nil, nil, fmt.Errorf("the archive holds none of the log from base %s's position on (%s); the follower started after it", pick.BaseID, gap)
	}
	end := newestPush(run)
	switch {
	case o.Point != nil:
		p := o.Point.Stream
		last := run[len(run)-1]
		if p == nil || last.File < p.FileNum || (last.File == p.FileNum && last.End < p.Pos) {
			if gap != "" {
				return nil, nil, fmt.Errorf("the archive is missing the log before restore point %s (first out of place: %s)", o.Point.Name, gap)
			}
			return nil, nil, fmt.Errorf("the archive's log does not reach restore point %s yet", o.Point.Name)
		}
	case o.Target.IsZero():
		if gap != "" {
			return nil, nil, fmt.Errorf("the archive is missing the log after %s (first out of place: %s); give --to a moment before it", end.Format("2006-01-02 15:04:05 UTC"), gap)
		}
	case o.Target.After(end):
		if gap != "" {
			return nil, nil, fmt.Errorf("the archive is missing the log after %s (first out of place: %s), before the moment asked for", end.Format("2006-01-02 15:04:05 UTC"), gap)
		}
		return nil, nil, fmt.Errorf("the archive's log reaches %s; nothing later is archived yet", end.Format("2006-01-02 15:04:05 UTC"))
	}
	return pick, run, nil
}

// RestoreMySQL loads the base into an empty database and replays the
// binary log to the target: whole transactions of the surface's database,
// those committed at or before it.
func (a *Archive) RestoreMySQL(ctx context.Context, o StreamRestoreOptions) (StreamRestoreResult, error) {
	var res StreamRestoreResult
	base, run, err := a.planStream(ctx, StreamMySQL, o)
	if err != nil {
		return res, err
	}
	res.Base, res.ArchiveEnd, res.ReachedAt = *base, newestPush(run), base.EndedAt
	if err := a.loadBase(ctx, *base, dump.NewMySQLRestorer(o.TargetURL)); err != nil {
		return res, err
	}
	dir, err := os.MkdirTemp(o.WorkDir, "binlog-replay-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(dir)
	bp := base.Stream
	var files []string
	done := false
	for i, e := range run {
		if done {
			break
		}
		body, err := a.readStreamEntry(ctx, e)
		if err != nil {
			return res, err
		}
		fd, events, err := readSegmentBody(body)
		if err != nil {
			return res, fmt.Errorf("%s: %w", e.Name, err)
		}
		g := txGrouper{fd: fd}
		var keep []binlogEvent
		for _, ev := range events {
			t := g.add(ev)
			if t == nil {
				continue
			}
			if e.File == bp.FileNum && uint64(t.begin()) < bp.Pos {
				continue // in the base already
			}
			if p := o.Point; p != nil && p.Stream != nil && (e.File > p.Stream.FileNum || (e.File == p.Stream.FileNum && uint64(t.end()) > p.Stream.Pos)) {
				done = true
				break
			}
			if !o.Target.IsZero() && !txAtOrBefore(t, o.Target) {
				done = true
				break
			}
			kept, ok := filterTx(fd, t, bp.Database)
			if !ok {
				continue
			}
			keep = append(keep, kept...)
			res.Transactions++
			res.ReachedAt = t.At
		}
		if len(keep) == 0 {
			continue
		}
		f := filepath.Join(dir, fmt.Sprintf("%06d.bin", i))
		if err := os.WriteFile(f, segmentBody(fd, keep), 0o600); err != nil {
			return res, err
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return res, nil
	}
	if err := dump.MySQLReplay(ctx, dump.MySQLReplayOptions{TargetURL: o.TargetURL, SourceDB: bp.Database, Files: files, MariaDB: bp.MariaDB}); err != nil {
		return res, fmt.Errorf("replaying the binary log over base %s: %w. The target holds the base and part of the log; empty it before trying again", base.BaseID, err)
	}
	return res, nil
}

// txAtOrBefore says a transaction committed at or before target. A commit
// time known only to the second (MariaDB) counts as before only once that
// whole second is.
func txAtOrBefore(t *binlogTx, target time.Time) bool {
	if t.Exact {
		return !t.At.After(target)
	}
	return !t.At.Add(time.Second).After(target)
}

// loadBase decrypts a base into the restore every backup of its engine
// uses.
func (a *Archive) loadBase(ctx context.Context, b BaseInfo, r dump.Restorer) error {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(a.readStreamBase(ctx, b, pw)) }()
	_, err := r.Restore(ctx, pr)
	pr.CloseWithError(io.ErrClosedPipe)
	if err != nil {
		return fmt.Errorf("loading base %s: %w", b.BaseID, err)
	}
	return nil
}

// StreamPointReachable says a restore to point would find a base before it
// and the archive's log unbroken up to it.
func (a *Archive) StreamPointReachable(ctx context.Context, engine string, point RestorePoint) bool {
	_, _, err := a.planStream(ctx, engine, StreamRestoreOptions{Point: &point})
	return err == nil
}
