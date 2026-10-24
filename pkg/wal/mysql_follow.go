package wal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/dump"
)

// MySQLServer is what the follower and a base read about a server before
// they start.
type MySQLServer struct {
	MariaDB  bool
	Version  string
	SystemID string
	// File and Pos are the binary log's current end.
	File string
	Pos  uint64
	// Files are the binary log files the server still has, oldest first.
	Files []string
}

// sqlString reads one value; a NULL reads as "".
func sqlString(ctx context.Context, db *sql.DB, q string) (string, error) {
	var v sql.NullString
	err := db.QueryRowContext(ctx, q).Scan(&v)
	return v.String, err
}

// InspectMySQL checks the server keeps a binary log a restore can replay,
// and reads its identity and position. The account needs REPLICATION
// CLIENT (BINLOG MONITOR on MariaDB) for the position and the files.
func InspectMySQL(ctx context.Context, databaseURL string) (MySQLServer, error) {
	var s MySQLServer
	db, err := dump.OpenMySQL(databaseURL)
	if err != nil {
		return s, err
	}
	defer db.Close()
	if s.Version, err = sqlString(ctx, db, "SELECT VERSION()"); err != nil {
		return s, fmt.Errorf("connecting: %w", err)
	}
	s.MariaDB = strings.Contains(strings.ToLower(s.Version), "mariadb")
	logBin, err := sqlString(ctx, db, "SELECT @@log_bin")
	if err != nil {
		return s, err
	}
	if logBin != "1" && !strings.EqualFold(logBin, "ON") {
		if s.MariaDB {
			return s, errors.New("the binary log is off on this server (log_bin), so there is nothing to follow. Set log_bin and server_id in its configuration and restart it")
		}
		return s, errors.New("the binary log is off on this server (log_bin), so there is nothing to follow. Remove skip-log-bin (or disable-log-bin) from its configuration and restart it")
	}
	format, err := sqlString(ctx, db, "SELECT @@binlog_format")
	if err != nil {
		return s, err
	}
	if !strings.EqualFold(format, "ROW") {
		return s, fmt.Errorf("binlog_format is %s; a replay needs ROW. Set binlog_format = ROW in the server's configuration", format)
	}
	if !s.MariaDB {
		if c, err := sqlString(ctx, db, "SELECT @@binlog_transaction_compression"); err == nil && (c == "1" || strings.EqualFold(c, "ON")) {
			return s, errors.New("binlog_transaction_compression is ON; the follower reads which database each change is in and cannot read inside a compressed transaction. Turn it off to follow this server")
		}
	}
	// The identity: MySQL's server_uuid; MariaDB has none, so its server
	// id, its binary log's base name and its GTID domain.
	var ident string
	if s.MariaDB {
		var id, base, domain string
		if err := db.QueryRowContext(ctx, "SELECT @@server_id, COALESCE(@@log_bin_basename, ''), @@gtid_domain_id").Scan(&id, &base, &domain); err != nil {
			return s, err
		}
		ident = "mariadb:" + id + ":" + base + ":" + domain
	} else {
		u, err := sqlString(ctx, db, "SELECT @@server_uuid")
		if err != nil {
			return s, err
		}
		ident = "mysql:" + u
	}
	sum := sha256.Sum256([]byte(ident))
	s.SystemID = strconv.FormatUint(binary.BigEndian.Uint64(sum[:8])>>1|1<<62, 10)

	status := "SHOW BINARY LOG STATUS"
	if s.MariaDB {
		status = "SHOW MASTER STATUS"
	}
	rows, err := db.QueryContext(ctx, status)
	if err != nil && !s.MariaDB {
		rows, err = db.QueryContext(ctx, "SHOW MASTER STATUS")
	}
	if err != nil {
		return s, fmt.Errorf("reading the binary log position: %w. Grant %s ON *.* to this account", err, mysqlMonitorGrant(s.MariaDB))
	}
	if err := scanFirstTwo(rows, &s.File, &s.Pos); err != nil {
		return s, err
	}
	if s.File == "" {
		return s, fmt.Errorf("%s returned no row: this account may not read the position. Grant %s ON *.* to it", status, mysqlMonitorGrant(s.MariaDB))
	}
	rows, err = db.QueryContext(ctx, "SHOW BINARY LOGS")
	if err != nil {
		return s, fmt.Errorf("listing the binary log files: %w. Grant %s ON *.* to this account", err, mysqlMonitorGrant(s.MariaDB))
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		var name string
		vals[0] = &name
		for i := 1; i < len(vals); i++ {
			vals[i] = new(sql.RawBytes)
		}
		if err := rows.Scan(vals...); err != nil {
			return s, err
		}
		s.Files = append(s.Files, name)
	}
	return s, rows.Err()
}

func scanFirstTwo(rows *sql.Rows, file *string, pos *uint64) error {
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	if !rows.Next() {
		return rows.Err()
	}
	vals := make([]any, len(cols))
	vals[0] = file
	vals[1] = pos
	for i := 2; i < len(vals); i++ {
		vals[i] = new(sql.RawBytes)
	}
	return rows.Scan(vals...)
}

func mysqlMonitorGrant(mariaDB bool) string {
	if mariaDB {
		return "BINLOG MONITOR"
	}
	return "REPLICATION CLIENT"
}

// MySQLFollowerStatus is what the follower last did, for the daemon to say.
type MySQLFollowerStatus struct {
	Following bool
	File      string
	Pos       uint64
	LastPush  time.Time
	LastError string
}

// MySQLFollower follows one server's binary log into an archive.
type MySQLFollower struct {
	Archive *Archive
	URL     string
	// Interval is how often completed transactions are pushed.
	Interval time.Duration
	// ServerID is the replica id the follower gives the server; zero
	// derives one from the surface id.
	ServerID    uint32
	Logf, Warnf func(format string, args ...any)
	// OnGap is called when the follower could not resume where the
	// archive ends and started a new run: a new base is needed.
	OnGap func()

	mu     sync.Mutex
	status MySQLFollowerStatus
}

// Status is what the follower last did.
func (f *MySQLFollower) Status() MySQLFollowerStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *MySQLFollower) note(fn func(*MySQLFollowerStatus)) {
	f.mu.Lock()
	fn(&f.status)
	f.mu.Unlock()
}

func (f *MySQLFollower) logf(format string, args ...any) {
	if f.Logf != nil {
		f.Logf(format, args...)
	}
}

func (f *MySQLFollower) warnf(format string, args ...any) {
	if f.Warnf != nil {
		f.Warnf(format, args...)
	}
}

func (f *MySQLFollower) serverID() uint32 {
	if f.ServerID != 0 {
		return f.ServerID
	}
	h := fnv.New32a()
	h.Write([]byte("safegrd:" + f.Archive.SurfaceID))
	return 1<<31 | h.Sum32()&(1<<31-1)
}

// Run follows the binary log until ctx ends. A failure closes the
// connection and starts again after a pause, resuming where the archive
// ends.
func (f *MySQLFollower) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := f.Follow(ctx)
		if ctx.Err() != nil {
			return
		}
		f.note(func(s *MySQLFollowerStatus) { s.Following, s.LastError = false, err.Error() })
		f.warnf("following the binary log: %v. Starting again in 30s", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

// Follow follows until ctx ends or the connection fails.
func (f *MySQLFollower) Follow(ctx context.Context) error {
	srv, err := InspectMySQL(ctx, f.URL)
	if err != nil {
		return err
	}
	f.Archive.SystemID = srv.SystemID
	file, pos, err := f.startAt(ctx, srv)
	if err != nil {
		return err
	}
	ci, err := dump.MySQLConnectionInfo(f.URL)
	if err != nil {
		return err
	}
	ci.Database = ""
	c, err := dialMySQL(ctx, ci)
	if err != nil {
		return fmt.Errorf("connecting for the binary log: %w", err)
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	// The stream carries checksums, and heartbeats every 30 seconds when
	// nothing is written. MySQL renamed the variables in 8.0.26 and
	// MariaDB kept the old names, so both are set and a refusal ignored.
	for _, q := range []string{
		"SET @source_binlog_checksum = @@global.binlog_checksum",
		"SET @master_binlog_checksum = @@global.binlog_checksum",
		"SET @source_heartbeat_period = 30000000000",
		"SET @master_heartbeat_period = 30000000000",
		"SET @mariadb_slave_capability = 4",
	} {
		_ = c.exec(q) // each server knows some of them
	}
	if err := c.dumpBinlog(file, uint32(pos), f.serverID(), 0); err != nil {
		return err
	}
	f.note(func(s *MySQLFollowerStatus) { s.Following, s.File, s.Pos, s.LastError = true, file, pos, "" })
	f.logf("following the binary log from %s at %d", file, pos)

	type got struct {
		raw []byte
		err error
	}
	events := make(chan got, 256)
	go func() {
		for {
			_ = c.nc.SetReadDeadline(time.Now().Add(100 * time.Second))
			raw, err := c.readEvent()
			select {
			case events <- got{raw, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	num, err := binlogFileNumber(file)
	if err != nil {
		return err
	}
	st := &mysqlStreamState{f: f, fileName: file, file: num, start: pos, end: pos, lastPush: time.Now()}
	tick := time.NewTicker(f.interval())
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err := st.flush(ctx, false); err != nil {
				return err
			}
		case g := <-events:
			if g.err == io.EOF {
				return errors.New("the server ended the binary log stream")
			}
			if g.err != nil {
				return g.err
			}
			if err := st.take(ctx, g.raw); err != nil {
				return err
			}
		}
	}
}

func (f *MySQLFollower) interval() time.Duration {
	if f.Interval > 0 {
		return f.Interval
	}
	return 5 * time.Second
}

// startAt is where the follower asks the server to start: after the
// archive's newest segment when the server still has that file, else the
// server's current end, with the gap said.
func (f *MySQLFollower) startAt(ctx context.Context, srv MySQLServer) (string, uint64, error) {
	last, ok, err := f.Archive.StreamCatalogEnd(ctx, StreamMySQL)
	if err != nil {
		return "", 0, err
	}
	if !ok {
		return srv.File, srv.Pos, nil
	}
	num, pos := last.File, last.End
	if last.Rotates {
		num, pos = last.File+1, 4
	}
	name := binlogFileName(srv.File, num)
	for _, have := range srv.Files {
		if have == name {
			return name, pos, nil
		}
	}
	if fn, _ := binlogFileNumber(srv.File); last.Rotates && num > fn {
		// The archive ends at a rotate the server has not finished.
		return srv.File, srv.Pos, nil
	}
	f.warnf("the server no longer has %s, where the archive ends (it was purged while nothing followed). "+
		"The archive has a gap from there, and restores reach past it only from the next base backup, which the daemon takes now. "+
		"Following from %s at %d", name, srv.File, srv.Pos)
	if f.OnGap != nil {
		f.OnGap()
	}
	return srv.File, srv.Pos, nil
}

// mysqlStreamState is the follower's place in the stream: the file it
// reads, the start of the segment being gathered, and the transactions
// complete since.
type mysqlStreamState struct {
	f        *MySQLFollower
	fd       formatDesc
	haveFD   bool
	fileName string
	file     uint32
	start    uint64 // where the next segment starts
	end      uint64 // the end of the last complete transaction
	ready    []binlogEvent
	g        txGrouper
	lastPush time.Time
}

func (s *mysqlStreamState) take(ctx context.Context, raw []byte) error {
	e, err := parseEventHeader(raw)
	if err != nil {
		return err
	}
	switch e.Type {
	case evHeartbeat, evHeartbeatV2:
		return nil
	case evFormatDesc:
		fd, err := parseFormatDesc(raw)
		if err != nil {
			return err
		}
		s.fd, s.haveFD = fd, true
		s.g.fd = fd
		return nil
	case evRotate:
		if e.LogPos == 0 || e.Flags&flagArtificial != 0 {
			return nil // the server saying which file it starts in
		}
	}
	if !s.haveFD {
		return errors.New("the server sent an event before the format description")
	}
	// MariaDB sends the events inside a transaction with no end position
	// (0); only the flag marks an event the server made up.
	if e.Flags&flagArtificial != 0 {
		return nil
	}
	if err := s.fd.checkCRC(e); err != nil {
		return err
	}
	if e.Type == evTxPayload {
		return fmt.Errorf("the server wrote a compressed transaction at %s %d (binlog_transaction_compression is on for some session). "+
			"The follower cannot tell which database it changed, so it stops here rather than archive a log a restore would replay wrongly. "+
			"Turn binlog_transaction_compression off for every session", s.fileName, e.start())
	}
	tx := s.g.add(e)
	if tx == nil {
		return nil
	}
	s.ready = append(s.ready, tx.Events...)
	s.end = uint64(tx.end())
	if e.Type == evRotate {
		// The file ends here. Push what it holds, and the next file starts
		// at its beginning.
		next, err := s.rotateTarget(e)
		if err != nil {
			return err
		}
		if err := s.flush(ctx, true); err != nil {
			return err
		}
		num, err := binlogFileNumber(next)
		if err != nil {
			return err
		}
		s.fileName, s.file, s.start, s.end, s.haveFD = next, num, 4, 4, false
	}
	return nil
}

func (s *mysqlStreamState) rotateTarget(e binlogEvent) (string, error) {
	b := s.fd.body(e)
	if len(b) < 8 {
		return "", errors.New("a short rotate event")
	}
	return string(b[8:]), nil
}

// flush pushes the transactions complete since the last push as one
// segment. With nothing complete, it pushes an empty segment once a minute
// so the archive says the follower was caught up then.
func (s *mysqlStreamState) flush(ctx context.Context, rotates bool) error {
	if !s.haveFD {
		return nil
	}
	seg := StreamSeg{File: s.file, Start: s.start, End: s.end, Rotates: rotates}
	if len(s.ready) == 0 && !rotates {
		if s.g.pending() || time.Since(s.lastPush) < time.Minute {
			return nil
		}
		seg.Start = s.end
		seg.Idle = uint32(time.Now().Unix())
	}
	name := mysqlSegName(seg)
	if err := s.f.Archive.PushNew(ctx, name, segmentBody(s.fd, s.ready)); err != nil {
		return fmt.Errorf("pushing %s: %w", name, err)
	}
	s.ready, s.start, s.lastPush = nil, s.end, time.Now()
	s.f.note(func(st *MySQLFollowerStatus) {
		st.File, st.Pos, st.LastPush, st.LastError = s.fileName, s.end, time.Now().UTC(), ""
	})
	return nil
}

// MySQLStreamCheck is what doctor learns about following a server.
type MySQLStreamCheck struct {
	Server MySQLServer
	// RowImage is binlog_row_image; Retention how long the server keeps
	// its binary log (zero when it purges none by age).
	RowImage  string
	Retention time.Duration
	// LockGrant says the account may hold FLUSH TABLES WITH READ LOCK
	// (MySQL), which a base and a restore point need.
	LockGrant bool
}

// CheckMySQLStream reads what following the server needs, and asks for the
// binary log once, without waiting, so a missing REPLICATION SLAVE grant is
// found here and not by the daemon.
func CheckMySQLStream(ctx context.Context, databaseURL string) (MySQLStreamCheck, error) {
	var out MySQLStreamCheck
	srv, err := InspectMySQL(ctx, databaseURL)
	out.Server = srv
	if err != nil {
		return out, err
	}
	db, err := dump.OpenMySQL(databaseURL)
	if err != nil {
		return out, err
	}
	defer db.Close()
	out.RowImage, _ = sqlString(ctx, db, "SELECT @@binlog_row_image")
	if v, err := sqlString(ctx, db, "SELECT @@binlog_expire_logs_seconds"); err == nil {
		if n, _ := strconv.ParseInt(v, 10, 64); n > 0 {
			out.Retention = time.Duration(n) * time.Second
		}
	}
	if out.Retention == 0 {
		if v, err := sqlString(ctx, db, "SELECT @@expire_logs_days"); err == nil {
			if d, _ := strconv.ParseFloat(v, 64); d > 0 {
				out.Retention = time.Duration(d * float64(24*time.Hour))
			}
		}
	}
	out.LockGrant = srv.MariaDB
	if !srv.MariaDB {
		if rows, err := db.QueryContext(ctx, "SHOW GRANTS"); err == nil {
			for rows.Next() {
				var g string
				if rows.Scan(&g) == nil {
					u := strings.ToUpper(g)
					if strings.Contains(u, " ON *.*") && (strings.Contains(u, "FLUSH_TABLES") || strings.Contains(u, "RELOAD") || strings.Contains(u, "ALL PRIVILEGES")) {
						out.LockGrant = true
					}
				}
			}
			rows.Close()
		}
	}
	ci, err := dump.MySQLConnectionInfo(databaseURL)
	if err != nil {
		return out, err
	}
	ci.Database = ""
	c, err := dialMySQL(ctx, ci)
	if err != nil {
		return out, fmt.Errorf("connecting for the binary log: %w", err)
	}
	defer c.Close()
	_ = c.exec("SET @source_binlog_checksum = @@global.binlog_checksum")
	_ = c.exec("SET @master_binlog_checksum = @@global.binlog_checksum")
	_ = c.exec("SET @mariadb_slave_capability = 4")
	_ = c.nc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := c.dumpBinlog(srv.File, uint32(srv.Pos), 1<<31|12345, 1); err != nil {
		return out, err
	}
	for {
		_, err := c.readEvent()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			var me *MySQLError
			if errors.As(err, &me) && (me.Code == 1227 || me.Code == 1045) {
				return out, fmt.Errorf("this account may not read the binary log (%v). Grant REPLICATION SLAVE ON *.* to it", err)
			}
			return out, fmt.Errorf("reading the binary log: %w", err)
		}
	}
}
