package wal

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
)

// BaseInfo is what a base backup covers. Its presence in the archive is what
// makes the base complete: it is written only once every WAL file the base
// needs is archived.
type BaseInfo struct {
	Version          int       `json:"version"`
	BaseID           string    `json:"base_id"`
	SurfaceID        string    `json:"surface_id"`
	SystemID         string    `json:"system_id"`
	StartedAt        time.Time `json:"started_at"`
	EndedAt          time.Time `json:"ended_at"`
	ServerVersionNum int       `json:"server_version_num"`
	SegmentSize      uint64    `json:"wal_segment_size"`
	Timeline         uint32    `json:"timeline"`
	StartLSN         string    `json:"start_lsn"`
	EndLSN           string    `json:"end_lsn"`
	// StartWAL and EndWAL are the first and last WAL file a restore from
	// this base needs before the database is consistent.
	StartWAL    string    `json:"start_wal"`
	EndWAL      string    `json:"end_wal"`
	TarBytes    int64     `json:"tar_bytes"`
	TarSha256   string    `json:"tar_sha256"`
	StoredBytes int64     `json:"stored_bytes"`
	LockedUntil time.Time `json:"locked_until,omitzero"`
	// ChecksumFailures counts the pages PostgreSQL read twice and found
	// failing their checksum as it sent the base, ChecksumFiles them by
	// file. The base holds those pages as they were read.
	ChecksumFailures int            `json:"checksum_failures,omitempty"`
	ChecksumFiles    map[string]int `json:"checksum_files,omitempty"`
	// Source is the server the base was taken from, as host:port, and
	// FromStandby says it was a standby: its WAL comes from the primary's
	// archive. ReplayLagSeconds is how far the standby's replay was behind
	// its primary's last commit when the base began.
	Source           string   `json:"source,omitempty"`
	FromStandby      bool     `json:"from_standby,omitempty"`
	ReplayLagSeconds *float64 `json:"replay_lag_seconds,omitempty"`

	// Kind is "sqlite" for a SQLite generation's base, a copy of the
	// database file; TarBytes and TarSha256 are then the file's. The
	// generation's WAL starts at the first frame of the WAL these salts head.
	Kind       string `json:"kind,omitempty"`
	Generation string `json:"generation,omitempty"`
	WALSalt1   uint32 `json:"wal_salt1,omitempty"`
	WALSalt2   uint32 `json:"wal_salt2,omitempty"`
	PageSize   uint32 `json:"page_size,omitempty"`
}

// Major is the PostgreSQL major version the base was taken from.
func (b BaseInfo) Major() int { return b.ServerVersionNum / 10000 }

func (a *Archive) baseKey(id, file string) string { return path.Join(a.prefix(), "base", id, file) }

// Server is what the replication protocol says about a cluster.
type Server struct {
	SystemID   string
	Timeline   uint32
	VersionNum int
	SegSize    uint64
	// Standby is a server in recovery: a standby, whose WAL its primary
	// archives.
	Standby bool
}

// Identify asks the cluster at connURL who it is, over a replication
// connection: the one a base backup takes, so a role that may not replicate
// is refused here and not halfway through.
func Identify(ctx context.Context, connURL string) (Server, error) {
	var s Server
	cfg, err := pgconn.ParseConfig(connURL)
	if err != nil {
		return s, fmt.Errorf("the connection URL does not parse: %w", err)
	}
	cfg.RuntimeParams["replication"] = "true"
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return s, fmt.Errorf("connecting for replication: %w. The role needs REPLICATION, and pg_hba.conf a 'replication' line for this host", err)
	}
	defer conn.Close(context.Background())
	rows, err := conn.Exec(ctx, "IDENTIFY_SYSTEM").ReadAll()
	if err != nil {
		return s, fmt.Errorf("IDENTIFY_SYSTEM: %w", err)
	}
	if len(rows) != 1 || len(rows[0].Rows) != 1 || len(rows[0].Rows[0]) < 2 {
		return s, fmt.Errorf("IDENTIFY_SYSTEM returned no row")
	}
	s.SystemID = string(rows[0].Rows[0][0])
	tli, err := strconv.ParseUint(string(rows[0].Rows[0][1]), 10, 32)
	if err != nil {
		return s, fmt.Errorf("IDENTIFY_SYSTEM timeline %q: %w", rows[0].Rows[0][1], err)
	}
	s.Timeline = uint32(tli)
	show := func(name string) (string, error) {
		r, err := conn.Exec(ctx, "SHOW "+name).ReadAll()
		if err != nil {
			return "", fmt.Errorf("SHOW %s: %w", name, err)
		}
		if len(r) != 1 || len(r[0].Rows) != 1 || len(r[0].Rows[0]) != 1 {
			return "", fmt.Errorf("SHOW %s returned no row", name)
		}
		return string(r[0].Rows[0][0]), nil
	}
	v, err := show("server_version_num")
	if err != nil {
		return s, err
	}
	if s.VersionNum, err = strconv.Atoi(v); err != nil {
		return s, fmt.Errorf("server_version_num %q: %w", v, err)
	}
	seg, err := show("wal_segment_size")
	if err != nil {
		return s, err
	}
	if s.SegSize, err = ParseSegmentSize(seg); err != nil {
		return s, err
	}
	// A standby replays its primary's WAL, which the primary archives; its
	// own archive_mode is about WAL it would write itself.
	if hs, err := show("in_hot_standby"); err == nil {
		s.Standby = hs == "on"
	} else if ro, err := show("transaction_read_only"); err == nil {
		s.Standby = ro == "on"
	}
	mode, err := show("archive_mode")
	if err != nil {
		return s, err
	}
	if mode == "off" && !s.Standby {
		return s, fmt.Errorf("archive_mode is off on this cluster, so no WAL reaches the archive and a base backup could not be restored. Set archive_mode = on and archive_command, and restart PostgreSQL")
	}
	return s, ValidSystemID(s.SystemID)
}

// BaseOptions are one base backup.
type BaseOptions struct {
	ConnURL string
	Server  Server
	// PgBasebackup is the binary to run; "" finds one.
	PgBasebackup string
	// WaitForWAL bounds how long the archive is polled for the base's last
	// WAL file after pg_basebackup returns.
	WaitForWAL time.Duration
	// BeforeWALCheck, when set, runs before each look for the base's WAL
	// in the archive: a host that spools its WAL uploads the spool there.
	BeforeWALCheck func(context.Context)
	// ListTablespaces, when set, stands in for Tablespaces.
	ListTablespaces func(ctx context.Context, connURL string) ([]Tablespace, error)
}

// Base takes a base backup with pg_basebackup and streams it into the
// archive as one locked object. The base is complete, and base.json written,
// only once every WAL file from its start to its end is archived.
func (a *Archive) Base(ctx context.Context, o BaseOptions) (BaseInfo, error) {
	// pg_basebackup writes one tar to stdout only for a cluster whose data
	// all lives in its data directory. Asked first, so a cluster with other
	// tablespaces is refused before anything is written to the archive.
	list := o.ListTablespaces
	if list == nil {
		list = Tablespaces
	}
	spaces, err := list(ctx, o.ConnURL)
	if err != nil {
		return BaseInfo{}, err
	}
	if len(spaces) > 0 {
		return BaseInfo{}, &TablespaceError{Spaces: spaces}
	}
	srv := o.Server
	a.SystemID = srv.SystemID
	bin := o.PgBasebackup
	if bin == "" {
		if bin, err = FindPgBasebackup(ctx, srv.VersionNum/10000); err != nil {
			return BaseInfo{}, err
		}
	}
	started := a.now()
	info := BaseInfo{Version: 1, BaseID: newID("b", started, randomHex()), SurfaceID: a.SurfaceID, SystemID: srv.SystemID,
		StartedAt: started, ServerVersionNum: srv.VersionNum, SegmentSize: srv.SegSize, FromStandby: srv.Standby}
	if cfg, err := pgconn.ParseConfig(o.ConnURL); err == nil {
		info.Source = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	}
	if srv.Standby {
		info.ReplayLagSeconds = replayLag(ctx, o.ConnURL)
	}
	// The lock is set when the upload starts, before the end is known: the
	// base has to outlive the window's oldest moment until the next base
	// ends, a base interval and the base's own duration later.
	if a.Store.Locks() {
		info.LockedUntil = started.Add(a.Window + a.BaseEvery + lockSlack)
	}

	// The password travels in a 0600 file named by PGPASSFILE, never on
	// the command line, which every user on the host reads from the
	// process table; pg_dump is run the same way.
	dsn, env, cleanup, err := dump.PgToolEnv(o.ConnURL)
	if err != nil {
		return info, err
	}
	defer cleanup()
	cmd := exec.CommandContext(ctx, bin, "-d", dsn, "-D", "-", "-Ft", "-X", "none", "--checkpoint=fast", "--no-password")
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return info, err
	}
	if err := cmd.Start(); err != nil {
		return info, fmt.Errorf("running %s: %w", bin, err)
	}
	// Nothing is written until the tar starts: a pg_basebackup that fails
	// before its first block would otherwise leave a locked empty object.
	tarStream := bufio.NewReaderSize(stdout, 64<<10)
	if _, err := tarStream.Peek(512); err != nil {
		waitErr := cmd.Wait()
		return info, fmt.Errorf("pg_basebackup wrote no backup: %v\n%s", errors.Join(waitErr, err), strings.TrimSpace(stderr.String()))
	}

	scanR, scanW := io.Pipe()
	scanned := make(chan tarFacts, 1)
	go func() {
		f := scanTar(scanR)
		_, _ = io.Copy(io.Discard, scanR) // the tar's trailing blocks
		scanned <- f
	}()
	upR, upW := io.Pipe()
	type putResult struct {
		lock time.Time
		err  error
	}
	put := make(chan putResult, 1)
	go func() {
		lock, err := a.Store.Put(ctx, a.baseKey(info.BaseID, "base.tar.zst.age"), upR, info.LockedUntil)
		upR.CloseWithError(io.ErrClosedPipe)
		put <- putResult{lock, err}
	}()
	stored := &countWriter{w: upW}
	m, encErr := crypto.EncryptStream(io.TeeReader(tarStream, scanW), stored, a.Recipient)
	scanW.Close()
	upW.CloseWithError(encErr)
	waitErr := cmd.Wait()
	pr := <-put
	putErr := pr.err
	info.LockedUntil = pr.lock
	facts := <-scanned
	// Pages that failed their checksum end the backup with an error after
	// every file was sent. The base is whole; what failed is counted on it.
	if waitErr != nil && encErr == nil && putErr == nil && facts.err == nil {
		if byFile, ok := checksumFailures(stderr.String()); ok {
			waitErr = nil
			info.ChecksumFiles = byFile
			for _, n := range byFile {
				info.ChecksumFailures += n
			}
		}
	}
	switch {
	case waitErr != nil:
		return info, fmt.Errorf("could not take a base backup with pg_basebackup: %w\n%s", waitErr, strings.TrimSpace(stderr.String()))
	case encErr != nil:
		return info, fmt.Errorf("encrypting the base backup: %w", encErr)
	case putErr != nil:
		return info, putErr
	case facts.err != nil:
		return info, fmt.Errorf("reading the base backup's tar: %w", facts.err)
	}
	info.TarBytes, info.TarSha256, info.StoredBytes = m.RawBytes, m.RawSha256, stored.n

	if facts.systemID != srv.SystemID {
		return info, fmt.Errorf("the base backup's pg_control names system %s, the server said %s", facts.systemID, srv.SystemID)
	}
	ranges, err := facts.walRanges()
	if err != nil {
		return info, err
	}
	first, last := ranges[0], ranges[len(ranges)-1]
	info.Timeline, info.StartLSN, info.EndLSN = last.Timeline, first.Start.String(), last.End.String()
	need := neededWAL(ranges, srv.SegSize)
	info.StartWAL, info.EndWAL = need[0], need[len(need)-1]

	wait := o.WaitForWAL
	if wait == 0 {
		wait = time.Minute
	}
	deadline := time.Now().Add(wait)
	for {
		if o.BeforeWALCheck != nil {
			o.BeforeWALCheck(ctx)
		}
		missing, err := a.missingWAL(ctx, need)
		if err != nil {
			return info, err
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			return info, fmt.Errorf("base %s is not complete: %d WAL file(s) it needs are not in the archive (first %s). Check archive_command and pg_stat_archiver", info.BaseID, len(missing), missing[0])
		}
		select {
		case <-ctx.Done():
			return info, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	info.EndedAt = a.now()
	if _, err := a.writeRecord(ctx, a.baseKey(info.BaseID, "base.json"), info, info.LockedUntil); err != nil {
		return info, fmt.Errorf("writing base %s's record: %w", info.BaseID, err)
	}
	return info, nil
}

// Tablespace is a tablespace of the cluster other than pg_default and
// pg_global, and the directory it lives in.
type Tablespace struct {
	Name     string
	Location string
}

// Tablespaces lists the cluster's tablespaces other than pg_default and
// pg_global. It reads the catalog over an ordinary connection: a
// replication connection takes no SQL.
func Tablespaces(ctx context.Context, connURL string) ([]Tablespace, error) {
	conn, err := pgconn.Connect(ctx, connURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to check the cluster's tablespaces before a base backup: %w", err)
	}
	defer conn.Close(context.Background())
	rows, err := conn.Exec(ctx, "SELECT spcname, pg_tablespace_location(oid) FROM pg_tablespace WHERE spcname NOT IN ('pg_default', 'pg_global') ORDER BY spcname").ReadAll()
	if err != nil {
		return nil, fmt.Errorf("listing the cluster's tablespaces before a base backup: %w", err)
	}
	var out []Tablespace
	for _, r := range rows {
		for _, row := range r.Rows {
			if len(row) < 2 {
				continue
			}
			out = append(out, Tablespace{Name: string(row[0]), Location: string(row[1])})
		}
	}
	return out, nil
}

// TablespaceError refuses a base backup of a cluster with tablespaces
// outside its data directory: pg_basebackup streams only the data
// directory to stdout, and a base without the tablespaces would not
// restore.
type TablespaceError struct {
	Spaces []Tablespace
}

func (e *TablespaceError) Error() string {
	names := make([]string, len(e.Spaces))
	for i, s := range e.Spaces {
		names[i] = s.Name
		if s.Location != "" {
			names[i] += " at " + s.Location
		}
	}
	return fmt.Sprintf("this cluster keeps data in %d tablespace(s) outside its data directory: %s. "+
		"A base backup takes only the data directory, so no base was taken and nothing was uploaded, and point-in-time recovery is not available for this cluster. "+
		"The surface's logical backups (safegrd backup) cover every tablespace. "+
		"To use point-in-time recovery, move those tables to pg_default (ALTER TABLE ... SET TABLESPACE pg_default) and drop the tablespaces. "+
		"Otherwise remove the surface's wal: block",
		len(e.Spaces), strings.Join(names, ", "))
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// walRange is one entry of backup_manifest's WAL-Ranges.
type walRange struct {
	Timeline   uint32
	Start, End LSN
}

type tarFacts struct {
	label    string
	manifest []byte
	systemID string
	err      error
}

// scanTar reads the files a base backup is described by as the tar passes.
func scanTar(r io.Reader) tarFacts {
	var f tarFacts
	tr := tar.NewReader(r)
	last := ""
	for {
		h, err := tr.Next()
		if err == io.EOF || (errors.Is(err, io.ErrUnexpectedEOF) && last == "backup_manifest" && f.manifest != nil) {
			// PostgreSQL 13 and 14 end a tar written to stdout right after
			// the manifest's last byte, without padding its block or the
			// end-of-archive blocks. The manifest read whole is the end.
			return f
		}
		if err != nil {
			f.err = err
			return f
		}
		last = strings.TrimPrefix(h.Name, "./")
		switch last {
		case "backup_label":
			b, err := io.ReadAll(tr)
			if err != nil {
				f.err = err
				return f
			}
			f.label = string(b)
		case "backup_manifest":
			b, err := io.ReadAll(tr)
			if err != nil {
				f.err = err
				return f
			}
			f.manifest = b
		case "global/pg_control":
			head := make([]byte, 12)
			if _, err := io.ReadFull(tr, head); err != nil {
				f.err = err
				return f
			}
			f.systemID, f.err = systemIDFromControl(head, "the base backup's global/pg_control")
			if f.err != nil {
				return f
			}
		}
	}
}

var labelStartRe = regexp.MustCompile(`START WAL LOCATION: ([0-9A-F]+/[0-9A-F]+)`)

func (f tarFacts) walRanges() ([]walRange, error) {
	if len(f.manifest) == 0 {
		return nil, errors.New("the base backup has no backup_manifest, which PostgreSQL 13 and newer write; it says which WAL the base needs")
	}
	var m struct {
		Ranges []struct {
			Timeline uint32 `json:"Timeline"`
			Start    string `json:"Start-LSN"`
			End      string `json:"End-LSN"`
		} `json:"WAL-Ranges"`
	}
	if err := json.Unmarshal(f.manifest, &m); err != nil {
		return nil, fmt.Errorf("backup_manifest does not parse: %w", err)
	}
	var out []walRange
	for _, r := range m.Ranges {
		s, err1 := ParseLSN(r.Start)
		e, err2 := ParseLSN(r.End)
		if err1 != nil || err2 != nil || e < s {
			return nil, fmt.Errorf("backup_manifest has a WAL range %s to %s", r.Start, r.End)
		}
		out = append(out, walRange{Timeline: r.Timeline, Start: s, End: e})
	}
	if len(out) == 0 {
		return nil, errors.New("backup_manifest lists no WAL range")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	if lm := labelStartRe.FindStringSubmatch(f.label); lm != nil {
		if s, err := ParseLSN(lm[1]); err == nil && s != out[0].Start {
			return nil, fmt.Errorf("backup_label starts at %s and backup_manifest at %s", s, out[0].Start)
		}
	}
	return out, nil
}

// neededWAL lists every WAL file the ranges touch, in order.
func neededWAL(ranges []walRange, segSize uint64) []string {
	var out []string
	for _, r := range ranges {
		first := uint64(r.Start) / segSize
		end := uint64(r.End)
		// An end exactly on a boundary is the end of the previous file.
		if end%segSize == 0 && end > uint64(r.Start) {
			end--
		}
		for seg := first; seg <= end/segSize; seg++ {
			out = append(out, segName(r.Timeline, seg, segSize))
		}
	}
	return out
}

// archivedNames is every WAL file name the archive holds, unlocked or
// bundled.
func (a *Archive) archivedNames(ctx context.Context) (map[string]time.Time, error) {
	have := map[string]time.Time{}
	pushed, err := a.Pushed(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pushed {
		have[p.Name] = p.PushedAt
	}
	bundles, err := a.Bundles(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range bundles {
		for _, f := range b.Files {
			if t, ok := have[f.Name]; !ok || f.PushedAt.Before(t) {
				have[f.Name] = f.PushedAt
			}
		}
	}
	return have, nil
}

func (a *Archive) missingWAL(ctx context.Context, need []string) ([]string, error) {
	have, err := a.archivedNames(ctx)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, n := range need {
		if _, ok := have[n]; !ok {
			missing = append(missing, n)
		}
	}
	return missing, nil
}

// Bases lists the complete base backups, oldest first, and the ids of any
// whose upload finished without a record (incomplete: their WAL never all
// arrived, or the run was stopped).
func (a *Archive) Bases(ctx context.Context) (complete []BaseInfo, incomplete []string, err error) {
	objs, err := a.Store.List(ctx, path.Join(a.prefix(), "base")+"/")
	if err != nil {
		return nil, nil, err
	}
	tars := map[string]bool{}
	records := map[string]bool{}
	for _, o := range objs {
		dir, file := path.Split(o.Key)
		id := path.Base(dir)
		if !baseIDRe.MatchString(id) {
			continue
		}
		switch file {
		case "base.tar.zst.age", "base.db.zst.age":
			tars[id] = true
		case "base.json", "base.json" + copySuffix:
			records[id] = true
		}
	}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		key := a.baseKey(id, "base.json")
		rec, err := a.readRecordRaw(ctx, key)
		if err != nil {
			return nil, nil, fmt.Errorf("base %s: %w", id, err)
		}
		var b BaseInfo
		if err := json.Unmarshal(rec, &b); err != nil {
			return nil, nil, fmt.Errorf("%s does not parse: %w", key, err)
		}
		if b.BaseID != id || b.SystemID != a.SystemID {
			return nil, nil, fmt.Errorf("%s names base %s of system %s", key, b.BaseID, b.SystemID)
		}
		complete = append(complete, b)
	}
	done := map[string]bool{}
	for _, b := range complete {
		done[b.BaseID] = true
	}
	for id := range tars {
		if !done[id] {
			incomplete = append(incomplete, id)
		}
	}
	sort.Slice(complete, func(i, j int) bool { return complete[i].StartedAt.Before(complete[j].StartedAt) })
	sort.Strings(incomplete)
	return complete, incomplete, nil
}

var pgToolVersionRe = regexp.MustCompile(`\(PostgreSQL\)\s+(\d+)`)

// FindPgBasebackup returns a pg_basebackup of at least minMajor, the newest
// installed: SAFEGRD_PG_BINDIR, then PATH, then the directories distributions
// install PostgreSQL under. A pg_basebackup reads servers of its own major
// and older.
func FindPgBasebackup(ctx context.Context, minMajor int) (string, error) {
	var dirs []string
	if d := os.Getenv("SAFEGRD_PG_BINDIR"); d != "" {
		dirs = []string{d}
	} else {
		if p, err := exec.LookPath("pg_basebackup"); err == nil {
			dirs = append(dirs, filepath.Dir(p))
		}
		globs := []string{"/usr/lib/postgresql/*/bin", "/usr/pgsql-*/bin", "/usr/local/pgsql/bin", "/usr/libexec/postgresql*"}
		if runtime.GOOS == "darwin" {
			globs = append(globs, "/opt/homebrew/opt/postgresql@*/bin", "/opt/homebrew/opt/libpq/bin", "/usr/local/opt/postgresql@*/bin", "/Applications/Postgres.app/Contents/Versions/*/bin")
		}
		for _, g := range globs {
			m, _ := filepath.Glob(g)
			dirs = append(dirs, m...)
		}
	}
	best, bestMajor := "", 0
	var found []string
	for _, d := range dirs {
		p := filepath.Join(d, "pg_basebackup")
		out, err := exec.CommandContext(ctx, p, "--version").Output()
		if err != nil {
			continue
		}
		m := pgToolVersionRe.FindStringSubmatch(string(out))
		if m == nil {
			continue
		}
		major, _ := strconv.Atoi(m[1])
		found = append(found, fmt.Sprintf("%s (%d)", p, major))
		if major >= minMajor && major > bestMajor {
			best, bestMajor = p, major
		}
	}
	if best != "" {
		return best, nil
	}
	if len(found) == 0 {
		return "", fmt.Errorf("no pg_basebackup on this host. Install the PostgreSQL %d client tools, or set SAFEGRD_PG_BINDIR", minMajor)
	}
	return "", fmt.Errorf("the server is PostgreSQL %d and this host has only %s. Install pg_basebackup %d or newer, or set SAFEGRD_PG_BINDIR", minMajor, strings.Join(found, ", "), minMajor)
}

// replayLag is how many seconds a standby's replay is behind the last
// commit its primary sent, nil when it cannot say (nothing replayed yet).
func replayLag(ctx context.Context, connURL string) *float64 {
	conn, err := pgconn.Connect(ctx, connURL)
	if err != nil {
		return nil
	}
	defer conn.Close(context.Background())
	rows, err := conn.Exec(ctx, "SELECT EXTRACT(epoch FROM now() - pg_last_xact_replay_timestamp())::float8").ReadAll()
	if err != nil || len(rows) != 1 || len(rows[0].Rows) != 1 || rows[0].Rows[0][0] == nil {
		return nil
	}
	lag, err := strconv.ParseFloat(string(rows[0].Rows[0][0]), 64)
	if err != nil {
		return nil
	}
	if lag < 0 {
		lag = 0
	}
	return &lag
}

// SourceWords says where a base came from: "the standby db-2:5432, 0.4s
// behind its primary", or "" for a primary.
func (b BaseInfo) SourceWords() string {
	if !b.FromStandby {
		return ""
	}
	w := "the standby " + b.Source
	if b.ReplayLagSeconds != nil {
		w += fmt.Sprintf(", %.1fs behind its primary", *b.ReplayLagSeconds)
	}
	return w
}
