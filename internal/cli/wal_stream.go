package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/wal"
)

// A MySQL or MongoDB surface with a wal: block has its binary log or oplog
// followed by the resident daemon into the same archive PostgreSQL's WAL
// goes to. Its base backups are dumps that know their place in the log, and
// a restore loads one into an empty database and replays the log to a
// moment.

// walStreamEngine is the log a surface's archive follows: wal.StreamMySQL,
// wal.StreamMongo, or "" for PostgreSQL and SQLite.
func walStreamEngine(s *config.SurfaceConfig) string {
	switch strings.ToLower(s.Type) {
	case "mysql", "mariadb":
		return wal.StreamMySQL
	case "mongodb", "mongo":
		return wal.StreamMongo
	}
	return ""
}

func walIsStream(s *config.SurfaceConfig) bool { return walStreamEngine(s) != "" }

func streamLogWord(engine string) string {
	if engine == wal.StreamMongo {
		return "oplog"
	}
	return "binary log"
}

// walStreamURL is the surface's database URL for a base, a restore point
// or the follower, the held credential fetched when SafeGrd holds it.
func walStreamURL(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (string, error) {
	if s.FromSafeGrd() {
		st := loadDaemonState(filepath.Join(resolveStateDir("", c), "daemon_state.json"))
		node := s.ID
		if ss, ok := st.Surfaces[s.ID]; ok && ss.ServerNodeID != "" {
			node = ss.ServerNodeID
		}
		fetchHeldSurfaceSecret(ctx, c, node, s)
	}
	u, err := resolveSurfaceDatabaseURL(ctx, c, s)
	if err != nil {
		return "", err
	}
	if u == "" {
		return "", fmt.Errorf("surface %s names no database_url", s.ID)
	}
	return u, nil
}

// walStreamBase takes one base backup of a MySQL or MongoDB surface.
func walStreamBase(ctx context.Context, c *config.CLIConfig, a *wal.Archive, s *config.SurfaceConfig) (wal.BaseInfo, error) {
	u, err := walStreamURL(ctx, c, s)
	if err != nil {
		return wal.BaseInfo{}, err
	}
	var info wal.BaseInfo
	if walStreamEngine(s) == wal.StreamMongo {
		info, err = a.MongoBase(ctx, u)
	} else {
		// Following the binary log needs REPLICATION SLAVE. A base taken
		// without it is one nothing can replay past, so it is refused here,
		// in words, and not left for the daemon to find.
		if _, err := wal.CheckMySQLStream(ctx, u); err != nil {
			return info, classed(exitSource, err)
		}
		info, err = a.MySQLBase(ctx, u)
	}
	if err != nil {
		return info, classed(exitSource, err)
	}
	return info, nil
}

func printStreamBase(a *wal.Archive, info wal.BaseInfo) {
	fmt.Printf("Base backup %s (%s, %s), %s\n", info.BaseID, formatBytes(info.StoredBytes),
		info.EndedAt.Sub(info.StartedAt).Round(time.Second), walLockLine(a, info.LockedUntil))
	p := info.Stream
	if p == nil {
		return
	}
	if p.Engine == wal.StreamMongo {
		fmt.Printf("   Database %s; the oplog from %s replays over it, to any moment from %s\n", p.Database,
			wal.MongoTSTime(p.Pos).Format("2006-01-02 15:04:05 UTC"), wal.MongoTSTime(p.Until).Format("2006-01-02 15:04:05 UTC"))
		return
	}
	line := fmt.Sprintf("   Database %s, from %s at %d", p.Database, p.File, p.Pos)
	if p.GTIDs != "" {
		line += " (GTIDs " + p.GTIDs + ")"
	}
	fmt.Println(line)
}

// walStreamPoint records a restore point of a MySQL or MongoDB surface.
func walStreamPoint(ctx context.Context, c *config.CLIConfig, a *wal.Archive, s *config.SurfaceConfig) (wal.RestorePoint, error) {
	u, err := walStreamURL(ctx, c, s)
	if err != nil {
		return wal.RestorePoint{}, err
	}
	if walStreamEngine(s) == wal.StreamMongo {
		return a.MongoRestorePoint(ctx, u)
	}
	return a.MySQLRestorePoint(ctx, u)
}

// walStreamRestore restores a MySQL or MongoDB surface into an empty
// database, to a moment, a restore point or the end of the archive.
func walStreamRestore(ctx context.Context, a *wal.Archive, s *config.SurfaceConfig, target time.Time, toPoint, targetURL string) error {
	engine := walStreamEngine(s)
	if targetURL == "" {
		return fmt.Errorf("--target-url is required for a %s surface: an empty database to restore into", s.Type)
	}
	resolved, err := ResolveSecretRef("target-url", targetURL)
	if err != nil {
		return err
	}
	o := wal.StreamRestoreOptions{Target: target, TargetURL: resolved, WorkDir: resolveStateDir("", cfg)}
	if err := os.MkdirAll(o.WorkDir, 0o700); err != nil {
		return err
	}
	if toPoint != "" {
		points, err := a.RestorePoints(ctx)
		if err != nil {
			return storageFailure(err)
		}
		for i := range points {
			if points[i].Name == toPoint {
				o.Point = &points[i]
			}
		}
		if o.Point == nil {
			return fmt.Errorf("the archive records no restore point %s. 'safegrd wal point' makes one", toPoint)
		}
	}
	restore := a.RestoreMySQL
	if engine == wal.StreamMongo {
		restore = a.RestoreMongo
	}
	res, err := restore(ctx, o)
	if err != nil {
		return err
	}
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }
	what := "transactions"
	if engine == wal.StreamMongo {
		what = "oplog entries"
	}
	fmt.Printf("Restored base %s into %s, and replayed %d %s of %s\n", res.Base.BaseID, redactURL(resolved), res.Transactions, what, res.Base.Stream.Database)
	switch {
	case o.Point != nil:
		fmt.Printf("   At restore point %s (%s)\n", o.Point.Name, ts(o.Point.At))
	case target.IsZero():
		fmt.Printf("   To the end of the archive: the last change replayed committed at %s\n", ts(res.ReachedAt))
	default:
		fmt.Printf("   Holds every change committed by %s; the last one replayed committed at %s\n", ts(target), ts(res.ReachedAt))
	}
	return nil
}

// redactURL drops a URL's password for printing.
func redactURL(u string) string {
	at := strings.LastIndex(u, "@")
	scheme := strings.Index(u, "://")
	if at < 0 || scheme < 0 || at < scheme {
		return u
	}
	creds := u[scheme+3 : at]
	if i := strings.IndexByte(creds, ':'); i >= 0 {
		creds = creds[:i]
	}
	return u[:scheme+3] + creds + u[at:]
}

// runStreamDrill restores a MySQL or MongoDB archive into the surface's
// drill.sandbox_url, emptied first: to the newest restore point it can
// reach, comparing every table's count with the point's, then to the end of
// the archive. Without a sandbox the drill is blocked, not failed.
func runStreamDrill(ctx context.Context, c *config.CLIConfig, a *wal.Archive, s *config.SurfaceConfig) *model.WALDrill {
	d := &model.WALDrill{At: time.Now().UTC()}
	blocked := func(why string) *model.WALDrill { d.Blocked = why; return d }
	failed := func(why string) *model.WALDrill { d.Detail = why; return d }
	if a.Identity = daemonPrivateKey(ctx, c); a.Identity == "" {
		return blocked("this host holds no private key to decrypt the archive")
	}
	sandbox, err := surfaceSandboxURL(ctx, c, s)
	if err != nil {
		return blocked(err.Error())
	}
	if sandbox == "" {
		return blocked("the surface has no drill.sandbox_url, an empty database the drill restores into")
	}
	engine := walStreamEngine(s)
	empty := func() error {
		if engine == wal.StreamMongo {
			client, db, err := dump.OpenMongo(ctx, sandbox)
			if err != nil {
				return err
			}
			defer client.Disconnect(context.Background()) //nolint:errcheck
			return dump.MongoResetDatabase(ctx, db)
		}
		db, err := dump.OpenMySQL(sandbox)
		if err != nil {
			return err
		}
		defer db.Close()
		return dump.MySQLResetDatabase(ctx, db)
	}
	restore := a.RestoreMySQL
	if engine == wal.StreamMongo {
		restore = a.RestoreMongo
	}
	work := resolveStateDir("", c)
	_ = os.MkdirAll(work, 0o700)
	defer func() { _ = empty() }()

	points, err := a.RestorePoints(ctx)
	if err != nil {
		return failed("reading the restore points: " + err.Error())
	}
	st, err := a.StreamStatus(ctx, engine)
	if err != nil {
		return failed("reading the archive: " + err.Error())
	}
	if !st.HasWindow {
		return blocked("the archive has no window yet: no base backup has the " + streamLogWord(engine) + " after it archived")
	}
	// The newest point a restore reaches: a base before it and the log
	// unbroken up to it.
	var point *wal.RestorePoint
	for i := len(points) - 1; i >= 0; i-- {
		p := points[i]
		if p.Stream != nil && a.StreamPointReachable(ctx, engine, p) {
			point = &p
			break
		}
	}
	if point != nil {
		d.RestorePoint, d.PointAt = point.Name, point.At
		if err := empty(); err != nil {
			return blocked("emptying the sandbox: " + err.Error())
		}
		if _, err := restore(ctx, wal.StreamRestoreOptions{Point: point, TargetURL: sandbox, WorkDir: work}); err != nil {
			return failed("restoring to restore point " + point.Name + ": " + err.Error())
		}
		got, err := streamCounts(ctx, engine, sandbox)
		if err != nil {
			return failed("counting the restored tables: " + err.Error())
		}
		exact, wrong := point.CheckCounts(got)
		d.Tables, d.Exact = len(point.Tables), exact
		if len(wrong) > 0 {
			return failed(strings.Join(wrong, "; "))
		}
	}
	if err := empty(); err != nil {
		return blocked("emptying the sandbox: " + err.Error())
	}
	if _, err := restore(ctx, wal.StreamRestoreOptions{TargetURL: sandbox, WorkDir: work}); err != nil {
		return failed("restoring to the end of the archive: " + err.Error())
	}
	d.ReachedEnd, d.Passed = true, true
	if point == nil {
		d.Detail = "no restore point to drill to yet; the restore to the end was drilled"
	}
	return d
}

// streamCounts counts every table or collection of a restored database.
func streamCounts(ctx context.Context, engine, url string) (map[string]int64, error) {
	if engine == wal.StreamMongo {
		return wal.MongoCounts(ctx, url)
	}
	db, err := dump.OpenMySQL(url)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'`)
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
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+strings.ReplaceAll(n, "`", "``")+"`").Scan(&c); err != nil {
			return nil, err
		}
		out[n] = c
	}
	return out, nil
}

// streamFollower is a running follower of either engine.
type streamFollower interface {
	Run(ctx context.Context)
}

var (
	streamFollowers sync.Map // surface id -> streamFollower
	// streamGaps is when each surface's follower last found a gap, which
	// makes a new base due.
	streamGaps sync.Map
)

// startStreamFollowers follows the binary log or oplog of every MySQL and
// MongoDB surface with a wal: block, until ctx ends. Only a resident daemon
// does.
func startStreamFollowers(ctx context.Context, c *config.CLIConfig) {
	for i := range c.Surfaces {
		s := c.Surfaces[i]
		if s.WAL == nil || !walIsStream(&s) {
			continue
		}
		f, err := newStreamFollower(ctx, c, &s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Surface %s: cannot follow its %s: %v\n", s.ID, streamLogWord(walStreamEngine(&s)), err)
			continue
		}
		streamFollowers.Store(s.ID, f)
		fmt.Printf("   Following:           %s's %s\n", s.ID, streamLogWord(walStreamEngine(&s)))
		go f.Run(ctx)
	}
}

func newStreamFollower(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (streamFollower, error) {
	a, _, err := walArchive(ctx, c, s.ID, "")
	if err != nil {
		return nil, err
	}
	if a.Recipient == "" {
		return nil, errors.New("encryption.public_key is not set, and the log is encrypted to it")
	}
	u, err := walStreamURL(ctx, c, s)
	if err != nil {
		return nil, err
	}
	interval := 5 * time.Second
	if s.WAL.IntervalSeconds > 0 {
		interval = time.Duration(s.WAL.IntervalSeconds) * time.Second
	}
	id := s.ID
	logf := func(format string, args ...any) { fmt.Printf("Surface "+id+": "+format+"\n", args...) }
	warnf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "Warning: Surface "+id+": "+format+"\n", args...)
	}
	onGap := func() { streamGaps.Store(id, time.Now().UTC()) }
	if walStreamEngine(s) == wal.StreamMongo {
		return &wal.MongoFollower{Archive: a, URL: u, Interval: interval, Logf: logf, Warnf: warnf, OnGap: onGap}, nil
	}
	return &wal.MySQLFollower{Archive: a, URL: u, Interval: interval, ServerID: s.WAL.ServerID, Logf: logf, Warnf: warnf, OnGap: onGap}, nil
}

// streamGapSince says the surface's follower found a gap after t.
func streamGapSince(id string, t time.Time) bool {
	v, ok := streamGaps.Load(id)
	return ok && v.(time.Time).After(t)
}

// streamFollowError is why the daemon is not following a surface's log, or
// "".
func streamFollowError(id string) string {
	v, ok := streamFollowers.Load(id)
	if !ok {
		return ""
	}
	switch f := v.(type) {
	case *wal.MySQLFollower:
		if st := f.Status(); !st.Following {
			return st.LastError
		}
	case *wal.MongoFollower:
		if st := f.Status(); !st.Following {
			return st.LastError
		}
	}
	return ""
}

// warnStreamOnce says, for a pass from cron, which surfaces it cannot
// follow.
func warnStreamOnce(c *config.CLIConfig) {
	for i := range c.Surfaces {
		s := c.Surfaces[i]
		if s.WAL != nil && walIsStream(&s) {
			fmt.Fprintf(os.Stderr, "Warning: Surface %s: its %s is followed only by the resident daemon ('safegrd daemon run' without --once); this pass bundles what was archived and copies nothing new.\n",
				s.ID, streamLogWord(walStreamEngine(&s)))
		}
	}
}
