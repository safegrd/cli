package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/diskspace"
	"github.com/safegrd/cli/pkg/model"
)

// A sandbox drill needs an empty database, and asking every customer to
// create one per surface is the step most of them skip. A host that has the
// PostgreSQL server installed can start one of its own: a cluster made by
// initdb for one drill, listening on a socket in a private directory only,
// and deleted when the drill ends.
//
// Postgres writes restored rows to disk, so memory stays at what the settings
// below allow (well under 200 MB whatever the database's size). Disk is the
// cost: about the database's size, on the host that may run production, so the
// cluster refuses to start where it would not fit with room to spare. It is
// never put under /tmp, which is memory on several distributions.

// PgServer is a located initdb and postgres from one installation.
type PgServer struct {
	BinDir  string
	Version string // "16.4"
	Major   int
}

var pgServerVersionRe = regexp.MustCompile(`\(PostgreSQL\)\s+(\d+)(?:\.(\d+))?`)

// pgServerDirs lists the directories that may hold initdb and postgres, the
// override first. Debian and Ubuntu install the server under
// /usr/lib/postgresql/<major>/bin and put neither on PATH; Homebrew's libpq
// carries pg_dump but no server, so a host with pg_dump may still have none.
func pgServerDirs() []string {
	if d := os.Getenv("SAFEGRD_PG_BINDIR"); d != "" {
		return []string{d}
	}
	var out []string
	if p, err := exec.LookPath("initdb"); err == nil {
		out = append(out, filepath.Dir(p))
	}
	globs := []string{"/usr/lib/postgresql/*/bin", "/usr/pgsql-*/bin", "/usr/local/pgsql/bin"}
	if runtime.GOOS == "darwin" {
		globs = append(globs,
			"/opt/homebrew/opt/postgresql@*/bin", "/opt/homebrew/opt/postgresql/bin",
			"/usr/local/opt/postgresql@*/bin", "/usr/local/opt/postgresql/bin",
			"/Applications/Postgres.app/Contents/Versions/*/bin")
	}
	for _, g := range globs {
		m, _ := filepath.Glob(g)
		out = append(out, m...)
	}
	return out
}

// FindPgServer returns the newest PostgreSQL server installed here that is at
// least minMajor, or an error that says what was found and what is needed. A
// pg_dump schema loads into its own major or a newer one; an older server may
// not know its syntax.
func FindPgServer(ctx context.Context, minMajor int) (*PgServer, error) {
	var found []*PgServer
	var broken []string
	seen := map[string]bool{}
	for _, dir := range pgServerDirs() {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			dir = real
		}
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if !isExecutable(filepath.Join(dir, "initdb")) || !isExecutable(filepath.Join(dir, "postgres")) {
			continue
		}
		out, err := exec.CommandContext(ctx, filepath.Join(dir, "postgres"), "--version").Output()
		m := pgServerVersionRe.FindStringSubmatch(string(out))
		if err != nil || m == nil {
			broken = append(broken, filepath.Join(dir, "postgres"))
			continue
		}
		major, _ := strconv.Atoi(m[1])
		v := m[1]
		if m[2] != "" {
			v += "." + m[2]
		}
		found = append(found, &PgServer{BinDir: dir, Version: v, Major: major})
	}
	need := "the PostgreSQL server package"
	if minMajor > 0 {
		need = fmt.Sprintf("the PostgreSQL %d server (or newer)", minMajor)
	}
	if len(found) == 0 {
		if len(broken) > 0 {
			return nil, fmt.Errorf("%s does not run (postgres --version failed); install %s, or set SAFEGRD_PG_BINDIR",
				strings.Join(broken, ", "), need)
		}
		return nil, fmt.Errorf("no PostgreSQL server (initdb and postgres) on this host; install %s, or set SAFEGRD_PG_BINDIR", need)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Major > found[j].Major })
	best := found[0]
	if minMajor > 0 && best.Major < minMajor {
		return nil, fmt.Errorf("the newest PostgreSQL server here is %s (%s), older than the PostgreSQL %d database "+
			"this snapshot came from; install %s, or set SAFEGRD_PG_BINDIR", best.Version, best.BinDir, minMajor, need)
	}
	return best, nil
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

var sourceMajorRe = regexp.MustCompile(`PostgreSQL (\d+)`)

// SourceMajor is the major version of the server a Postgres snapshot was
// taken from, or 0 when the snapshot does not say.
func SourceMajor(meta *model.SnapshotMetadata) int {
	m := sourceMajorRe.FindStringSubmatch(meta.PostgresVersion)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// The room a restore needs: the source's tables as they sat on disk (indexes
// and TOAST included, which a fresh load does not exceed), a quarter again for
// what that misses, and a fixed allowance for the cluster itself.
const (
	sandboxClusterBytes = 1 << 30
)

// SandboxBytesNeeded is how much free disk a restore of meta needs.
func SandboxBytesNeeded(meta *model.SnapshotMetadata) int64 {
	var onDisk int64
	for _, t := range meta.TableStats {
		onDisk += t.SizeBytes
	}
	if meta.RawSizeBytes > onDisk {
		onDisk = meta.RawSizeBytes
	}
	return onDisk + onDisk/4 + sandboxClusterBytes
}

// LocalPostgres is a running throwaway cluster. URL connects to its empty
// postgres database over a Unix socket; Stop ends it and deletes it.
type LocalPostgres struct {
	URL     string
	Server  *PgServer
	dataDir string
	sockDir string
	cmd     *exec.Cmd
	exited  chan struct{}
	waitErr error
	log     *boundedBuffer
}

// sandboxSettings keep the cluster small and fast. Nothing in it outlives the
// drill, so durability is switched off. wal_level=minimal lets a COPY into a
// table created in the same transaction, which is how a restore loads, skip
// the WAL altogether.
var sandboxSettings = []string{
	"listen_addresses=", "unix_socket_permissions=0700",
	"max_connections=5", "superuser_reserved_connections=1",
	"shared_buffers=64MB", "work_mem=4MB", "maintenance_work_mem=64MB",
	"max_parallel_workers_per_gather=0", "max_parallel_maintenance_workers=0",
	"fsync=off", "synchronous_commit=off", "full_page_writes=off",
	"wal_level=minimal", "max_wal_senders=0", "archive_mode=off",
	"autovacuum=off", "huge_pages=off", "logging_collector=off",
	"log_min_messages=warning",
}

// localSandboxPrefix names the data directories under <state>/drill, so a
// cluster left behind by a daemon that was killed can be found and removed.
const localSandboxPrefix = "pg-"

// StartLocalPostgres starts a throwaway cluster from srv under stateDir/drill,
// after checking the disk has room for need bytes. The caller must Stop it.
func StartLocalPostgres(ctx context.Context, srv *PgServer, stateDir string, need int64) (*LocalPostgres, error) {
	base := filepath.Join(stateDir, "drill")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create %s for a local sandbox: %w", base, err)
	}
	// PostgreSQL refuses to run as root, and a system service runs the daemon
	// as root: the cluster runs as whoever owns the state directory.
	cred, err := sandboxCredential(stateDir)
	if err != nil {
		return nil, err
	}
	if err := cred.own(base); err != nil {
		return nil, err
	}
	SweepLocalSandboxes(stateDir)
	if err := diskspace.CheckFreeSpace(base, need, "a local sandbox",
		"free some space, set daemon.state_dir on a larger disk, or point drill.sandbox_url at a database elsewhere"); err != nil {
		return nil, err
	}

	dataDir, err := os.MkdirTemp(base, localSandboxPrefix)
	if err != nil {
		return nil, fmt.Errorf("cannot create a data directory for a local sandbox: %w", err)
	}
	// The socket's path has to fit in about 100 bytes, which a state
	// directory deep in a home may not leave room for. It holds a socket and
	// a lock file, nothing else, so a short path under /tmp is fine.
	sockDir, err := os.MkdirTemp(shortTempDir(), "safegrd-pg-")
	if err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, fmt.Errorf("cannot create a socket directory for a local sandbox: %w", err)
	}
	lp := &LocalPostgres{Server: srv, dataDir: dataDir, sockDir: sockDir, exited: make(chan struct{}), log: &boundedBuffer{max: 8 << 10}}
	fail := func(err error) (*LocalPostgres, error) {
		lp.Stop()
		return nil, err
	}
	for _, d := range []string{dataDir, sockDir} {
		if err := os.Chmod(d, 0o700); err != nil {
			return fail(err)
		}
		if err := cred.own(d); err != nil {
			return fail(err)
		}
	}

	env := []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "LANG=C", "TZ=UTC"}
	initdb := exec.CommandContext(ctx, filepath.Join(srv.BinDir, "initdb"),
		"-D", dataDir, "-U", "safegrd", "-A", "trust", "-E", "UTF8", "--locale=C", "--no-sync")
	initdb.Env = env
	initdb.Dir = dataDir
	cred.apply(initdb)
	if out, err := initdb.CombinedOutput(); err != nil {
		return fail(fmt.Errorf("initdb (%s) could not create a local sandbox: %v: %s", srv.Version, err, lastLines(string(out), 5)))
	}

	args := []string{"-D", dataDir, "-k", sockDir, "-p", "5432"}
	for _, s := range sandboxSettings {
		args = append(args, "-c", s)
	}
	// Not CommandContext: a cancelled drill stops the cluster through Stop,
	// with a shutdown it can finish, not a SIGKILL.
	cmd := exec.Command(filepath.Join(srv.BinDir, "postgres"), args...)
	cmd.Env = env
	cmd.Dir = dataDir
	cmd.Stdout, cmd.Stderr = lp.log, lp.log
	cred.apply(cmd)
	if err := cmd.Start(); err != nil {
		return fail(fmt.Errorf("could not start postgres for a local sandbox: %w", err))
	}
	lp.cmd = cmd
	go func() {
		lp.waitErr = cmd.Wait()
		close(lp.exited)
	}()

	lp.URL = fmt.Sprintf("host=%s port=5432 user=safegrd dbname=postgres sslmode=disable", sockDir)
	deadline := time.Now().Add(60 * time.Second)
	for {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := pgx.Connect(cctx, lp.URL)
		cancel()
		if err == nil {
			_ = conn.Close(context.Background())
			return lp, nil
		}
		select {
		case <-lp.exited:
			return fail(fmt.Errorf("postgres (%s) exited while starting a local sandbox: %v: %s", srv.Version, lp.waitErr, lastLines(lp.log.String(), 5)))
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fail(fmt.Errorf("postgres (%s) did not accept connections within 60s: %s", srv.Version, lastLines(lp.log.String(), 5)))
		}
	}
}

// MissingExtensions lists the names in want that this cluster cannot create.
// A snapshot that uses an extension the host's server lacks would fail its
// restore for a reason that says nothing about the backup.
func (lp *LocalPostgres) MissingExtensions(ctx context.Context, want []string) ([]string, error) {
	if len(want) == 0 {
		return nil, nil
	}
	conn, err := pgx.Connect(ctx, lp.URL)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	rows, err := conn.Query(ctx, "SELECT name FROM pg_available_extensions")
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		have[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var missing []string
	for _, w := range want {
		if !have[w] {
			missing = append(missing, w)
		}
	}
	return missing, nil
}

// Stop shuts the cluster down and deletes it. It is safe to call more than
// once and on a cluster that never started.
func (lp *LocalPostgres) Stop() {
	if lp.cmd != nil && lp.cmd.Process != nil {
		// SIGINT is PostgreSQL's fast shutdown: open transactions roll back
		// and the server exits without waiting for clients.
		_ = lp.cmd.Process.Signal(os.Interrupt)
		select {
		case <-lp.exited:
		case <-time.After(30 * time.Second):
			_ = lp.cmd.Process.Kill()
			<-lp.exited
		}
		lp.cmd = nil
	}
	if lp.dataDir != "" {
		if err := os.RemoveAll(lp.dataDir); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Could not delete the local sandbox at %s: %v. Delete it by hand to free the disk.\n", lp.dataDir, err)
		}
		lp.dataDir = ""
	}
	if lp.sockDir != "" {
		_ = os.RemoveAll(lp.sockDir)
		lp.sockDir = ""
	}
}

// SweepLocalSandboxes removes clusters a killed daemon left under
// stateDir/drill, stopping any postgres still running in one first.
func SweepLocalSandboxes(stateDir string) {
	dirs, _ := filepath.Glob(filepath.Join(stateDir, "drill", localSandboxPrefix+"*"))
	for _, d := range dirs {
		stopLeftoverPostmaster(d)
		if err := os.RemoveAll(d); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Could not delete a local sandbox left by an earlier drill at %s: %v\n", d, err)
		}
	}
}

// stopLeftoverPostmaster stops the postgres that postmaster.pid in dataDir
// names, if that process is still a postgres serving dataDir. The check
// matters: after a reboot the pid may belong to anything.
func stopLeftoverPostmaster(dataDir string) {
	b, err := os.ReadFile(filepath.Join(dataDir, "postmaster.pid"))
	if err != nil {
		return
	}
	lines := strings.SplitN(string(b), "\n", 3)
	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil || pid <= 1 {
		return
	}
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil || !strings.Contains(string(out), "postgres") || !strings.Contains(string(out), dataDir) {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Signal(os.Interrupt)
	for range 100 {
		if _, err := os.Stat(filepath.Join(dataDir, "postmaster.pid")); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = p.Kill()
}

func shortTempDir() string {
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
			return "/tmp"
		}
	}
	return os.TempDir()
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// boundedBuffer keeps the last max bytes written to it: postgres's log, for
// an error message, without holding a long run's output.
type boundedBuffer struct {
	max int
	mu  sync.Mutex
	buf []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
