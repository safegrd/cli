package runner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/diskspace"
	"github.com/safegrd/cli/pkg/model"
)

func TestSandboxBytesNeededCoversTheLargerOfTablesAndArchive(t *testing.T) {
	meta := &model.SnapshotMetadata{RawSizeBytes: 100 << 20, TableStats: []model.TableStat{
		{SizeBytes: 300 << 20}, {SizeBytes: 100 << 20},
	}}
	if got, want := SandboxBytesNeeded(meta), int64(400<<20+100<<20+sandboxClusterBytes); got != want {
		t.Errorf("tables of 400 MiB: need %d, want %d", got, want)
	}
	meta.RawSizeBytes = 800 << 20
	if got, want := SandboxBytesNeeded(meta), int64(800<<20+200<<20+sandboxClusterBytes); got != want {
		t.Errorf("an archive of 800 MiB: need %d, want %d", got, want)
	}
}

func TestSourceMajorReadsTheRecordedServer(t *testing.T) {
	for v, want := range map[string]int{
		"PostgreSQL 16.4 on x86_64-pc-linux-musl, compiled by gcc": 16,
		"PostgreSQL 9.6.24 on x86_64-pc-linux-gnu":                 9,
		"": 0,
	} {
		if got := SourceMajor(&model.SnapshotMetadata{PostgresVersion: v}); got != want {
			t.Errorf("%q: major %d, want %d", v, got, want)
		}
	}
}

// sandboxStateDir is a state directory a local sandbox can run under: the
// test's own, or, as root, one handed to nobody in a tree nobody can reach.
func sandboxStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if os.Geteuid() != 0 {
		return dir
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(state, nobody, nobody); err != nil {
		t.Fatal(err)
	}
	return state
}

const nobody = 65534

// fakePgServer writes an initdb and a postgres that only answer --version.
func fakePgServer(t *testing.T, version string, works bool) string {
	t.Helper()
	dir := t.TempDir()
	pg := "#!/bin/sh\necho 'postgres (PostgreSQL) " + version + "'\n"
	if !works {
		pg = "#!/bin/sh\necho 'Library not loaded: libicui18n.71.dylib' >&2\nexit 1\n"
	}
	for name, body := range map[string]string{"postgres": pg, "initdb": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A pg_dump schema loads into its own major or newer, so a server older than
// the snapshot's is refused, with what to install.
func TestFindPgServerRefusesOneOlderThanTheSnapshot(t *testing.T) {
	ctx := context.Background()
	t.Setenv("SAFEGRD_PG_BINDIR", fakePgServer(t, "15.2", true))
	if _, err := FindPgServer(ctx, 16); err == nil || !strings.Contains(err.Error(), "older than the PostgreSQL 16 database") ||
		!strings.Contains(err.Error(), "install the PostgreSQL 16 server (or newer)") {
		t.Errorf("a 15 server for a 16 snapshot: %v", err)
	}
	srv, err := FindPgServer(ctx, 15)
	if err != nil || srv.Major != 15 || srv.Version != "15.2" {
		t.Errorf("a 15 server for a 15 snapshot: %+v %v", srv, err)
	}

	t.Setenv("SAFEGRD_PG_BINDIR", fakePgServer(t, "", false))
	if _, err := FindPgServer(ctx, 16); err == nil || !strings.Contains(err.Error(), "does not run") {
		t.Errorf("a postgres that cannot start: %v", err)
	}
	t.Setenv("SAFEGRD_PG_BINDIR", t.TempDir())
	if _, err := FindPgServer(ctx, 16); err == nil || !strings.Contains(err.Error(), "no PostgreSQL server (initdb and postgres) on this host") {
		t.Errorf("no server at all: %v", err)
	}
}

// The cluster lands on the host that may run production: a restore that
// would leave its disk nearly full is refused before initdb runs.
func TestCheckRoomRefusesARestoreThatWouldFillTheDisk(t *testing.T) {
	dir := sandboxStateDir(t)
	if _, err := StartLocalPostgres(context.Background(), &PgServer{BinDir: t.TempDir()}, dir, 1<<60); err == nil ||
		!strings.Contains(err.Error(), "not enough disk") {
		t.Errorf("StartLocalPostgres did not check the disk first: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "drill", localSandboxPrefix+"*")); len(left) != 0 {
		t.Errorf("a refused sandbox left %v behind", left)
	}
}

// A real cluster from this host's PostgreSQL server: it starts on a socket
// only, says which extensions it lacks, and Stop leaves nothing behind. A
// cluster a killed daemon left running is stopped and removed by the next.
func TestALocalSandboxStartsAndIsDeleted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	srv, err := FindPgServer(ctx, 0)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI installs the PostgreSQL server, and none was found: %v", err)
		}
		t.Skipf("this host cannot start a local PostgreSQL: %v", err)
	}
	stateDir := sandboxStateDir(t)
	lp, err := StartLocalPostgres(ctx, srv, stateDir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	dataDir, sockDir := lp.dataDir, lp.sockDir
	conn, err := pgx.Connect(ctx, lp.URL)
	if err != nil {
		lp.Stop()
		t.Fatal(err)
	}
	var listen, fsync string
	_ = conn.QueryRow(ctx, "SELECT current_setting('listen_addresses'), current_setting('fsync')").Scan(&listen, &fsync)
	_ = conn.Close(ctx)
	if listen != "" || fsync != "off" {
		t.Errorf("listen_addresses %q (want none: socket only), fsync %q", listen, fsync)
	}
	if err := CheckSandboxEmpty(ctx, lp.URL); err != nil {
		t.Errorf("a fresh cluster is not an empty sandbox: %v", err)
	}
	missing, err := lp.MissingExtensions(ctx, []string{"plpgsql", "no_such_extension_here"})
	if err != nil || len(missing) != 1 || missing[0] != "no_such_extension_here" {
		t.Errorf("missing extensions: %v %v", missing, err)
	}
	lp.Stop()
	lp.Stop()
	for _, d := range []string{dataDir, sockDir} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("%s is still there after Stop (%v)", d, err)
		}
	}

	// A daemon killed mid-drill leaves its cluster running.
	left, err := StartLocalPostgres(ctx, srv, stateDir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(left.Stop)
	SweepLocalSandboxes(stateDir)
	select {
	case <-left.exited:
	case <-time.After(15 * time.Second):
		t.Errorf("the sweep did not stop the cluster a killed daemon left running")
	}
	if _, err := os.Stat(left.dataDir); !os.IsNotExist(err) {
		t.Errorf("the sweep left %s behind (%v)", left.dataDir, err)
	}
}

// A system service runs the daemon as root, which PostgreSQL refuses: the
// cluster runs as the user who owns the state directory, and a state directory
// root owns is refused with what to do. Runs only as root (in a container).
func TestALocalSandboxUnderRootRunsAsTheStateDirsOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only as root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	srv, err := FindPgServer(ctx, 0)
	if err != nil {
		t.Skipf("this host cannot start a local PostgreSQL: %v", err)
	}
	rootOwned := t.TempDir()
	if _, err := StartLocalPostgres(ctx, srv, rootOwned, 1<<20); err == nil ||
		!strings.Contains(err.Error(), "root owns its state directory") {
		t.Errorf("a root-owned state directory: %v", err)
	}

	// The enrolling user's state directory, in a tree that user can reach.
	stateDir := sandboxStateDir(t)
	lp, err := StartLocalPostgres(ctx, srv, stateDir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer lp.Stop()
	if lp.cmd.SysProcAttr == nil || lp.cmd.SysProcAttr.Credential == nil || lp.cmd.SysProcAttr.Credential.Uid != nobody {
		t.Errorf("postgres was not started as the state directory's owner")
	}
	if err := CheckSandboxEmpty(ctx, lp.URL); err != nil {
		t.Errorf("the cluster does not answer: %v", err)
	}
}

// A files drill restores the whole tree to this host's disk. One that cannot
// fit is not run and not reported: it says nothing about the backup, and the
// daemon reports it as blocked instead of failed.
func TestARepoDrillThatCannotFitIsBlockedNotFailed(t *testing.T) {
	posted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posted = true }))
	defer srv.Close()
	v := NewVerifier(nil, srv.URL)
	v.SetServerToken("token")
	scratch := filepath.Join(t.TempDir(), "restore-1")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := &model.SnapshotMetadata{SnapshotID: "snap-big", SurfaceType: model.SurfaceTypeFiles, RawSizeBytes: 1 << 60}
	report, err := v.RunRepoDrill(context.Background(), RepoDrill{Meta: meta, Scratch: scratch}, "")
	var blocked *DrillBlockedError
	if !errors.As(err, &blocked) || !errors.Is(err, diskspace.ErrNotEnoughDisk) || report != nil {
		t.Fatalf("an exabyte tree: report %v, err %v; want blocked for disk", report, err)
	}
	if !strings.Contains(err.Error(), "for a Fire Drill of snap-big, which restores every file") {
		t.Errorf("the reason does not name the drill: %v", err)
	}
	if posted {
		t.Error("a drill that never ran was reported to the remote server")
	}
	if _, err := os.Stat(scratch); !os.IsNotExist(err) {
		t.Errorf("the scratch directory was left behind (%v)", err)
	}
}
