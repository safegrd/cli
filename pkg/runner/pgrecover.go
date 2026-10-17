package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/diskspace"
)

// A point-in-time drill restores a base backup and replays WAL into it. The
// cluster runs from the restored data directory with the host's own server of
// the base's major version, under the sandbox's user, and reads WAL only from
// a staging directory the daemon filled: restore_command copies from there,
// so the sandbox's user never needs the storage key or the private key.

// recoverySettings override what the restored postgresql.conf says: the
// source's preload libraries, TLS files, ports and archive settings are the
// source host's, not this one's. hot_standby is off, so the cluster takes
// no connection until recovery ends and needs none of the source's sizes.
var recoverySettings = []string{
	"listen_addresses=", "unix_socket_permissions=0700",
	"hot_standby=off", "archive_mode=off", "shared_preload_libraries=", "ssl=off",
	"max_wal_senders=0", "max_replication_slots=0", "fsync=off", "synchronous_commit=off",
	"logging_collector=off", "log_destination=stderr", "log_min_messages=log",
	"autovacuum=off", "huge_pages=off", "cluster_name=",
}

// StartRecoveredPostgres makes a data directory and a WAL staging directory
// under stateDir/drill, has fill write the base backup and its recovery
// settings into the first and the WAL into the second, and starts postgres on
// it. restore_command in what fill writes must copy from the staging
// directory. The cluster is replaying when this returns; WaitPromoted waits
// for the end. The caller must Stop it.
func StartRecoveredPostgres(ctx context.Context, srv *PgServer, stateDir string, need int64, fill func(dataDir, walDir string) error) (*LocalPostgres, error) {
	cred, err := sandboxCredential(stateDir)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(stateDir, "drill")
	if d := cred.dir(); d != "" {
		base = d
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create %s for a point-in-time drill: %w", base, err)
	}
	if err := cred.own(base); err != nil {
		return nil, err
	}
	SweepLocalSandboxes(stateDir)
	if err := diskspace.CheckFreeSpace(base, need, "a point-in-time drill",
		"free some space, or set daemon.state_dir on a larger disk"); err != nil {
		return nil, err
	}
	dataDir, err := os.MkdirTemp(base, localSandboxPrefix)
	if err != nil {
		return nil, err
	}
	lp := &LocalPostgres{Server: srv, dataDir: dataDir, exited: make(chan struct{}), log: &boundedBuffer{max: 64 << 10}}
	fail := func(err error) (*LocalPostgres, error) {
		lp.Stop()
		return nil, err
	}
	walDir, err := os.MkdirTemp(base, localSandboxPrefix)
	if err != nil {
		return fail(err)
	}
	lp.extra = append(lp.extra, walDir)
	if lp.sockDir, err = os.MkdirTemp(shortTempDir(), "safegrd-pg-"); err != nil {
		return fail(err)
	}
	if err := fill(dataDir, walDir); err != nil {
		return fail(err)
	}
	// A cluster that kept its configuration outside the data directory
	// (Debian, Ubuntu) restores without one; postgres will not start
	// without a file, and the settings below are all it needs.
	if _, err := os.Stat(filepath.Join(dataDir, "postgresql.conf")); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(filepath.Join(dataDir, "postgresql.conf"), nil, 0o600); err != nil {
			return fail(err)
		}
	}
	hba := filepath.Join(lp.sockDir, "hba.conf")
	ident := filepath.Join(lp.sockDir, "ident.conf")
	if err := os.WriteFile(hba, []byte("local all all trust\n"), 0o600); err != nil {
		return fail(err)
	}
	if err := os.WriteFile(ident, nil, 0o600); err != nil {
		return fail(err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return fail(err)
	}
	for _, d := range []string{dataDir, walDir, lp.sockDir} {
		if err := ownTree(cred, d); err != nil {
			return fail(err)
		}
	}
	args := []string{"-D", dataDir, "-k", lp.sockDir, "-p", "5432", "-c", "hba_file=" + hba, "-c", "ident_file=" + ident}
	for _, s := range recoverySettings {
		args = append(args, "-c", s)
	}
	cmd := exec.Command(filepath.Join(srv.BinDir, "postgres"), args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "LANG=C", "TZ=UTC"}
	cmd.Dir = dataDir
	cmd.Stdout, cmd.Stderr = lp.log, lp.log
	cred.apply(cmd)
	if err := cmd.Start(); err != nil {
		return fail(fmt.Errorf("could not start postgres for a point-in-time drill: %w", err))
	}
	lp.cmd = cmd
	go func() {
		lp.waitErr = cmd.Wait()
		close(lp.exited)
	}()
	return lp, nil
}

// ownTree hands every file under dir to the sandbox's user.
func ownTree(cred *runAs, dir string) error {
	if cred == nil {
		return nil
	}
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return cred.own(p)
	})
}

// WaitPromoted waits until the recovered cluster has replayed and promoted,
// then returns a connection string as role to database. A cluster that
// stops instead (a target past the WAL, a missing file) returns its log.
func (lp *LocalPostgres) WaitPromoted(ctx context.Context, role, database string, limit time.Duration) (string, error) {
	url := fmt.Sprintf("host=%s port=5432 user=%s dbname=%s sslmode=disable", lp.sockDir, pgQuoteConn(role), pgQuoteConn(database))
	deadline := time.Now().Add(limit)
	for {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := pgx.Connect(cctx, url)
		if err == nil {
			var recovering bool
			qerr := conn.QueryRow(cctx, "SELECT pg_is_in_recovery()").Scan(&recovering)
			_ = conn.Close(context.Background())
			cancel()
			if qerr == nil && !recovering {
				lp.URL = url
				return url, nil
			}
		} else {
			cancel()
		}
		select {
		case <-lp.exited:
			return "", fmt.Errorf("postgres stopped during recovery: %v: %s", lp.waitErr, lastLines(lp.log.String(), 8))
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("recovery did not finish within %s: %s", limit, lastLines(lp.log.String(), 8))
		}
	}
}

var redoDoneRe = regexp.MustCompile(`redo done at ([0-9A-F]+/[0-9A-F]+)`)

// RedoDone is the LSN the replay ended at, from the server's log, or "".
func (lp *LocalPostgres) RedoDone() string {
	if m := redoDoneRe.FindStringSubmatch(lp.log.String()); m != nil {
		return m[1]
	}
	return ""
}

// pgQuoteConn quotes a value for a libpq key=value string.
func pgQuoteConn(s string) string {
	out := []byte{'\''}
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' || s[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(append(out, '\''))
}

// FindPgServerMajor returns an installed server of exactly major: WAL
// replays only on the major version that wrote it.
func FindPgServerMajor(ctx context.Context, major int) (*PgServer, error) {
	srv, err := FindPgServer(ctx, major)
	if err != nil {
		return nil, err
	}
	if srv.Major != major {
		return nil, &pgServerError{ErrPgServerTooOld, fmt.Sprintf("WAL from PostgreSQL %d replays only on PostgreSQL %d, and this host's newest server is %s; install PostgreSQL %d, or set SAFEGRD_PG_BINDIR", major, major, srv.Version, major)}
	}
	return srv, nil
}
