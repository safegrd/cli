package dump

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// MySQLPosition is where in the server's binary log a dump's snapshot sits,
// as the dump tool wrote it at the head of the dump: replaying the log from
// there over the dump gives the database at any later moment.
type MySQLPosition struct {
	File string `json:"file"`
	Pos  uint64 `json:"pos"`
	// GTIDs is the GTID state the tool wrote beside the position: MySQL's
	// executed set, or MariaDB's gtid_slave_pos. Empty when it wrote none.
	GTIDs string `json:"gtids,omitempty"`
}

var (
	mysqlSourcePosRe = regexp.MustCompile(`^-- CHANGE (?:REPLICATION SOURCE|MASTER) TO (?:SOURCE|MASTER)_LOG_FILE='([^']+)', (?:SOURCE|MASTER)_LOG_POS=(\d+);`)
	mysqlGTIDPurged  = regexp.MustCompile(`^/\* SET @@GLOBAL\.GTID_PURGED='\+?([^']*)';\s*\*/`)
	mariaGTIDPos     = regexp.MustCompile(`^-- SET GLOBAL gtid_slave_pos='([^']*)';`)
)

// mysqlPositionScanner reads the position lines out of the head of a dump as
// it streams past. Only the first lines are looked at: the tool writes them
// before the first table.
type mysqlPositionScanner struct {
	pos  MySQLPosition
	line []byte
	seen int64
	done bool
}

const mysqlPositionScanLimit = 1 << 20

func (s *mysqlPositionScanner) Write(p []byte) (int, error) {
	n := len(p)
	if s.done {
		return n, nil
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if len(s.line) < 64<<10 {
				s.line = append(s.line, p...)
			}
			break
		}
		s.line = append(s.line, p[:i]...)
		s.endLine()
		p = p[i+1:]
	}
	s.seen += int64(n)
	if s.seen > mysqlPositionScanLimit {
		s.done = true
	}
	return n, nil
}

func (s *mysqlPositionScanner) endLine() {
	line := string(s.line)
	s.line = s.line[:0]
	if m := mysqlSourcePosRe.FindStringSubmatch(line); m != nil {
		s.pos.File = m[1]
		s.pos.Pos, _ = strconv.ParseUint(m[2], 10, 64)
	} else if m := mysqlGTIDPurged.FindStringSubmatch(line); m != nil {
		s.pos.GTIDs = m[1]
	} else if m := mariaGTIDPos.FindStringSubmatch(line); m != nil {
		s.pos.GTIDs = m[1]
	} else if strings.HasPrefix(line, "-- Table structure for table") {
		s.done = true
	}
}

// mysqlPositionArgs are the dump tool's options that make it write the
// snapshot's binary log position: --source-data (MySQL 8.0.26 and newer) or
// --master-data, and the GTID state beside it.
func mysqlPositionArgs(ctx context.Context, tool *MySQLTool) []string {
	help := ""
	if out, err := exec.CommandContext(ctx, tool.Path, "--help").Output(); err == nil {
		help = string(out)
	}
	if tool.MariaDB {
		return []string{"--master-data=2", "--gtid"}
	}
	args := []string{"--master-data=2"}
	if strings.Contains(help, "--source-data") {
		args = []string{"--source-data=2"}
	}
	if strings.Contains(help, "COMMENTED") {
		args = append(args, "--set-gtid-purged=COMMENTED")
	}
	return args
}

// MySQLConnInfo is how to reach a MySQL server over its own protocol: the
// address, the account and the TLS settings the URL asks for. TLS is nil for
// none; Preferred means try TLS and go on without it.
type MySQLConnInfo struct {
	Addr, User, Password, Database string
	TLS                            *tls.Config
	Preferred                      bool
}

// MySQLConnectionInfo reads a mysql:// URL for a connection made outside the
// Go driver: the binary log reader's.
func MySQLConnectionInfo(databaseURL string) (MySQLConnInfo, error) {
	t, err := parseMySQLURL(databaseURL)
	if err != nil {
		return MySQLConnInfo{}, err
	}
	ci := MySQLConnInfo{Addr: fmt.Sprintf("%s:%d", t.Host, t.Port), User: t.User, Password: t.Password, Database: t.Database}
	switch {
	case t.CAFile != "":
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return ci, fmt.Errorf("reading ssl-ca %s: %w", t.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return ci, fmt.Errorf("no certificates in ssl-ca %s", t.CAFile)
		}
		ci.TLS = &tls.Config{RootCAs: pool, ServerName: t.Host, MinVersion: tls.VersionTLS12}
	case t.TLS == "true":
		ci.TLS = &tls.Config{ServerName: t.Host, MinVersion: tls.VersionTLS12}
	case t.TLS == "skip-verify":
		ci.TLS = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // what tls=skip-verify asks for
	case t.TLS == "preferred":
		ci.TLS = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // what tls=preferred asks for
		ci.Preferred = true
	}
	return ci, nil
}

// MySQLReplayOptions is one replay of binary log files into a database.
type MySQLReplayOptions struct {
	// TargetURL is the database the log is replayed into.
	TargetURL string
	// SourceDB is the database the log was written for; when it differs
	// from the target's, mysqlbinlog --rewrite-db moves it.
	SourceDB string
	// Files are binary log files, replayed in order.
	Files []string
	// MariaDB picks mariadb-binlog over MySQL's mysqlbinlog.
	MariaDB bool
}

// MySQLReplay pipes binary log files through the server's own project's
// mysqlbinlog into its mysql client. The client stops at the first error,
// and the error says which statement.
func MySQLReplay(ctx context.Context, o MySQLReplayOptions) error {
	target, err := parseMySQLURL(o.TargetURL)
	if err != nil {
		return err
	}
	binlog, err := findMySQLTool(ctx, "binlog", o.MariaDB)
	if err != nil {
		return err
	}
	client, err := findMySQLTool(ctx, "client", o.MariaDB)
	if err != nil {
		return err
	}
	cnf, cleanup, err := target.defaultsFile()
	if err != nil {
		return err
	}
	defer cleanup()
	// MySQL's GTIDs would be refused on a server that already ran them;
	// MariaDB's tool has no such option and its GTIDs need no privilege.
	args := []string{"--skip-gtids"}
	if binlog.MariaDB {
		args = []string{"--skip-gtid-strict-mode"}
	}
	if o.SourceDB != "" && o.SourceDB != target.Database {
		args = append(args, fmt.Sprintf("--rewrite-db=%s->%s", o.SourceDB, target.Database))
	}
	dec := exec.CommandContext(ctx, binlog.Path, append(args, o.Files...)...)
	load := exec.CommandContext(ctx, client.Path, "--defaults-extra-file="+cnf, "--binary-mode", "--database="+target.Database)
	pr, pw := io.Pipe()
	var decErr, loadErr bytes.Buffer
	dec.Stdout, dec.Stderr = pw, &decErr
	load.Stdin, load.Stderr = pr, &loadErr
	if err := load.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", client, err)
	}
	if err := dec.Start(); err != nil {
		pw.Close()
		_ = load.Wait()
		return fmt.Errorf("starting %s: %w", binlog, err)
	}
	derr := dec.Wait()
	pw.Close()
	lerr := load.Wait()
	pr.Close()
	if lerr != nil {
		return fmt.Errorf("%s stopped replaying the binary log: %v: %s", client, lerr, strings.TrimSpace(toolMessage(loadErr.String())))
	}
	if derr != nil {
		return fmt.Errorf("%s could not read the binary log: %v: %s", binlog, derr, strings.TrimSpace(toolMessage(decErr.String())))
	}
	return nil
}

// MySQLServerIsMariaDB says whether the database URL's server is MariaDB,
// and its version.
func MySQLServerIsMariaDB(ctx context.Context, databaseURL string) (bool, string, error) {
	db, err := OpenMySQL(databaseURL)
	if err != nil {
		return false, "", err
	}
	defer db.Close()
	v, maria, err := mysqlServer(ctx, db)
	return maria, v, err
}

// MySQLBinlogToolFor finds the binary log reader a restore of this server's
// log uses, for doctor.
func MySQLBinlogToolFor(ctx context.Context, mariaDB bool) (*MySQLTool, error) {
	return findMySQLTool(ctx, "binlog", mariaDB)
}
