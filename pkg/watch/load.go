package watch

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/safegrd/cli/pkg/dump"
)

// Load restores the backup at file into the empty database sandboxURL names,
// in one transaction that stops at the first error, without owners or
// privileges. A custom-format archive is turned into SQL by pg_restore
// first, so both formats go through one filter into psql. The filter leaves
// out the rows of pg_cron's job table (a dump carries them, and loaded into
// a database pg_cron schedules from they would run), COMMENT ON EXTENSION
// (which only the extension's owner may run), and settings the sandbox's
// server does not have: pg_dump 18 writes SET transaction_timeout, which a
// PostgreSQL 16 sandbox refuses. The caller holds the loaded rows to c.
func Load(ctx context.Context, file string, c *Contents, sandboxURL string) error {
	if !c.Loadable() {
		return errors.New("a dump that creates databases or roles is not loaded into a sandbox; it is checked in memory")
	}
	known, err := serverSettings(ctx, sandboxURL)
	if err != nil {
		return err
	}
	dsn, env, cleanup, err := dump.PgToolEnv(sandboxURL)
	if err != nil {
		return err
	}
	defer cleanup()
	psqlPath, err := clientTool("psql")
	if err != nil {
		return err
	}
	var src io.Reader
	var wait func() error
	if c.Format == FormatCustom {
		if c.Gzipped {
			plain, err := gunzipTo(file)
			if err != nil {
				return err
			}
			defer os.Remove(plain)
			file = plain
		}
		rd, w, err := customAsSQL(ctx, file)
		if err != nil {
			return err
		}
		src, wait = rd, w
	} else {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		src = f
		if c.Gzipped {
			gz, err := gzip.NewReader(f)
			if err != nil {
				return err
			}
			defer gz.Close()
			src = gz
		}
	}
	cmd := exec.CommandContext(ctx, psqlPath, "-X", "-q", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-d", dsn, "-f", "-")
	cmd.Env = append(os.Environ(), env...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return err
	}
	filterErr := filterSQL(src, in, known)
	_ = in.Close()
	if wait != nil {
		if err := wait(); err != nil && filterErr == nil {
			filterErr = err
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("psql stopped, and the sandbox was rolled back: %v: %s", err, lastLine(out.Bytes()))
	}
	return filterErr
}

// customAsSQL streams a custom-format archive as the SQL pg_restore would
// run, without owners, privileges or comments.
func customAsSQL(ctx context.Context, file string) (io.Reader, func() error, error) {
	tool, err := clientTool("pg_restore")
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, tool, "--no-owner", "--no-acl", "--no-comments", "-f", "-", file)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return out, func() error {
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("pg_restore could not read the archive: %v: %s", err, lastLine(stderr.Bytes()))
		}
		return nil
	}, nil
}

// serverSettings are the settings the sandbox's server has.
func serverSettings(ctx context.Context, sandboxURL string) (map[string]bool, error) {
	conn, err := pgx.Connect(ctx, sandboxURL)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to the sandbox database: %w", err)
	}
	defer conn.Close(context.Background())
	rows, err := conn.Query(ctx, "SELECT name FROM pg_settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	known := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		known[n] = true
	}
	return known, rows.Err()
}

var (
	setRe       = regexp.MustCompile(`^SET (?:SESSION |LOCAL )?([a-z_][a-z0-9_.]*) (?:=|TO) `)
	setConfigRe = regexp.MustCompile(`^SELECT pg_catalog\.set_config\('([a-z_][a-z0-9_.]*)'`)
)

// filterSQL copies a dump's SQL, leaving out pg_cron's job rows, COMMENT ON
// EXTENSION, and settings known does not have.
func filterSQL(src io.Reader, dst io.Writer, known map[string]bool) error {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	w := bufio.NewWriter(dst)
	skipping := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case skipping:
			if line == `\.` {
				skipping = false
			}
			continue
		case strings.HasPrefix(line, "COPY cron.job ") && strings.HasSuffix(line, "FROM stdin;"):
			skipping = true
			continue
		case strings.HasPrefix(line, "COMMENT ON EXTENSION "):
			continue
		}
		if m := setRe.FindStringSubmatch(line); m != nil && !known[m[1]] && !strings.Contains(m[1], ".") {
			continue
		}
		if m := setConfigRe.FindStringSubmatch(line); m != nil && !known[m[1]] && !strings.Contains(m[1], ".") {
			continue
		}
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return w.Flush()
}

func gunzipTo(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	out, err := os.CreateTemp(filepath.Dir(file), "watched-gunzip-*")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, gz); err != nil {
		out.Close()
		os.Remove(out.Name())
		return "", err
	}
	return out.Name(), out.Close()
}

func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines[len(lines)-1]
}
