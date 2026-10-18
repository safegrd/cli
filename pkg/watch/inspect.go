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
	"sort"
	"strings"

	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
)

// The formats a backup can be in.
const (
	// FormatCustom is pg_dump --format=custom, which Coolify writes.
	FormatCustom = "custom"
	// FormatPlain is pg_dump's plain SQL, gzipped or not.
	FormatPlain = "plain"
	// FormatCluster is pg_dumpall's: every database of a server, with its
	// roles. It is read, never loaded: loading creates roles and databases.
	FormatCluster = "cluster"
)

// Contents is what a check read in a backup.
type Contents struct {
	Format  string
	Gzipped bool
	// Tables are the tables whose rows the backup holds, with the rows it
	// holds of each. pg_cron's tables are left out: a drill does not load
	// them, so nothing the backup scheduled can run.
	Tables     []model.TableStat
	Rows       int64
	Extensions []string
	// ServerVersion is the server the dump was taken from, as its header
	// says ("16.4").
	ServerVersion string
	// CronJobs is how many pg_cron jobs the backup carries.
	CronJobs int
	// CreatesDatabase is set for a plain dump that creates its database
	// (pg_dump --create): loading it would create a database beside the
	// sandbox, so it is read and not loaded, as a cluster dump is.
	CreatesDatabase bool
}

// Loadable reports whether a drill may load the backup into a sandbox.
func (c *Contents) Loadable() bool {
	return c.Format != FormatCluster && !c.CreatesDatabase
}

var (
	// ident is a name as pg_dump writes it: bare, or double-quoted with ""
	// for a quote; qualified, one or two of them joined by a dot.
	ident       = `(?:"(?:[^"]|"")+"|[^\s".(]+)`
	qualifiedRe = `(` + ident + `(?:\.` + ident + `)?)`
	copyRe      = regexp.MustCompile(`^COPY ` + qualifiedRe + ` (?:\(.*\) )?FROM stdin;$`)
	insertRe    = regexp.MustCompile(`^INSERT INTO ` + qualifiedRe + `[ (]`)
	extensionRe = regexp.MustCompile(`^CREATE EXTENSION (?:IF NOT EXISTS )?("?[\w-]+"?)`)
	versionRe   = regexp.MustCompile(`^-- Dumped from database version (\S+)`)
	connectRe   = regexp.MustCompile(`^\\connect (?:-reuse-previous=on )?"?([^" ]+)"?`)
)

// Inspect reads the backup at file and counts what it holds. A file that
// ends early, or is not a PostgreSQL dump, is an error that says so.
func Inspect(ctx context.Context, file string) (*Contents, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, 5)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	c := &Contents{}
	var src io.Reader = f
	if bytes.HasPrefix(head, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("the backup is gzip but cannot be opened: %w", err)
		}
		defer gz.Close()
		c.Gzipped = true
		br := bufio.NewReader(gz)
		peek, _ := br.Peek(5)
		if bytes.Equal(peek, []byte("PGDMP")) {
			// A custom-format archive gzipped again: pg_restore reads it
			// from a plain file only.
			tmp, err := os.CreateTemp(filepath.Dir(file), "watched-gunzip-*")
			if err != nil {
				return nil, err
			}
			defer os.Remove(tmp.Name())
			if _, err := io.Copy(tmp, br); err != nil {
				tmp.Close()
				return nil, fmt.Errorf("the backup's gzip stream is damaged: %w", err)
			}
			if err := tmp.Close(); err != nil {
				return nil, err
			}
			return inspectCustom(ctx, tmp.Name(), c)
		}
		src = br
	} else if bytes.Equal(head, []byte("PGDMP")) {
		return inspectCustom(ctx, file, c)
	}
	c.Format = FormatPlain
	if err := c.scan(src); err != nil {
		return nil, err
	}
	return c, nil
}

func inspectCustom(ctx context.Context, file string, c *Contents) (*Contents, error) {
	c.Format = FormatCustom
	tool, err := clientTool("pg_restore")
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, tool, "-f", "-", file)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	scanErr := c.scan(out)
	_, _ = io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("pg_restore could not read the archive: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return c, scanErr
}

// scan reads SQL text as pg_dump and pg_dumpall write it.
func (c *Contents) scan(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	rows := map[string]int64{}
	exts := map[string]bool{}
	db := ""
	var table string
	inCopy, sawDump := false, false
	for sc.Scan() {
		line := sc.Text()
		if inCopy {
			if line == `\.` {
				inCopy = false
				continue
			}
			rows[table]++
			continue
		}
		switch {
		case strings.HasPrefix(line, "-- PostgreSQL database cluster dump"):
			c.Format, sawDump = FormatCluster, true
		case strings.HasPrefix(line, "-- PostgreSQL database dump"):
			sawDump = true
		case strings.HasPrefix(line, "CREATE DATABASE "):
			c.CreatesDatabase = true
		}
		if m := versionRe.FindStringSubmatch(line); m != nil && c.ServerVersion == "" {
			c.ServerVersion = m[1]
		}
		if m := connectRe.FindStringSubmatch(line); m != nil {
			db = m[1]
			continue
		}
		if m := extensionRe.FindStringSubmatch(line); m != nil {
			exts[strings.Trim(m[1], `"`)] = true
			continue
		}
		if m := copyRe.FindStringSubmatch(line); m != nil {
			table, inCopy = qualify(db, m[1]), true
			if _, ok := rows[table]; !ok {
				rows[table] = 0
			}
			continue
		}
		if m := insertRe.FindStringSubmatch(line); m != nil {
			rows[qualify(db, m[1])]++
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("the backup could not be read to its end: %w", err)
	}
	if inCopy {
		return fmt.Errorf("the backup ends inside the rows of %s: it was cut short", table)
	}
	if !sawDump && len(rows) == 0 {
		return errors.New("this is not a PostgreSQL dump (no pg_dump header, no table rows)")
	}
	for name, n := range rows {
		if name == "cron.job" || strings.HasSuffix(name, ":cron.job") {
			c.CronJobs += int(n)
			continue
		}
		if name == "cron.job_run_details" || strings.HasSuffix(name, ":cron.job_run_details") {
			continue
		}
		schema, tbl, _ := strings.Cut(name, ".")
		c.Tables = append(c.Tables, model.TableStat{Schema: schema, TableName: tbl, RowCount: n})
		c.Rows += n
	}
	sort.Slice(c.Tables, func(i, j int) bool {
		if c.Tables[i].Schema != c.Tables[j].Schema {
			return c.Tables[i].Schema < c.Tables[j].Schema
		}
		return c.Tables[i].TableName < c.Tables[j].TableName
	})
	for e := range exts {
		c.Extensions = append(c.Extensions, e)
	}
	sort.Strings(c.Extensions)
	return nil
}

// qualify is a table named in a dump as schema.table, unquoted, and in a
// cluster dump prefixed with its database: db:schema.table.
func qualify(db, name string) string {
	parts := splitIdents(name)
	schema, table := "public", ""
	switch len(parts) {
	case 1:
		table = parts[0]
	default:
		schema, table = parts[0], parts[1]
	}
	q := schema + "." + table
	if db != "" {
		return db + ":" + q
	}
	return q
}

// clientTool finds a PostgreSQL client program beside the newest pg_dump
// on this host.
func clientTool(name string) (string, error) {
	pd, err := dump.FindPgDump(context.Background(), 0)
	if err != nil {
		return "", fmt.Errorf("%s is needed to read this backup: %w", name, err)
	}
	p := filepath.Join(filepath.Dir(pd.Path), name)
	if _, err := os.Stat(p); err != nil {
		if lp, lerr := exec.LookPath(name); lerr == nil {
			return lp, nil
		}
		return "", fmt.Errorf("%s is needed to read this backup, and there is none beside %s", name, pd.Path)
	}
	return p, nil
}

// splitIdents splits a qualified name at its unquoted dots and unquotes
// each part.
func splitIdents(name string) []string {
	var parts []string
	var cur strings.Builder
	quoted := false
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch == '"' && quoted && i+1 < len(name) && name[i+1] == '"':
			cur.WriteByte('"')
			i++
		case ch == '"':
			quoted = !quoted
		case ch == '.' && !quoted:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	return append(parts, cur.String())
}
