package dump

import (
	"archive/tar"
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/model"
)

// SQLExport is what ExportSQL wrote.
type SQLExport struct {
	Manifest *model.SnapshotMetadata
	Dir      string
	Tables   int
	Rows     int64
}

// ExportSQL writes a PostgreSQL snapshot archive into dir as files that psql
// loads with no SafeGrd involved: the schema as SQL, each table's rows as the
// binary COPY stream pg_dump-era tooling reads, and load.sql, which runs them
// in order in one transaction. dir must not exist or be empty. The files hold
// the database in plaintext, so dir is 0700 and every file 0600.
//
// Each table's rows are counted back from the file written and held to the
// count the manifest recorded at backup time, as a restore is.
func ExportSQL(src io.Reader, dir string) (*SQLExport, error) {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty; give a new directory", dir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}

	type tableFile struct {
		schema, table, file string
		rows                int64
	}
	var (
		tables   []tableFile
		manifest *model.SnapshotMetadata
		sqlFiles = map[string]bool{}
	)
	write := func(name string, r io.Reader) error {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, r); err != nil {
			f.Close()
			return fmt.Errorf("writing %s: %w", name, err)
		}
		return f.Close()
	}

	streams := &tableStreams{
		consume: func(schema, table string, rd io.Reader) error {
			name := fmt.Sprintf("data/%04d.copy", len(tables)+1)
			if err := write(name, rd); err != nil {
				return err
			}
			rows, err := countBinaryCopyRows(filepath.Join(dir, name))
			if err != nil {
				return fmt.Errorf("%s.%s: %w", schema, table, err)
			}
			tables = append(tables, tableFile{schema: schema, table: table, file: name, rows: rows})
			return nil
		},
		other: func(hdr *tar.Header, rd io.Reader) error {
			switch hdr.Name {
			case entryManifest:
				data, err := io.ReadAll(rd)
				if err != nil {
					return err
				}
				var m model.SnapshotMetadata
				if err := json.Unmarshal(data, &m); err != nil {
					return fmt.Errorf("the archive's manifest is unreadable: %w", err)
				}
				manifest = &m
				return write(entryManifest, strings.NewReader(string(data)))
			case entryPreData, entrySchema, entryPostData, entrySequences:
				data, err := io.ReadAll(rd)
				if err != nil {
					return err
				}
				sqlFiles[hdr.Name] = true
				return write(hdr.Name, strings.NewReader(portableSQL(string(data))))
			}
			return nil
		},
	}
	if err := streams.Run(tar.NewReader(src)); err != nil {
		return nil, err
	}
	if !sqlFiles[entryPreData] && !sqlFiles[entrySchema] {
		return nil, fmt.Errorf("the archive holds no schema; it is not a Postgres snapshot")
	}
	if manifest == nil {
		return nil, fmt.Errorf("the archive holds no manifest.json")
	}
	counted := map[string]int64{}
	var total int64
	for _, t := range tables {
		counted[t.schema+"."+t.table] = t.rows
		total += t.rows
	}
	if manifest.SchemaSource != "" {
		for _, t := range manifest.TableStats {
			if got := counted[t.Schema+"."+t.TableName]; got != t.RowCount {
				return nil, fmt.Errorf("%s.%s holds %d rows; the snapshot recorded %d", t.Schema, t.TableName, got, t.RowCount)
			}
		}
	}

	var b strings.Builder
	b.WriteString("-- Loads this SafeGrd snapshot into an empty PostgreSQL database, in one\n")
	b.WriteString("-- transaction. Run it from this directory:\n")
	b.WriteString("--   psql \"postgres://user@host/empty_db\" -f load.sql\n")
	b.WriteString("\\set ON_ERROR_STOP on\nBEGIN;\n")
	for _, name := range []string{entryPreData, entrySchema} {
		if sqlFiles[name] {
			fmt.Fprintf(&b, "\\ir %s\n", name)
		}
	}
	for _, t := range tables {
		fmt.Fprintf(&b, "\\copy %s FROM '%s' WITH (FORMAT binary)\n", pgx.Identifier{t.schema, t.table}.Sanitize(), t.file)
	}
	for _, name := range []string{entryPostData, entrySequences} {
		if sqlFiles[name] {
			fmt.Fprintf(&b, "\\ir %s\n", name)
		}
	}
	b.WriteString("COMMIT;\n")
	if err := write("load.sql", strings.NewReader(b.String())); err != nil {
		return nil, err
	}
	return &SQLExport{Manifest: manifest, Dir: dir, Tables: len(tables), Rows: total}, nil
}

// countBinaryCopyRows counts the tuples in a file of PostgreSQL's binary COPY
// format: an 11-byte signature, a flags word, a header extension, then for
// each tuple a 16-bit field count and each field's 32-bit length and bytes
// (-1 for NULL), ended by a field count of -1.
func countBinaryCopyRows(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	sig := make([]byte, 11)
	if _, err := io.ReadFull(r, sig); err != nil {
		return 0, fmt.Errorf("the COPY stream has no header: %w", err)
	}
	if string(sig) != "PGCOPY\n\xff\r\n\x00" {
		return 0, fmt.Errorf("the COPY stream is not in binary format")
	}
	var flags, extLen uint32
	if err := binary.Read(r, binary.BigEndian, &flags); err != nil {
		return 0, err
	}
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		return 0, err
	}
	if _, err := r.Discard(int(extLen)); err != nil {
		return 0, err
	}
	var rows int64
	for {
		var fields int16
		if err := binary.Read(r, binary.BigEndian, &fields); err != nil {
			return 0, fmt.Errorf("the COPY stream ends without its trailer after %d rows: %w", rows, err)
		}
		if fields == -1 {
			return rows, nil
		}
		for i := int16(0); i < fields; i++ {
			var n int32
			if err := binary.Read(r, binary.BigEndian, &n); err != nil {
				return 0, fmt.Errorf("the COPY stream is cut short in row %d: %w", rows+1, err)
			}
			if n > 0 {
				if _, err := r.Discard(int(n)); err != nil {
					return 0, fmt.Errorf("the COPY stream is cut short in row %d: %w", rows+1, err)
				}
			}
		}
		rows++
	}
}

var sessionSetLineRe = regexp.MustCompile(`(?m)^SET ([a-z_]+) = ([^;\n]*);$`)

// portableSQL makes pg_dump's output load under psql's ON_ERROR_STOP on a
// server older than the pg_dump that wrote it, which NativeRestorer does by
// asking the target what it supports. Here there is no target yet, so each
// session SET becomes a set_config that runs only where the setting exists
// (pg_dump 17 writes transaction_timeout, which PostgreSQL 16 rejects), and
// COMMENT ON EXTENSION, which only the extension's owner may run and a managed
// database's provider owns, is dropped as the restore drops it.
func portableSQL(sqlText string) string {
	sqlText = extensionCommentRe.ReplaceAllString(sqlText, "")
	return sessionSetLineRe.ReplaceAllStringFunc(sqlText, func(line string) string {
		m := sessionSetLineRe.FindStringSubmatch(line)
		name, value := m[1], strings.TrimSpace(m[2])
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = strings.ReplaceAll(value[1:len(value)-1], "''", "'")
		}
		return fmt.Sprintf("SELECT pg_catalog.set_config(%s, %s, false) FROM pg_catalog.pg_settings WHERE name = %s;",
			quoteLiteral(name), quoteLiteral(value), quoteLiteral(name))
	})
}
