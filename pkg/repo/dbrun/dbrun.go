// Package dbrun stores a database dump as one snapshot of a repository and
// reads it back. The snapshot's files are the dump archive's entries, one per
// section and one per table:
//
//	pre-data.sql                 (schema.sql when no pg_dump was usable)
//	data/<schema>/<table>.copy   a table's rows as one binary COPY stream
//	post-data.sql
//	sequences.sql
//	manifest.json
//
// so a table whose rows did not move stores no new chunks, and a restore
// rebuilds the archive stream the archive restorers already read.
//
// A SQLite run holds the database file, copied page for page, and the
// manifest:
//
//	sqlite/database.sqlite
//	manifest.json
//
// so a page no write touched stores no new chunk.
package dbrun

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/write"
)

// Source dumps database through d into the run. The dump's metadata is
// stored in *meta once the source returns without error. A table the dump
// marks Carried is stored as the run before stored it, unread.
func Source(d dump.Dumper, database string, meta **model.SnapshotMetadata) write.Source {
	return func(ctx context.Context, emit func(write.Entry) error) error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		pr, pw := io.Pipe()
		type result struct {
			meta *model.SnapshotMetadata
			err  error
		}
		done := make(chan result, 1)
		go func() {
			m, err := d.Dump(ctx, database, pw)
			_ = pw.CloseWithError(err)
			done <- result{m, err}
		}()
		err := dump.ArchiveEntries(pr, func(name string, r io.Reader) error {
			return emit(write.Entry{Path: name, Reader: r})
		})
		if err != nil {
			// The dump is blocked on a pipe nobody reads.
			_ = pr.CloseWithError(err)
			cancel()
		}
		res := <-done
		if res.err != nil {
			return res.err
		}
		if err != nil {
			return err
		}
		if res.meta == nil {
			return fmt.Errorf("the dump returned no metadata")
		}
		// Tables the dump did not read, because nothing wrote them since
		// the last run, keep that run's file.
		for _, t := range res.meta.TableStats {
			if t.Carried {
				if err := emit(write.Entry{Path: dump.TablePath(t.Schema, t.TableName), Carry: true}); err != nil {
					return err
				}
			}
		}
		*meta = res.meta
		return nil
	}
}

// Sections a run holds, in the order the archive restorers read them.
const (
	PreData   = "pre-data.sql"
	Schema    = "schema.sql"
	PostData  = "post-data.sql"
	Sequences = "sequences.sql"
	Manifest  = "manifest.json"
	dataDir   = "data/"
	// SQLiteDatabase is a SQLite run's database file.
	SQLiteDatabase = "sqlite/database.sqlite"
	sqliteDir      = "sqlite"
)

// Files lists the files of a database run in archive order: the schema,
// every table's rows, the post-data section, the sequences and the manifest;
// or, for SQLite, the database file and the manifest. It refuses a snapshot
// holding anything else, or both shapes at once, which is not a database run.
func Files(ctx context.Context, r *read.Repo, idx read.Index, s format.Snapshot) ([]read.Item, error) {
	root, err := format.ParseID(s.RootTree)
	if err != nil {
		return nil, err
	}
	var sections = map[string]read.Item{}
	var tables []read.Item
	var sqliteDB *read.Item
	err = r.Walk(ctx, idx, root, func(it read.Item) error {
		switch {
		case it.Node.Type == format.NodeDir && (it.Path == "data" || strings.HasPrefix(it.Path, dataDir)):
			return nil
		case it.Node.Type == format.NodeDir && it.Path == sqliteDir:
			return nil
		case it.Node.Type == format.NodeFile && it.Path == SQLiteDatabase:
			sqliteDB = &it
		case it.Node.Type != format.NodeFile:
			return fmt.Errorf("snapshot %s holds %s, which is not part of a database dump", s.SnapshotID, it.Path)
		case strings.HasPrefix(it.Path, dataDir) && strings.HasSuffix(it.Path, ".copy"):
			tables = append(tables, it)
		case it.Path == PreData || it.Path == Schema || it.Path == PostData || it.Path == Sequences || it.Path == Manifest:
			sections[it.Path] = it
		default:
			return fmt.Errorf("snapshot %s holds %s, which is not part of a database dump", s.SnapshotID, it.Path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	manifest, ok := sections[Manifest]
	if !ok {
		return nil, fmt.Errorf("snapshot %s has no %s: it is not a database run", s.SnapshotID, Manifest)
	}
	if sqliteDB != nil {
		if len(sections) > 1 || len(tables) > 0 {
			return nil, fmt.Errorf("snapshot %s holds a SQLite database and PostgreSQL sections: it is not one database run", s.SnapshotID)
		}
		return []read.Item{*sqliteDB, manifest}, nil
	}
	_, pre := sections[PreData]
	_, schema := sections[Schema]
	if !pre && !schema {
		return nil, fmt.Errorf("snapshot %s has no schema section", s.SnapshotID)
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Path < tables[j].Path })
	var out []read.Item
	for _, name := range []string{PreData, Schema} {
		if it, ok := sections[name]; ok {
			out = append(out, it)
		}
	}
	out = append(out, tables...)
	for _, name := range []string{PostData, Sequences, Manifest} {
		if it, ok := sections[name]; ok {
			out = append(out, it)
		}
	}
	return out, nil
}

// Archive writes a database run to w as the tar archive a backup in archive
// format would have been, each file checked against its SHA-256 as it is
// read. A table is one entry however large it is.
func Archive(ctx context.Context, r *read.Repo, idx read.Index, files []read.Item, w io.Writer) error {
	tw := tar.NewWriter(w)
	for _, it := range files {
		if err := tw.WriteHeader(&tar.Header{Name: it.Path, Mode: 0o600, Size: it.Node.Size,
			ModTime: it.Node.ModTime.Truncate(time.Second), Format: tar.FormatPAX}); err != nil {
			return err
		}
		if err := r.Cat(ctx, idx, it.Node, tw); err != nil {
			return err
		}
	}
	return tw.Close()
}

// ReadManifest returns the run's manifest: the dump's metadata, with every
// table's exact row count.
func ReadManifest(ctx context.Context, r *read.Repo, idx read.Index, files []read.Item) (*model.SnapshotMetadata, error) {
	for _, it := range files {
		if it.Path != Manifest {
			continue
		}
		var b bytes.Buffer
		if err := r.Cat(ctx, idx, it.Node, &b); err != nil {
			return nil, err
		}
		var m model.SnapshotMetadata
		if err := json.Unmarshal(b.Bytes(), &m); err != nil {
			return nil, fmt.Errorf("the run's manifest does not parse: %w", err)
		}
		return &m, nil
	}
	return nil, fmt.Errorf("the run has no manifest")
}
