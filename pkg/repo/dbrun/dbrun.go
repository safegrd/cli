// Package dbrun stores a database dump as one snapshot of a repository and
// reads it back. The snapshot's files are the dump archive's entries, one per
// section and one per table:
//
//	roles.sql                    the roles the schema names, when it names any
//	pre-data.sql                 (schema.sql when no pg_dump was usable)
//	data/<schema>/<table>.copy   a table's rows as one binary COPY stream
//	large-objects.json           the large objects' oids, owners and sizes
//	large-objects/<oid>.lo       one large object's bytes
//	post-data.sql
//	sequences.sql
//	cron-jobs.json               pg_cron's jobs, when the database has any
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
//
// A MySQL run holds the dump tool's stream cut per table, and a MongoDB run
// mongodump's archive taken apart per collection (pkg/dump, mysql_run.go
// and mongo_run.go):
//
//	mysql/head.sql  mysql/tables/<table>.sql ...  mysql/tail.sql  manifest.json
//	mongo/prelude.bson  mongo/collections/<collection>.bson ...  manifest.json
//
// Archive puts each back together as the one-stream archive its engine's
// restorer and inspector read.
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
		// A dumper reading over several connections hands each table's
		// rows (PostgreSQL) or section (MySQL) here, and they are stored as
		// they are read, beside the rest of the stream.
		stream := func(path string, fill func(io.Writer) error) error {
			pr, pw := io.Pipe()
			go func() {
				_ = pw.CloseWithError(fill(pw))
			}()
			err := emit(write.Entry{Path: path, Reader: pr})
			_ = pr.CloseWithError(io.ErrClosedPipe)
			return err
		}
		if nd, ok := d.(*dump.NativeDumper); ok && nd.Parallel > 1 {
			nd.Rows = func(ctx context.Context, schema, table string, copy func(io.Writer) (int64, error)) error {
				return stream(dump.TablePath(schema, table), func(w io.Writer) error {
					_, err := copy(w)
					return err
				})
			}
		}
		if gd, ok := d.(*dump.MongoDumper); ok && gd.Parallel > 1 {
			// mongodump's archive interleaves the collections it reads at
			// once; each is stored from a stream of its own.
			gd.Streams = func(entry string) (io.WriteCloser, func() error) {
				pr, pw := io.Pipe()
				done := make(chan error, 1)
				go func() {
					err := emit(write.Entry{Path: entry, Reader: pr})
					_ = pr.CloseWithError(io.ErrClosedPipe)
					done <- err
				}()
				return pw, func() error { return <-done }
			}
		}
		if md, ok := d.(*dump.MySQLDumper); ok && md.Parallel > 1 {
			md.Sections = func(ctx context.Context, entry string, fill func(io.Writer) error) error {
				return stream(entry, fill)
			}
		}
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
	// LeftOut names the tables the backup's role could not read; restore
	// reads it before post-data, which may point at them.
	LeftOut   = "left-out.json"
	Roles     = "roles.sql"
	PreData   = "pre-data.sql"
	Schema    = "schema.sql"
	PostData  = "post-data.sql"
	Sequences = "sequences.sql"
	CronJobs  = "cron-jobs.json"
	Manifest  = "manifest.json"
	dataDir   = "data/"
	// SQLiteDatabase is a SQLite run's database file.
	SQLiteDatabase = "sqlite/database.sqlite"
	sqliteDir      = "sqlite"
	mysqlDir       = "mysql"
	mongoDir       = "mongo"
	// mysqlDump and mongoDump are the one-stream entries a rebuilt archive
	// holds, the names the engines' archive readers expect.
	mysqlDump = "mysql/dump.sql"
	mongoDump = "mongo/dump.archive"
)

// TablePath is the file a run keeps a table's or collection's data in, for
// the engine of kind: a PostgreSQL table's COPY stream, a MySQL table's
// section of the dump, a MongoDB collection's documents. "" for SQLite,
// whose run has no per-table file.
func TablePath(kind model.SurfaceType, schema, table string) string {
	switch kind {
	case model.SurfaceTypeMySQL:
		return dump.MySQLTableEntry(table)
	case model.SurfaceTypeMongoDB:
		return dump.MongoCollectionEntry(table)
	case model.SurfaceTypeSQLite:
		return ""
	}
	return dump.TablePath(schema, table)
}

// Shape is which engine's files a run holds.
type Shape int

const (
	ShapePostgres Shape = iota
	ShapeSQLite
	ShapeMySQL
	ShapeMongo
)

// ShapeOf is the shape of a run from the files Files returned.
func ShapeOf(files []read.Item) Shape {
	for _, it := range files {
		switch {
		case it.Path == SQLiteDatabase:
			return ShapeSQLite
		case strings.HasPrefix(it.Path, mysqlDir+"/"):
			return ShapeMySQL
		case strings.HasPrefix(it.Path, mongoDir+"/"):
			return ShapeMongo
		}
	}
	return ShapePostgres
}

// Files lists the files of a database run in archive order: the tables left
// out, the schema,
// every table's rows, the post-data section, the sequences and the manifest;
// or, for SQLite, the database file and the manifest; or a MySQL dump's head,
// its tables by name and its tail; or a MongoDB prelude and its collections
// by name. It refuses a snapshot holding anything else, or two shapes at
// once, which is not a database run.
func Files(ctx context.Context, r *read.Repo, idx read.Index, s format.Snapshot) ([]read.Item, error) {
	root, err := format.ParseID(s.RootTree)
	if err != nil {
		return nil, err
	}
	var sections = map[string]read.Item{}
	var tables, mysqlTables, mongoColls, largeObjects []read.Item
	var sqliteDB, mysqlHead, mysqlTail, prelude *read.Item
	shapes := map[Shape]bool{}
	err = r.Walk(ctx, idx, root, func(it read.Item) error {
		switch {
		case it.Node.Type == format.NodeDir && (it.Path == "data" || strings.HasPrefix(it.Path, dataDir) || it.Path == "large-objects"):
			return nil
		case it.Node.Type == format.NodeDir && (it.Path == sqliteDir || it.Path == mysqlDir || it.Path+"/" == dump.MySQLTablesDir || it.Path == mongoDir || it.Path+"/" == dump.MongoCollectionsDir):
			return nil
		case it.Node.Type != format.NodeFile:
			return fmt.Errorf("snapshot %s holds %s, which is not part of a database dump", s.SnapshotID, it.Path)
		case it.Path == SQLiteDatabase:
			sqliteDB, shapes[ShapeSQLite] = &it, true
		case it.Path == dump.MySQLHeadEntry:
			mysqlHead, shapes[ShapeMySQL] = &it, true
		case it.Path == dump.MySQLTailEntry:
			mysqlTail, shapes[ShapeMySQL] = &it, true
		case dump.MySQLRunTable(it.Path) != "" && strings.HasSuffix(it.Path, ".sql"):
			mysqlTables, shapes[ShapeMySQL] = append(mysqlTables, it), true
		case it.Path == dump.MongoPreludeEntry:
			prelude, shapes[ShapeMongo] = &it, true
		case dump.MongoRunCollection(it.Path) != "" && strings.HasSuffix(it.Path, ".bson"):
			mongoColls, shapes[ShapeMongo] = append(mongoColls, it), true
		case strings.HasPrefix(it.Path, dataDir) && strings.HasSuffix(it.Path, ".copy"):
			tables, shapes[ShapePostgres] = append(tables, it), true
		case dump.IsLargeObjectEntry(it.Path):
			largeObjects, shapes[ShapePostgres] = append(largeObjects, it), true
		case it.Path == LeftOut || it.Path == Roles || it.Path == PreData || it.Path == Schema || it.Path == PostData || it.Path == Sequences || it.Path == CronJobs:
			sections[it.Path], shapes[ShapePostgres] = it, true
		case it.Path == Manifest:
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
	if len(shapes) > 1 {
		return nil, fmt.Errorf("snapshot %s holds the files of two database engines: it is not one database run", s.SnapshotID)
	}
	if sqliteDB != nil {
		return []read.Item{*sqliteDB, manifest}, nil
	}
	if shapes[ShapeMySQL] {
		if mysqlHead == nil {
			return nil, fmt.Errorf("snapshot %s has no %s: it is not a MySQL run", s.SnapshotID, dump.MySQLHeadEntry)
		}
		// The dump tool writes tables in name order, so the sections
		// concatenate to the dump it wrote.
		sort.Slice(mysqlTables, func(i, j int) bool {
			return dump.MySQLRunTable(mysqlTables[i].Path) < dump.MySQLRunTable(mysqlTables[j].Path)
		})
		out := append([]read.Item{*mysqlHead}, mysqlTables...)
		if mysqlTail != nil {
			out = append(out, *mysqlTail)
		}
		return append(out, manifest), nil
	}
	if shapes[ShapeMongo] {
		if prelude == nil {
			return nil, fmt.Errorf("snapshot %s has no %s: it is not a MongoDB run", s.SnapshotID, dump.MongoPreludeEntry)
		}
		sort.Slice(mongoColls, func(i, j int) bool { return mongoColls[i].Path < mongoColls[j].Path })
		return append(append([]read.Item{*prelude}, mongoColls...), manifest), nil
	}
	_, pre := sections[PreData]
	_, schema := sections[Schema]
	if !pre && !schema {
		return nil, fmt.Errorf("snapshot %s has no schema section", s.SnapshotID)
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Path < tables[j].Path })
	var out []read.Item
	for _, name := range []string{LeftOut, Roles, PreData, Schema} {
		if it, ok := sections[name]; ok {
			out = append(out, it)
		}
	}
	out = append(out, tables...)
	// The list before the objects, which sort in oid order by name.
	sort.Slice(largeObjects, func(i, j int) bool {
		li, lj := largeObjects[i].Path == "large-objects.json", largeObjects[j].Path == "large-objects.json"
		if li != lj {
			return li
		}
		return largeObjects[i].Path < largeObjects[j].Path
	})
	out = append(out, largeObjects...)
	for _, name := range []string{PostData, Sequences, CronJobs, Manifest} {
		if it, ok := sections[name]; ok {
			out = append(out, it)
		}
	}
	return out, nil
}

// Archive writes a database run to w as the tar archive a backup in archive
// format would have been, each file checked against its SHA-256 as it is
// read. A table is one entry however large it is. A MySQL run's sections are
// concatenated into the one mysql/dump.sql entry, and a MongoDB run's
// prelude and collections framed back into the one mongo/dump.archive
// entry, so each engine's archive readers read a run unchanged.
func Archive(ctx context.Context, r *read.Repo, idx read.Index, files []read.Item, w io.Writer) error {
	tw := tar.NewWriter(w)
	switch ShapeOf(files) {
	case ShapeMySQL:
		var size int64
		for _, it := range files {
			if it.Path != Manifest {
				size += it.Node.Size
			}
		}
		if err := tw.WriteHeader(&tar.Header{Name: mysqlDump, Mode: 0o600, Size: size, ModTime: files[0].Node.ModTime.Truncate(time.Second), Format: tar.FormatPAX}); err != nil {
			return err
		}
		for _, it := range files {
			if it.Path == Manifest {
				continue
			}
			if err := r.Cat(ctx, idx, it.Node, tw); err != nil {
				return err
			}
		}
		files = files[len(files)-1:]
	case ShapeMongo:
		var prelude bytes.Buffer
		if err := r.Cat(ctx, idx, files[0].Node, &prelude); err != nil {
			return err
		}
		var parts []dump.MongoRunPart
		for _, it := range files[1:] {
			if it.Path == Manifest {
				continue
			}
			node := it.Node
			parts = append(parts, dump.MongoRunPart{Collection: dump.MongoRunCollection(it.Path), Size: it.Node.Size,
				Open: func(w io.Writer) error { return r.Cat(ctx, idx, node, w) }})
		}
		size, err := dump.MongoRunArchiveSize(prelude.Bytes(), parts)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: mongoDump, Mode: 0o600, Size: size, ModTime: files[0].Node.ModTime.Truncate(time.Second), Format: tar.FormatPAX}); err != nil {
			return err
		}
		if err := dump.WriteMongoRunArchive(prelude.Bytes(), parts, tw); err != nil {
			return err
		}
		files = files[len(files)-1:]
	}
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

// SplitRows takes a PostgreSQL run's table files out of files, for a
// restore that loads them over several connections at once: rest is what
// the stream still carries, and each table's Open writes its chunks in
// order. Largest first, so the longest load starts first. Another shape of
// run is returned whole, with no tables.
func SplitRows(ctx context.Context, r *read.Repo, idx read.Index, files []read.Item) (rest []read.Item, tables []dump.TableData) {
	if ShapeOf(files) != ShapePostgres {
		return files, nil
	}
	type tableFiles struct {
		schema, table string
		parts         map[int]read.Item
		size          int64
	}
	byTable := map[string]*tableFiles{}
	for _, it := range files {
		schema, table, part, ok := dump.ParseTableEntry(it.Path)
		if !ok {
			rest = append(rest, it)
			continue
		}
		k := schema + "." + table
		tf := byTable[k]
		if tf == nil {
			tf = &tableFiles{schema: schema, table: table, parts: map[int]read.Item{}}
			byTable[k] = tf
		}
		tf.parts[part] = it
		tf.size += it.Node.Size
	}
	list := make([]*tableFiles, 0, len(byTable))
	for _, tf := range byTable {
		list = append(list, tf)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].size != list[j].size {
			return list[i].size > list[j].size
		}
		return list[i].schema+"."+list[i].table < list[j].schema+"."+list[j].table
	})
	for _, tf := range list {
		parts := make([]int, 0, len(tf.parts))
		for p := range tf.parts {
			parts = append(parts, p)
		}
		sort.Ints(parts)
		items := make([]read.Item, 0, len(parts))
		for _, p := range parts {
			items = append(items, tf.parts[p])
		}
		tables = append(tables, dump.TableData{Schema: tf.schema, Table: tf.table, Open: func(w io.Writer) error {
			for _, it := range items {
				if err := r.Cat(ctx, idx, it.Node, w); err != nil {
					return err
				}
			}
			return nil
		}})
	}
	return rest, tables
}
