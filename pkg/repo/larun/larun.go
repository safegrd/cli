// Package larun reads a Laravel app's snapshot back from a repository. The
// snapshot's files are:
//
//	db/...                         the database as its engine's surface stores it
//	files/.env                     the app's .env
//	files/storage/app/...          uploaded and generated files
//	files/database/migrations/...  the migration files, and database/schema
//	manifest.json                  the snapshot's metadata
//
// so the database restores and drills through its engine's own code, and an
// unchanged upload stores no new chunks.
package larun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/dbrun"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/read"
)

// Paths of a Laravel snapshot.
const (
	DBDir        = "db"
	FilesDir     = "files"
	ManifestFile = "manifest.json"
	mysqlDump    = "mysql/dump.sql"
)

// Run is a Laravel snapshot's files.
type Run struct {
	// DB are the database's files relative to db/, in the order its
	// engine's archive holds them.
	DB []read.Item
	// Files are the app's files, at their paths in the snapshot
	// (files/...). Directories and symlinks are not listed.
	Files    []read.Item
	Env      *read.Item
	Manifest read.Item
	// Migrations are the names of the migration files, without .php.
	Migrations []string
}

// Files lists a Laravel snapshot's files. It refuses a snapshot holding
// anything else at its top, or no database or manifest.
func Files(ctx context.Context, r *read.Repo, idx read.Index, s format.Snapshot) (*Run, error) {
	root, err := format.ParseID(s.RootTree)
	if err != nil {
		return nil, err
	}
	top, err := r.Tree(ctx, idx, root)
	if err != nil {
		return nil, err
	}
	run := &Run{}
	var dbTree, filesTree *format.ID
	sawManifest := false
	for _, n := range top.Entries {
		switch {
		case n.Name == DBDir && n.Type == format.NodeDir:
			id := n.Subtree
			dbTree = &id
		case n.Name == FilesDir && n.Type == format.NodeDir:
			id := n.Subtree
			filesTree = &id
		case n.Name == ManifestFile && n.Type == format.NodeFile:
			run.Manifest, sawManifest = read.Item{Path: ManifestFile, Node: n}, true
		default:
			return nil, fmt.Errorf("snapshot %s holds %s, which is not part of a Laravel app", s.SnapshotID, n.Name)
		}
	}
	if !sawManifest {
		return nil, fmt.Errorf("snapshot %s has no %s: it is not a Laravel app", s.SnapshotID, ManifestFile)
	}
	if dbTree == nil {
		return nil, fmt.Errorf("snapshot %s holds no database", s.SnapshotID)
	}
	if run.DB, err = dbFiles(ctx, r, idx, s.SnapshotID, *dbTree); err != nil {
		return nil, err
	}
	if filesTree != nil {
		err = r.Walk(ctx, idx, *filesTree, func(it read.Item) error {
			if it.Node.Type != format.NodeFile {
				return nil
			}
			it.Path = FilesDir + "/" + it.Path
			run.Files = append(run.Files, it)
			rel := strings.TrimPrefix(it.Path, FilesDir+"/")
			switch {
			case rel == dump.LaravelEnvFile:
				e := it
				run.Env = &e
			case path.Dir(rel) == dump.LaravelMigrationsDir && strings.HasSuffix(rel, ".php"):
				run.Migrations = append(run.Migrations, strings.TrimSuffix(path.Base(rel), ".php"))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(run.Migrations)
	return run, nil
}

// dbFiles orders the database's files as its engine's archive holds them:
// a MySQL dump's parts then its manifest, or a PostgreSQL or SQLite run.
func dbFiles(ctx context.Context, r *read.Repo, idx read.Index, snapshotID string, tree format.ID) ([]read.Item, error) {
	isMySQL := false
	var items []read.Item
	err := r.Walk(ctx, idx, tree, func(it read.Item) error {
		if it.Path == "mysql" && it.Node.Type == format.NodeDir {
			isMySQL = true
		}
		items = append(items, it)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !isMySQL {
		return dbrun.Files(ctx, r, idx, format.Snapshot{SnapshotID: snapshotID, RootTree: tree.String()})
	}
	parts := map[int]read.Item{}
	var manifest *read.Item
	for _, it := range items {
		switch {
		case it.Path == "mysql" && it.Node.Type == format.NodeDir:
		case it.Node.Type != format.NodeFile:
			return nil, fmt.Errorf("snapshot %s holds db/%s, which is not part of a MySQL dump", snapshotID, it.Path)
		case it.Path == dbrun.Manifest:
			m := it
			manifest = &m
		case it.Path == mysqlDump:
			parts[0] = it
		case strings.HasPrefix(it.Path, mysqlDump+"."):
			n, err := strconv.Atoi(strings.TrimPrefix(it.Path, mysqlDump+"."))
			if err != nil || n < 1 {
				return nil, fmt.Errorf("snapshot %s holds db/%s, which is not a part of the dump", snapshotID, it.Path)
			}
			parts[n] = it
		default:
			return nil, fmt.Errorf("snapshot %s holds db/%s, which is not part of a MySQL dump", snapshotID, it.Path)
		}
	}
	if manifest == nil {
		return nil, fmt.Errorf("snapshot %s has no db/%s", snapshotID, dbrun.Manifest)
	}
	out := make([]read.Item, 0, len(parts)+1)
	for i := 0; i < len(parts); i++ {
		it, ok := parts[i]
		if !ok {
			return nil, fmt.Errorf("snapshot %s: part %d of the dump is missing", snapshotID, i)
		}
		out = append(out, it)
	}
	return append(out, *manifest), nil
}

// DatabaseArchive writes the database to w as its engine's archive, each file
// checked against its SHA-256 as it is read.
func DatabaseArchive(ctx context.Context, r *read.Repo, idx read.Index, run *Run, w io.Writer) error {
	return dbrun.Archive(ctx, r, idx, run.DB, w)
}

// ReadFile returns one small file of the run whole, checked against its
// SHA-256.
func ReadFile(ctx context.Context, r *read.Repo, idx read.Index, it read.Item) ([]byte, error) {
	if it.Node.Size > 16<<20 {
		return nil, fmt.Errorf("%s is %d bytes; it is read whole only up to 16 MiB", it.Path, it.Node.Size)
	}
	var b bytes.Buffer
	if err := r.Cat(ctx, idx, it.Node, &b); err != nil {
		return nil, fmt.Errorf("reading %s: %w", it.Path, err)
	}
	return b.Bytes(), nil
}

// ReadManifest returns the snapshot's metadata as the snapshot holds it.
func ReadManifest(ctx context.Context, r *read.Repo, idx read.Index, run *Run) (*model.SnapshotMetadata, error) {
	b, err := ReadFile(ctx, r, idx, run.Manifest)
	if err != nil {
		return nil, err
	}
	var m model.SnapshotMetadata
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("the snapshot's %s: %w", ManifestFile, err)
	}
	return &m, nil
}
