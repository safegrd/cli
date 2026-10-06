// Package wprun reads a WordPress site's snapshot back from a repository. The
// snapshot's files are the site archive's entries:
//
//	mysql/dump.sql, mysql/dump.sql.1, ...  the dump: a header, one part per table, a footer
//	files/<path>                           wp-config.php, .htaccess and the content directory
//	manifest.json                          the snapshot's metadata
//
// so a table or a file that did not change stores no new chunks, and the
// drill and the restore read the archive stream they already understand.
package wprun

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/read"
)

const (
	dumpFile     = "mysql/dump.sql"
	filesPrefix  = "files/"
	manifestFile = "manifest.json"
	fileList     = "files.json"
)

// Run is a WordPress snapshot's files, in the order the archive holds them.
type Run struct {
	Dump     []read.Item
	Files    []read.Item
	Manifest read.Item
}

// Files lists a WordPress snapshot's files. It refuses a snapshot holding
// anything else, a dump whose parts do not run 0, 1, 2 ... without a gap, or
// no manifest: none of those is a site this reads.
func Files(ctx context.Context, r *read.Repo, idx read.Index, s format.Snapshot) (*Run, error) {
	root, err := format.ParseID(s.RootTree)
	if err != nil {
		return nil, err
	}
	run := &Run{}
	parts := map[int]read.Item{}
	sawManifest := false
	err = r.Walk(ctx, idx, root, func(it read.Item) error {
		switch {
		case it.Node.Type == format.NodeDir && (it.Path == "mysql" || it.Path == "files" || strings.HasPrefix(it.Path, filesPrefix)):
			return nil
		case it.Node.Type != format.NodeFile:
			return fmt.Errorf("snapshot %s holds %s, which is not part of a WordPress site", s.SnapshotID, it.Path)
		case it.Path == manifestFile:
			run.Manifest, sawManifest = it, true
		case strings.HasPrefix(it.Path, filesPrefix):
			run.Files = append(run.Files, it)
		case it.Path == dumpFile:
			parts[0] = it
		case strings.HasPrefix(it.Path, dumpFile+"."):
			n, err := strconv.Atoi(strings.TrimPrefix(it.Path, dumpFile+"."))
			if err != nil || n < 1 {
				return fmt.Errorf("snapshot %s holds %s, which is not a part of the dump", s.SnapshotID, it.Path)
			}
			parts[n] = it
		default:
			return fmt.Errorf("snapshot %s holds %s, which is not part of a WordPress site", s.SnapshotID, it.Path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !sawManifest {
		return nil, fmt.Errorf("snapshot %s has no %s: it is not a WordPress site", s.SnapshotID, manifestFile)
	}
	for i := 0; i < len(parts); i++ {
		it, ok := parts[i]
		if !ok {
			return nil, fmt.Errorf("snapshot %s: part %d of the dump is missing", s.SnapshotID, i)
		}
		run.Dump = append(run.Dump, it)
	}
	sort.Slice(run.Files, func(i, j int) bool { return run.Files[i].Path < run.Files[j].Path })
	return run, nil
}

// Archive writes the snapshot to w as the site archive the WordPress drill and
// restore read: the dump's parts in order, every file, the file list, and the
// manifest. Every file is checked against its SHA-256 as it is read, so the
// list the archive carries is what the run holds.
func Archive(ctx context.Context, r *read.Repo, idx read.Index, run *Run, w io.Writer) error {
	tw := tar.NewWriter(w)
	put := func(it read.Item, name string, mode int64) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: it.Node.Size,
			ModTime: it.Node.ModTime.Truncate(time.Second), Format: tar.FormatPAX, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		return r.Cat(ctx, idx, it.Node, tw)
	}
	for i, it := range run.Dump {
		name := dumpFile
		if i > 0 {
			name = dumpFile + "." + strconv.Itoa(i)
		}
		if err := put(it, name, 0o600); err != nil {
			return err
		}
	}
	list := make([]dump.WordPressFileEntry, 0, len(run.Files))
	for _, it := range run.Files {
		if err := put(it, it.Path, int64(it.Node.Mode&0o7777)); err != nil {
			return err
		}
		list = append(list, dump.WordPressFileEntry{Path: strings.TrimPrefix(it.Path, filesPrefix), Size: it.Node.Size, Sha256: it.Node.SHA256})
	}
	body, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: fileList, Mode: 0o600, Size: int64(len(body)), Format: tar.FormatPAX, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := tw.Write(body); err != nil {
		return err
	}
	if err := put(run.Manifest, manifestFile, 0o600); err != nil {
		return err
	}
	return tw.Close()
}
