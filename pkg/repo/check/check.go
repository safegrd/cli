// Package check verifies a repository without writing to it: that every pack
// a snapshot names is present, that each pack's trailer agrees with the index,
// that every tree decodes and every blob it names is indexed, optionally that
// every blob opens and hashes to its id, that the content root recomputed
// from the trees matches the one recorded, and that the catalog agrees with
// the trees. It shares the byte encodings with the writer and nothing else.
package check

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
)

// Options select how deep a check goes.
type Options struct {
	// ReadData opens every blob a snapshot references and checks its hash.
	ReadData bool
}

// Report is what a check found.
type Report struct {
	Snapshots   int
	Packs       int
	BlobsRead   int
	ContentRoot string
	Problems    []string
}

// OK reports whether the check found nothing wrong.
func (r *Report) OK() bool { return len(r.Problems) == 0 }

func (r *Report) add(format_ string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format_, args...))
}

// Err is the report's problems as one error, or nil.
func (r *Report) Err() error {
	if r.OK() {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(r.Problems, "; "))
}

type sidecar struct {
	Format         string `json:"format"`
	EpochID        string `json:"epoch_id"`
	ObjectClass    string `json:"object_class"`
	Sha256Checksum string `json:"sha256_checksum"`
	SnapshotID     string `json:"snapshot_id"`
}

// Snapshots lists the snapshot ids of an epoch that have a sidecar, which is
// what makes a snapshot exist.
func Snapshots(ctx context.Context, b sink.Backend, e sink.EpochInfo) ([]string, error) {
	objs, err := b.List(ctx, e, "snapshots")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, o := range objs {
		base := o.Key[strings.LastIndex(o.Key, "/")+1:]
		if id, ok := strings.CutSuffix(base, ".meta.json"); ok {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Snapshot checks one snapshot of an epoch.
func Snapshot(ctx context.Context, b sink.Backend, e sink.EpochInfo, snapshotID string, ids []age.Identity, o Options) (*Report, error) {
	rep := &Report{Snapshots: 1}
	r := read.Open(b, e, ids)
	metaKey, err := sink.ObjectKey(e.Prefix, sink.KindMeta, snapshotID)
	if err != nil {
		return nil, err
	}
	metaBody, err := b.Get(ctx, metaKey)
	if err != nil {
		rep.add("snapshot %s has no metadata sidecar: %v", snapshotID, err)
		return rep, nil
	}
	var sc sidecar
	if err := json.Unmarshal(metaBody, &sc); err != nil {
		rep.add("snapshot %s: the sidecar does not parse: %v", snapshotID, err)
		return rep, nil
	}
	snap, err := r.Snapshot(ctx, snapshotID)
	if err != nil {
		rep.add("%v", err)
		return rep, nil
	}
	if sc.Format != format.SidecarFormat || sc.EpochID != e.Epoch.EpochID || sc.ObjectClass != snap.Class {
		rep.add("snapshot %s: the sidecar says format %q, epoch %q, class %q; the snapshot says %s, %s, %s",
			snapshotID, sc.Format, sc.EpochID, sc.ObjectClass, format.SidecarFormat, snap.EpochID, snap.Class)
	}

	// Every pack the snapshot names is present.
	listed, err := b.List(ctx, e, "packs")
	if err != nil {
		return nil, err
	}
	sizes := map[string]int64{}
	for _, ob := range listed {
		sizes[ob.Key[strings.LastIndex(ob.Key, "/")+1:]] = ob.Size
	}
	for _, p := range snap.Packs {
		if _, ok := sizes[p]; !ok {
			rep.add("pack %s, which snapshot %s needs, is missing", p, snapshotID)
		}
	}
	if !rep.OK() {
		return rep, nil
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		rep.add("%v", err)
		return rep, nil
	}

	// Each pack's trailer agrees with the index.
	byPack := map[string][]format.BlobEntry{}
	for _, loc := range idx {
		byPack[loc.Pack] = append(byPack[loc.Pack], loc.Entry)
	}
	needed := map[string]bool{}
	for _, p := range snap.Packs {
		needed[p] = true
	}
	for p := range needed {
		rep.Packs++
		size := sizes[p]
		if err := checkTrailer(ctx, b, r, e, p, size, byPack[p], ids); err != nil {
			rep.add("pack %s: %v", p, err)
		}
	}

	// Every tree decodes, every blob it names is indexed, and the content
	// root recomputed from the trees matches.
	root, err := format.ParseID(snap.RootTree)
	if err != nil {
		return nil, err
	}
	type line struct {
		path  string
		typ   byte
		value string
	}
	var lines []line
	var data []format.ID
	walkErr := r.Walk(ctx, idx, root, func(it read.Item) error {
		n := it.Node
		switch n.Type {
		case format.NodeDir:
			lines = append(lines, line{it.Path, format.ContentDir, "-"})
		case format.NodeSymlink:
			lines = append(lines, line{it.Path, format.ContentSymlink, format.ContentValue(format.ContentSymlink, "", n.Target)})
		case format.NodeFile:
			lines = append(lines, line{it.Path, format.ContentFile, n.SHA256})
			var total int64
			for _, id := range n.Content {
				loc, ok := idx[id]
				if !ok {
					rep.add("%s: blob %s is in no index the snapshot lists", it.Path, id)
					continue
				}
				if format.BlobKind(loc.Entry.Type) != format.BlobData {
					rep.add("%s: blob %s is stored as a tree", it.Path, id)
				}
				if !needed[loc.Pack] {
					rep.add("%s: blob %s is in pack %s, which the snapshot does not list", it.Path, id, loc.Pack)
				}
				total += loc.Entry.RawLength
				data = append(data, id)
			}
			if total != n.Size {
				rep.add("%s: its blobs hold %d bytes, the tree says %d", it.Path, total, n.Size)
			}
		}
		return nil
	})
	if walkErr != nil {
		rep.add("snapshot %s: %v", snapshotID, walkErr)
		return rep, nil
	}
	sort.Slice(lines, func(i, j int) bool { return bytes.Compare([]byte(lines[i].path), []byte(lines[j].path)) < 0 })
	cr := format.NewContentRoot()
	for _, l := range lines {
		cr.Add(l.typ, l.value, l.path)
	}
	sum, err := cr.Sum()
	if err != nil {
		rep.add("snapshot %s: %v", snapshotID, err)
		return rep, nil
	}
	rep.ContentRoot = sum
	if sum != snap.ContentRoot {
		rep.add("snapshot %s: the trees give content root %s, the snapshot recorded %s", snapshotID, sum, snap.ContentRoot)
	}
	if sum != sc.Sha256Checksum {
		rep.add("snapshot %s: the trees give content root %s, the sidecar recorded %s", snapshotID, sum, sc.Sha256Checksum)
	}

	if o.ReadData {
		n, err := readData(ctx, b, r, e, idx, data)
		rep.BlobsRead = n
		if err != nil {
			rep.add("%v", err)
		}
	}

	// The catalog, replayed to this snapshot, agrees with the trees.
	if err := checkCatalog(ctx, b, r, e, snap, lines2map(lines, func(l line) (string, byte, string) { return l.path, l.typ, l.value }), ids); err != nil {
		rep.add("snapshot %s: %v", snapshotID, err)
	}
	return rep, nil
}

func lines2map[T any](ls []T, f func(T) (string, byte, string)) map[string][2]string {
	m := make(map[string][2]string, len(ls))
	for _, l := range ls {
		p, t, v := f(l)
		m[p] = [2]string{string(t), v}
	}
	return m
}

func checkTrailer(ctx context.Context, b sink.Backend, r *read.Repo, e sink.EpochInfo, pack string, size int64, want []format.BlobEntry, ids []age.Identity) error {
	key, _ := sink.ObjectKey(e.Prefix, sink.KindPack, pack)
	head, err := b.GetRange(ctx, key, 0, format.PackHeaderProbe)
	if err != nil {
		return err
	}
	n, err := format.PackHeaderLen(head)
	if err != nil {
		return err
	}
	if n > len(head) {
		if head, err = b.GetRange(ctx, key, 0, int64(n)); err != nil {
			return err
		}
	}
	wrapped, hdr, err := format.ParsePackHeader(head)
	if err != nil {
		return err
	}
	k, err := unseal.UnwrapKey(wrapped, ids)
	if err != nil {
		return err
	}
	o, err := unseal.NewOpener(k)
	if err != nil {
		return err
	}
	foot, err := b.GetRange(ctx, key, size-format.PackFooterLen, format.PackFooterLen)
	if err != nil {
		return err
	}
	tl, err := format.ParsePackFooter(foot, size, hdr)
	if err != nil {
		return err
	}
	rec, err := b.GetRange(ctx, key, size-format.PackFooterLen-int64(tl), int64(tl))
	if err != nil {
		return err
	}
	tr, err := o.Trailer(pack, rec)
	if err != nil {
		return err
	}
	have := map[string]format.BlobEntry{}
	for _, be := range tr.Blobs {
		if err := be.ValidateIn(hdr, size, tl); err != nil {
			return fmt.Errorf("trailer: %w", err)
		}
		have[be.ID] = be
	}
	for _, w := range want {
		got, ok := have[w.ID]
		if !ok {
			return fmt.Errorf("the index places blob %s here, the trailer does not list it", w.ID)
		}
		if got != w {
			return fmt.Errorf("blob %s: the index says %+v, the trailer %+v", w.ID, w, got)
		}
	}
	return nil
}

func readData(ctx context.Context, b sink.Backend, r *read.Repo, e sink.EpochInfo, idx read.Index, ids []format.ID) (int, error) {
	byPack := map[string][]format.ID{}
	seen := map[format.ID]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		byPack[idx[id].Pack] = append(byPack[idx[id].Pack], id)
	}
	n := 0
	packs := make([]string, 0, len(byPack))
	for p := range byPack {
		packs = append(packs, p)
	}
	sort.Strings(packs)
	for _, p := range packs {
		key, _ := sink.ObjectKey(e.Prefix, sink.KindPack, p)
		body, err := b.Get(ctx, key)
		if err != nil {
			return n, fmt.Errorf("pack %s: %w", p, err)
		}
		wrapped, _, err := format.ParsePackHeader(body)
		if err != nil {
			return n, fmt.Errorf("pack %s: %w", p, err)
		}
		k, err := unseal.UnwrapKey(wrapped, r.IDs)
		if err != nil {
			return n, fmt.Errorf("pack %s: %w", p, err)
		}
		o, _ := unseal.NewOpener(k)
		for _, id := range byPack[p] {
			en := idx[id].Entry
			if en.Offset+en.Length > int64(len(body)) {
				return n, fmt.Errorf("pack %s: blob %s lies past its end", p, id)
			}
			if _, err := o.Blob(body[en.Offset:en.Offset+en.Length], en); err != nil {
				return n, fmt.Errorf("pack %s: %w", p, err)
			}
			n++
		}
	}
	return n, nil
}

// checkCatalog replays the epoch's catalog deltas in run order up to snap and
// compares the result with the trees: the same paths, of the same types, and
// for files the same SHA-256.
func checkCatalog(ctx context.Context, b sink.Backend, r *read.Repo, e sink.EpochInfo, snap format.Snapshot, trees map[string][2]string, ids []age.Identity) error {
	snapIDs, err := Snapshots(ctx, b, e)
	if err != nil {
		return err
	}
	var snaps []format.Snapshot
	for _, id := range snapIDs {
		s, err := r.Snapshot(ctx, id)
		if err != nil {
			return err
		}
		snaps = append(snaps, s)
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].CreatedAt.Before(snaps[j].CreatedAt) })
	state := map[string][2]string{}
	found := false
	for _, s := range snaps {
		key, _ := sink.ObjectKey(e.Prefix, sink.KindCatalog, s.RunID)
		body, err := b.Get(ctx, key)
		if err != nil {
			return fmt.Errorf("the catalog of run %s: %w", s.RunID, err)
		}
		var c format.Catalog
		if err := unseal.Object(body, ids, &c); err != nil {
			return fmt.Errorf("the catalog of run %s: %w", s.RunID, err)
		}
		if err := c.Validate(); err != nil {
			return err
		}
		if c.Complete {
			state = map[string][2]string{}
		}
		for _, en := range c.Entries {
			switch en.Event {
			case format.EventDeleted:
				delete(state, en.Path)
			default:
				v := en.SHA256
				if en.Type != "f" {
					v = ""
				}
				state[en.Path] = [2]string{en.Type, v}
			}
		}
		if s.SnapshotID == snap.SnapshotID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no catalog leads to snapshot %s", snap.SnapshotID)
	}
	for p, t := range trees {
		c, ok := state[p]
		if !ok {
			return fmt.Errorf("the catalog does not list %s", p)
		}
		if c[0] != t[0] || (t[0] == "f" && c[1] != t[1]) {
			return fmt.Errorf("the catalog lists %s as %s %s, the tree as %s %s", p, c[0], c[1], t[0], t[1])
		}
	}
	for p := range state {
		if _, ok := trees[p]; !ok {
			return fmt.Errorf("the catalog lists %s, which the tree does not hold", p)
		}
	}
	return nil
}

// DirContentRoot computes the content root of a directory on disk: every
// entry below dir, by its path relative to dir. A drill runs it over the
// files it just restored, so the root it compares with the recorded one comes
// from the bytes on disk and not from the trees the restore used.
func DirContentRoot(dir string) (root string, files int64, err error) {
	type line struct {
		path  string
		typ   byte
		value string
	}
	var lines []line
	err = filepath.WalkDir(dir, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case de.Type()&fs.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			lines = append(lines, line{rel, format.ContentSymlink, hex.EncodeToString([]byte(t))})
		case de.IsDir():
			lines = append(lines, line{rel, format.ContentDir, "-"})
		case de.Type().IsRegular():
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return err
			}
			files++
			lines = append(lines, line{rel, format.ContentFile, hex.EncodeToString(h.Sum(nil))})
		default:
			return fmt.Errorf("%s is neither a file, a directory nor a symlink", rel)
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Slice(lines, func(i, j int) bool { return bytes.Compare([]byte(lines[i].path), []byte(lines[j].path)) < 0 })
	h := sha256.New()
	for _, l := range lines {
		h.Write(format.ContentLine(l.typ, l.value, l.path))
	}
	return hex.EncodeToString(h.Sum(nil)), files, nil
}
