package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/sftpdial"
)

// SFTPStorageProvider keeps snapshots in a directory on an SSH server, laid
// out as a local directory is: <path>/<node>/<id>.safegrd beside its
// .meta.json and recovery document. The server has no Object Lock: the
// retention date in each snapshot's metadata is when prune may delete it,
// and nothing on the server enforces it.
type SFTPStorageProvider struct {
	conn   *sftpdial.Conn
	base   string
	nodeID string
}

// NewSFTPStorage opens nothing yet: the server is dialled on first use.
// cfg's password and private key must already be resolved from any env: or
// file: reference.
func NewSFTPStorage(cfg config.StorageConfig) (*SFTPStorageProvider, error) {
	if cfg.SFTP == nil {
		return nil, errors.New("storage type sftp needs a storage.sftp block")
	}
	if err := cfg.ValidateSFTP("storage"); err != nil {
		return nil, err
	}
	conn, err := sftpdial.New(*cfg.SFTP)
	if err != nil {
		return nil, err
	}
	return &SFTPStorageProvider{conn: conn, base: path.Clean(cfg.SFTP.Path), nodeID: strings.TrimSpace(cfg.NodeID)}, nil
}

// Conn is the provider's session, shared with a repository store on the
// same server.
func (s *SFTPStorageProvider) Conn() *sftpdial.Conn { return s.conn }

// SetNodeID configures the active node ID for scoped storage path segmentation.
func (s *SFTPStorageProvider) SetNodeID(nodeID string) { s.nodeID = strings.TrimSpace(nodeID) }

func (s *SFTPStorageProvider) Type() string { return "sftp" }

// Close closes the session now rather than when it goes idle.
func (s *SFTPStorageProvider) Close() error { return s.conn.Close() }

func (s *SFTPStorageProvider) dir() string {
	if s.nodeID != "" {
		return path.Join(s.base, s.nodeID)
	}
	return s.base
}

func (s *SFTPStorageProvider) snapshotPath(id string) string {
	return path.Join(s.dir(), id+".safegrd")
}
func (s *SFTPStorageProvider) metadataPath(id string) string {
	return path.Join(s.dir(), id+".meta.json")
}

// flat is where a snapshot written before node segmentation sits.
func (s *SFTPStorageProvider) flat(id, suffix string) string { return path.Join(s.base, id+suffix) }

func tmpName(p string) string {
	var b [6]byte
	_, _ = rand.Read(b[:]) // crypto/rand does not fail on supported platforms
	return path.Join(path.Dir(p), ".put-"+hex.EncodeToString(b[:])+"-"+path.Base(p))
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist)
}

// writeNew writes r to p through a temporary name. With replace false it
// fails rather than replace an existing p: SFTP's rename refuses an existing
// target, which is the guarantee that a snapshot is never written twice.
func writeNew(c *sftp.Client, p string, r io.Reader, replace bool) error {
	if err := c.MkdirAll(path.Dir(p)); err != nil {
		return fmt.Errorf("creating %s: %w", path.Dir(p), err)
	}
	tmp := tmpName(p)
	f, err := c.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmp, err)
	}
	if _, err := f.ReadFrom(r); err != nil {
		f.Close()
		_ = c.Remove(tmp) // the write already failed; this only tidies
		return fmt.Errorf("writing %s: %w", p, err)
	}
	if err := f.Close(); err != nil {
		_ = c.Remove(tmp)
		return fmt.Errorf("writing %s: %w", p, err)
	}
	if replace {
		err = c.PosixRename(tmp, p)
	} else {
		err = c.Rename(tmp, p)
	}
	if err != nil {
		_ = c.Remove(tmp)
		if _, statErr := c.Stat(p); !replace && statErr == nil {
			return fmt.Errorf("%s already exists on the server, and a backup is never written twice", p)
		}
		return fmt.Errorf("renaming %s into place: %w", p, err)
	}
	return nil
}

func (s *SFTPStorageProvider) UploadSnapshot(ctx context.Context, snapshotID string, stream io.Reader, size int64, retentionUntil time.Time) (string, error) {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return "", err
	}
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return "", err
	}
	defer done()
	dst := s.snapshotPath(snapshotID)
	if _, err := c.Stat(dst); err == nil {
		return "", fmt.Errorf("snapshot %s already exists on the server, and a backup is never written twice", snapshotID)
	}
	if err := writeNew(c, dst, stream, false); err != nil {
		return "", err
	}
	// Read-only, as a local sink writes it. Prune deletes it all the same:
	// removing a file needs the directory's permission, not the file's.
	if err := c.Chmod(dst, 0o400); err != nil {
		return "", fmt.Errorf("snapshot written, but it could not be made read-only: %w", err)
	}
	// The retention date is what prune reads back, so it is recorded with
	// the snapshot, before its metadata is complete.
	if !retentionUntil.IsZero() {
		existing, _ := s.DownloadMetadata(ctx, snapshotID)
		if existing == nil {
			existing = &model.SnapshotMetadata{SnapshotID: snapshotID}
		}
		if existing.WORMRetentionUntil.IsZero() {
			existing.WORMRetentionUntil = retentionUntil
			if err := s.UploadMetadata(ctx, snapshotID, existing); err != nil {
				return "", fmt.Errorf("snapshot written but its retention date could not be recorded: %w", err)
			}
		}
	}
	return s.conn.URI(strings.TrimPrefix(dst, s.base+"/")), nil
}

// sftpReader hands the session back when the download is closed.
type sftpReader struct {
	*sftp.File
	done func()
}

func (r *sftpReader) Close() error {
	err := r.File.Close()
	r.done()
	return err
}

func (s *SFTPStorageProvider) open(ctx context.Context, paths ...string) (io.ReadCloser, error) {
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return nil, err
	}
	var first error
	for _, p := range paths {
		f, err := c.Open(p)
		if err == nil {
			return &sftpReader{File: f, done: done}, nil
		}
		if first == nil {
			first = err
		}
	}
	done()
	return nil, first
}

func (s *SFTPStorageProvider) DownloadSnapshot(ctx context.Context, snapshotID string) (io.ReadCloser, error) {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return nil, err
	}
	r, err := s.open(ctx, s.snapshotPath(snapshotID), s.flat(snapshotID, ".safegrd"))
	if err != nil {
		return nil, fmt.Errorf("snapshot %s not found on %s: %w", snapshotID, s.conn.Describe(), err)
	}
	return r, nil
}

func (s *SFTPStorageProvider) UploadMetadata(ctx context.Context, snapshotID string, meta *model.SnapshotMetadata) error {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return err
	}
	defer done()
	return writeNew(c, s.metadataPath(snapshotID), strings.NewReader(string(data)), true)
}

func (s *SFTPStorageProvider) UploadRecoveryDoc(ctx context.Context, snapshotID string, doc []byte, sealed bool, _ time.Time) error {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return err
	}
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return err
	}
	defer done()
	dst := strings.TrimSuffix(s.metadataPath(snapshotID), ".meta.json") + RecoveryDocSuffix(sealed)
	return writeNew(c, dst, strings.NewReader(string(doc)), true)
}

func (s *SFTPStorageProvider) DownloadMetadata(ctx context.Context, snapshotID string) (*model.SnapshotMetadata, error) {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return nil, err
	}
	r, err := s.open(ctx, s.metadataPath(snapshotID), s.flat(snapshotID, ".meta.json"))
	if err != nil {
		return nil, fmt.Errorf("metadata for snapshot %s not found: %w", snapshotID, err)
	}
	defer r.Close()
	var meta model.SnapshotMetadata
	if err := json.NewDecoder(io.LimitReader(r, 64<<20)).Decode(&meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	return &meta, nil
}

// walk lists every file under base, as paths relative to it, skipping
// partial writes. A base that does not exist yet holds nothing.
func (s *SFTPStorageProvider) walk(ctx context.Context) ([]sftpFile, error) {
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return walkFiles(c, s.base)
}

type sftpFile struct {
	rel     string
	size    int64
	modTime time.Time
}

func walkFiles(c *sftp.Client, base string) ([]sftpFile, error) {
	var out []sftpFile
	w := c.Walk(base)
	for w.Step() {
		if err := w.Err(); err != nil {
			if w.Path() == base && isNotExist(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("listing %s: %w", w.Path(), err)
		}
		fi := w.Stat()
		if fi.IsDir() || strings.HasPrefix(fi.Name(), ".put-") {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(w.Path(), base), "/")
		out = append(out, sftpFile{rel: rel, size: fi.Size(), modTime: fi.ModTime()})
	}
	return out, nil
}

func (s *SFTPStorageProvider) ListSnapshots(ctx context.Context) ([]string, error) {
	files, err := s.walk(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f.rel, ".safegrd") && !isRepoPath(f.rel) {
			out = append(out, strings.TrimSuffix(path.Base(f.rel), ".safegrd"))
		}
	}
	sort.Strings(out)
	return out, nil
}

// isRepoPath reports whether rel is inside an incremental repository
// (repo/… or <node>/repo/…), whose objects are not archives.
func isRepoPath(rel string) bool {
	parts := strings.Split(rel, "/")
	return (len(parts) > 1 && parts[0] == "repo") || (len(parts) > 2 && parts[1] == "repo")
}

// SnapshotNodes reports which node each snapshot is filed under.
func (s *SFTPStorageProvider) SnapshotNodes(ctx context.Context) (map[string]string, error) {
	files, err := s.walk(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		if isRepoPath(f.rel) {
			continue
		}
		if id, node, ok := nodeOfKey("", f.rel); ok {
			out[id] = node
		}
	}
	return out, nil
}

func (s *SFTPStorageProvider) SnapshotExists(ctx context.Context, snapshotID string) (bool, error) {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return false, err
	}
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return false, err
	}
	defer done()
	for _, p := range []string{s.snapshotPath(snapshotID), s.flat(snapshotID, ".safegrd")} {
		_, err := c.Stat(p)
		if err == nil {
			return true, nil
		}
		if !isNotExist(err) {
			return false, err
		}
	}
	return false, nil
}

// DeleteSnapshot deletes a snapshot whose recorded retention date has
// passed. Nothing on the server holds it, so the date is checked here and
// the check fails closed: an archive whose metadata cannot be read stays.
func (s *SFTPStorageProvider) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return err
	}
	meta, metaErr := s.DownloadMetadata(ctx, snapshotID)
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return err
	}
	defer done()
	base := strings.TrimSuffix(s.metadataPath(snapshotID), ".meta.json")
	paths := []string{s.snapshotPath(snapshotID), s.metadataPath(snapshotID), base + RecoveryDocSuffix(false), base + RecoveryDocSuffix(true)}
	if s.nodeID != "" {
		paths = append(paths, s.flat(snapshotID, ".safegrd"), s.flat(snapshotID, ".meta.json"))
	}
	if metaErr != nil {
		for _, p := range paths {
			if _, err := c.Stat(p); err == nil && strings.HasSuffix(p, ".safegrd") {
				return fmt.Errorf("refusing to delete snapshot %s: its retention date cannot be read (%v)", snapshotID, metaErr)
			}
		}
	} else if !meta.WORMRetentionUntil.IsZero() && meta.WORMRetentionUntil.After(time.Now().UTC()) {
		return fmt.Errorf("refusing to delete snapshot %s: it is kept until %s", snapshotID, meta.WORMRetentionUntil.UTC().Format(time.RFC3339))
	}
	var errs []error
	for _, p := range paths {
		if err := c.Remove(p); err != nil && !isNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// --- Objects: the erasure record, beside the snapshots ---

func (s *SFTPStorageProvider) objectPath(name string) (string, error) {
	if err := validObjectName(name); err != nil {
		return "", err
	}
	return path.Join(s.base, name), nil
}

func (s *SFTPStorageProvider) PutObject(ctx context.Context, name string, data []byte, _ time.Time) error {
	p, err := s.objectPath(name)
	if err != nil {
		return err
	}
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return err
	}
	defer done()
	return writeNew(c, p, strings.NewReader(string(data)), true)
}

func (s *SFTPStorageProvider) ListObjects(ctx context.Context, prefix string) ([]string, error) {
	dir, err := s.objectPath(prefix)
	if err != nil {
		return nil, err
	}
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	files, err := walkFiles(c, dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, path.Join(prefix, f.rel))
	}
	sort.Strings(out)
	return out, nil
}

func (s *SFTPStorageProvider) GetObject(ctx context.Context, name string) ([]byte, error) {
	p, err := s.objectPath(name)
	if err != nil {
		return nil, err
	}
	r, err := s.open(ctx, p)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func (s *SFTPStorageProvider) DeleteObject(ctx context.Context, name string) error {
	p, err := s.objectPath(name)
	if err != nil {
		return err
	}
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return err
	}
	defer done()
	return c.Remove(p)
}

// --- what `safegrd prune` needs ---

// sftpVersion stands for the one copy of a file a server keeps: prune
// deletes by version id, and a server has no versions.
const sftpVersion = "current"

// SnapshotVersions lists every file under the directory, one "version" each.
func (s *SFTPStorageProvider) SnapshotVersions(ctx context.Context) ([]VersionInfo, error) {
	files, err := s.walk(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(files))
	for _, f := range files {
		out = append(out, VersionInfo{Key: path.Join(s.base, f.rel), VersionID: sftpVersion, LastModified: f.modTime, IsLatest: true})
	}
	return out, nil
}

// Prefix is the directory snapshots are filed under.
func (s *SFTPStorageProvider) Prefix() string { return s.base }

// LockDisabled is always true: an SFTP server has no Object Lock.
func (s *SFTPStorageProvider) LockDisabled() bool { return true }

// VersionLock is never asked of a store with no lock.
func (s *SFTPStorageProvider) VersionLock(context.Context, string, string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

// RecordedRetainUntil reads the "kept until" date in the metadata at key.
func (s *SFTPStorageProvider) RecordedRetainUntil(ctx context.Context, key string) (time.Time, error) {
	r, err := s.open(ctx, key)
	if err != nil {
		return time.Time{}, err
	}
	defer r.Close()
	var meta struct {
		WORMRetentionUntil time.Time `json:"worm_retention_until"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 16<<20)).Decode(&meta); err != nil {
		return time.Time{}, fmt.Errorf("reading %s: %w", key, err)
	}
	return meta.WORMRetentionUntil, nil
}

// DeleteVersion removes the file at key.
func (s *SFTPStorageProvider) DeleteVersion(ctx context.Context, key, versionID string) error {
	if versionID != sftpVersion {
		return fmt.Errorf("refusing to delete %s: version %q is not one this store listed", key, versionID)
	}
	if key != s.base && !strings.HasPrefix(key, s.base+"/") {
		return fmt.Errorf("refusing to delete %s: it is outside %s", key, s.base)
	}
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return err
	}
	defer done()
	return c.Remove(key)
}

// BucketNow is the time by the server's clock: the modification time of a
// file it has just written. A date a snapshot is kept until is judged by
// the server that keeps it, not by a host whose clock may be wrong.
func (s *SFTPStorageProvider) BucketNow(ctx context.Context) (time.Time, error) {
	c, done, err := s.conn.Use(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer done()
	return ServerNow(c, s.base)
}

// ServerNow writes and removes a probe file in dir and returns the time the
// server stamped on it.
func ServerNow(c *sftp.Client, dir string) (time.Time, error) {
	if err := c.MkdirAll(dir); err != nil {
		return time.Time{}, fmt.Errorf("creating %s: %w", dir, err)
	}
	p := tmpName(path.Join(dir, "clock"))
	f, err := c.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading the server's clock: %w", err)
	}
	f.Close()
	fi, statErr := c.Stat(p)
	if err := c.Remove(p); err != nil && statErr == nil {
		return time.Time{}, fmt.Errorf("reading the server's clock: could not remove %s: %w", p, err)
	}
	if statErr != nil {
		return time.Time{}, fmt.Errorf("reading the server's clock: %w", statErr)
	}
	return fi.ModTime().UTC(), nil
}
