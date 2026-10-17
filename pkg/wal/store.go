package wal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/safegrd/cli/pkg/repo/sink"
)

// ErrNotFound is a key that holds nothing.
var ErrNotFound = sink.ErrNotFound

// ErrDeleteDenied is a delete the store's credential may not make.
var ErrDeleteDenied = errors.New("this storage key cannot delete objects in the bucket")

// Object is one object in a listing.
type Object struct {
	Key  string
	Size int64
}

// Store is where an archive's objects go. Locked objects (base backups,
// bundles) are read so that a delete marker put over one does not hide it;
// unlocked WAL files are read as the bucket shows them now, since deleting
// them is how a bundle retires them.
type Store interface {
	// Put streams body to key, locked until lockUntil, or unlocked when it
	// is zero. It fails rather than overwrite, and returns the lock the
	// object got: zero in a store that locks nothing, and on hosted storage
	// the date the remote server chose.
	Put(ctx context.Context, key string, body io.Reader, lockUntil time.Time) (time.Time, error)
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	GetRange(ctx context.Context, key string, off, n int64) ([]byte, error)
	List(ctx context.Context, prefix string) ([]Object, error)
	// GetCurrent and ListCurrent read unlocked objects.
	GetCurrent(ctx context.Context, key string) (io.ReadCloser, error)
	ListCurrent(ctx context.Context, prefix string) ([]Object, error)
	// Delete removes an unlocked object for good, or returns
	// ErrDeleteDenied.
	Delete(ctx context.Context, key string) error
	// Children lists the names directly under prefix.
	Children(ctx context.Context, prefix string) ([]string, error)
	Root() string
	Describe() string
	// Locks says whether a lock date is applied at all.
	Locks() bool
}

// Retirer is a store that deletes bundled WAL files itself, given their
// keys: hosted storage, where the remote server checks each is in a bundle
// before it deletes it.
type Retirer interface {
	Retire(ctx context.Context, keys []string) (int, error)
}

// S3Store is an archive in a bucket the host holds a credential for.
type S3Store struct {
	Client *s3.Client
	Bucket string
	Prefix string
	// Mode is the bucket's Object Lock mode, "" for none.
	Mode s3types.ObjectLockMode
	// Now is the clock a lock date is checked against.
	Now func() time.Time

	locked *sink.S3
}

// NewS3Store returns the archive store over one bucket and prefix.
func NewS3Store(client *s3.Client, bucket, prefix string, mode s3types.ObjectLockMode) *S3Store {
	return &S3Store{Client: client, Bucket: bucket, Prefix: prefix, Mode: mode,
		locked: &sink.S3{Client: client, Bucket: bucket, Prefix: prefix, Mode: mode}}
}

func (s *S3Store) Root() string     { return strings.Trim(s.Prefix, "/") }
func (s *S3Store) Describe() string { return "s3://" + path.Join(s.Bucket, s.Root()) }
func (s *S3Store) Locks() bool      { return s.Mode != "" }

func (s *S3Store) Put(ctx context.Context, key string, body io.Reader, lockUntil time.Time) (time.Time, error) {
	in := &s3.PutObjectInput{
		Bucket:      &s.Bucket,
		Key:         &key,
		Body:        body,
		ContentType: aws.String("application/octet-stream"),
	}
	if s.Mode != "" && !lockUntil.IsZero() {
		now := time.Now
		if s.Now != nil {
			now = s.Now
		}
		if !lockUntil.After(now()) {
			return time.Time{}, fmt.Errorf("%s: the lock date %s is not in the future", key, lockUntil.UTC().Format(time.RFC3339))
		}
		in.ObjectLockMode = s.Mode
		in.ObjectLockRetainUntilDate = aws.Time(lockUntil.UTC())
	}
	up := manager.NewUploader(s.Client, func(u *manager.Uploader) {
		u.PartSize = 64 << 20
		u.Concurrency = 4
	})
	if _, err := up.Upload(ctx, in); err != nil {
		return time.Time{}, fmt.Errorf("writing s3://%s/%s: %w", s.Bucket, key, err)
	}
	if s.Mode == "" {
		return time.Time{}, nil
	}
	return lockUntil, nil
}

func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.locked.Get(ctx, key)
}

func (s *S3Store) GetRange(ctx context.Context, key string, off, n int64) ([]byte, error) {
	return s.locked.GetRange(ctx, key, off, n)
}

func (s *S3Store) List(ctx context.Context, prefix string) ([]Object, error) {
	objs, err := s.locked.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]Object, len(objs))
	for i, o := range objs {
		out[i] = Object{Key: o.Key, Size: o.Size}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (s *S3Store) GetCurrent(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.Bucket, Key: &key})
	if err != nil {
		if notFound(err) {
			return nil, fmt.Errorf("s3://%s/%s: %w", s.Bucket, key, ErrNotFound)
		}
		return nil, fmt.Errorf("reading s3://%s/%s: %w", s.Bucket, key, err)
	}
	return out.Body, nil
}

func (s *S3Store) ListCurrent(ctx context.Context, prefix string) ([]Object, error) {
	var out []Object
	p := s3.NewListObjectsV2Paginator(s.Client, &s3.ListObjectsV2Input{Bucket: &s.Bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing s3://%s/%s: %w", s.Bucket, prefix, err)
		}
		for _, o := range page.Contents {
			out = append(out, Object{Key: aws.ToString(o.Key), Size: aws.ToInt64(o.Size)})
		}
	}
	return out, nil
}

// Delete removes every version of key. A plain DELETE in a versioned bucket
// only puts a marker over the bytes, which then stay and are billed, so a
// credential that may not delete versions leaves the object as it is.
func (s *S3Store) Delete(ctx context.Context, key string) error {
	var versions []string
	p := s3.NewListObjectVersionsPaginator(s.Client, &s3.ListObjectVersionsInput{Bucket: &s.Bucket, Prefix: &key})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("listing versions of s3://%s/%s: %w", s.Bucket, key, err)
		}
		for _, v := range page.Versions {
			if aws.ToString(v.Key) == key {
				versions = append(versions, aws.ToString(v.VersionId))
			}
		}
		for _, m := range page.DeleteMarkers {
			if aws.ToString(m.Key) == key {
				versions = append(versions, aws.ToString(m.VersionId))
			}
		}
	}
	for _, v := range versions {
		_, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.Bucket, Key: &key, VersionId: aws.String(v)})
		if err == nil {
			continue
		}
		if !accessDenied(err) {
			return fmt.Errorf("deleting s3://%s/%s: %w", s.Bucket, key, err)
		}
		// A bucket with versioning never turned on holds the one "null"
		// version, which a plain DELETE removes for good.
		if v == "null" && len(versions) == 1 {
			if _, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.Bucket, Key: &key}); err == nil {
				continue
			} else if !accessDenied(err) {
				return fmt.Errorf("deleting s3://%s/%s: %w", s.Bucket, key, err)
			}
		}
		return ErrDeleteDenied
	}
	return nil
}

func (s *S3Store) Children(ctx context.Context, prefix string) ([]string, error) {
	return s.locked.Children(ctx, prefix)
}

func notFound(err error) bool {
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var api smithy.APIError
	return errors.As(err, &api) && (api.ErrorCode() == "NoSuchKey" || api.ErrorCode() == "NotFound")
}

func accessDenied(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "AccessDenied", "Forbidden", "AllAccessDisabled":
		return true
	}
	return false
}

// DirStore is an archive in a local directory. Nothing locks it.
type DirStore struct {
	base string
	root string
}

// NewDirStore returns the archive store under base, with keys starting at
// root.
func NewDirStore(base, root string) (*DirStore, error) {
	abs, err := filepath.Abs(base)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", abs, err)
	}
	return &DirStore{base: abs, root: strings.Trim(root, "/")}, nil
}

func (d *DirStore) Root() string     { return d.root }
func (d *DirStore) Describe() string { return filepath.Join(d.base, filepath.FromSlash(d.root)) }
func (d *DirStore) Locks() bool      { return false }

func (d *DirStore) path(key string) (string, error) {
	clean := path.Clean("/" + key)
	if clean == "/" || clean != "/"+key {
		return "", fmt.Errorf("key %q is not clean", key)
	}
	return filepath.Join(d.base, filepath.FromSlash(clean[1:])), nil
}

func (d *DirStore) Put(_ context.Context, key string, body io.Reader, _ time.Time) (time.Time, error) {
	return time.Time{}, d.put(key, body)
}

func (d *DirStore) put(key string, body io.Reader) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".put-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return err
	}
	// A hard link fails when the name exists, which a rename would not.
	if err := os.Link(tmp.Name(), p); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists, and an object is never written twice", key)
		}
		return err
	}
	return nil
}

func (d *DirStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	return f, err
}

func (d *DirStore) GetRange(_ context.Context, key string, off, n int64) ([]byte, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, off)
	if err == io.EOF {
		err = nil
	}
	return buf[:got], err
}

func (d *DirStore) List(_ context.Context, prefix string) ([]Object, error) {
	var out []Object
	start := filepath.Join(d.base, filepath.FromSlash(strings.TrimSuffix(prefix, "/")))
	if !strings.HasSuffix(prefix, "/") && prefix != "" {
		start = filepath.Dir(start)
	}
	err := filepath.WalkDir(start, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if de.IsDir() || strings.HasPrefix(de.Name(), ".put-") {
			return nil
		}
		rel, err := filepath.Rel(d.base, p)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		info, err := de.Info()
		if err != nil {
			return err
		}
		out = append(out, Object{Key: key, Size: info.Size()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, err
}

func (d *DirStore) GetCurrent(ctx context.Context, key string) (io.ReadCloser, error) {
	return d.Get(ctx, key)
}

func (d *DirStore) ListCurrent(ctx context.Context, prefix string) ([]Object, error) {
	return d.List(ctx, prefix)
}

func (d *DirStore) Children(_ context.Context, prefix string) ([]string, error) {
	des, err := os.ReadDir(filepath.Join(d.base, filepath.FromSlash(strings.Trim(prefix, "/"))))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, de := range des {
		if de.IsDir() {
			out = append(out, de.Name())
		}
	}
	return out, nil
}

func (d *DirStore) Delete(_ context.Context, key string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	return os.Remove(p)
}
