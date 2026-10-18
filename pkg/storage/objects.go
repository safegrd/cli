package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Objects is a provider that keeps named objects of its own beside the
// snapshots: the erasure record. A name is relative to the provider's root,
// above any node segment, so a host restoring another host's snapshot finds
// the objects at the name the snapshot recorded.
type Objects interface {
	// PutObject writes data at name, locked until retainUntil where the
	// sink applies Object Lock; a zero time writes it unlocked.
	PutObject(ctx context.Context, name string, data []byte, retainUntil time.Time) error
	// ListObjects returns the names under prefix, sorted.
	ListObjects(ctx context.Context, prefix string) ([]string, error)
	GetObject(ctx context.Context, name string) ([]byte, error)
	// DeleteObject deletes every version of name. A locked object, or a
	// bucket whose policy refuses deletes, returns the refusal.
	DeleteObject(ctx context.Context, name string) error
}

// validObjectName refuses a name that would leave the provider's root.
func validObjectName(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("object name %q is not a relative path", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("object name %q is not a relative path", name)
		}
	}
	return nil
}

func (l *LocalStorageProvider) objectPath(name string) (string, error) {
	if err := validObjectName(name); err != nil {
		return "", err
	}
	return filepath.Join(l.baseDir, filepath.FromSlash(name)), nil
}

// PutObject writes the file whole or not at all. A directory has no lock.
func (l *LocalStorageProvider) PutObject(_ context.Context, name string, data []byte, _ time.Time) error {
	p, err := l.objectPath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".part"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (l *LocalStorageProvider) ListObjects(_ context.Context, prefix string) ([]string, error) {
	dir, err := l.objectPath(prefix)
	if err != nil {
		return nil, err
	}
	var out []string
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && p == dir {
				return filepath.SkipDir
			}
			return err
		}
		if d.IsDir() || strings.HasSuffix(p, ".part") {
			return nil
		}
		rel, err := filepath.Rel(l.baseDir, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func (l *LocalStorageProvider) GetObject(_ context.Context, name string) ([]byte, error) {
	p, err := l.objectPath(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (l *LocalStorageProvider) DeleteObject(_ context.Context, name string) error {
	p, err := l.objectPath(name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

func (s *S3StorageProvider) objectKey(name string) (string, error) {
	if err := validObjectName(name); err != nil {
		return "", err
	}
	return path.Join(s.prefix, name), nil
}

// PutObject locks the object in the bucket's mode until retainUntil, as a
// snapshot is locked, unless the sink applies no Object Lock.
func (s *S3StorageProvider) PutObject(ctx context.Context, name string, data []byte, retainUntil time.Time) error {
	key, err := s.objectKey(name)
	if err != nil {
		return err
	}
	in := &s3.PutObjectInput{Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(data), ContentType: ptr("application/octet-stream")}
	if !retainUntil.IsZero() && !s.lockDisabled {
		mode := s.wormMode
		if mode == "" {
			mode = s3types.ObjectLockModeCompliance
		}
		in.ObjectLockMode, in.ObjectLockRetainUntilDate = mode, &retainUntil
	}
	if _, err := s.client.PutObject(ctx, in); err != nil {
		return fmt.Errorf("failed to write s3://%s/%s: %w", s.bucket, key, err)
	}
	return nil
}

func (s *S3StorageProvider) ListObjects(ctx context.Context, prefix string) ([]string, error) {
	key, err := s.objectKey(prefix)
	if err != nil {
		return nil, err
	}
	key += "/"
	var out []string
	var token *string
	for {
		page, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &key, ContinuationToken: token})
		if err != nil {
			return nil, fmt.Errorf("failed to list s3://%s/%s: %w", s.bucket, key, err)
		}
		for _, o := range page.Contents {
			if o.Key == nil {
				continue
			}
			rel := strings.TrimPrefix(*o.Key, s.prefix)
			out = append(out, strings.TrimPrefix(rel, "/"))
		}
		if page.IsTruncated == nil || !*page.IsTruncated {
			break
		}
		token = page.NextContinuationToken
	}
	sort.Strings(out)
	return out, nil
}

func (s *S3StorageProvider) GetObject(ctx context.Context, name string) ([]byte, error) {
	key, err := s.objectKey(name)
	if err != nil {
		return nil, err
	}
	o, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return nil, fmt.Errorf("failed to read s3://%s/%s: %w", s.bucket, key, err)
	}
	defer o.Body.Close()
	return io.ReadAll(o.Body)
}

// DeleteObject deletes every version by id, as DeleteSnapshot does: on a
// versioned bucket a keyed delete only writes a marker.
func (s *S3StorageProvider) DeleteObject(ctx context.Context, name string) error {
	key, err := s.objectKey(name)
	if err != nil {
		return err
	}
	versions, err := s.listVersions(ctx, key)
	if err != nil {
		return s.deleteKeyWithoutVersioning(ctx, key)
	}
	for _, v := range versions {
		if v.Key != key {
			continue
		}
		id := v.VersionID
		if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &v.Key, VersionId: &id}); err != nil {
			return fmt.Errorf("failed to delete a version of s3://%s/%s: %w", s.bucket, key, err)
		}
	}
	return nil
}
