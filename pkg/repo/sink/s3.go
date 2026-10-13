package sink

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3 is a store in a bucket the host holds a credential for. Every object is
// written with the lock of its class, under the bucket's Object Lock mode.
// Keys carry 128 random bits, so a run never writes a key twice; in a
// versioned bucket an overwrite would keep the earlier version anyway.
type S3 struct {
	Client *s3.Client
	Bucket string
	// Prefix is the key prefix of this host's objects.
	Prefix string
	// Mode is the Object Lock mode, "" for a bucket with none.
	Mode s3types.ObjectLockMode
	// Now is the clock a lock date is checked against.
	Now func() time.Time
	// Warnf, when set, receives the line said about an object that was
	// deleted or overwritten after it was written; nil prints it to stderr.
	Warnf func(format string, args ...any)

	mu sync.Mutex
	// written is, per directory, each key's first version: the one a
	// backup wrote, since a run never writes a key twice. Read under a lock
	// only; a directory whose versions could not be listed maps to nil.
	written map[string]map[string]writtenVersion
	warned  map[string]bool
}

// writtenVersion is the version a backup wrote of a key, and whether a delete
// marker or a later version has been put over it since.
type writtenVersion struct {
	id       string
	size     int64
	shadowed bool
}

// pinned returns the version of key a backup wrote, in a bucket under
// Object Lock. Keys carry 128 random bits and are written once, so a later
// version or a delete marker is someone else's: under Object Lock a DELETE
// adds a marker and a PUT adds a version, and both hide the locked one from a
// read by key alone. "" reads by key: a bucket with no lock, a key with no
// version, or a credential that may not list versions.
func (s *S3) pinned(ctx context.Context, key string) string {
	if s.Mode == "" {
		return ""
	}
	dir := path.Dir(key) + "/"
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.written == nil {
		s.written = map[string]map[string]writtenVersion{}
		s.warned = map[string]bool{}
	}
	byKey, listed := s.written[dir]
	if !listed {
		byKey = s.listWritten(ctx, dir)
		s.written[dir] = byKey
	}
	v, ok := byKey[key]
	if !ok {
		return ""
	}
	if v.shadowed && !s.warned[key] {
		s.warned[key] = true
		warn := s.Warnf
		if warn == nil {
			warn = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "Warning: "+f+"\n", a...) }
		}
		warn("s3://%s/%s was deleted or overwritten after the backup wrote it. Object Lock kept the version the backup wrote, and it is read instead. Find out which credential did it.", s.Bucket, key)
	}
	return v.id
}

// listWritten lists the versions directly under dir and returns each key's
// first real version. nil when the listing is refused.
func (s *S3) listWritten(ctx context.Context, dir string) map[string]writtenVersion {
	type seen struct {
		v     writtenVersion
		count int
	}
	keys := map[string]*seen{}
	delim := "/"
	p := s3.NewListObjectVersionsPaginator(s.Client, &s3.ListObjectVersionsInput{Bucket: &s.Bucket, Prefix: &dir, Delimiter: &delim})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil
		}
		// Versions come newest first for each key, so the last real one
		// listed is the first written.
		for _, v := range page.Versions {
			k := aws.ToString(v.Key)
			e := keys[k]
			if e == nil {
				e = &seen{}
				keys[k] = e
			}
			e.count++
			shadowed := e.v.shadowed || e.count > 1
			e.v = writtenVersion{id: aws.ToString(v.VersionId), size: aws.ToInt64(v.Size), shadowed: shadowed}
		}
		for _, m := range page.DeleteMarkers {
			k := aws.ToString(m.Key)
			e := keys[k]
			if e == nil {
				e = &seen{}
				keys[k] = e
			}
			e.v.shadowed = true
		}
	}
	out := make(map[string]writtenVersion, len(keys))
	for k, e := range keys {
		if e.count > 0 {
			out[k] = e.v
		}
	}
	return out
}

func (s *S3) Root() string     { return strings.Trim(s.Prefix, "/") }
func (s *S3) Describe() string { return "s3://" + path.Join(s.Bucket, s.Root()) }

func (s *S3) Put(ctx context.Context, key string, body []byte, md5 [16]byte, retainUntil time.Time) error {
	in := &s3.PutObjectInput{
		Bucket:        &s.Bucket,
		Key:           &key,
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		ContentMD5:    aws.String(base64.StdEncoding.EncodeToString(md5[:])),
		ContentType:   aws.String("application/octet-stream"),
	}
	// A zero date is a run the project keeps unlocked (Direct.Put under a
	// kept rule): written with no lock headers. Any other date has to be
	// ahead, or the object would go in unlocked by mistake.
	if s.Mode != "" && !retainUntil.IsZero() {
		now := time.Now
		if s.Now != nil {
			now = s.Now
		}
		if !retainUntil.After(now()) {
			return fmt.Errorf("%s: the lock date %s is not in the future, and an object is never written unlocked into a locked bucket",
				key, retainUntil.UTC().Format(time.RFC3339))
		}
		in.ObjectLockMode = s.Mode
		in.ObjectLockRetainUntilDate = aws.Time(retainUntil.UTC())
	}
	if _, err := s.Client.PutObject(ctx, in); err != nil {
		return fmt.Errorf("writing s3://%s/%s: %w", s.Bucket, key, err)
	}
	return nil
}

func notFound(err error) bool {
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var api smithy.APIError
	return errors.As(err, &api) && (api.ErrorCode() == "NoSuchKey" || api.ErrorCode() == "NotFound")
}

func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	in := &s3.GetObjectInput{Bucket: &s.Bucket, Key: &key}
	if v := s.pinned(ctx, key); v != "" {
		in.VersionId = aws.String(v)
	}
	out, err := s.Client.GetObject(ctx, in)
	if err != nil {
		if notFound(err) {
			return nil, fmt.Errorf("s3://%s/%s: %w", s.Bucket, key, ErrNotFound)
		}
		return nil, fmt.Errorf("reading s3://%s/%s: %w", s.Bucket, key, err)
	}
	return out.Body, nil
}

func (s *S3) GetRange(ctx context.Context, key string, off, n int64) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	rng := fmt.Sprintf("bytes=%d-%d", off, off+n-1)
	in := &s3.GetObjectInput{Bucket: &s.Bucket, Key: &key, Range: &rng}
	if v := s.pinned(ctx, key); v != "" {
		in.VersionId = aws.String(v)
	}
	out, err := s.Client.GetObject(ctx, in)
	if err != nil {
		if notFound(err) {
			return nil, fmt.Errorf("s3://%s/%s: %w", s.Bucket, key, ErrNotFound)
		}
		var api smithy.APIError
		if errors.As(err, &api) && api.ErrorCode() == "InvalidRange" {
			return nil, nil
		}
		return nil, fmt.Errorf("reading s3://%s/%s: %w", s.Bucket, key, err)
	}
	defer out.Body.Close()
	return io.ReadAll(io.LimitReader(out.Body, n))
}

func (s *S3) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	if s.Mode != "" {
		// A key behind a delete marker is still a backup's object.
		if out, err := s.listByVersions(ctx, prefix); err == nil {
			return out, nil
		}
	}
	var out []ObjectInfo
	p := s3.NewListObjectsV2Paginator(s.Client, &s3.ListObjectsV2Input{Bucket: &s.Bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing s3://%s/%s: %w", s.Bucket, prefix, err)
		}
		for _, o := range page.Contents {
			out = append(out, ObjectInfo{Key: aws.ToString(o.Key), Size: aws.ToInt64(o.Size)})
		}
	}
	return out, nil
}

// listByVersions lists every key under prefix that holds a real version,
// with its first version's size.
func (s *S3) listByVersions(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var out []ObjectInfo
	idx := map[string]int{}
	p := s3.NewListObjectVersionsPaginator(s.Client, &s3.ListObjectVersionsInput{Bucket: &s.Bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Versions {
			k := aws.ToString(v.Key)
			if i, ok := idx[k]; ok {
				out[i].Size = aws.ToInt64(v.Size) // older: closer to the first written
				continue
			}
			idx[k] = len(out)
			out = append(out, ObjectInfo{Key: k, Size: aws.ToInt64(v.Size)})
		}
	}
	return out, nil
}

// Version is one version of one object, for prune.
type Version struct {
	Key, VersionID string
	Size           int64
	IsMarker       bool
}

// Versions lists every version and delete marker under prefix.
func (s *S3) Versions(ctx context.Context, prefix string) ([]Version, error) {
	var out []Version
	p := s3.NewListObjectVersionsPaginator(s.Client, &s3.ListObjectVersionsInput{Bucket: &s.Bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing versions under s3://%s/%s: %w", s.Bucket, prefix, err)
		}
		for _, v := range page.Versions {
			out = append(out, Version{Key: aws.ToString(v.Key), VersionID: aws.ToString(v.VersionId), Size: aws.ToInt64(v.Size)})
		}
		for _, m := range page.DeleteMarkers {
			out = append(out, Version{Key: aws.ToString(m.Key), VersionID: aws.ToString(m.VersionId), IsMarker: true})
		}
	}
	return out, nil
}

// Extend moves the lock on key's current version to until when it is
// unlocked or locked earlier, in the bucket's mode. A lock already later
// stays.
func (s *S3) Extend(ctx context.Context, key string, until time.Time) error {
	if s.Mode == "" {
		return nil
	}
	// The version the backup wrote, not one put over it since: locking
	// that would leave the backup's own version unlocked.
	version := s.pinned(ctx, key)
	if version == "" {
		head, err := s.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &s.Bucket, Key: &key})
		if err != nil {
			return fmt.Errorf("s3://%s/%s: %w", s.Bucket, key, err)
		}
		version = aws.ToString(head.VersionId)
	}
	cur, err := s.Retention(ctx, key, version)
	if err != nil {
		return err
	}
	if !cur.IsZero() && !cur.Before(until) {
		return nil
	}
	_, err = s.Client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{Bucket: &s.Bucket, Key: &key, VersionId: aws.String(version),
		Retention: &s3types.ObjectLockRetention{Mode: s3types.ObjectLockRetentionMode(s.Mode), RetainUntilDate: aws.Time(until.UTC())}})
	if err != nil {
		return fmt.Errorf("s3://%s/%s: %w", s.Bucket, key, err)
	}
	return nil
}

// Retention reads one version's lock date by the bucket's own record. A
// version with no lock returns the zero time.
func (s *S3) Retention(ctx context.Context, key, versionID string) (time.Time, error) {
	out, err := s.Client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: &s.Bucket, Key: &key, VersionId: &versionID})
	if err != nil {
		var api smithy.APIError
		if errors.As(err, &api) && (api.ErrorCode() == "NoSuchObjectLockConfiguration" || api.ErrorCode() == "ObjectLockConfigurationNotFoundError") {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	if out.Retention == nil || out.Retention.RetainUntilDate == nil {
		return time.Time{}, nil
	}
	return *out.Retention.RetainUntilDate, nil
}

// DeleteVersion deletes one version. Only prune calls it.
func (s *S3) DeleteVersion(ctx context.Context, key, versionID string) error {
	_, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.Bucket, Key: &key, VersionId: &versionID})
	return err
}

// Children lists the names directly under prefix, by a delimiter listing.
func (s *S3) Children(ctx context.Context, prefix string) ([]string, error) {
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	delim := "/"
	if s.Mode != "" {
		// A directory whose objects are all behind delete markers is
		// still there.
		var out []string
		p := s3.NewListObjectVersionsPaginator(s.Client, &s3.ListObjectVersionsInput{Bucket: &s.Bucket, Prefix: &prefix, Delimiter: &delim})
		ok := true
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				ok = false
				break
			}
			for _, cp := range page.CommonPrefixes {
				out = append(out, strings.TrimSuffix(strings.TrimPrefix(aws.ToString(cp.Prefix), prefix), "/"))
			}
		}
		if ok {
			return out, nil
		}
	}
	var out []string
	p := s3.NewListObjectsV2Paginator(s.Client, &s3.ListObjectsV2Input{Bucket: &s.Bucket, Prefix: &prefix, Delimiter: &delim})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing s3://%s/%s: %w", s.Bucket, prefix, err)
		}
		for _, cp := range page.CommonPrefixes {
			out = append(out, strings.TrimSuffix(strings.TrimPrefix(aws.ToString(cp.Prefix), prefix), "/"))
		}
	}
	return out, nil
}
