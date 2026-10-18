// Package watch checks the PostgreSQL backups another tool writes (Coolify's
// scheduled backups, a cron pg_dump, a download kept in a bucket) where that
// tool puts them, without copying them anywhere.
//
// A check takes the newest dump at a location, reads it once and records
// what it holds: its SHA-256, its format, and every table's rows counted from
// its COPY blocks. A drill reads it again, loads it into an empty database
// in one transaction and holds the loaded rows to what the check recorded.
// Nothing here can prove the dump was complete: the database it was taken
// from was never read.
package watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/safegrd/cli/pkg/dump"
)

// Location is where another tool writes its backups: a prefix in a bucket
// (s3://bucket/prefix) or a directory on this host.
type Location struct {
	URL string
	// Endpoint, Region and the keys reach a bucket that is not on AWS, as a
	// bucket source of a files surface does.
	Endpoint, Region, AccessKeyID, SecretAccessKey string
	// Match, when set, is a glob a dump's file name must match
	// (pg-dump-*.dmp), for a location that holds other files as well.
	Match string
}

// Object is one backup at a location.
type Object struct {
	// URI is s3://bucket/key or file:///path.
	URI      string
	Key      string
	Size     int64
	Modified time.Time
	ETag     string
}

// Same reports whether two objects are the same backup.
func (o Object) Same(other Object) bool {
	return o.URI == other.URI && o.Size == other.Size && o.Modified.Equal(other.Modified)
}

// otherEngines are file name prefixes Coolify writes for databases this
// package does not read, so a prefix that holds them is not misread.
var otherEngines = []string{"mysql-dump-", "mariadb-dump-", "mongo-dump-", "clickhouse-backup-", "sqlite-backup-"}

func (l Location) isDump(name string) bool {
	base := path.Base(name)
	if strings.HasSuffix(base, ".part") || strings.HasSuffix(base, ".tmp") || strings.HasPrefix(base, ".") {
		return false
	}
	if l.Match != "" {
		ok, _ := path.Match(l.Match, base)
		return ok
	}
	for _, p := range otherEngines {
		if strings.HasPrefix(base, p) {
			return false
		}
	}
	return true
}

func (l Location) bucket() (src dump.ObjectStoreSource, ok bool) {
	bucket, prefix, ok := dump.ParseObjectStoreRoot(l.URL)
	if !ok {
		return src, false
	}
	return dump.ObjectStoreSource{Endpoint: l.Endpoint, Region: l.Region, Bucket: bucket, Prefix: prefix,
		AccessKeyID: l.AccessKeyID, SecretAccessKey: l.SecretAccessKey}, true
}

func (l Location) dir() (string, error) {
	d := strings.TrimPrefix(l.URL, "file://")
	if !filepath.IsAbs(d) {
		return "", fmt.Errorf("watch: %q is neither s3://bucket/prefix nor an absolute directory", l.URL)
	}
	return d, nil
}

// ErrNoBackup is a location that holds no backup at all.
var ErrNoBackup = errors.New("no backup there")

// Newest returns the newest backup at the location.
func (l Location) Newest(ctx context.Context) (Object, error) {
	var all []Object
	if src, ok := l.bucket(); ok {
		client, err := src.Client(ctx)
		if err != nil {
			return Object{}, err
		}
		prefix := strings.Trim(src.Prefix, "/")
		if prefix != "" {
			prefix += "/"
		}
		var token *string
		for {
			page, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &src.Bucket, Prefix: &prefix, ContinuationToken: token})
			if err != nil {
				return Object{}, fmt.Errorf("listing %s: %w", l.URL, err)
			}
			for _, o := range page.Contents {
				if o.Key == nil || strings.HasSuffix(*o.Key, "/") || !l.isDump(*o.Key) {
					continue
				}
				obj := Object{URI: "s3://" + src.Bucket + "/" + *o.Key, Key: *o.Key}
				if o.Size != nil {
					obj.Size = *o.Size
				}
				if o.LastModified != nil {
					obj.Modified = o.LastModified.UTC()
				}
				if o.ETag != nil {
					obj.ETag = strings.Trim(*o.ETag, `"`)
				}
				all = append(all, obj)
			}
			if page.IsTruncated == nil || !*page.IsTruncated {
				break
			}
			token = page.NextContinuationToken
		}
	} else {
		d, err := l.dir()
		if err != nil {
			return Object{}, err
		}
		err = filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() || !l.isDump(p) {
				return nil
			}
			fi, err := e.Info()
			if err != nil {
				return err
			}
			all = append(all, Object{URI: "file://" + p, Key: p, Size: fi.Size(), Modified: fi.ModTime().UTC()})
			return nil
		})
		if err != nil {
			return Object{}, fmt.Errorf("reading %s: %w", d, err)
		}
	}
	if len(all) == 0 {
		return Object{}, fmt.Errorf("%s: %w", l.URL, ErrNoBackup)
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].Modified.Equal(all[j].Modified) {
			return all[i].Modified.After(all[j].Modified)
		}
		return all[i].Key > all[j].Key
	})
	return all[0], nil
}

// Download copies obj into a new file in dir and returns its path and the
// SHA-256 of its bytes. The caller removes the file.
func (l Location) Download(ctx context.Context, obj Object, dir string) (string, string, error) {
	var rd io.ReadCloser
	if src, ok := l.bucket(); ok {
		client, err := src.Client(ctx)
		if err != nil {
			return "", "", err
		}
		out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &src.Bucket, Key: &obj.Key})
		if err != nil {
			return "", "", fmt.Errorf("reading %s: %w", obj.URI, err)
		}
		rd = out.Body
	} else {
		f, err := os.Open(obj.Key)
		if err != nil {
			return "", "", err
		}
		rd = f
	}
	defer rd.Close()
	f, err := os.CreateTemp(dir, "watched-*")
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), rd)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && obj.Size > 0 && n != obj.Size {
		err = fmt.Errorf("read %d bytes of %s, which is %d", n, obj.URI, obj.Size)
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", "", fmt.Errorf("downloading %s: %w", obj.URI, err)
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// Tool names the tool that made a backup when its file name says, or "".
func Tool(obj Object) string {
	if strings.HasPrefix(path.Base(obj.Key), "pg-dump-") {
		return "Coolify"
	}
	return ""
}
