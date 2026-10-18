package dump

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ObjectStoreSource is a files surface read from a bucket over the S3 API:
// Supabase Storage, or any S3-compatible store. Every object under Prefix is
// backed up as a regular file at its key, so the archive restores into a
// directory like any other files snapshot, and its manifest carries each
// object's content type so it can be uploaded back as it was.
//
// The source uses ListObjectsV2 and GetObject only. It needs no versioning,
// Object Lock or ACLs, none of which Supabase Storage's S3 endpoint has.
type ObjectStoreSource struct {
	Endpoint        string
	Region          string
	Bucket          string
	Prefix          string
	AccessKeyID     string
	SecretAccessKey string
}

// Root is the source as a path: s3://bucket/prefix. It is the manifest's
// root_path and what the backup prints.
func (o ObjectStoreSource) Root() string {
	if p := strings.Trim(o.Prefix, "/"); p != "" {
		return "s3://" + o.Bucket + "/" + p
	}
	return "s3://" + o.Bucket
}

// ParseObjectStoreRoot reads s3://bucket or s3://bucket/prefix. It reports
// ok false for any other string, so a local path is never mistaken for one.
func ParseObjectStoreRoot(root string) (bucket, prefix string, ok bool) {
	if !strings.HasPrefix(root, "s3://") {
		return "", "", false
	}
	rest := strings.TrimPrefix(root, "s3://")
	bucket, prefix, _ = strings.Cut(rest, "/")
	if bucket == "" {
		return "", "", false
	}
	return bucket, strings.Trim(prefix, "/"), true
}

// Client is the S3 client the source reads with.
func (o ObjectStoreSource) Client(ctx context.Context) (*s3.Client, error) { return o.client(ctx) }

func (o ObjectStoreSource) client(ctx context.Context) (*s3.Client, error) {
	if o.Bucket == "" {
		return nil, errors.New("object store source: bucket is required")
	}
	if o.AccessKeyID == "" || o.SecretAccessKey == "" {
		return nil, errors.New("object store source: access key id and secret access key are required")
	}
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(o.AccessKeyID, o.SecretAccessKey, "")),
	}
	region := o.Region
	if region == "" {
		// The SDK refuses to sign without one. Supabase and MinIO accept
		// any region in the signature; AWS itself needs the bucket's.
		region = "us-east-1"
	}
	opts = append(opts, awsconfig.WithRegion(region))
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("object store source: %w", err)
	}
	s3Opts := []func(*s3.Options){func(so *s3.Options) { so.DisableLogOutputChecksumValidationSkipped = true }}
	if o.Endpoint != "" {
		endpoint := o.Endpoint
		s3Opts = append(s3Opts, func(so *s3.Options) {
			so.BaseEndpoint = &endpoint
			// Supabase Storage and MinIO address the bucket in the path.
			so.UsePathStyle = true
		})
	}
	return s3.NewFromConfig(awsCfg, s3Opts...), nil
}

// objectInfo is an object as os.FileInfo, so the tar header and the manifest
// are built the way they are for a file on disk. Mode is 0644 for an object
// and 0755 for a directory the keys imply; the store records neither.
type objectInfo struct {
	name    string
	size    int64
	modTime time.Time
	isDir   bool
}

func (i objectInfo) Name() string { return i.name }
func (i objectInfo) Size() int64  { return i.size }
func (i objectInfo) Mode() os.FileMode {
	if i.isDir {
		return os.ModeDir | 0o755
	}
	return 0o644
}
func (i objectInfo) ModTime() time.Time { return i.modTime }
func (i objectInfo) IsDir() bool        { return i.isDir }
func (i objectInfo) Sys() any           { return nil }

// scanObjects lists every object under the source's prefix as an item, with
// the directories its keys imply. A key that ends in "/" is a folder marker
// some consoles write; it is recorded as a directory, never as a file.
func (fc *FileCollector) scanObjects(ctx context.Context) ([]collectedItem, error) {
	src := fc.cfg.Source
	client, err := src.client(ctx)
	if err != nil {
		return nil, err
	}
	fc.objects = client
	prefix := strings.Trim(src.Prefix, "/")
	listPrefix := prefix
	if listPrefix != "" {
		listPrefix += "/"
	}

	dirs := map[string]time.Time{}
	var items []collectedItem
	noteDir := func(rel string, at time.Time) {
		for d := path.Dir(rel); d != "." && d != "/" && d != ""; d = path.Dir(d) {
			if prev, ok := dirs[d]; !ok || at.After(prev) {
				dirs[d] = at
			}
		}
	}

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(src.Bucket),
		Prefix: aws.String(listPrefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", src.Root(), err)
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			rel := strings.TrimPrefix(key, listPrefix)
			if rel == "" {
				continue
			}
			modTime := time.Time{}
			if obj.LastModified != nil {
				modTime = obj.LastModified.UTC().Truncate(time.Second)
			}
			if strings.HasSuffix(rel, "/") {
				d := strings.TrimSuffix(rel, "/")
				if prev, ok := dirs[d]; !ok || modTime.After(prev) {
					dirs[d] = modTime
				}
				noteDir(d, modTime)
				continue
			}
			if MatchesExclude(rel, fc.cfg.Excludes) {
				continue
			}
			noteDir(rel, modTime)
			items = append(items, collectedItem{
				relPath:   rel,
				objectKey: key,
				info:      objectInfo{name: path.Base(rel), size: aws.ToInt64(obj.Size), modTime: modTime},
			})
		}
	}
	for d, at := range dirs {
		if MatchesExclude(d, fc.cfg.Excludes) {
			continue
		}
		items = append(items, collectedItem{
			relPath: d,
			info:    objectInfo{name: path.Base(d), modTime: at, isDir: true},
			isDir:   true,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].relPath < items[j].relPath })
	return items, nil
}

// openObject reads one object. The hash pass records the content type the
// store reports, so the manifest can carry it.
func (fc *FileCollector) openObject(ctx context.Context, item *collectedItem) (io.ReadCloser, error) {
	out, err := fc.objects.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(fc.cfg.Source.Bucket),
		Key:    aws.String(item.objectKey),
	})
	if err != nil {
		var missing *s3types.NoSuchKey
		if errors.As(err, &missing) {
			// Supabase Storage lists what its storage.objects table holds,
			// and a row written by SQL, or left by a restore of the rows
			// alone, has no file behind it. The backup fails rather than
			// record a file it did not read.
			return nil, fmt.Errorf("the store lists %s but has no object for it: a row in its object table with no file behind it. Upload the file again, or delete the entry through the store's own API, then back up again", item.objectKey)
		}
		return nil, fmt.Errorf("reading %s: %w", item.objectKey, err)
	}
	if ct := aws.ToString(out.ContentType); ct != "" && item.contentType == "" {
		item.contentType = ct
	}
	return out.Body, nil
}
