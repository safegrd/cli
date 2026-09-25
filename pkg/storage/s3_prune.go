package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// What `safegrd prune` needs from a bucket, and nothing more: the rules for
// what may go live with the command. The bucket's own lock and clock decide;
// the host's clock never does.

// VersionInfo is one version, or delete marker, of one object.
type VersionInfo struct {
	Key          string
	VersionID    string
	LastModified time.Time
	IsMarker     bool
	IsLatest     bool
}

// SnapshotVersions lists every version and delete marker under the
// snapshot prefix.
func (s *S3StorageProvider) SnapshotVersions(ctx context.Context) ([]VersionInfo, error) {
	vs, err := s.listVersions(ctx, s.prefix)
	if err != nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(vs))
	for _, v := range vs {
		out = append(out, VersionInfo{Key: v.Key, VersionID: v.VersionID, LastModified: v.LastModified, IsMarker: v.IsMarker, IsLatest: v.IsLatest})
	}
	return out, nil
}

// Prefix is where snapshots are filed in the bucket.
func (s *S3StorageProvider) Prefix() string { return s.prefix }

// LockDisabled reports an explicit worm_mode: NONE.
func (s *S3StorageProvider) LockDisabled() bool { return s.lockDisabled }

// VersionLock is the bucket's own record of one version's lock: until when,
// and whether a legal hold is on. A version with no lock returns a zero time.
func (s *S3StorageProvider) VersionLock(ctx context.Context, key, versionID string) (until time.Time, hold bool, err error) {
	ret, err := s.client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: &s.bucket, Key: &key, VersionId: &versionID})
	switch {
	case err == nil && ret.Retention != nil && ret.Retention.RetainUntilDate != nil:
		until = *ret.Retention.RetainUntilDate
	case err != nil && !noLockConfigured(err):
		return time.Time{}, false, err
	}
	lh, err := s.client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{Bucket: &s.bucket, Key: &key, VersionId: &versionID})
	switch {
	case err == nil && lh.LegalHold != nil:
		hold = lh.LegalHold.Status == s3types.ObjectLockLegalHoldStatusOn
	case err != nil && !noLockConfigured(err):
		return time.Time{}, false, err
	}
	return until, hold, nil
}

func noLockConfigured(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "NoSuchObjectLockConfiguration", "ObjectLockConfigurationNotFoundError", "InvalidRequest":
		return true
	}
	return false
}

// RecordedRetainUntil reads the "kept until" date written in the snapshot
// metadata at key, which is what decides expiry under worm_mode: NONE. It
// takes the key as listed, not a snapshot id: the agent files each surface
// under its own node, which is not the node this provider was opened for.
func (s *S3StorageProvider) RecordedRetainUntil(ctx context.Context, key string) (time.Time, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return time.Time{}, err
	}
	defer out.Body.Close()
	var meta struct {
		WORMRetentionUntil time.Time `json:"worm_retention_until"`
	}
	if err := json.NewDecoder(io.LimitReader(out.Body, 16<<20)).Decode(&meta); err != nil {
		return time.Time{}, fmt.Errorf("reading %s: %w", key, err)
	}
	return meta.WORMRetentionUntil, nil
}

// DeleteVersion permanently removes one version or delete marker. It never
// deletes by key alone, which on a versioned bucket only adds a marker.
func (s *S3StorageProvider) DeleteVersion(ctx context.Context, key, versionID string) error {
	if versionID == "" {
		return errors.New("refusing to delete without a version id")
	}
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key, VersionId: &versionID})
	return err
}

// BucketNow is the time by the bucket's own clock: the Date header of its
// answer to a HeadBucket. The host's clock may be wrong; this one is the one
// that enforces the locks.
func (s *S3StorageProvider) BucketNow(ctx context.Context) (time.Time, error) {
	out, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket})
	if err != nil {
		return time.Time{}, fmt.Errorf("reading bucket %s: %w", s.bucket, err)
	}
	if raw, ok := awsmiddleware.GetRawResponse(out.ResultMetadata).(*smithyhttp.Response); ok && raw != nil {
		if d := raw.Header.Get("Date"); d != "" {
			if t, err := http.ParseTime(d); err == nil {
				return t.UTC(), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("bucket %s sent no Date header, so there is no clock but this host's to judge a lock by", s.bucket)
}
