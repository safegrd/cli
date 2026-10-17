package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// S3StorageProvider implements StorageProvider with S3 Object Lock (WORM).
type S3StorageProvider struct {
	client        *s3.Client
	bucket        string
	prefix        string
	nodeID        string
	wormMode      s3types.ObjectLockMode
	retentionDays int
	// storageClass is set on each archive, never on its manifest.
	storageClass s3types.StorageClass

	// lockDisabled records an explicit worm_mode: NONE. It is a separate flag
	// rather than an empty wormMode because an empty wormMode already means
	// "unset" further down, where it re-applies COMPLIANCE — which would turn
	// an opt-out into the strictest possible lock.
	lockDisabled bool
}

// NewS3Storage creates an S3 WORM storage provider.
func NewS3Storage(ctx context.Context, cfg config.StorageConfig) (*S3StorageProvider, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3 bucket must be specified")
	}

	optFns := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		optFns = append(optFns, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		optFns = append(optFns, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS credentials/config: %w", err)
	}

	if cfg.IAMRoleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		awsCfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, cfg.IAMRoleARN))
	}

	// Providers that return no response checksum (DigitalOcean Spaces) made
	// the SDK log a WARN line to stdout for every object read.
	s3OptFns := []func(*s3.Options){func(o *s3.Options) { o.DisableLogOutputChecksumValidationSkipped = true }}
	if cfg.Endpoint != "" {
		s3OptFns = append(s3OptFns, func(o *s3.Options) {
			o.BaseEndpoint = &cfg.Endpoint
			// A custom endpoint (MinIO, B2, R2, Spaces) is addressed path style:
			// not every one serves a bucket as a subdomain.
			o.UsePathStyle = true
		})
	} else if cfg.ForcePathStyle {
		s3OptFns = append(s3OptFns, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3OptFns...)

	// Resolved rather than branched on: an unrecognised worm_mode used to fall
	// out of this if/else with no lock here and compliance mode in the CLI, so
	// the two halves of the same product disagreed about retention. Refusing is
	// the only outcome that cannot silently be the wrong one.
	wormMode, err := cfg.ResolveWORMMode()
	if err != nil {
		return nil, err
	}
	var mode s3types.ObjectLockMode
	lockDisabled := wormMode == config.WORMModeNone
	switch wormMode {
	case config.WORMModeGovernance:
		mode = s3types.ObjectLockModeGovernance
	case config.WORMModeNone:
		mode = ""
	default:
		mode = s3types.ObjectLockModeCompliance
	}

	class, err := cfg.ResolveStorageClass()
	if err != nil {
		return nil, err
	}

	retention := cfg.RetentionDays
	if retention <= 0 {
		retention = 14
	}

	pfx := cfg.Prefix
	if pfx == "" {
		pfx = "safegrd/snapshots"
	}

	return &S3StorageProvider{
		client:        client,
		bucket:        cfg.Bucket,
		prefix:        strings.Trim(pfx, "/"),
		nodeID:        strings.TrimSpace(cfg.NodeID),
		wormMode:      mode,
		retentionDays: retention,
		lockDisabled:  lockDisabled,
		storageClass:  s3types.StorageClass(class),
	}, nil
}

// ObjectStore returns the client and bucket this provider writes to, the key
// prefix its snapshots go under (the node segment included), and the Object
// Lock mode it applies, "" when the sink has none. An incremental repository
// writes its own objects through it with the same credentials.
func (s *S3StorageProvider) ObjectStore() (client *s3.Client, bucket, prefix string, mode s3types.ObjectLockMode) {
	prefix = s.prefix
	if s.nodeID != "" && !strings.Contains(s.prefix, s.nodeID) {
		prefix = path.Join(s.prefix, s.nodeID)
	}
	return s.client, s.bucket, prefix, s.wormMode
}

// SetNodeID configures the active node ID for scoped storage path segmentation.
func (s *S3StorageProvider) SetNodeID(nodeID string) {
	s.nodeID = strings.TrimSpace(nodeID)
}

func (s *S3StorageProvider) snapshotKey(snapshotID string) string {
	if s.nodeID != "" && !strings.Contains(s.prefix, s.nodeID) {
		return path.Join(s.prefix, s.nodeID, snapshotID+".safegrd")
	}
	return path.Join(s.prefix, snapshotID+".safegrd")
}

func (s *S3StorageProvider) metadataKey(snapshotID string) string {
	if s.nodeID != "" && !strings.Contains(s.prefix, s.nodeID) {
		return path.Join(s.prefix, s.nodeID, snapshotID+".meta.json")
	}
	return path.Join(s.prefix, snapshotID+".meta.json")
}

func (s *S3StorageProvider) UploadSnapshot(ctx context.Context, snapshotID string, stream io.Reader, size int64, retentionUntil time.Time) (string, error) {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return "", err
	}
	key := s.snapshotKey(snapshotID)

	// Check if object already exists (WORM protection check)
	exists, err := s.SnapshotExists(ctx, snapshotID)
	if err == nil && exists {
		return "", fmt.Errorf("WORM violation: snapshot %s already exists in S3 bucket %s", snapshotID, s.bucket)
	}

	putInput := &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         &key,
		Body:        stream,
		ContentType: ptr("application/octet-stream"),
	}
	if s.storageClass != "" {
		putInput.StorageClass = s.storageClass
	}

	effectiveRetention := retentionUntil
	if s.wormMode != "" {
		if effectiveRetention.IsZero() {
			if s.retentionDays > 0 {
				effectiveRetention = time.Now().UTC().AddDate(0, 0, s.retentionDays)
			} else {
				return "", fmt.Errorf("WORM compliance mode enabled but retention period is not set: refusing silent WORM downgrade")
			}
		}
		if !effectiveRetention.After(time.Now().UTC()) {
			return "", fmt.Errorf("WORM compliance mode enabled but retention date is in the past: refusing silent WORM downgrade")
		}
		putInput.ObjectLockMode = s.wormMode
		putInput.ObjectLockRetainUntilDate = &effectiveRetention
	} else if !effectiveRetention.IsZero() && !s.lockDisabled {
		putInput.ObjectLockMode = s3types.ObjectLockModeCompliance
		putInput.ObjectLockRetainUntilDate = &effectiveRetention
	}

	// Use AWS S3 transfer manager for streaming multipart uploads (supports > 5GB up to 5TB)
	uploader := manager.NewUploader(s.client, func(u *manager.Uploader) {
		u.PartSize = 64 * 1024 * 1024 // 64 MB part size
		u.Concurrency = 4
	})

	_, err = uploader.Upload(ctx, putInput)
	if err != nil {
		if strings.Contains(err.Error(), "InvalidRequest") || strings.Contains(err.Error(), "ObjectLockConfigurationNotFoundError") {
			return "", fmt.Errorf("WORM compliance failure: bucket %s rejected Object Lock retention (bucket may not have Object Lock enabled): %w", s.bucket, err)
		}
		return "", fmt.Errorf("failed to upload snapshot to s3://%s/%s: %w", s.bucket, key, err)
	}

	return fmt.Sprintf("s3://%s/%s", s.bucket, key), nil
}

func (s *S3StorageProvider) DownloadSnapshot(ctx context.Context, snapshotID string) (io.ReadCloser, error) {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return nil, err
	}
	key := s.snapshotKey(snapshotID)
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	if err != nil {
		// Fallback check to flat path for backward compatibility
		if s.nodeID != "" {
			flatKey := path.Join(s.prefix, snapshotID+".safegrd")
			if flatOut, flatErr := s.client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &s.bucket,
				Key:    &flatKey,
			}); flatErr == nil {
				return flatOut.Body, nil
			}
		}
		// The current version may be a delete marker. The locked
		// bytes are still there; a plain GET simply cannot see them. Read the
		// newest real version by id rather than reporting the backup as gone.
		if versionID, _, vErr := s.liveVersionID(ctx, key); vErr == nil && versionID != "" {
			if vOut, vGetErr := s.client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    &s.bucket,
				Key:       &key,
				VersionId: &versionID,
			}); vGetErr == nil {
				return vOut.Body, nil
			}
		}
		return nil, fmt.Errorf("failed to download snapshot from s3://%s/%s: %w", s.bucket, key, err)
	}
	return out.Body, nil
}

func (s *S3StorageProvider) UploadMetadata(ctx context.Context, snapshotID string, meta *model.SnapshotMetadata) error {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return err
	}
	key := s.metadataKey(snapshotID)
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	putInput := &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         &key,
		Body:        bytes.NewReader(data),
		ContentType: ptr("application/json"),
	}

	// Apply S3 Object Lock to the metadata manifest if retention is configured.
	//
	// The lockDisabled check is load-bearing, not defensive. Without it this
	// set ObjectLockRetainUntilDate with an EMPTY ObjectLockMode under
	// worm_mode: NONE, and a bucket with no Object Lock rejects the request —
	// so on DigitalOcean Spaces the ciphertext uploaded and the manifest
	// beside it did not. `safegrd list` then printed "[metadata unavailable]"
	// and `verify` had no digest to check, which is the product's own claim
	// quietly reduced to a file copy (found dogfooding, 2026-09-21).
	switch {
	case s.lockDisabled:
		// Nothing to apply, and saying so here is cheaper than a comment
		// three call sites away wondering why the manifest is missing.
	case !meta.WORMRetentionUntil.IsZero():
		putInput.ObjectLockMode = s.wormMode
		putInput.ObjectLockRetainUntilDate = &meta.WORMRetentionUntil
	case s.retentionDays > 0:
		retentionUntil := time.Now().Add(time.Duration(s.retentionDays) * 24 * time.Hour)
		putInput.ObjectLockMode = s.wormMode
		putInput.ObjectLockRetainUntilDate = &retentionUntil
	case s.wormMode != "":
		return fmt.Errorf("WORM compliance mode enabled but retention period is not set for metadata: refusing silent WORM downgrade")
	}

	_, err = s.client.PutObject(ctx, putInput)
	if err != nil {
		return fmt.Errorf("failed to upload metadata to s3://%s/%s: %w", s.bucket, key, err)
	}
	return nil
}

// UploadRecoveryDoc writes the recovery document beside the metadata, locked
// the same way: a reader who has only the bucket finds it next to the archive.
func (s *S3StorageProvider) UploadRecoveryDoc(ctx context.Context, snapshotID string, doc []byte, sealed bool, retainUntil time.Time) error {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return err
	}
	key := strings.TrimSuffix(s.metadataKey(snapshotID), ".meta.json") + RecoveryDocSuffix(sealed)
	contentType := "text/markdown; charset=utf-8"
	if sealed {
		contentType = "application/octet-stream"
	}
	putInput := &s3.PutObjectInput{Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(doc), ContentType: &contentType}
	switch {
	case s.lockDisabled:
	case !retainUntil.IsZero():
		putInput.ObjectLockMode = s.wormMode
		putInput.ObjectLockRetainUntilDate = &retainUntil
	case s.retentionDays > 0:
		until := time.Now().Add(time.Duration(s.retentionDays) * 24 * time.Hour)
		putInput.ObjectLockMode = s.wormMode
		putInput.ObjectLockRetainUntilDate = &until
	case s.wormMode != "":
		return fmt.Errorf("WORM compliance mode enabled but retention period is not set for the recovery document: refusing silent WORM downgrade")
	}
	if _, err := s.client.PutObject(ctx, putInput); err != nil {
		return fmt.Errorf("failed to upload the recovery document to s3://%s/%s: %w", s.bucket, key, err)
	}
	return nil
}

func (s *S3StorageProvider) DownloadMetadata(ctx context.Context, snapshotID string) (*model.SnapshotMetadata, error) {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return nil, err
	}
	key := s.metadataKey(snapshotID)
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	if err != nil {
		// Fallback check to flat path for backward compatibility
		if s.nodeID != "" {
			flatKey := path.Join(s.prefix, snapshotID+".meta.json")
			if flatOut, flatErr := s.client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &s.bucket,
				Key:    &flatKey,
			}); flatErr == nil {
				defer flatOut.Body.Close()
				data, readErr := io.ReadAll(flatOut.Body)
				if readErr == nil {
					var meta model.SnapshotMetadata
					if json.Unmarshal(data, &meta) == nil {
						return &meta, nil
					}
				}
			}
		}
		// Same delete-marker fallback as DownloadSnapshot. Metadata and
		// ciphertext are separate keys, so a delete can hide either one, and a
		// restore that finds the bytes but not the manifest is still a failed
		// restore.
		if versionID, _, vErr := s.liveVersionID(ctx, key); vErr == nil && versionID != "" {
			if vOut, vGetErr := s.client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    &s.bucket,
				Key:       &key,
				VersionId: &versionID,
			}); vGetErr == nil {
				defer vOut.Body.Close()
				if data, readErr := io.ReadAll(vOut.Body); readErr == nil {
					var meta model.SnapshotMetadata
					if json.Unmarshal(data, &meta) == nil {
						return &meta, nil
					}
				}
			}
		}
		return nil, fmt.Errorf("failed to get metadata from s3://%s/%s: %w", s.bucket, key, err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata body: %w", err)
	}

	var meta model.SnapshotMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &meta, nil
}

func (s *S3StorageProvider) ListSnapshots(ctx context.Context) ([]string, error) {
	// Versions, not current keys. A single DELETE writes a delete
	// marker over a snapshot, and listing current keys then reports "no
	// snapshots found" for a bucket that still holds every locked byte —
	// which reads like nothing was ever configured, at the exact moment
	// someone is trying to recover.
	//
	// ListObjectVersions is a versioning API, and several S3-compatible
	// providers — DigitalOcean Spaces among them — do not implement it. A
	// provider with no versioning has no delete markers to see past, so there
	// is nothing to lose by falling back: what it lists IS what is there.
	// Failing outright instead would mean `safegrd list` and `restore` dying on
	// a bucket that works perfectly, because of a feature it never had.
	versions, err := s.listVersions(ctx, s.prefix+"/")
	if err != nil {
		return s.listSnapshotsWithoutVersioning(ctx)
	}

	seen := map[string]bool{}
	var snapshots []string
	for _, v := range versions {
		if v.IsMarker || !strings.HasSuffix(v.Key, ".safegrd") {
			continue
		}
		id := strings.TrimSuffix(path.Base(v.Key), ".safegrd")
		if seen[id] {
			continue
		}
		seen[id] = true
		snapshots = append(snapshots, id)
	}

	return snapshots, nil
}

func (s *S3StorageProvider) SnapshotExists(ctx context.Context, snapshotID string) (bool, error) {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return false, err
	}
	key := s.snapshotKey(snapshotID)
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	if err == nil {
		return true, nil
	}

	// Fallback check to flat path for backward compatibility
	if s.nodeID != "" {
		flatKey := path.Join(s.prefix, snapshotID+".safegrd")
		if _, flatErr := s.client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &s.bucket,
			Key:    &flatKey,
		}); flatErr == nil {
			return true, nil
		}
	}

	// A delete marker makes HeadObject answer 404 for an object that is still
	// there and still locked. Existence is about the bytes.
	if versionID, _, vErr := s.liveVersionID(ctx, key); vErr == nil && versionID != "" {
		return true, nil
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && (apiErr.ErrorCode() == "NotFound" || apiErr.ErrorCode() == "NoSuchKey") {
		return false, nil
	}

	// In some S3 implementations, HeadObject returns 404 without standard API error
	if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "NotFound") {
		return false, nil
	}

	return false, err
}

func (s *S3StorageProvider) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return err
	}
	// Check retention first
	meta, err := s.DownloadMetadata(ctx, snapshotID)
	if err == nil && meta != nil && !meta.WORMRetentionUntil.IsZero() {
		if meta.WORMRetentionUntil.After(time.Now().UTC()) {
			return fmt.Errorf("WORM compliance refusal: snapshot %s is locked under WORM retention until %s", snapshotID, meta.WORMRetentionUntil.Format(time.RFC3339))
		}
	}

	// The archive, the manifest and the recovery document beside them.
	base := strings.TrimSuffix(s.metadataKey(snapshotID), ".meta.json")
	keys := []string{s.snapshotKey(snapshotID), s.metadataKey(snapshotID), base + RecoveryDocSuffix(false), base + RecoveryDocSuffix(true)}
	if s.nodeID != "" {
		keys = append(keys,
			path.Join(s.prefix, snapshotID+".safegrd"),
			path.Join(s.prefix, snapshotID+".meta.json"),
		)
	}

	// Every version, by id — not a plain DELETE on the key.
	//
	// On a versioned bucket a keyed DELETE writes a delete marker and removes
	// nothing. The read paths deliberately see through those, so a
	// keyed delete here would leave the snapshot listed and downloadable
	// forever AND report it as shadowed, which raises the "someone deleted your
	// backups" alarm on our own routine expiry. An alarm that fires on normal
	// operation is an alarm nobody reads — the exact failure seeing
	// through delete markers was about, inverted.
	//
	// Expect this to be REFUSED in a correctly configured bucket: the documented
	// bucket policy denies s3:DeleteObjectVersion precisely so nothing can destroy history,
	// and expiry is the bucket's lifecycle policy's job rather than ours. A
	// clear refusal is the right outcome. Appearing to succeed while leaving
	// the data in place is not.
	var deletedAny bool
	for _, key := range keys {
		versions, vErr := s.listVersions(ctx, key)
		if vErr != nil {
			// Same fallback the read paths take, and here it is the difference
			// between expiry working and a bucket that fills up forever: a
			// provider without ListObjectVersions has no versions to address,
			// so a plain keyed DELETE destroys the object outright — which is
			// exactly the right behaviour there, and is what the delete-marker
			// problem does not apply to.
			if dErr := s.deleteKeyWithoutVersioning(ctx, key); dErr != nil {
				return fmt.Errorf("failed to delete s3://%s/%s: %w", s.bucket, key, dErr)
			}
			deletedAny = true
			continue
		}
		for _, v := range versions {
			if v.Key != key {
				continue
			}
			versionID := v.VersionID
			if _, dErr := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &s.bucket,
				Key:       &v.Key,
				VersionId: &versionID,
			}); dErr != nil {
				return fmt.Errorf("failed to delete version of s3://%s/%s: %w", s.bucket, key, dErr)
			}
			deletedAny = true
		}
	}

	if !deletedAny {
		return fmt.Errorf("snapshot %s not found in s3://%s/%s", snapshotID, s.bucket, s.prefix)
	}
	return nil
}

func (s *S3StorageProvider) Type() string {
	return "s3"
}

// VerifyBucketObjectLock asserts that the destination bucket has S3 Object Lock enabled.
func (s *S3StorageProvider) VerifyBucketObjectLock(ctx context.Context) error {
	// An explicit worm_mode: NONE has already said this bucket has no Object
	// Lock. Demanding it here would make the opt-out unusable, and the warning
	// the operator needs is printed by the backup command on every run rather
	// than hidden in a preflight they asked to skip.
	if s.lockDisabled {
		return nil
	}
	out, err := s.client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: &s.bucket,
	})
	if err != nil {
		return fmt.Errorf("failed to verify Object Lock on bucket %s: %w", s.bucket, err)
	}
	if out.ObjectLockConfiguration == nil || out.ObjectLockConfiguration.ObjectLockEnabled != s3types.ObjectLockEnabledEnabled {
		return fmt.Errorf("WORM compliance failure: bucket %s does not have Object Lock enabled", s.bucket)
	}
	return nil
}

func ptr[T any](v T) *T {
	return &v
}
