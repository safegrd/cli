package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// RetentionExtender is a provider that can move one snapshot's lock later,
// the one change Object Lock allows.
type RetentionExtender interface {
	// ExtendRetention locks the snapshot's archive, metadata and recovery
	// document until until, and fails before changing anything when one is
	// locked later already.
	ExtendRetention(ctx context.Context, snapshotID string, until time.Time) error
}

// ErrLockLater is returned when a snapshot is locked past the date asked
// for: a lock can be extended, never shortened.
var ErrLockLater = errors.New("locked later already")

// ExtendRetention puts a later compliance (or governance) lock on the latest
// version of each of the snapshot's objects, in the mode the object has.
func (s *S3StorageProvider) ExtendRetention(ctx context.Context, snapshotID string, until time.Time) error {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return err
	}
	if s.lockDisabled {
		return fmt.Errorf("this sink is written with worm_mode NONE, so nothing in it is locked and there is no lock to extend")
	}
	base := strings.TrimSuffix(s.metadataKey(snapshotID), ".meta.json")
	type target struct {
		key  string
		mode s3types.ObjectLockRetentionMode
	}
	var targets []target
	for _, key := range []string{s.snapshotKey(snapshotID), base + ".meta.json", base + RecoveryDocSuffix(false), base + RecoveryDocSuffix(true)} {
		out, err := s.client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: &s.bucket, Key: aws.String(key)})
		if err != nil {
			var api smithy.APIError
			if errors.As(err, &api) && (api.ErrorCode() == "NoSuchKey" || api.ErrorCode() == "NotFound") {
				if key == s.snapshotKey(snapshotID) {
					return fmt.Errorf("snapshot %s is not in bucket %s", snapshotID, s.bucket)
				}
				continue
			}
			return fmt.Errorf("reading the lock on %s: %w", key, err)
		}
		mode := s3types.ObjectLockRetentionModeCompliance
		if out.Retention != nil {
			if out.Retention.Mode != "" {
				mode = out.Retention.Mode
			}
			if cur := aws.ToTime(out.Retention.RetainUntilDate); until.Before(cur) {
				return fmt.Errorf("%w: %s is locked until %s", ErrLockLater, key, cur.UTC().Format(time.RFC3339))
			}
		}
		targets = append(targets, target{key, mode})
	}
	for _, t := range targets {
		if _, err := s.client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{Bucket: &s.bucket, Key: aws.String(t.key),
			Retention: &s3types.ObjectLockRetention{Mode: t.mode, RetainUntilDate: aws.Time(until.UTC())}}); err != nil {
			return fmt.Errorf("extending the lock on %s: %w", t.key, err)
		}
	}
	return nil
}

// ExtendRetention moves the retention date a local sink keeps in the
// snapshot's metadata, which is the lock DeleteSnapshot honours there.
func (l *LocalStorageProvider) ExtendRetention(ctx context.Context, snapshotID string, until time.Time) error {
	if err := ValidateSnapshotID(snapshotID); err != nil {
		return err
	}
	meta, err := l.DownloadMetadata(ctx, snapshotID)
	if err != nil {
		return err
	}
	if until.Before(meta.WORMRetentionUntil) {
		return fmt.Errorf("%w: snapshot %s is kept until %s", ErrLockLater, snapshotID, meta.WORMRetentionUntil.UTC().Format(time.RFC3339))
	}
	meta.WORMRetentionUntil = until.UTC()
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	p := l.metadataPath(snapshotID)
	tmp := p + ".keep"
	if err := os.WriteFile(tmp, data, 0o400); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
