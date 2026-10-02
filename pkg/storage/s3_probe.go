package storage

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// DeleteProbe asks the bucket whether this provider's credential may delete,
// without touching any snapshot. It works on a key no snapshot uses.
//
// canDeleteVersions: a DeleteObject naming the "null" version of that absent
// key is a no-op the bucket still authorizes, so it answers whether the key
// holds s3:DeleteObjectVersion, which removes data for good once a lock ends
// (or at once, under governance mode with bypass), and changes nothing.
//
// canDelete: a plain DeleteObject answers s3:DeleteObject. On a versioned
// bucket a permitted one leaves a delete marker on the probe key, which hides
// nothing. The probe removes the marker again when it can; marker reports one
// it could not remove.
func (s *S3StorageProvider) DeleteProbe(ctx context.Context) (canDelete, canDeleteVersions bool, marker string, err error) {
	key := path.Join(s.prefix, ".safegrd-delete-probe")
	null := "null"
	_, verErr := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key, VersionId: &null})
	switch {
	case verErr == nil:
		canDeleteVersions = true
	case !accessDenied(verErr):
		return false, false, "", fmt.Errorf("asking the bucket about version deletes: %w", verErr)
	}
	out, delErr := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key})
	switch {
	case delErr == nil:
		canDelete = true
	case !accessDenied(delErr):
		return false, canDeleteVersions, "", fmt.Errorf("asking the bucket about deletes: %w", delErr)
	}
	if canDelete && out.VersionId != nil && *out.VersionId != "" {
		if !canDeleteVersions {
			return canDelete, canDeleteVersions, key, nil
		}
		if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key, VersionId: out.VersionId}); err != nil {
			return canDelete, canDeleteVersions, key, nil
		}
	}
	return canDelete, canDeleteVersions, "", nil
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
