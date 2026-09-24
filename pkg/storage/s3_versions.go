package storage

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Seeing past delete markers.
//
// Object Lock protects a *version*. It does not stop anyone with s3:DeleteObject
// from issuing a plain DELETE, which on a versioned bucket does not destroy
// anything — it writes a **delete marker** as the new current version. The
// locked bytes are still there, still immutable, still billable.
//
// But every plain read goes to the current version, so the delete marker makes
// `list` print "No snapshots found in storage" and `restore` fail with
// NoSuchKey. The data survived; the recoverability did not. From the customer's
// position at the moment they need it, that is indistinguishable from
// ransomware having destroyed the backups — and undoing it by hand needs S3
// version expertise this product exists to make unnecessary.
//
// So: read through the marker. A snapshot whose current version is a delete
// marker is still listed, still downloadable, and reported as shadowed rather
// than as absent.

// objectVersion is one version of one key, reduced to what matters here.
type objectVersion struct {
	Key          string
	VersionID    string
	LastModified time.Time
	IsMarker     bool
	// IsLatest is S3's own answer to "is this the version a plain GET would
	// reach". Reconstructing that by sorting on LastModified looks equivalent
	// and is not: a delete marker written in the same second as the object it
	// covers ties, and a stable sort then decides by whatever order the API
	// happened to return, which is data before markers. That would silently
	// disable the whole fix on a fast bucket.
	IsLatest bool
}

// listVersions returns every version under a prefix, newest first per key.
//
// A bucket with versioning suspended answers with a single "null" version per
// key and no markers, so this degrades to the same answer ListObjectsV2 gives.
func (s *S3StorageProvider) listVersions(ctx context.Context, prefix string) ([]objectVersion, error) {
	var out []objectVersion
	var keyMarker, versionMarker *string

	for {
		page, err := s.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:          &s.bucket,
			Prefix:          &prefix,
			KeyMarker:       keyMarker,
			VersionIdMarker: versionMarker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed listing versions in bucket %s: %w", s.bucket, err)
		}
		for _, v := range page.Versions {
			if v.Key == nil {
				continue
			}
			ov := objectVersion{Key: *v.Key}
			if v.IsLatest != nil {
				ov.IsLatest = *v.IsLatest
			}
			if v.VersionId != nil {
				ov.VersionID = *v.VersionId
			}
			if v.LastModified != nil {
				ov.LastModified = *v.LastModified
			}
			out = append(out, ov)
		}
		for _, d := range page.DeleteMarkers {
			if d.Key == nil {
				continue
			}
			ov := objectVersion{Key: *d.Key, IsMarker: true}
			if d.IsLatest != nil {
				ov.IsLatest = *d.IsLatest
			}
			if d.VersionId != nil {
				ov.VersionID = *d.VersionId
			}
			if d.LastModified != nil {
				ov.LastModified = *d.LastModified
			}
			out = append(out, ov)
		}

		if page.IsTruncated == nil || !*page.IsTruncated {
			break
		}
		keyMarker, versionMarker = page.NextKeyMarker, page.NextVersionIdMarker
		if keyMarker == nil && versionMarker == nil {
			break
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].LastModified.After(out[j].LastModified)
	})
	return out, nil
}

// liveVersionID returns the version id of the newest real (non-marker) version
// of a key, and whether a delete marker is currently hiding it.
//
// An empty version id with shadowed=false means the key genuinely has no
// content: never written, or every version expired.
func (s *S3StorageProvider) liveVersionID(ctx context.Context, key string) (versionID string, shadowed bool, err error) {
	versions, err := s.listVersions(ctx, key)
	if err != nil {
		return "", false, err
	}

	for _, v := range versions {
		if v.Key != key {
			continue
		}
		if v.IsMarker {
			if v.IsLatest {
				shadowed = true
			}
			continue
		}
		if versionID == "" {
			versionID = v.VersionID
		}
	}
	return versionID, shadowed && versionID != "", nil
}

// ShadowedSnapshot names a snapshot whose current version is a delete marker.
//
// Someone issued a DELETE against a backup. Under Object Lock the bytes
// survived, which is the system working — but a snapshot in this state is the
// loudest signal of attack this product can receive, and it used to be
// reported as "no snapshots found", which reads like nothing is configured.
type ShadowedSnapshot struct {
	SnapshotID string
	Key        string
	// MarkerVersionID is what `UndeleteSnapshot` removes to bring it back.
	MarkerVersionID string
	DeletedAt       time.Time
}

// ListShadowedSnapshots reports snapshots hidden behind a delete marker.
//
// Optional on the provider interface, discovered by type assertion the way
// VerifyBucketObjectLock is: local WORM storage has no versioning, so it has no
// such state to report and implementing it there would be inventing an answer.
func (s *S3StorageProvider) ListShadowedSnapshots(ctx context.Context) ([]ShadowedSnapshot, error) {
	versions, err := s.listVersions(ctx, s.prefix+"/")
	if err != nil {
		// No versioning means no delete markers, so the honest answer is
		// "none", not an error. This runs from `list`, `restore` and `verify`
		// as a warning path; making it fatal would break those commands on a
		// provider that simply lacks the feature.
		return nil, nil
	}

	type state struct {
		markerLatest bool
		marker       objectVersion
		hasReal      bool
	}
	byKey := map[string]*state{}
	for _, v := range versions {
		if !strings.HasSuffix(v.Key, ".safegrd") {
			continue
		}
		st, ok := byKey[v.Key]
		if !ok {
			st = &state{}
			byKey[v.Key] = st
		}
		if v.IsMarker {
			if v.IsLatest {
				st.markerLatest, st.marker = true, v
			}
			continue
		}
		st.hasReal = true
	}

	var out []ShadowedSnapshot
	for key, st := range byKey {
		if !st.markerLatest || !st.hasReal {
			continue
		}
		out = append(out, ShadowedSnapshot{
			SnapshotID:      strings.TrimSuffix(path.Base(key), ".safegrd"),
			Key:             key,
			MarkerVersionID: st.marker.VersionID,
			DeletedAt:       st.marker.LastModified,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SnapshotID < out[j].SnapshotID })
	return out, nil
}

// UndeleteSnapshot removes the delete markers hiding a snapshot and its
// metadata, bringing the locked versions back as current.
//
// This deletes ONLY delete markers, addressed by version id, and never a
// version holding data — which is also why it is safe to offer: a delete marker
// carries no bytes, and Object Lock does not protect one. Without this command
// the runbook for the scenario the product exists for is "install mc, learn S3
// versioning, hope".
func (s *S3StorageProvider) UndeleteSnapshot(ctx context.Context, snapshotID string) (int, error) {
	keys := []string{s.snapshotKey(snapshotID), s.metadataKey(snapshotID)}
	if s.nodeID != "" {
		keys = append(keys,
			path.Join(s.prefix, snapshotID+".safegrd"),
			path.Join(s.prefix, snapshotID+".meta.json"),
		)
	}

	removed := 0
	for _, key := range keys {
		versions, err := s.listVersions(ctx, key)
		if err != nil {
			return removed, err
		}
		for _, v := range versions {
			if v.Key != key || !v.IsMarker {
				continue
			}
			versionID := v.VersionID
			if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &s.bucket,
				Key:       &v.Key,
				VersionId: &versionID,
			}); err != nil {
				return removed, fmt.Errorf("failed removing delete marker for %s: %w", key, err)
			}
			removed++
		}
	}
	return removed, nil
}

// listSnapshotsWithoutVersioning is the fallback for a bucket whose provider
// does not implement ListObjectVersions.
//
// It is the original implementation, kept deliberately. On such a provider a
// DELETE destroys the object outright rather than writing a delete marker, so
// there is no hidden version to find and nothing this loses — and a customer on
// that provider should be told plainly that the undelete path does not exist
// for them, which is what a provider support matrix is for.
func (s *S3StorageProvider) listSnapshotsWithoutVersioning(ctx context.Context) ([]string, error) {
	prefix := s.prefix + "/"
	var snapshots []string

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: &s.bucket,
		Prefix: &prefix,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed listing snapshots in bucket %s: %w", s.bucket, err)
		}
		for _, obj := range page.Contents {
			if obj.Key != nil && strings.HasSuffix(*obj.Key, ".safegrd") {
				snapshots = append(snapshots, strings.TrimSuffix(path.Base(*obj.Key), ".safegrd"))
			}
		}
	}
	return snapshots, nil
}

// deleteKeyWithoutVersioning removes a key on a provider that cannot enumerate
// versions.
//
// Paired with listSnapshotsWithoutVersioning, and it exists for the same
// reason: DeleteSnapshot addresses versions by id, so a provider that does not
// implement ListObjectVersions would make retention cleanup fail for every
// object forever — a bucket that only ever grows, on a nightly timer, billed to
// the customer. A keyed DELETE is correct there because there is no version to
// leave behind and no delete marker to strand.
//
// A missing object is not an error: DeleteSnapshot's caller already decided
// this snapshot should be gone.
func (s *S3StorageProvider) deleteKeyWithoutVersioning(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	return err
}
