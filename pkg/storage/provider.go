package storage

import (
	"context"
	"io"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// StorageProvider abstracts immutable snapshot persistence.
type StorageProvider interface {
	// UploadSnapshot streams encrypted ciphertext to immutable WORM storage.
	UploadSnapshot(ctx context.Context, snapshotID string, stream io.Reader, size int64, retentionUntil time.Time) (string, error)

	// DownloadSnapshot opens a readable stream for a stored encrypted snapshot.
	DownloadSnapshot(ctx context.Context, snapshotID string) (io.ReadCloser, error)

	// UploadMetadata persists the snapshot's non-sensitive inspection metadata.
	UploadMetadata(ctx context.Context, snapshotID string, meta *model.SnapshotMetadata) error

	// DownloadMetadata retrieves the snapshot metadata manifest.
	DownloadMetadata(ctx context.Context, snapshotID string) (*model.SnapshotMetadata, error)

	// ListSnapshots returns all stored snapshot IDs in chronological or catalog order.
	ListSnapshots(ctx context.Context) ([]string, error)

	// SnapshotExists checks if a snapshot exists in storage.
	SnapshotExists(ctx context.Context, snapshotID string) (bool, error)

	// DeleteSnapshot deletes an expired snapshot and its metadata.
	// Strictly refuses deletion if WORM retention period is still active.
	DeleteSnapshot(ctx context.Context, snapshotID string) error

	// Type returns the provider backend name ("s3" or "local").
	Type() string
}
