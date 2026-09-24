package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// LocalStorageProvider implements StorageProvider on the local filesystem with WORM simulation.
type LocalStorageProvider struct {
	baseDir string
	nodeID  string
}

// NewLocalStorage creates a LocalStorageProvider ensuring the directory exists.
func NewLocalStorage(baseDir string) (*LocalStorageProvider, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create local storage directory %s: %w", baseDir, err)
	}
	return &LocalStorageProvider{baseDir: baseDir}, nil
}

// SetNodeID configures the active node ID for scoped storage path segmentation.
func (l *LocalStorageProvider) SetNodeID(nodeID string) {
	l.nodeID = strings.TrimSpace(nodeID)
}

func (l *LocalStorageProvider) snapshotPath(snapshotID string) string {
	if l.nodeID != "" {
		return filepath.Join(l.baseDir, l.nodeID, snapshotID+".safegrd")
	}
	return filepath.Join(l.baseDir, snapshotID+".safegrd")
}

func (l *LocalStorageProvider) metadataPath(snapshotID string) string {
	if l.nodeID != "" {
		return filepath.Join(l.baseDir, l.nodeID, snapshotID+".meta.json")
	}
	return filepath.Join(l.baseDir, snapshotID+".meta.json")
}

func (l *LocalStorageProvider) UploadSnapshot(ctx context.Context, snapshotID string, stream io.Reader, size int64, retentionUntil time.Time) (string, error) {
	dstPath := l.snapshotPath(snapshotID)
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create directory for snapshot %s: %w", snapshotID, err)
	}

	// WORM Enforce: Cannot overwrite an existing snapshot
	if _, err := os.Stat(dstPath); err == nil {
		return "", fmt.Errorf("WORM violation: snapshot %s already exists and is immutable", snapshotID)
	}

	tempFile := dstPath + ".tmp"
	f, err := os.OpenFile(tempFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot file: %w", err)
	}

	if _, err := io.Copy(f, stream); err != nil {
		f.Close()
		os.Remove(tempFile)
		return "", fmt.Errorf("failed writing snapshot data: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tempFile)
		return "", fmt.Errorf("failed to close snapshot file: %w", err)
	}

	// Move to final path and mark READ-ONLY (WORM mode simulation)
	if err := os.Rename(tempFile, dstPath); err != nil {
		return "", fmt.Errorf("failed to finalize snapshot: %w", err)
	}

	// Lock down file permissions to read-only (0400)
	_ = os.Chmod(dstPath, 0400)

	if !retentionUntil.IsZero() {
		existing, _ := l.DownloadMetadata(ctx, snapshotID)
		if existing == nil {
			_ = l.UploadMetadata(ctx, snapshotID, &model.SnapshotMetadata{
				SnapshotID:         snapshotID,
				WORMRetentionUntil: retentionUntil,
			})
		} else if existing.WORMRetentionUntil.IsZero() {
			existing.WORMRetentionUntil = retentionUntil
			_ = l.UploadMetadata(ctx, snapshotID, existing)
		}
	}

	return "file://" + dstPath, nil
}

func (l *LocalStorageProvider) DownloadSnapshot(ctx context.Context, snapshotID string) (io.ReadCloser, error) {
	dstPath := l.snapshotPath(snapshotID)
	f, err := os.Open(dstPath)
	if err != nil && l.nodeID != "" {
		// Fallback check to flat path for backward compatibility
		flatPath := filepath.Join(l.baseDir, snapshotID+".safegrd")
		if flatF, flatErr := os.Open(flatPath); flatErr == nil {
			return flatF, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("snapshot %s not found: %w", snapshotID, err)
	}
	return f, nil
}

func (l *LocalStorageProvider) UploadMetadata(ctx context.Context, snapshotID string, meta *model.SnapshotMetadata) error {
	dstPath := l.metadataPath(snapshotID)
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for metadata %s: %w", snapshotID, err)
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	tempPath := dstPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	if err := os.Rename(tempPath, dstPath); err != nil {
		return fmt.Errorf("failed to finalize metadata file: %w", err)
	}

	return nil
}

func (l *LocalStorageProvider) DownloadMetadata(ctx context.Context, snapshotID string) (*model.SnapshotMetadata, error) {
	dstPath := l.metadataPath(snapshotID)
	data, err := os.ReadFile(dstPath)
	if err != nil && l.nodeID != "" {
		// Fallback check to flat path for backward compatibility
		flatPath := filepath.Join(l.baseDir, snapshotID+".meta.json")
		if flatData, flatErr := os.ReadFile(flatPath); flatErr == nil {
			data = flatData
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("metadata for snapshot %s not found: %w", snapshotID, err)
	}

	var meta model.SnapshotMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &meta, nil
}

func (l *LocalStorageProvider) ListSnapshots(ctx context.Context) ([]string, error) {
	var snapshots []string
	err := filepath.Walk(l.baseDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".safegrd") {
			id := strings.TrimSuffix(info.Name(), ".safegrd")
			snapshots = append(snapshots, id)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read storage directory: %w", err)
	}

	sort.Strings(snapshots)
	return snapshots, nil
}

func (l *LocalStorageProvider) SnapshotExists(ctx context.Context, snapshotID string) (bool, error) {
	dstPath := l.snapshotPath(snapshotID)
	_, err := os.Stat(dstPath)
	if err == nil {
		return true, nil
	}
	if l.nodeID != "" {
		flatPath := filepath.Join(l.baseDir, snapshotID+".safegrd")
		if _, err := os.Stat(flatPath); err == nil {
			return true, nil
		}
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (l *LocalStorageProvider) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	// Check retention first
	meta, err := l.DownloadMetadata(ctx, snapshotID)
	if err == nil && meta != nil && !meta.WORMRetentionUntil.IsZero() {
		if meta.WORMRetentionUntil.After(time.Now().UTC()) {
			return fmt.Errorf("WORM compliance refusal: snapshot %s is locked under WORM retention until %s", snapshotID, meta.WORMRetentionUntil.Format(time.RFC3339))
		}
	}

	snapPath := l.snapshotPath(snapshotID)
	metaPath := l.metadataPath(snapshotID)

	removeFile := func(p string) error {
		if _, err := os.Stat(p); err == nil {
			_ = os.Chmod(p, 0600)
			return os.Remove(p)
		}
		return nil
	}

	_ = removeFile(snapPath)
	_ = removeFile(metaPath)

	if l.nodeID != "" {
		_ = removeFile(filepath.Join(l.baseDir, snapshotID+".safegrd"))
		_ = removeFile(filepath.Join(l.baseDir, snapshotID+".meta.json"))
	}
	return nil
}

func (l *LocalStorageProvider) Type() string {
	return "local"
}
