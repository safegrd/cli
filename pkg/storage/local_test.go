package storage

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

func TestLocalStorageWORM(t *testing.T) {
	tempDir := t.TempDir()
	storageDir := filepath.Join(tempDir, "safegrd-store")

	provider, err := NewLocalStorage(storageDir)
	if err != nil {
		t.Fatalf("failed to create local storage: %v", err)
	}

	ctx := context.Background()
	snapshotID := "snap-2026-09-18-001"
	payload := []byte("encrypted-ciphertext-mock-data-123456")
	retentionUntil := time.Now().Add(14 * 24 * time.Hour)

	// 1. Upload snapshot
	uri, err := provider.UploadSnapshot(ctx, snapshotID, bytes.NewReader(payload), int64(len(payload)), retentionUntil)
	if err != nil {
		t.Fatalf("UploadSnapshot failed: %v", err)
	}
	if uri == "" {
		t.Error("expected non-empty storage URI")
	}

	// 2. WORM test: Overwrite must fail
	_, err = provider.UploadSnapshot(ctx, snapshotID, bytes.NewReader([]byte("tampered-data")), 13, retentionUntil)
	if err == nil {
		t.Fatal("expected error on overwrite due to WORM immutability, got nil")
	}

	// 3. Exists
	exists, err := provider.SnapshotExists(ctx, snapshotID)
	if err != nil || !exists {
		t.Errorf("expected snapshot to exist: err=%v, exists=%v", err, exists)
	}

	// 4. Download and verify content
	rc, err := provider.DownloadSnapshot(ctx, snapshotID)
	if err != nil {
		t.Fatalf("DownloadSnapshot failed: %v", err)
	}
	defer rc.Close()

	downloaded, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("failed to read downloaded stream: %v", err)
	}
	if !bytes.Equal(downloaded, payload) {
		t.Errorf("downloaded content mismatch: expected %s, got %s", string(payload), string(downloaded))
	}

	// 5. Metadata upload & download
	meta := &model.SnapshotMetadata{
		SnapshotID:         snapshotID,
		NodeID:             "node-test",
		DatabaseName:       "testdb",
		PostgresVersion:    "PostgreSQL 16.2",
		EncryptedSizeBytes: int64(len(payload)),
		RawSizeBytes:       1024,
		TableStats: []model.TableStat{
			{Schema: "public", TableName: "users", RowCount: 1500, SizeBytes: 40960},
		},
		TotalTables: 1,
		TotalRows:   1500,
	}

	if err := provider.UploadMetadata(ctx, snapshotID, meta); err != nil {
		t.Fatalf("UploadMetadata failed: %v", err)
	}

	fetchedMeta, err := provider.DownloadMetadata(ctx, snapshotID)
	if err != nil {
		t.Fatalf("DownloadMetadata failed: %v", err)
	}

	if fetchedMeta.SnapshotID != snapshotID {
		t.Errorf("metadata SnapshotID mismatch: %s vs %s", fetchedMeta.SnapshotID, snapshotID)
	}
	if fetchedMeta.TotalRows != 1500 {
		t.Errorf("metadata TotalRows mismatch: %d vs 1500", fetchedMeta.TotalRows)
	}

	// 6. List snapshots
	list, err := provider.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("ListSnapshots failed: %v", err)
	}
	if len(list) != 1 || list[0] != snapshotID {
		t.Errorf("expected [%s], got %v", snapshotID, list)
	}
}

func TestLocalStorage_NodeSegmentationAndFallback(t *testing.T) {
	tempDir := t.TempDir()
	storageDir := filepath.Join(tempDir, "safegrd-store")

	provider, err := NewLocalStorage(storageDir)
	if err != nil {
		t.Fatalf("failed to create local storage: %v", err)
	}
	provider.SetNodeID("node-alpha")

	ctx := context.Background()
	snapID := "snap-segmented-001"
	payload := []byte("segmented-node-data")
	retention := time.Now().Add(7 * 24 * time.Hour)

	// Upload should place it in node directory
	uri, err := provider.UploadSnapshot(ctx, snapID, bytes.NewReader(payload), int64(len(payload)), retention)
	if err != nil {
		t.Fatalf("UploadSnapshot failed: %v", err)
	}
	if !strings.Contains(uri, "node-alpha") {
		t.Errorf("expected URI to contain node-alpha, got %s", uri)
	}

	// Download via segmented provider
	rc, err := provider.DownloadSnapshot(ctx, snapID)
	if err != nil {
		t.Fatalf("DownloadSnapshot failed: %v", err)
	}
	content, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(content, payload) {
		t.Errorf("content mismatch: %s vs %s", string(content), string(payload))
	}

	// Flat provider listing finds it
	flatProvider, _ := NewLocalStorage(storageDir)
	snaps, err := flatProvider.ListSnapshots(ctx)
	if err != nil || len(snaps) != 1 || snaps[0] != snapID {
		t.Errorf("expected flatProvider to list segmented snapshot, got %v", snaps)
	}
}
