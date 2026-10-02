package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// filepath.Join collapses "..", so a snapshot ID used to be a path: a
// --tag of "../../x" wrote the backup outside the storage root.
func TestASnapshotIDCannotLeaveTheStorageRoot(t *testing.T) {
	root := t.TempDir()
	provider, err := NewLocalStorage(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []string{"../../escaped", "snap-../../x", "a/b", `a\b`, ".hidden", "", "snap\n1"} {
		if _, err := provider.UploadSnapshot(ctx, id, strings.NewReader("x"), 1, time.Now().Add(time.Hour)); err == nil {
			t.Errorf("UploadSnapshot(%q) was accepted", id)
		}
		if _, err := provider.DownloadSnapshot(ctx, id); err == nil {
			t.Errorf("DownloadSnapshot(%q) was accepted", id)
		}
		if err := provider.DeleteSnapshot(ctx, id); err == nil {
			t.Errorf("DeleteSnapshot(%q) was accepted", id)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "escaped.safegrd")); err == nil {
		t.Fatal("a file was written outside the storage root")
	}
	for _, id := range []string{"snap-20261002-120000-ab12cd", "snap-nightly_v2.1-ab12cd"} {
		if err := ValidateSnapshotID(id); err != nil {
			t.Errorf("ValidateSnapshotID(%q) = %v", id, err)
		}
	}
}

// Local storage has no Object Lock, so a sidecar that cannot be read must
// refuse the delete rather than skip the retention check.
func TestLocalDeleteRefusesWhenRetentionCannotBeRead(t *testing.T) {
	provider, err := NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const id = "snap-locked-1"
	if _, err := provider.UploadSnapshot(ctx, id, strings.NewReader("payload"), 7, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	metaPath := provider.metadataPath(id)
	_ = os.Chmod(metaPath, 0o600)
	if err := os.WriteFile(metaPath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provider.DeleteSnapshot(ctx, id); err == nil {
		t.Fatal("a snapshot whose retention could not be read was deleted")
	}
	if _, err := os.Stat(provider.snapshotPath(id)); err != nil {
		t.Fatalf("the payload is gone: %v", err)
	}
}
