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
	// The store sits two levels down, so "../../escaped" from it names a
	// file in root. A snapshot is planted there: a Download that followed
	// the name would read it, where one that refuses reads nothing.
	root := t.TempDir()
	provider, err := NewLocalStorage(filepath.Join(root, "a", "store"))
	if err != nil {
		t.Fatal(err)
	}
	escaped := filepath.Join(root, "escaped.safegrd")
	if err := os.WriteFile(escaped, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "snapshot ID")
	}
	ctx := context.Background()
	for _, id := range []string{"../../escaped", "snap-../../x", "a/b", `a\b`, ".hidden", "", "snap\n1"} {
		if _, err := provider.UploadSnapshot(ctx, id, strings.NewReader("x"), 1, time.Now().Add(time.Hour)); !refused(err) {
			t.Errorf("UploadSnapshot(%q): %v, want the ID refused", id, err)
		}
		if _, err := provider.DownloadSnapshot(ctx, id); !refused(err) {
			t.Errorf("DownloadSnapshot(%q): %v, want the ID refused", id, err)
		}
		if err := provider.DeleteSnapshot(ctx, id); !refused(err) {
			t.Errorf("DeleteSnapshot(%q): %v, want the ID refused", id, err)
		}
	}
	if b, err := os.ReadFile(escaped); err != nil || string(b) != "planted" {
		t.Fatalf("the file outside the storage root was changed or removed: %q %v", b, err)
	}
	if left, err := filepath.Glob(filepath.Join(root, "*")); err != nil || len(left) != 2 {
		t.Fatalf("a file was written outside the storage root: %v %v", left, err)
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
	if err := os.Chmod(metaPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provider.DeleteSnapshot(ctx, id); err == nil || !strings.Contains(err.Error(), "its retention cannot be read") {
		t.Fatalf("deleting a snapshot whose retention cannot be read: %v", err)
	}
	if _, err := os.Stat(provider.snapshotPath(id)); err != nil {
		t.Fatalf("the payload is gone: %v", err)
	}
}
