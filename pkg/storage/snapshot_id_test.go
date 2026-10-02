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
