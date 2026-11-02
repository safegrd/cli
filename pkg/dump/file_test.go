package dump

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func createTestTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// files in root
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Hello SafeGrd"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.log"), []byte("log line 1\nlog line 2"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "temp.tmp"), []byte("should be excluded"), 0644); err != nil {
		t.Fatal(err)
	}

	// subfolder
	sub := filepath.Join(dir, "src", "pkg")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "main.go"), []byte("package main\nfunc main() {}"), 0644); err != nil {
		t.Fatal(err)
	}

	// excluded directory
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]"), 0644); err != nil {
		t.Fatal(err)
	}

	return dir
}

func TestFileCollector_GlobExclusion(t *testing.T) {
	dir := createTestTree(t)

	collector := NewFileCollector(FileCollectorConfig{
		RootDir:  dir,
		Excludes: []string{"*.tmp", ".git/*", ".git"},
	})

	ctx := context.Background()
	reader, meta, err := collector.ScanAndStream(ctx)
	if err != nil {
		t.Fatalf("ScanAndStream failed: %v", err)
	}

	if meta.TotalItems != 3 { // README.md, app.log, src/pkg/main.go (excluding temp.tmp and .git/config)
		t.Fatalf("expected 3 files, got %d", meta.TotalItems)
	}

	restorer := NewFileRestorer()
	res, err := restorer.InspectFileArchive(ctx, reader, meta)
	if err != nil {
		t.Fatalf("InspectFileArchive failed: %v", err)
	}

	if !res.Passed {
		t.Fatalf("expected inspection to pass, error: %s", res.ErrorMessage)
	}

	for _, entry := range res.SealedManifest.Entries {
		if filepath.Ext(entry.Path) == ".tmp" {
			t.Fatalf("excluded file %s found in archive", entry.Path)
		}
		if filepath.HasPrefix(entry.Path, ".git") {
			t.Fatalf("excluded path %s found in archive", entry.Path)
		}
	}
}

// A symlink back to the root is stored as a symlink, never followed, so it
// cannot loop. This test used to assert the opposite — that such a tree fails
// to back up — which failed every tree with a link to a directory already
// walked.
func TestFileCollector_SymlinkToAnAncestorIsKept(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on windows require privileges")
	}

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(sub, "loop")); err != nil {
		t.Fatal(err)
	}

	stream, _, err := NewFileCollector(FileCollectorConfig{RootDir: dir}).ScanAndStream(context.Background())
	if err != nil {
		t.Fatalf("a link to an ancestor failed the backup: %v", err)
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		t.Fatal(err)
	}
}

func TestFileCollector_PermissionDeniedFailsLoudly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}

	dir := t.TempDir()
	secretDir := filepath.Join(dir, "unreadable")
	if err := os.MkdirAll(secretDir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(secretDir, 0755)

	collector := NewFileCollector(FileCollectorConfig{
		RootDir: dir,
	})

	_, _, err := collector.ScanAndStream(context.Background())
	wantErr(t, err, "unreadable", "permission denied")
}

// Two archives of an unchanged tree are the same bytes, though the first
// pass read every file (moving its atime). No golden digest is pinned: the
// sealed manifest records each file's owner, which differs between hosts.
func TestFileCollector_GoldenReproducibleTar(t *testing.T) {
	dir := createTestTree(t)

	// Fix modtimes of all files to ensure stable timestamps
	fixedTime := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(p, fixedTime, fixedTime)
	})
	if err != nil {
		t.Fatal(err)
	}

	collector := NewFileCollector(FileCollectorConfig{
		RootDir:     dir,
		Excludes:    []string{"*.tmp", ".git/*"},
		ArchiveTime: fixedTime,
	})
	pass := func() (string, int64) {
		t.Helper()
		r, _, err := collector.ScanAndStream(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		n, err := io.Copy(h, r)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(h.Sum(nil)), n
	}
	sum1, n1 := pass()
	sum2, n2 := pass()
	if n1 == 0 || n1 != n2 {
		t.Fatalf("the archives are %d and %d bytes", n1, n2)
	}
	if sum1 != sum2 {
		t.Fatalf("tar output was not deterministic:\npass1=%s\npass2=%s", sum1, sum2)
	}
}

func TestFileCollector_MismatchedManifestFailsDrill(t *testing.T) {
	dir := createTestTree(t)
	collector := NewFileCollector(FileCollectorConfig{
		RootDir:  dir,
		Excludes: []string{"*.tmp", ".git/*"},
	})

	reader, meta, err := collector.ScanAndStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	archive, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	restorer := NewFileRestorer()

	// The archive with its own record passes: what fails below is the
	// count alone.
	res, err := restorer.InspectFileArchive(context.Background(), bytes.NewReader(archive), meta)
	if err != nil || !res.Passed {
		t.Fatalf("the untampered archive did not pass: %v %s %+v", err, res.ErrorMessage, res.Assertions)
	}

	tamperedMeta := *meta
	tamperedMeta.TotalItems = meta.TotalItems + 999
	res, err = restorer.InspectFileArchive(context.Background(), bytes.NewReader(archive), &tamperedMeta)
	if err != nil {
		t.Fatalf("InspectFileArchive error: %v", err)
	}
	if res.Passed {
		t.Fatalf("expected dry restore drill to FAIL on mismatched file count, but it passed")
	}
	if a := assertion(t, res.Assertions, "Archive File Count Matches Manifest"); a.Passed {
		t.Fatalf("the count assertion passed over a record of %d files: %+v", tamperedMeta.TotalItems, a)
	}
	if want := fmt.Sprintf("the snapshot record says %d", tamperedMeta.TotalItems); !strings.Contains(res.ErrorMessage, want) {
		t.Fatalf("the failure does not name the count it disagreed with: %q", res.ErrorMessage)
	}
}

func TestFileCollector_DiskExtraction(t *testing.T) {
	dir := createTestTree(t)
	collector := NewFileCollector(FileCollectorConfig{
		RootDir:  dir,
		Excludes: []string{"*.tmp", ".git/*", ".git"},
	})

	reader, _, err := collector.ScanAndStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Read stream to memory buffer so we can extract it
	tarData, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	targetDir := t.TempDir()
	restorer := NewFileRestorer()
	extractRes, err := restorer.ExtractArchive(context.Background(), bytes.NewReader(tarData), targetDir)
	if err != nil {
		t.Fatalf("ExtractArchive failed: %v", err)
	}
	if extractRes.FilesExtracted != 3 {
		t.Fatalf("expected 3 files extracted, got %d", extractRes.FilesExtracted)
	}

	// Every file the backup took comes back byte for byte, and nothing it
	// excluded does.
	want := map[string]string{}
	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if filepath.Ext(rel) == ".tmp" || strings.HasPrefix(rel, ".git") {
			return nil
		}
		b, err := os.ReadFile(p)
		want[filepath.ToSlash(rel)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	err = filepath.Walk(targetDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(targetDir, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		got[filepath.ToSlash(rel)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 3 || !reflect.DeepEqual(got, want) {
		t.Fatalf("restored %v, the source holds %v", got, want)
	}
}

// A symlink is counted as an item by the collector and stores no payload bytes
// in the archive. Until the two sides agreed on that, the collector sealed a
// manifest claiming the symlink's target-string length as archive bytes and
// counted it as a file, while the dry restorer counted symlink entries as
// neither files nor directories. Every tree containing a symlink then failed
// verification -- a backup that restored perfectly but could never be proven,
// which is the product's whole claim. Found by the first real file-surface
// dogfood; the suite was green because no fixture had a symlink in it.
func TestFileCollector_SymlinkAccountingAgreesBetweenSealAndDrill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require privilege on Windows")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("top level config"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nested", "leaf.md"), []byte("nested payload"), 0644); err != nil {
		t.Fatal(err)
	}
	// A relative target pointing back out of the subdirectory, which is the
	// shape that occurs in real trees (sites-enabled -> ../sites-available).
	if err := os.Symlink("../plain.txt", filepath.Join(dir, "nested", "link.txt")); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	collector := NewFileCollector(FileCollectorConfig{RootDir: dir})
	reader, meta, err := collector.ScanAndStream(ctx)
	if err != nil {
		t.Fatalf("ScanAndStream failed: %v", err)
	}

	// plain.txt, nested/leaf.md and the symlink.
	if meta.TotalItems != 3 {
		t.Fatalf("collector counted %d items, want 3 (the symlink is backed up and restored)", meta.TotalItems)
	}

	res, err := NewFileRestorer().InspectFileArchive(ctx, reader, meta)
	if err != nil {
		t.Fatalf("InspectFileArchive failed: %v", err)
	}
	if !res.Passed {
		t.Fatalf("a tree with a symlink must verify, got: %s", res.ErrorMessage)
	}

	// The three numbers an operator can compare: what the collector reported,
	// what it sealed into the manifest, and what the drill counted in the
	// archive. A disagreement in any pair is the defect this test exists for.
	if res.TotalFiles != meta.TotalItems {
		t.Fatalf("drill counted %d files, collector reported %d", res.TotalFiles, meta.TotalItems)
	}
	if res.SealedManifest.TotalFiles != res.TotalFiles {
		t.Fatalf("sealed manifest declares %d files, drill counted %d", res.SealedManifest.TotalFiles, res.TotalFiles)
	}
	if res.SealedManifest.RawSizeBytes != res.TotalRawBytes {
		t.Fatalf("sealed manifest declares %d bytes, archive carries %d -- a symlink stores no payload",
			res.SealedManifest.RawSizeBytes, res.TotalRawBytes)
	}

	// The target has to survive, or the manifest attests that a link exists
	// without attesting where it points.
	var found bool
	for _, e := range res.SealedManifest.Entries {
		if e.IsSymlink {
			found = true
			if e.LinkTarget != "../plain.txt" {
				t.Fatalf("symlink target recorded as %q, want ../plain.txt", e.LinkTarget)
			}
			if e.Size != 0 {
				t.Fatalf("symlink sealed with size %d, want 0", e.Size)
			}
		}
	}
	if !found {
		t.Fatal("no symlink entry in the sealed manifest")
	}
}
