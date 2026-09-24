//go:build unix

package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// What a file restore brings back, and what it refuses to do. The
// hostile archives are built by hand on purpose: an attacker who
// can write the bucket builds them by hand too.

type tarEntry struct {
	name, link string
	typ        byte
	mode       int64
	body       string
}

func craftTar(t *testing.T, entries ...tarEntry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link, Size: int64(len(e.body)), ModTime: time.Unix(1_700_000_000, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestRestoreNeverWritesThroughASymlinkedParent(t *testing.T) {
	outside := t.TempDir()
	target := t.TempDir()
	archive := craftTar(t,
		tarEntry{name: "a", typ: tar.TypeSymlink, link: outside, mode: 0o777},
		tarEntry{name: "a/passwd", typ: tar.TypeReg, mode: 0o644, body: "owned"},
	)
	_, err := NewFileRestorer().ExtractArchive(context.Background(), archive, target)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("restore through a symlinked parent: err = %v, want a refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "passwd")); !os.IsNotExist(statErr) {
		t.Fatalf("the restore wrote outside its target: %v", statErr)
	}
}

func TestRestoreNeverTruncatesThroughASymlink(t *testing.T) {
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	archive := craftTar(t,
		tarEntry{name: "x", typ: tar.TypeSymlink, link: victim, mode: 0o777},
		tarEntry{name: "x", typ: tar.TypeReg, mode: 0o644, body: "overwritten"},
	)
	if _, err := NewFileRestorer().ExtractArchive(context.Background(), archive, target); err == nil {
		t.Fatal("a regular file written over a symlink was accepted")
	}
	if got, _ := os.ReadFile(victim); string(got) != "original" {
		t.Fatalf("the file behind the symlink was overwritten: %q", got)
	}
}

func TestRestoreRefusesAnAbsoluteOrEscapingName(t *testing.T) {
	for _, name := range []string{"../escape", "a/../../escape"} {
		target := t.TempDir()
		archive := craftTar(t, tarEntry{name: name, typ: tar.TypeReg, mode: 0o644, body: "x"})
		if _, err := NewFileRestorer().ExtractArchive(context.Background(), archive, target); err == nil {
			t.Errorf("entry %q was restored", name)
		}
	}
}

func TestRestoreNamesWhatItDoesNotCreate(t *testing.T) {
	target := t.TempDir()
	archive := craftTar(t,
		tarEntry{name: "f", typ: tar.TypeReg, mode: 0o644, body: "data"},
		tarEntry{name: "hard", typ: tar.TypeLink, link: "f"},
		tarEntry{name: "pipe", typ: tar.TypeFifo, mode: 0o644},
	)
	res, err := NewFileRestorer().ExtractArchive(context.Background(), archive, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 2 || !strings.Contains(strings.Join(res.Skipped, ","), "hard link") {
		t.Errorf("skipped entries were not reported: %q", res.Skipped)
	}
}

// fidelityTree is the shape a home directory has: a private directory, a
// private file, a group-writable file, a symlink, and a link to a
// directory that has already been walked.
func fidelityTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mk := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	mk(os.MkdirAll(filepath.Join(dir, "releases", "42"), 0o755))
	mk(os.WriteFile(filepath.Join(dir, "releases", "42", "app"), []byte("binary"), 0o755))
	mk(os.Mkdir(filepath.Join(dir, "ssh"), 0o700))
	mk(os.WriteFile(filepath.Join(dir, "ssh", "id_ed25519"), []byte("private key"), 0o600))
	mk(os.WriteFile(filepath.Join(dir, "shared.txt"), []byte("the group edits this"), 0o664))
	mk(os.Symlink("releases/42", filepath.Join(dir, "zz-current")))
	mk(os.Symlink(".", filepath.Join(dir, "zz-self")))
	// Modes set after creation, so the process umask cannot have trimmed them.
	mk(os.Chmod(filepath.Join(dir, "ssh"), 0o700))
	mk(os.Chmod(filepath.Join(dir, "shared.txt"), 0o664))
	old := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	mk(os.Chtimes(filepath.Join(dir, "ssh"), old, old))
	return dir
}

func TestFileRoundTripKeepsModesTimesAndLinks(t *testing.T) {
	// A restore running under the usual umask must still produce the modes
	// that were backed up: creation modes pass through it.
	defer syscall.Umask(syscall.Umask(0o022))

	src := fidelityTree(t)
	collector := NewFileCollector(FileCollectorConfig{RootDir: src})
	stream, _, err := collector.ScanAndStream(context.Background())
	if err != nil {
		t.Fatalf("a tree with links to walked directories failed to back up: %v", err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	res, err := NewFileRestorer().ExtractArchive(context.Background(), stream, target)
	if err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]os.FileMode{
		"ssh":             0o700,
		"ssh/id_ed25519":  0o600,
		"shared.txt":      0o664,
		"releases/42/app": 0o755,
	} {
		fi, err := os.Stat(filepath.Join(target, path))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s restored as %o, backed up as %o", path, got, want)
		}
	}
	fi, _ := os.Stat(filepath.Join(target, "ssh"))
	if want := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC); !fi.ModTime().Equal(want) {
		t.Errorf("directory time restored as %v, want %v", fi.ModTime().UTC(), want)
	}
	for link, want := range map[string]string{"zz-current": "releases/42", "zz-self": "."} {
		if got, err := os.Readlink(filepath.Join(target, link)); err != nil || got != want {
			t.Errorf("%s restored as %q (%v), want a link to %q", link, got, err, want)
		}
	}
	if res.SymlinksExtracted != 2 {
		t.Errorf("symlinks restored: %d, want 2", res.SymlinksExtracted)
	}
	if !canChown() && (res.OwnershipRestored || !strings.Contains(res.OwnershipNote, "needs root")) {
		t.Errorf("a restore without root must say ownership was not reapplied: %+v", res)
	}
}

func TestBackupSkipsSpecialFilesAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.txt"), []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Unix socket paths are short; listen in a short directory and link it in.
	sockDir, err := os.MkdirTemp("", "sg")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	l, err := net.Listen("unix", filepath.Join(sockDir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Rename(filepath.Join(sockDir, "s"), filepath.Join(dir, "agent.sock")); err != nil {
		t.Fatal(err)
	}

	collector := NewFileCollector(FileCollectorConfig{RootDir: dir})
	done := make(chan error, 1)
	go func() {
		stream, meta, err := collector.ScanAndStream(context.Background())
		if err == nil {
			var buf bytes.Buffer
			_, err = buf.ReadFrom(stream)
			if err == nil && meta.FileStats.TotalFiles != 1 {
				err = &os.PathError{Op: "count", Path: dir, Err: os.ErrInvalid}
			}
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a tree holding a FIFO and a socket failed to back up: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the backup hung on a FIFO")
	}
	got := strings.Join(collector.Skipped(), ",")
	if !strings.Contains(got, "pipe (named pipe)") || !strings.Contains(got, "agent.sock (socket)") {
		t.Errorf("skipped entries not reported: %q", got)
	}
}

// An archive written by v0.0.2, before owners were recorded and before
// modes were restored, still verifies and restores (testdata was generated
// with that collector and committed before either change).
func TestAnArchiveFromV002StillVerifiesAndRestores(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "files-v0.0.2.tar"))
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := NewFileRestorer().InspectFileArchive(context.Background(), bytes.NewReader(raw), nil)
	if err != nil || !inspected.Passed {
		t.Fatalf("the v0.0.2 archive no longer verifies: %v %+v", err, inspected)
	}
	target := t.TempDir()
	res, err := NewFileRestorer().ExtractArchive(context.Background(), bytes.NewReader(raw), target)
	if err != nil {
		t.Fatal(err)
	}
	if res.OwnershipRestored || !strings.Contains(res.OwnershipNote, "predates") {
		t.Errorf("ownership for an archive without owners: %+v", res)
	}
	for path, want := range map[string]os.FileMode{"notes": 0o700, "notes/secret.txt": 0o600, "readme.txt": 0o664} {
		fi, err := os.Stat(filepath.Join(target, path))
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s from the v0.0.2 archive: %v %v, want %o", path, err, fi, want)
		}
	}
}

// Ownership needs root, so this runs in the Linux container the release
// is built in, and skips elsewhere.
func TestOwnershipIsRestoredAsRoot(t *testing.T) {
	if !canChown() {
		t.Skip("restoring ownership needs root")
	}
	src := t.TempDir()
	file := filepath.Join(src, "owned.txt")
	if err := os.WriteFile(file, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(file, 4321, 8765); err != nil {
		t.Fatal(err)
	}
	stream, _, err := NewFileCollector(FileCollectorConfig{RootDir: src}).ScanAndStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	res, err := NewFileRestorer().ExtractArchive(context.Background(), stream, target)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(target, "owned.txt"))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != 4321 || st.Gid != 8765 || !res.OwnershipRestored {
		t.Errorf("owner restored as %d:%d (%+v), want 4321:8765", st.Uid, st.Gid, res)
	}
}

func TestMailIsRestoredPrivateAndNeverThroughASymlink(t *testing.T) {
	target := t.TempDir()
	archive := craftTar(t,
		tarEntry{name: "INBOX", typ: tar.TypeDir, mode: 0o755},
		tarEntry{name: "INBOX/1.eml", typ: tar.TypeReg, mode: 0o644, body: "Subject: payroll\r\n\r\nprivate"},
	)
	if _, err := NewEmailRestorer().ExtractEmailArchive(context.Background(), archive, target); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{"INBOX": 0o700, "INBOX/1.eml": 0o600} {
		if fi, err := os.Stat(filepath.Join(target, path)); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s restored as %v (%v), want %o", path, fi.Mode().Perm(), err, want)
		}
	}

	outside := t.TempDir()
	target2 := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(target2, "INBOX")); err != nil {
		t.Fatal(err)
	}
	archive = craftTar(t, tarEntry{name: "INBOX/1.eml", typ: tar.TypeReg, mode: 0o644, body: "x"})
	if _, err := NewEmailRestorer().ExtractEmailArchive(context.Background(), archive, target2); err == nil {
		t.Error("a mail restore wrote through a symlink in its target")
	}
	if _, err := os.Stat(filepath.Join(outside, "1.eml")); !os.IsNotExist(err) {
		t.Errorf("the mail restore wrote outside its target: %v", err)
	}
}
