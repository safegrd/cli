package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeBucket records the objects a PutObject wrote. It answers PutObject
// only: a restore into a bucket needs nothing else.
type fakeBucket struct {
	mu      sync.Mutex
	objects map[string]string
	types   map[string]string
}

func (f *fakeBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut || r.URL.Query().Has("uploadId") {
		http.Error(w, "not in this fake", http.StatusNotImplemented)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.objects[r.URL.Path] = string(body)
	f.types[r.URL.Path] = r.Header.Get("Content-Type")
	f.mu.Unlock()
	w.Header().Set("ETag", `"x"`)
}

type archiveFile struct {
	name, body, contentType string
	sealedSha               string // overrides the true digest when set
}

func filesArchive(t *testing.T, files []archiveFile, links map[string]string) []byte {
	t.Helper()
	m := SealedFileManifest{Version: "1"}
	for _, f := range files {
		sum := sha256.Sum256([]byte(f.body))
		sha := hex.EncodeToString(sum[:])
		if f.sealedSha != "" {
			sha = f.sealedSha
		}
		m.Entries = append(m.Entries, FileEntryManifest{Path: f.name, Size: int64(len(f.body)), Sha256: sha, ContentType: f.contentType})
	}
	for name, target := range links {
		m.Entries = append(m.Entries, FileEntryManifest{Path: name, IsSymlink: true, LinkTarget: target})
	}
	raw, _ := json.Marshal(m)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(h *tar.Header, body []byte) {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	write(&tar.Header{Name: ".safegrd-manifest.json", Mode: 0o600, Size: int64(len(raw)), Typeflag: tar.TypeReg}, raw)
	write(&tar.Header{Name: "docs", Mode: 0o755, Typeflag: tar.TypeDir}, nil)
	for _, f := range files {
		write(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}, []byte(f.body))
	}
	for name, target := range links {
		write(&tar.Header{Name: name, Linkname: target, Typeflag: tar.TypeSymlink}, nil)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func restoreTarget(t *testing.T) (*fakeBucket, ObjectStoreSource) {
	t.Helper()
	fb := &fakeBucket{objects: map[string]string{}, types: map[string]string{}}
	srv := httptest.NewServer(fb)
	t.Cleanup(srv.Close)
	return fb, ObjectStoreSource{Endpoint: srv.URL, Bucket: "uploads", Prefix: "restored", AccessKeyID: "k", SecretAccessKey: "s"}
}

func TestARestoreIntoABucketWritesEachFileWithItsContentType(t *testing.T) {
	fb, dst := restoreTarget(t)
	archive := filesArchive(t, []archiveFile{
		{name: "docs/report.pdf", body: "%PDF-1.7", contentType: "application/pdf"},
		{name: "notes.txt", body: "plain", contentType: "text/plain"},
		{name: "empty/.emptyFolderPlaceholder", body: ""},
	}, nil)
	res, err := RestoreArchiveToObjectStore(context.Background(), bytes.NewReader(archive), dst)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.ObjectsWritten != 3 || res.WithContentType != 2 || res.Directories != 1 || res.BytesWritten != int64(len("%PDF-1.7plain")) {
		t.Fatalf("result: %+v", res)
	}
	if got := fb.objects["/uploads/restored/docs/report.pdf"]; got != "%PDF-1.7" {
		t.Fatalf("report.pdf: %q (objects %v)", got, fb.objects)
	}
	if got := fb.types["/uploads/restored/docs/report.pdf"]; got != "application/pdf" {
		t.Fatalf("report.pdf went up as %q", got)
	}
	if _, ok := fb.objects["/uploads/restored/empty/.emptyFolderPlaceholder"]; !ok {
		t.Fatalf("the folder placeholder was not written: %v", fb.objects)
	}
}

// A file whose bytes are not the ones sealed is never created, and the error
// names it and says how many files went before it.
func TestARestoreIntoABucketDoesNotWriteAFileThatFailsItsDigest(t *testing.T) {
	fb, dst := restoreTarget(t)
	archive := filesArchive(t, []archiveFile{
		{name: "a.txt", body: "fine"},
		{name: "b.txt", body: "tampered", sealedSha: strings.Repeat("0", 64)},
	}, nil)
	_, err := RestoreArchiveToObjectStore(context.Background(), bytes.NewReader(archive), dst)
	if err == nil {
		t.Fatal("a file that fails its digest was restored")
	}
	if !strings.Contains(err.Error(), "b.txt does not match the sealed manifest") || !strings.Contains(err.Error(), "1 files were written") {
		t.Fatalf("the error does not name the file and the count: %v", err)
	}
	if _, ok := fb.objects["/uploads/restored/b.txt"]; ok {
		t.Fatal("the tampered file was uploaded")
	}
	if _, ok := fb.objects["/uploads/restored/a.txt"]; !ok {
		t.Fatal("the file before it was not uploaded")
	}
}

func TestARestoreIntoABucketRefusesSymlinksBeforeWritingAnything(t *testing.T) {
	fb, dst := restoreTarget(t)
	archive := filesArchive(t, []archiveFile{{name: "a.txt", body: "fine"}}, map[string]string{"current": "a.txt"})
	_, err := RestoreArchiveToObjectStore(context.Background(), bytes.NewReader(archive), dst)
	if err == nil {
		t.Fatal("an archive with a symlink was restored into a bucket")
	}
	if !strings.Contains(err.Error(), "current") || !strings.Contains(err.Error(), "Nothing was written") {
		t.Fatalf("the refusal does not name the link: %v", err)
	}
	if len(fb.objects) != 0 {
		t.Fatalf("objects were written before the refusal: %v", fb.objects)
	}
}
