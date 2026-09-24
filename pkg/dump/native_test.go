package dump

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"
)

func TestWriteTarEntry(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	testData := []byte("SELECT * FROM users;")
	if err := writeTarEntry(tw, "schema.sql", testData); err != nil {
		t.Fatalf("writeTarEntry failed: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}

	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("tar read header failed: %v", err)
	}

	if hdr.Name != "schema.sql" {
		t.Errorf("expected name schema.sql, got %s", hdr.Name)
	}
	if hdr.Size != int64(len(testData)) {
		t.Errorf("expected size %d, got %d", len(testData), hdr.Size)
	}

	content, err := io.ReadAll(tr)
	if err != nil {
		t.Fatalf("failed to read tar content: %v", err)
	}

	if !bytes.Equal(content, testData) {
		t.Errorf("content mismatch: got %s, want %s", string(content), string(testData))
	}
}
