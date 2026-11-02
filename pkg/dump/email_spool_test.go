package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The bodies go to a spool on disk while the mailbox is fetched and come
// back into the archive as they were; the spool is gone once the archive is
// written, and when the backup fails before it.
func TestAnEmailBackupHoldsBodiesOnDiskAndRemovesThem(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	mock := createTestMailSource()
	want := map[string][]byte{}
	for _, msgs := range mock.messages {
		for _, m := range msgs {
			want[m.Sha256] = append([]byte(nil), m.Body...)
		}
	}
	reader, meta, err := NewEmailCollector(EmailCollectorConfig{Host: "imap.test", Username: "u"}).ScanAndStream(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	left := spoolDirs(t, tmp)
	if len(left) != 1 {
		t.Fatalf("while the archive is open, want one spool directory, found %v", left)
	}
	// Every body is on disk, not in memory.
	fi, err := os.Stat(filepath.Join(tmp, left[0], "bodies"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != meta.RawSizeBytes || fi.Size() == 0 {
		t.Fatalf("the spool holds %d bytes; the mailbox is %d", fi.Size(), meta.RawSizeBytes)
	}
	tr := tar.NewReader(reader)
	got := 0
	seen := map[string]int{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(hdr.Name, ".eml") {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		if w, ok := want[digest]; !ok || !bytes.Equal(b, w) {
			t.Errorf("%s in the archive is not a message the source held: %q", hdr.Name, b)
		}
		seen[digest]++
		got++
	}
	// Every message the source held, each once: none lost, none twice.
	if got != len(want) {
		t.Fatalf("the archive holds %d messages, the source %d", got, len(want))
	}
	for digest := range want {
		if seen[digest] != 1 {
			t.Errorf("message %s is in the archive %d times, want once", digest, seen[digest])
		}
	}
	if left := spoolDirs(t, tmp); len(left) != 0 {
		t.Fatalf("the spool is left behind after the archive was written: %v", left)
	}

	// A backup that fails before the archive removes its spool too.
	_, _, err = NewEmailCollector(EmailCollectorConfig{Host: "imap.test"}).ScanAndStream(context.Background(), &failingSource{})
	wantErr(t, err, "refused")
	if left := spoolDirs(t, tmp); len(left) != 0 {
		t.Fatalf("a failed backup left its spool behind: %v", left)
	}
}

func spoolDirs(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		if strings.HasPrefix(e.Name(), emailSpoolPrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

type failingSource struct{ mockIMAPSource }

func (*failingSource) Connect(context.Context) error { return errors.New("refused") }
