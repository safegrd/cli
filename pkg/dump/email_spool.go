package dump

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/safegrd/cli/pkg/diskspace"
)

// emailSpool holds the bodies of a mailbox's messages on disk while a backup
// collects them. The archive opens with the sealed manifest, which lists
// every message, so no body can be written to it before the last message is
// fetched; held in memory, a mailbox took more than its own size. The spool
// is one file in a private (0700) directory under the system temporary
// directory, written through the disk guard and removed when the archive has
// been written or the backup failed. The bodies are plaintext, as the
// SQLite backup's copy is.
type emailSpool struct {
	dir string
	f   *os.File
	bw  *bufio.Writer
	end int64
}

const emailSpoolPrefix = ".safegrd-email-"

func newEmailSpool() (*emailSpool, error) {
	dir, err := privateWorkDir(emailSpoolPrefix)
	if err != nil {
		return nil, fmt.Errorf("making a private directory for the messages: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "bodies"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("making the file the messages are held in: %w", err)
	}
	g := diskspace.NewGuard(f, dir, "an email backup, which holds each message on disk until the archive is written",
		"free some space, or set TMPDIR to a larger disk")
	return &emailSpool{dir: dir, f: f, bw: bufio.NewWriterSize(g, 1<<20)}, nil
}

// add writes n bytes from r and returns where they start.
func (s *emailSpool) add(r io.Reader, n int64) (int64, error) {
	at := s.end
	got, err := io.CopyN(s.bw, r, n)
	s.end += got
	if err != nil {
		return 0, err
	}
	return at, nil
}

// finish flushes what add buffered, before anything is read back.
func (s *emailSpool) finish() error { return s.bw.Flush() }

// open reads back n bytes from at.
func (s *emailSpool) open(at, n int64) io.Reader { return io.NewSectionReader(s.f, at, n) }

// close removes the spool.
func (s *emailSpool) close() {
	_ = s.f.Close()
	_ = os.RemoveAll(s.dir)
}

// headerPrefix keeps the first max bytes written to it, enough to read a
// message's headers from without holding its body.
type headerPrefix struct {
	b   bytes.Buffer
	max int
}

func (h *headerPrefix) Write(p []byte) (int, error) {
	if room := h.max - h.b.Len(); room > 0 {
		h.b.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}
