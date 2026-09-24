package dump

import (
	"archive/tar"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// A table's binary COPY stream is written to the archive in chunks of at most
// copyChunkSize bytes, so neither a backup nor a restore ever holds a whole
// table in memory. The first chunk keeps the name every
// archive has always used, data/<schema>/<table>.copy; the rest follow it as.
// copy.1, .copy.2 and so on, in order. An archive with small tables is
// therefore byte-for-byte the shape it always was.
//
// Nothing is spooled to disk: a plaintext table on the host's disk is exactly
// what a backup of that host must not leave behind.
const copyChunkSize = 16 << 20

// copyEntryName is the archive name of chunk part of a table's data.
func copyEntryName(schema, table string, part int) string {
	name := fmt.Sprintf("data/%s/%s.copy", schema, table)
	if part > 0 {
		name += "." + strconv.Itoa(part)
	}
	return name
}

// parseCopyEntry reports which table and chunk an archive entry holds.
func parseCopyEntry(name string) (schema, table string, part int, ok bool) {
	rest, found := strings.CutPrefix(name, "data/")
	if !found {
		return "", "", 0, false
	}
	schema, file, found := strings.Cut(rest, "/")
	if !found || schema == "" || strings.Contains(file, "/") {
		return "", "", 0, false
	}
	if t, found := strings.CutSuffix(file, ".copy"); found && t != "" {
		return schema, t, 0, true
	}
	i := strings.LastIndex(file, ".copy.")
	if i <= 0 {
		return "", "", 0, false
	}
	n, err := strconv.Atoi(file[i+len(".copy."):])
	if err != nil || n < 1 {
		return "", "", 0, false
	}
	return schema, file[:i], n, true
}

// chunkWriter is the io.Writer a COPY TO streams into. It cuts the stream
// into tar entries of copyChunkSize bytes as it goes.
type chunkWriter struct {
	tw    *tar.Writer
	name  func(part int) string
	buf   []byte
	part  int
	total int64
}

func newChunkWriter(tw *tar.Writer, schema, table string) *chunkWriter {
	return &chunkWriter{tw: tw, name: func(part int) string { return copyEntryName(schema, table, part) }}
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		room := copyChunkSize - len(c.buf)
		if room > len(p) {
			room = len(p)
		}
		c.buf = append(c.buf, p[:room]...)
		p = p[room:]
		if len(c.buf) == copyChunkSize {
			if err := c.flush(); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

func (c *chunkWriter) flush() error {
	if err := writeTarEntry(c.tw, c.name(c.part), c.buf); err != nil {
		return err
	}
	c.total += int64(len(c.buf))
	c.part++
	c.buf = c.buf[:0]
	return nil
}

// Close writes what is left. A table always has its first entry, even an
// empty one, so a reader can tell "no rows" from "missing".
func (c *chunkWriter) Close() error {
	if len(c.buf) > 0 || c.part == 0 {
		return c.flush()
	}
	return nil
}

// tableStreams hands each table's data to consume as one continuous stream,
// however many chunks it was written in, while the archive is read in order.
// Everything else goes to other. consume runs on its own goroutine and must
// read its reader to the end or return an error.
type tableStreams struct {
	consume func(schema, table string, r io.Reader) error
	other   func(hdr *tar.Header, r io.Reader) error
	// parse names the stream an entry belongs to; parseCopyEntry if nil.
	parse func(name string) (schema, table string, part int, ok bool)

	schema, table string
	part          int
	pw            *io.PipeWriter
	done          chan error
}

// Run reads the whole archive.
func (s *tableStreams) Run(tr *tar.Reader) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return s.finish()
		}
		if err != nil {
			s.abort(err)
			return fmt.Errorf("archive read error: %w", err)
		}
		parse := s.parse
		if parse == nil {
			parse = parseCopyEntry
		}
		schema, table, part, ok := parse(hdr.Name)
		if !ok {
			if err := s.finish(); err != nil {
				return err
			}
			if s.other != nil {
				if err := s.other(hdr, tr); err != nil {
					return err
				}
			}
			continue
		}
		if part == 0 {
			if err := s.finish(); err != nil {
				return err
			}
			s.start(schema, table)
		} else if s.pw == nil || schema != s.schema || table != s.table || part != s.part+1 {
			// A chunk out of order is a corrupt or altered archive; joining
			// it anyway would load rows from one table into another.
			s.abort(fmt.Errorf("out of order"))
			return fmt.Errorf("archive entry %s is out of order: expected part %d of %s.%s", hdr.Name, s.part+1, s.schema, s.table)
		}
		s.part = part
		if _, err := io.Copy(s.pw, tr); err != nil {
			// The consumer stopped reading: its own error says why.
			if cerr := s.finish(); cerr != nil {
				return cerr
			}
			return fmt.Errorf("reading %s: %w", hdr.Name, err)
		}
	}
}

func (s *tableStreams) start(schema, table string) {
	pr, pw := io.Pipe()
	s.schema, s.table, s.part, s.pw = schema, table, 0, pw
	s.done = make(chan error, 1)
	go func() {
		err := s.consume(schema, table, pr)
		// Unblock the writer if the consumer returned early.
		_ = pr.CloseWithError(fmt.Errorf("consumer finished: %v", err))
		s.done <- err
	}()
}

func (s *tableStreams) finish() error {
	if s.pw == nil {
		return nil
	}
	_ = s.pw.Close()
	err := <-s.done
	s.pw = nil
	return err
}

func (s *tableStreams) abort(cause error) {
	if s.pw == nil {
		return
	}
	_ = s.pw.CloseWithError(cause)
	<-s.done
	s.pw = nil
}

// writeTarEntry writes one complete entry.
func writeTarEntry(tw *tar.Writer, name string, content []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    int64(len(content)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}
