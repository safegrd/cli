package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// answeringStdio is stdin and stdout for `safegrd mcp`, with stdin's end of
// file held back until every request read from it has been answered. The MCP
// library ends the session as soon as its reader sees end of file and drops
// whatever is still running, so `printf '<requests>' | safegrd mcp` printed
// nothing at all.
type answeringStdio struct {
	in   io.ReadCloser
	out  io.Writer
	done <-chan struct{} // the command's context: stop waiting on Ctrl-C

	mu      sync.Mutex
	pending map[string]bool // ids of requests read and not yet answered
	idle    chan struct{}   // closed when pending empties, while a reader waits
	inLine  []byte          // the request line being read, up to its newline
	inSkip  bool            // that line is past the library's limit; not noted
	outLine []byte          // the response line being written
}

func newAnsweringStdio(in io.ReadCloser, out io.Writer, done <-chan struct{}) *answeringStdio {
	return &answeringStdio{in: in, out: out, done: done, pending: map[string]bool{}}
}

// transport is the MCP transport over s.
func (s *answeringStdio) transport() mcp.Transport {
	return &mcp.IOTransport{Reader: answeringReader{s}, Writer: answeringWriter{s}}
}

type answeringReader struct{ s *answeringStdio }

func (r answeringReader) Read(p []byte) (int, error) {
	s := r.s
	n, err := s.in.Read(p)
	s.mu.Lock()
	s.inLine, s.inSkip = s.scan(s.inLine, s.inSkip, p[:n], s.noteRead)
	if err == io.EOF && !s.inSkip && len(bytes.TrimSpace(s.inLine)) > 0 {
		// The last request had no newline after it.
		s.noteRead(s.inLine)
		s.inLine = nil
	}
	s.mu.Unlock()
	if err != io.EOF {
		return n, err
	}
	if n > 0 {
		return n, nil // the end of file comes back on the next read
	}
	for {
		s.mu.Lock()
		if len(s.pending) == 0 {
			s.mu.Unlock()
			return 0, io.EOF
		}
		if s.idle == nil {
			s.idle = make(chan struct{})
		}
		idle := s.idle
		s.mu.Unlock()
		select {
		case <-idle:
		case <-s.done:
			return 0, io.EOF
		}
	}
}

func (r answeringReader) Close() error { return r.s.in.Close() }

type answeringWriter struct{ s *answeringStdio }

func (w answeringWriter) Write(p []byte) (int, error) {
	s := w.s
	n, err := s.out.Write(p)
	s.mu.Lock()
	s.outLine, _ = s.scan(s.outLine, false, p[:n], s.noteWritten)
	s.mu.Unlock()
	return n, err
}

// Close leaves stdout open: the process exits right after.
func (answeringWriter) Close() error { return nil }

// scan appends b to line and hands each complete line to note. A line that
// grows past the library's own limit is dropped rather than held, since the
// library refuses it too. Called with s.mu held.
func (s *answeringStdio) scan(line []byte, skip bool, b []byte, note func([]byte)) ([]byte, bool) {
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		chunk := b
		if i >= 0 {
			chunk = b[:i]
		}
		if !skip {
			line = append(line, chunk...)
			if len(line) > mcp.DefaultMaxLineLength {
				line, skip = nil, true
			}
		}
		if i < 0 {
			break
		}
		if !skip {
			note(line)
		}
		line, skip = line[:0], false
		b = b[i+1:]
	}
	return line, skip
}

// rpcMessage is what the counting needs from a JSON-RPC message.
type rpcMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		RequestID json.RawMessage `json:"requestId"`
	} `json:"params"`
}

// rpcMessages reads one line: a message, or a batch of them.
func rpcMessages(line []byte) []rpcMessage {
	line = bytes.TrimSpace(line)
	var msgs []rpcMessage
	if len(line) > 0 && line[0] == '[' {
		_ = json.Unmarshal(line, &msgs) // not JSON-RPC: the library answers it
		return msgs
	}
	var m rpcMessage
	if json.Unmarshal(line, &m) != nil {
		return nil
	}
	return []rpcMessage{m}
}

// rpcID is an id as a map key: 1 and 1.0 are one request.
func rpcID(raw json.RawMessage) (string, bool) {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil || v == nil {
		return "", false
	}
	return fmt.Sprint(v), true
}

// noteRead counts the requests in a line from stdin. A cancelled request may
// never be answered, so it stops counting.
func (s *answeringStdio) noteRead(line []byte) {
	for _, m := range rpcMessages(line) {
		if m.Method == "notifications/cancelled" {
			if id, ok := rpcID(m.Params.RequestID); ok {
				s.answered(id)
			}
			continue
		}
		if id, ok := rpcID(m.ID); ok && m.Method != "" {
			s.pending[id] = true
		}
	}
}

// noteWritten counts the responses in a line written to stdout.
func (s *answeringStdio) noteWritten(line []byte) {
	for _, m := range rpcMessages(line) {
		if id, ok := rpcID(m.ID); ok && m.Method == "" {
			s.answered(id)
		}
	}
}

func (s *answeringStdio) answered(id string) {
	delete(s.pending, id)
	if len(s.pending) == 0 && s.idle != nil {
		close(s.idle)
		s.idle = nil
	}
}
