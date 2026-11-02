package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// capture runs fn with *f pointed at a pipe and returns everything written
// to it. It reads until the pipe is closed: a single Read returns only what
// had been written by then, so a test asserting that a line was not printed
// passed whenever another line came before it.
//
// This file is the one place a test swaps os.Stdout or os.Stderr.
func capture(t *testing.T, f **os.File, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := *f
	*f = w // swap: the capture helper itself
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		// A read error ends the capture early; what was read is returned,
		// and the assertions on it say what is missing.
		_, _ = io.Copy(&buf, r)
		r.Close()
		done <- buf.String()
	}()
	finished := false
	defer func() {
		// fn stopped the test (t.Fatal): put the file back and let the
		// reader finish, so the next test writes to the real one.
		if !finished {
			*f = orig // swap: the capture helper itself
			w.Close()
		}
	}()
	fn()
	*f = orig // swap: the capture helper itself
	finished = true
	w.Close()
	return <-done
}

// captureStderr runs fn and returns what it wrote to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	return capture(t, &os.Stderr, fn)
}

// captureStdout runs fn and returns what it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	return capture(t, &os.Stdout, fn)
}

// captureStdoutErr runs fn and returns its stdout, its stderr and its error.
func captureStdoutErr(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	var err error
	var out string
	errOut := captureStderr(t, func() {
		out = captureStdout(t, func() { err = fn() })
	})
	return out, errOut, err
}

// The capture keeps every write, however late, and does not stall a writer
// that prints more than a pipe holds. It used to keep the first write only.
func TestCaptureKeepsEveryWrite(t *testing.T) {
	big := strings.Repeat("x", 256<<10)
	got := captureStderr(t, func() {
		os.Stderr.WriteString("first\n")
		// Long enough for a reader that stops after one Read to have
		// returned with the first line only.
		time.Sleep(20 * time.Millisecond)
		os.Stderr.WriteString("second\n")
		os.Stderr.WriteString(big)
	})
	if !strings.HasPrefix(got, "first\nsecond\n") || len(got) != len("first\nsecond\n")+len(big) {
		t.Fatalf("captured %d bytes starting %q; want both lines and the %d bytes after them", len(got), got[:min(len(got), 20)], len(big))
	}
	if out := captureStdout(t, func() { os.Stdout.WriteString("a\n"); os.Stdout.WriteString("b\n") }); out != "a\nb\n" {
		t.Fatalf("stdout captured %q", out)
	}
}
