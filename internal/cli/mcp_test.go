package cli

import (
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

// The local MCP's restore ran `safegrd restore --target postgres://user:pass@…`,
// so the password sat in ps for the restore and the agent read the warning
// about it. The URL goes through the environment instead.
func TestTheLocalMCPRestoreKeepsTheURLOutOfTheCommandLine(t *testing.T) {
	url := "postgres://app:secret@db:5432/app_restored"
	argv, env := targetToEnv([]string{"restore", "--snapshot", "snap-1", "--target", url})
	if slices.ContainsFunc(argv, func(a string) bool { return strings.Contains(a, "secret") }) {
		t.Errorf("the password is on the command line: %v", argv)
	}
	if !slices.Equal(argv, []string{"restore", "--snapshot", "snap-1", "--target", "env:SAFEGRD_MCP_TARGET"}) ||
		!slices.Equal(env, []string{"SAFEGRD_MCP_TARGET=" + url}) {
		t.Errorf("argv %v, env %v", argv, env)
	}
	if argv, env := targetToEnv([]string{"restore", "--snapshot", "snap-1", "--target-dir", "/restore"}); env != nil || argv[4] != "/restore" {
		t.Errorf("a directory restore changed: %v %v", argv, env)
	}
}

// Reading rows out of a backup (verify --query) is for a person. No tool
// offers an argument that would carry a query.
func TestNoLocalMCPToolTakesAQuery(t *testing.T) {
	for name := range localArgDescriptions {
		if strings.Contains(name, "query") || strings.Contains(name, "sql") {
			t.Errorf("the local MCP takes %q", name)
		}
	}
}

// Stdin's end of file waits for the requests read before it, and a request
// the client cancelled is not waited for.
func TestTheLocalMCPHoldsEndOfFileUntilRequestsAreAnswered(t *testing.T) {
	in := io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/call"}` + "\n" + `{"jsonrpc":"2.0","id":"x","method":"tools/call"}`))
	var out strings.Builder
	s := newAnsweringStdio(in, &out, nil)
	r, w := answeringReader{s}, answeringWriter{s}
	if _, err := io.ReadAll(io.LimitReader(r, int64(len(`{"jsonrpc":"2.0","id":7,"method":"tools/call"}`)+1+len(`{"jsonrpc":"2.0","id":"x","method":"tools/call"}`)))); err != nil {
		t.Fatal(err)
	}
	eof := make(chan error, 1)
	go func() {
		_, err := r.Read(make([]byte, 16))
		eof <- err
	}()
	select {
	case err := <-eof:
		t.Fatalf("end of file before any answer: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := w.Write([]byte(`{"jsonrpc":"2.0","id":7.0,"result":{}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-eof:
		t.Fatalf("end of file with request x unanswered: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	s.mu.Lock()
	s.noteRead([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"x"}}`))
	s.mu.Unlock()
	select {
	case err := <-eof:
		if err != io.EOF {
			t.Fatalf("got %v, want end of file", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still waiting after every request was answered or cancelled")
	}
}
