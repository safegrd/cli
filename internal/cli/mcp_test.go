package cli

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
// offers an argument that would carry a query, and every argument a tool
// offers is described. Read from the tools as a client lists them, so an
// argument added to a tool and nowhere else is seen.
func TestNoLocalMCPToolTakesAQuery(t *testing.T) {
	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	addLocalTools(server, "/nonexistent/safegrd")
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) < 5 {
		t.Fatalf("the local MCP lists %d tools", len(res.Tools))
	}
	args := 0
	for _, tool := range res.Tools {
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("%s: %v", tool.Name, err)
		}
		for name, p := range schema.Properties {
			args++
			if strings.Contains(name, "query") || strings.Contains(name, "sql") {
				t.Errorf("the local MCP tool %s takes %q", tool.Name, name)
			}
			if p.Description == "" {
				t.Errorf("the local MCP tool %s offers %q with no description", tool.Name, name)
			}
		}
	}
	if args == 0 {
		t.Fatal("no tool offers any argument, so nothing was checked")
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
	// The reader is waiting once it has made the channel it waits on; until
	// then it may still return. Waiting for that state, rather than for a
	// stretch of time, is what makes "no end of file yet" a fact.
	waiting := func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.idle != nil
	}
	for deadline := time.Now().Add(5 * time.Second); !waiting(); time.Sleep(time.Millisecond) {
		select {
		case err := <-eof:
			t.Fatalf("end of file before any answer: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the reader neither returned nor waited for the answers")
		}
	}
	pending := func() []string {
		s.mu.Lock()
		defer s.mu.Unlock()
		var ids []string
		for id := range s.pending {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		return ids
	}
	if got := pending(); !slices.Equal(got, []string{"7", "x"}) {
		t.Fatalf("waiting on %v, want both requests", got)
	}
	if _, err := w.Write([]byte(`{"jsonrpc":"2.0","id":7.0,"result":{}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	// Request x is still unanswered, so the reader is still waiting: its
	// channel is open and it has said nothing.
	s.mu.Lock()
	idle := s.idle
	s.mu.Unlock()
	if got := pending(); !slices.Equal(got, []string{"x"}) || idle == nil {
		t.Fatalf("after answering 7: waiting on %v (channel %v), want x", got, idle)
	}
	select {
	case <-idle:
		t.Fatal("the reader was released with request x unanswered")
	case err := <-eof:
		t.Fatalf("end of file with request x unanswered: %v", err)
	default:
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
