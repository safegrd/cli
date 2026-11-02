package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeAPI is a remote server for a test that grants no more than the real
// one: a request without the bearer token it was given is answered 401, a
// route it was not given 404, and every request it answered is kept for the
// test to look at.
type fakeAPI struct {
	srv    *httptest.Server
	tokens map[string]bool
	routes map[string]http.HandlerFunc

	mu    sync.Mutex
	calls []apiCall
}

// apiCall is one request the fake answered.
type apiCall struct {
	Method, Path, Query, Auth string
	Body                      []byte
}

// newFakeAPI starts a fake answering routes, keyed "METHOD /path" or
// "/path" for any method. An exact method match wins. A key that starts
// "public " is a route the real server answers without a token, such as
// "public GET /api/v1/plans".
func newFakeAPI(t *testing.T, token string, routes map[string]http.HandlerFunc) *fakeAPI {
	t.Helper()
	f := &fakeAPI{tokens: map[string]bool{token: true}, routes: routes}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// newFakeAPITLS is newFakeAPI over HTTPS; its client is f.srv.Client().
func newFakeAPITLS(t *testing.T, token string, routes map[string]http.HandlerFunc) *fakeAPI {
	t.Helper()
	f := &fakeAPI{tokens: map[string]bool{token: true}, routes: routes}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) URL() string { return f.srv.URL }

// accept adds a token the fake answers, as a node token minted during the
// test. Call it before the request that uses it.
func (f *fakeAPI) accept(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[token] = true
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	h, ok := f.routes["public "+r.Method+" "+r.URL.Path]
	if !ok {
		auth := r.Header.Get("Authorization")
		f.mu.Lock()
		authorized := strings.HasPrefix(auth, "Bearer ") && f.tokens[strings.TrimPrefix(auth, "Bearer ")]
		f.mu.Unlock()
		if !authorized {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		h, ok = f.routes[r.Method+" "+r.URL.Path]
		if !ok {
			h, ok = f.routes[r.URL.Path]
		}
	}
	if !ok {
		http.Error(w, `{"error":"no such route"}`, http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	f.mu.Lock()
	f.calls = append(f.calls, apiCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
		Auth: r.Header.Get("Authorization"), Body: body})
	f.mu.Unlock()
	h(w, r)
}

// Calls returns the requests answered on path, in order.
func (f *fakeAPI) Calls(path string) []apiCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []apiCall
	for _, c := range f.calls {
		if c.Path == path {
			out = append(out, c)
		}
	}
	return out
}

// jsonReply answers every request with status and body.
func jsonReply(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// The fake refuses what the real server refuses: no token, a wrong one, a
// route it does not serve.
func TestTheFakeAPIRefusesWhatTheRemoteServerWould(t *testing.T) {
	f := newFakeAPI(t, "sg_tok_1", map[string]http.HandlerFunc{
		"GET /ok":           jsonReply(http.StatusOK, `{}`),
		"public GET /plans": jsonReply(http.StatusOK, `{}`),
	})
	for _, c := range []struct {
		path, token string
		want        int
	}{{"/ok", "sg_tok_1", 200}, {"/ok", "", 401}, {"/ok", "sg_tok_2", 401}, {"/other", "sg_tok_1", 404}, {"/plans", "", 200}} {
		req, err := http.NewRequest(http.MethodGet, f.URL()+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s with %q: %d, want %d", c.path, c.token, resp.StatusCode, c.want)
		}
	}
	if n := len(f.Calls("/ok")); n != 1 {
		t.Errorf("kept %d calls to /ok, want the one it answered", n)
	}
}
