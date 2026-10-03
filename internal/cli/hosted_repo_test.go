package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/repo/sink"
)

// fakeRepoHosted plays the remote server's repository endpoints and the
// bucket behind them, counting what the host asks for.
type fakeRepoHosted struct {
	srv *httptest.Server
	mu  sync.Mutex
	// downloads counts /repo/download calls; puts and gets count bucket
	// requests.
	downloads, puts, gets int
	objects               map[string][]byte
	// putScript and getScript are what the bucket does with each request
	// in turn: "ok", "503", "drop" (read the body, keep it, then close the
	// connection without answering) or "lose" (close without keeping it).
	putScript, getScript []string
	// uploadedScript is the status /uploaded answers with, in turn.
	uploadedScript []int
	uploadedCalls  int
}

func newFakeRepoHosted(t *testing.T) *fakeRepoHosted {
	f := &fakeRepoHosted{objects: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRepoHosted) next(script *[]string) string {
	if len(*script) == 0 {
		return "ok"
	}
	s := (*script)[0]
	*script = (*script)[1:]
	return s
}

func drop(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		conn.Close()
	}
}

func (f *fakeRepoHosted) serve(w http.ResponseWriter, r *http.Request) {
	const api = "/api/v1/nodes/node-1/hosted"
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == api+"/repo/download":
		var req struct {
			Keys []string `json:"keys"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.downloads++
		var objs []map[string]any
		for _, k := range req.Keys {
			objs = append(objs, map[string]any{"key": k, "url": f.srv.URL + "/bucket/get?k=" + k, "size": len(f.objects[k]),
				"expires_at": time.Now().Add(time.Hour)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"objects": objs})
	case strings.HasPrefix(r.URL.Path, api+"/repo/epochs/") && strings.HasSuffix(r.URL.Path, "/uploaded"):
		f.uploadedCalls++
		status := http.StatusOK
		if len(f.uploadedScript) > 0 {
			status, f.uploadedScript = f.uploadedScript[0], f.uploadedScript[1:]
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Hosted storage does not hold the key yet"})
	case r.URL.Path == "/bucket/get":
		f.gets++
		if f.next(&f.getScript) == "503" {
			http.Error(w, "SlowDown", http.StatusServiceUnavailable)
			return
		}
		b, ok := f.objects[r.URL.Query().Get("k")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, "", time.Time{}, strings.NewReader(string(b)))
	case r.URL.Path == "/bucket/put":
		f.puts++
		body, _ := io.ReadAll(r.Body)
		switch f.next(&f.putScript) {
		case "503":
			http.Error(w, "InternalError", http.StatusServiceUnavailable)
		case "drop":
			f.objects[r.URL.Query().Get("k")] = body
			drop(w)
		case "lose":
			drop(w)
		default:
			f.objects[r.URL.Query().Get("k")] = body
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeRepoHosted) repo() *hostedRepo {
	return &hostedRepo{
		c:        &hostedClient{base: f.srv.URL + "/api/v1/nodes/node-1/hosted", token: "t", api: f.srv.Client(), bucket: f.srv.Client()},
		node:     "node-1",
		prefixes: map[string]string{},
		gets:     map[string]signedGet{},
	}
}

func quickBackoff(t *testing.T) {
	t.Helper()
	old := hostedTransferBackoff
	hostedTransferBackoff = time.Millisecond
	t.Cleanup(func() { hostedTransferBackoff = old })
}

// Every signed download counts against the day's budget, so concurrent
// reads of one pack, as a restore makes them, ask the remote server once.
func TestConcurrentReadsOfOnePackSignItOnce(t *testing.T) {
	f := newFakeRepoHosted(t)
	const key = "orgs/o/safegrd/repo/node-1/s/e202610-00000000/packs/" + "0123456789abcdef0123456789abcdef"
	body := []byte(strings.Repeat("0123456789", 100))
	f.objects[key] = body
	h := f.repo()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := h.GetRange(context.Background(), key, int64(i*10), 10)
			if err != nil {
				errs <- err
				return
			}
			if string(got) != string(body[i*10:i*10+10]) {
				errs <- fmt.Errorf("range %d read %q", i, got)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if f.downloads != 1 {
		t.Fatalf("16 concurrent reads of one key signed it %d times", f.downloads)
	}
}

func TestADownloadIsTriedAgainAfterABucketFailure(t *testing.T) {
	quickBackoff(t)
	f := newFakeRepoHosted(t)
	f.objects["k"] = []byte("payload")
	f.getScript = []string{"503"}
	got, err := f.repo().Get(context.Background(), "k")
	if err != nil || string(got) != "payload" {
		t.Fatalf("after one 503: %q %v", got, err)
	}
	if f.gets != 2 {
		t.Fatalf("%d GETs", f.gets)
	}
}

func putSlot(f *fakeRepoHosted, key string) sink.Slot {
	return sink.Slot{Kind: sink.KindPack, Key: key, EpochID: "e202610-00000000", URL: f.srv.URL + "/bucket/put?k=" + key,
		Headers: map[string]string{"Content-Length": "7", "Content-MD5": "x"}}
}

func TestAPutIsTriedAgainAfterABucketFailure(t *testing.T) {
	quickBackoff(t)
	f := newFakeRepoHosted(t)
	f.putScript = []string{"503"}
	if err := f.repo().Put(context.Background(), putSlot(f, "k"), []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if f.puts != 2 || string(f.objects["k"]) != "payload" || f.uploadedCalls != 0 {
		t.Fatalf("%d PUTs, object %q, %d probes", f.puts, f.objects["k"], f.uploadedCalls)
	}
}

// A PUT whose connection dropped may have delivered the object. The remote
// server is asked; when the bucket holds it, it is not sent again, because a
// second version would be kept and billed.
func TestADroppedPutThatLandedIsNotSentAgain(t *testing.T) {
	quickBackoff(t)
	f := newFakeRepoHosted(t)
	f.putScript = []string{"drop"}
	f.uploadedScript = []int{http.StatusOK}
	if err := f.repo().Put(context.Background(), putSlot(f, "k"), []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if f.puts != 1 || f.uploadedCalls != 1 || string(f.objects["k"]) != "payload" {
		t.Fatalf("%d PUTs, %d probes, object %q", f.puts, f.uploadedCalls, f.objects["k"])
	}
}

func TestADroppedPutThatDidNotLandIsSentAgain(t *testing.T) {
	quickBackoff(t)
	f := newFakeRepoHosted(t)
	f.putScript = []string{"lose"}
	f.uploadedScript = []int{http.StatusConflict}
	if err := f.repo().Put(context.Background(), putSlot(f, "k"), []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if f.puts != 2 || f.uploadedCalls != 1 || string(f.objects["k"]) != "payload" {
		t.Fatalf("%d PUTs, %d probes, object %q", f.puts, f.uploadedCalls, f.objects["k"])
	}
}

// A refusal is final: the bucket said no, and asking again changes nothing.
func TestARefusedPutIsNotTriedAgain(t *testing.T) {
	quickBackoff(t)
	f := newFakeRepoHosted(t)
	f.putScript = []string{"403", "403"}
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bucket/put" {
			f.mu.Lock()
			f.puts++
			f.mu.Unlock()
			http.Error(w, "SignatureDoesNotMatch", http.StatusForbidden)
			return
		}
		f.serve(w, r)
	})
	err := f.repo().Put(context.Background(), putSlot(f, "k"), []byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a 403: %v", err)
	}
	if f.puts != 1 {
		t.Fatalf("a refused PUT was sent %d times", f.puts)
	}
}
