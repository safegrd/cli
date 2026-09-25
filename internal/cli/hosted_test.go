package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// fakeHosted plays the remote server and the bucket behind it: it grants part
// URLs that point back at itself, checks each PUT's length against the grant
// (as a signed content-length would), and assembles the object on completion.
type fakeHosted struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	parts    map[int32][]byte
	grants   map[int32]int64
	objects  map[string][]byte
	aborted  int
	inFlight int32
	maxIn    int32
	// failPuts makes the first n part PUTs fail with 403, as an expired URL would.
	failPuts int32
}

func newFakeHosted(t *testing.T) *fakeHosted {
	f := &fakeHosted{t: t, parts: map[int32][]byte{}, grants: map[int32]int64{}, objects: map[string][]byte{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHosted) serve(w http.ResponseWriter, r *http.Request) {
	const api = "/api/v1/nodes/node-1/hosted"
	switch {
	case r.URL.Path == "/bucket/part":
		var n int32
		fmt.Sscan(r.URL.Query().Get("n"), &n)
		if atomic.AddInt32(&f.failPuts, -1) >= 0 {
			http.Error(w, "Request has expired", http.StatusForbidden)
			return
		}
		cur := atomic.AddInt32(&f.inFlight, 1)
		defer atomic.AddInt32(&f.inFlight, -1)
		for {
			m := atomic.LoadInt32(&f.maxIn)
			if cur <= m || atomic.CompareAndSwapInt32(&f.maxIn, m, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		if int64(len(body)) != f.grants[n] || r.ContentLength != f.grants[n] {
			http.Error(w, "SignatureDoesNotMatch", http.StatusForbidden)
			return
		}
		f.parts[n] = body
	case r.URL.Path == "/bucket/object":
		f.mu.Lock()
		b, ok := f.objects[r.URL.Query().Get("p")]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	case r.Header.Get("Authorization") != "Bearer sg_tok_1":
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
	case r.URL.Path == api+"/uploads":
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.parts, f.grants = map[int32][]byte{}, map[int32]int64{}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"upload_id": "hup_1", "part_size": 1 << 20})
	case r.URL.Path == api+"/uploads/hup_1/parts":
		var req struct {
			Parts []struct {
				PartNumber int32 `json:"part_number"`
				Size       int64 `json:"size"`
			} `json:"parts"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var out []map[string]any
		f.mu.Lock()
		for _, p := range req.Parts {
			f.grants[p.PartNumber] = p.Size
			out = append(out, map[string]any{"part_number": p.PartNumber, "size": p.Size,
				"url": fmt.Sprintf("%s/bucket/part?n=%d", f.srv.URL, p.PartNumber)})
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"parts": out})
	case r.URL.Path == api+"/uploads/hup_1/complete":
		f.mu.Lock()
		var all []byte
		for n := int32(1); ; n++ {
			b, ok := f.parts[n]
			if !ok {
				break
			}
			all = append(all, b...)
		}
		f.objects["node-1/snap-1.safegrd"] = all
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"storage_uri": "s3://hosted/orgs/o/safegrd/snapshots/node-1/snap-1.safegrd", "bytes": len(all)})
	case r.URL.Path == api+"/uploads/hup_1/abort":
		f.mu.Lock()
		f.aborted++
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"aborted"}`))
	case r.URL.Path == api+"/downloads":
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		_, ok := f.objects[req["path"]]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"No such object"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"url": f.srv.URL + "/bucket/object?p=" + req["path"]})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeHosted) provider(t *testing.T) *hostedProvider {
	t.Helper()
	cfg := &config.CLIConfig{ServerURL: f.srv.URL, NodeID: "node-1", ServerToken: "sg_tok_1"}
	c, err := newHostedClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.api, c.bucket = f.srv.Client(), f.srv.Client()
	return &hostedProvider{client: c, nodeID: "node-1", retentionDays: 7}
}

func TestHostedUploadStreamsPartsInParallelAndRoundTrips(t *testing.T) {
	f := newFakeHosted(t)
	p := f.provider(t)
	data := make([]byte, 5<<20+12345) // five full parts and a short one
	_, _ = rand.Read(data)
	uri, err := p.UploadSnapshot(context.Background(), "snap-1", bytes.NewReader(data), -1, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(uri, "node-1/snap-1.safegrd") {
		t.Errorf("storage uri %q", uri)
	}
	if got := atomic.LoadInt32(&f.maxIn); got < 2 {
		t.Errorf("at most %d part uploads were in flight at once; the upload should be parallel", got)
	}
	rc, err := p.DownloadSnapshot(context.Background(), "snap-1")
	if err != nil {
		t.Fatal(err)
	}
	back, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(back, data) {
		t.Fatalf("round trip changed the bytes: %d in, %d out", len(data), len(back))
	}
}

func TestHostedUploadRetriesAnExpiredURLWithAFreshOne(t *testing.T) {
	f := newFakeHosted(t)
	f.failPuts = 2
	p := f.provider(t)
	if _, err := p.UploadSnapshot(context.Background(), "snap-1", bytes.NewReader(make([]byte, 100)), -1, time.Time{}); err != nil {
		t.Fatalf("two expired URLs in a row should be retried: %v", err)
	}
}

type brokenReader struct{ n int }

func (b *brokenReader) Read(p []byte) (int, error) {
	if b.n <= 0 {
		return 0, errors.New("pg_dump exited 1")
	}
	k := len(p)
	if k > b.n {
		k = b.n
	}
	b.n -= k
	return k, nil
}

func TestAFailedStreamAbortsTheUpload(t *testing.T) {
	// A dump that dies halfway must not leave a half-written object that
	// looks like a backup, nor unfinished parts that are billed.
	f := newFakeHosted(t)
	p := f.provider(t)
	_, err := p.UploadSnapshot(context.Background(), "snap-1", &brokenReader{n: 3 << 20}, -1, time.Time{})
	if err == nil || !strings.Contains(err.Error(), "pg_dump exited 1") {
		t.Fatalf("upload of a broken stream: %v", err)
	}
	if f.aborted != 1 || len(f.objects) != 0 {
		t.Errorf("aborted %d times, objects %d; want one abort and nothing stored", f.aborted, len(f.objects))
	}
}

func TestHostedDownloadFallsBackToTheFlatPrefix(t *testing.T) {
	f := newFakeHosted(t)
	f.objects["legacy.meta.json"] = []byte(`{"snapshot_id":"legacy"}`)
	p := f.provider(t)
	meta, err := p.DownloadMetadata(context.Background(), "legacy")
	if err != nil || meta.SnapshotID != "legacy" {
		t.Fatalf("flat metadata: %v %+v", err, meta)
	}
}

func TestHostedStorageNeverDeletes(t *testing.T) {
	f := newFakeHosted(t)
	if err := f.provider(t).DeleteSnapshot(context.Background(), "snap-1"); err == nil {
		t.Error("the hosted provider deleted a snapshot; no host may")
	}
}
