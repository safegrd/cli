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
	"github.com/safegrd/cli/pkg/model"
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
	// keep, when set, is the lock the server grants whatever is asked, as
	// the plan's range does; asked records each lock the host asked for.
	keep  time.Time
	asked []time.Time
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
		var req struct {
			RetainUntil time.Time `json:"retain_until"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.parts, f.grants = map[int32][]byte{}, map[int32]int64{}
		f.asked = append(f.asked, req.RetainUntil)
		keep := req.RetainUntil
		if !f.keep.IsZero() {
			keep = f.keep
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"upload_id": "hup_1", "part_size": 1 << 20, "retain_until": keep})
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
		_ = json.NewEncoder(w).Encode(map[string]any{"storage_uri": "hosted://snapshots/node-1/snap-1.safegrd", "bytes": len(all)})
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

// The lock a hosted backup reports is the one the remote server set, not the
// one the host asked for: the plan bounds it, and a manifest, a record and a
// printed line that named the asked date would claim a lock nobody set.
func TestAHostedBackupReportsTheLockTheServerKept(t *testing.T) {
	f := newFakeHosted(t)
	p := f.provider(t)
	asked := time.Now().UTC().AddDate(0, 0, 30).Truncate(time.Second)
	f.keep = time.Now().UTC().AddDate(0, 0, 14).Truncate(time.Second)
	if _, err := p.UploadSnapshot(context.Background(), "snap-1", bytes.NewReader(make([]byte, 100)), -1, asked); err != nil {
		t.Fatal(err)
	}
	meta := &model.SnapshotMetadata{SnapshotID: "snap-1", WORMRetentionUntil: asked}
	if err := p.UploadMetadata(context.Background(), "snap-1", meta); err != nil {
		t.Fatal(err)
	}
	if !meta.WORMRetentionUntil.Equal(f.keep) {
		t.Errorf("the snapshot reports a lock until %s, the server kept it until %s", meta.WORMRetentionUntil, f.keep)
	}
	if len(f.asked) != 2 || !f.asked[1].Equal(f.keep) {
		t.Errorf("the manifest asked for a lock other than the one its ciphertext has: %v", f.asked)
	}
}

// A part the bucket refused was reported with the raw body, so the console
// showed the reason as the XML declaration and nothing else.
func TestBucketErrorReadsS3sXML(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Error>
    <Code>InternalError</Code>
    <Message>An internal error occurred.  Please retry your upload.</Message>
</Error>`)
	got := bucketError("500 Internal Server Error", body).Error()
	want := "the bucket answered 500 Internal Server Error: InternalError: An internal error occurred.  Please retry your upload."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := bucketError("503 Service Unavailable", []byte("slow down\nmore")).Error(); got != "the bucket answered 503 Service Unavailable: slow down" {
		t.Errorf("a plain body gave %q", got)
	}
	if got := bucketError("500 Internal Server Error", nil).Error(); got != "the bucket answered 500 Internal Server Error" {
		t.Errorf("an empty body gave %q", got)
	}
}

// Every command on hosted storage starts by asking the remote server where
// the organization stands. That first call failed the command on one 429
// ("hosted storage: Rate limit exceeded"), while every later call waited it
// out, so a restore started while another host on the same address was busy
// stopped before it read a byte.
func TestTheFirstHostedCallWaitsOutARateLimit(t *testing.T) {
	var asked int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&asked, 1) <= 2 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Rate limit exceeded. Please try again later."})
			return
		}
		_ = json.NewEncoder(w).Encode(hostedInfo{WORMMode: "COMPLIANCE", RetentionDays: 14, PartSize: 5 << 20})
	}))
	defer srv.Close()
	saved, savedPause := http.DefaultTransport, hostedRetryPause
	http.DefaultTransport, hostedRetryPause = srv.Client().Transport, time.Millisecond
	defer func() { http.DefaultTransport, hostedRetryPause = saved, savedPause }()

	cfg := &config.CLIConfig{ServerURL: srv.URL, NodeID: "node-1", ServerToken: "sg_tok_1"}
	st := &config.StorageConfig{Type: config.StorageTypeHosted}
	info, err := resolveHostedStorage(context.Background(), cfg, st, false)
	if err != nil {
		t.Fatalf("two 429s then an answer: %v", err)
	}
	if info.RetentionDays != 14 || st.RetentionDays != 14 || atomic.LoadInt32(&asked) != 3 {
		t.Errorf("retention %d (config %d) after %d requests, want 14 after 3", info.RetentionDays, st.RetentionDays, asked)
	}
}

// A 429 that is a quota refusal is the answer, not a pause.
func TestAQuotaRefusalIsNotRetried(t *testing.T) {
	var asked int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&asked, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "This organization has downloaded its allowance this month."})
	}))
	defer srv.Close()
	c := &hostedClient{base: srv.URL, token: "t", api: srv.Client()}
	err := c.callRetry(context.Background(), http.MethodGet, "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "downloaded") || atomic.LoadInt32(&asked) != 1 {
		t.Errorf("a quota 429 was retried or lost: %v after %d requests", err, asked)
	}
}
