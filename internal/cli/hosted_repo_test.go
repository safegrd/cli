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

	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/format"
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
	// uploadedScript is the status /uploaded answers with, in turn;
	// epochClosed makes a 409 the closed-epoch refusal instead of "not
	// held yet".
	uploadedScript []int
	uploadedCalls  int
	epochClosed    bool
	// epochs is what GET /repo/epochs answers; epochLists and objectLists
	// count the listings.
	epochs                  []map[string]any
	epochLists, objectLists int
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
			// As the remote server does: a key it holds no object for is
			// refused, and nothing in the request is signed.
			if _, ok := f.objects[k]; !ok {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "No such object in hosted storage: " + k})
				return
			}
			objs = append(objs, map[string]any{"key": k, "url": f.srv.URL + "/bucket/get?k=" + k, "size": len(f.objects[k]),
				"expires_at": time.Now().Add(time.Hour)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"objects": objs})
	case r.URL.Path == api+"/repo/epochs" && r.Method == http.MethodGet:
		f.epochLists++
		_ = json.NewEncoder(w).Encode(map[string]any{"epochs": f.epochs})
	case strings.HasPrefix(r.URL.Path, api+"/repo/epochs/") && strings.HasSuffix(r.URL.Path, "/objects"):
		f.objectLists++
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, api+"/repo/epochs/"), "/objects")
		var prefix string
		for _, e := range f.epochs {
			if strings.Contains(string(e["epoch"].(json.RawMessage)), `"`+id+`"`) {
				prefix = e["prefix"].(string) + "/" + r.URL.Query().Get("sub") + "/"
			}
		}
		objs := []map[string]any{}
		for k, b := range f.objects {
			if prefix != "" && strings.HasPrefix(k, prefix) {
				objs = append(objs, map[string]any{"key": k, "size": len(b)})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"objects": objs})
	case strings.HasPrefix(r.URL.Path, api+"/repo/epochs/") && strings.HasSuffix(r.URL.Path, "/uploaded"):
		f.uploadedCalls++
		status := http.StatusOK
		if len(f.uploadedScript) > 0 {
			status, f.uploadedScript = f.uploadedScript[0], f.uploadedScript[1:]
		}
		w.WriteHeader(status)
		msg := "Hosted storage does not hold the key yet"
		if f.epochClosed {
			msg = "Epoch e202610-00000000 is closed; ask for the current epoch again."
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
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
		uris:     map[string]string{},
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

// A bucket that is busy answers 503 for a while. Four attempts gave up after
// 7 seconds and failed the drill reading it; the read now outlasts six.
func TestADownloadOutlastsABusyBucket(t *testing.T) {
	quickBackoff(t)
	f := newFakeRepoHosted(t)
	f.objects["k"] = []byte("payload")
	f.getScript = []string{"503", "503", "503", "503", "503", "503"}
	got, err := f.repo().Get(context.Background(), "k")
	if err != nil || string(got) != "payload" {
		t.Fatalf("after six 503s: %q %v", got, err)
	}
	if f.gets != 7 {
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

// A dropped PUT whose epoch closed meanwhile is not sent again: the signed
// URL may still be honoured, and the object would land in a closed epoch.
func TestADroppedPutIntoAClosedEpochIsNotSentAgain(t *testing.T) {
	quickBackoff(t)
	f := newFakeRepoHosted(t)
	f.putScript = []string{"lose"}
	f.uploadedScript = []int{http.StatusConflict}
	f.epochClosed = true
	err := f.repo().Put(context.Background(), putSlot(f, "k"), []byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("a closed epoch: %v", err)
	}
	if f.puts != 1 || f.uploadedCalls != 1 {
		t.Fatalf("%d PUTs, %d probes", f.puts, f.uploadedCalls)
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

// addEpoch files an epoch of surface under the fake, with a sidecar for
// each snapshot id, and returns its prefix.
func (f *fakeRepoHosted) addEpoch(t *testing.T, surface, epochID string, snapshots ...string) string {
	t.Helper()
	opened := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	e := format.Epoch{Format: format.FormatName, Version: format.Version, EpochID: epochID, SurfaceID: surface,
		OpenedAt: opened, PlannedEnd: opened.AddDate(0, 1, 0), Reason: format.ReasonFull, OpeningTier: format.TierBase,
		OpeningRetainUntil: opened.AddDate(0, 3, 0), LaterRetainUntil: opened.AddDate(0, 2, 0), Recipient: "age1x",
		Chunker: format.ChunkerParams{Algorithm: format.ChunkerAlgorithm, Min: 1, Avg: 2, Max: 3}, PackTargetBytes: 1}
	raw, err := format.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "orgs/o/safegrd/repo/node-1/" + surface + "/" + epochID
	f.epochs = append(f.epochs, map[string]any{"epoch": json.RawMessage(raw), "prefix": prefix, "node_id": "node-1", "surface_id": surface})
	for _, id := range snapshots {
		key, _ := sink.ObjectKey(prefix, sink.KindMeta, id)
		f.objects[key] = []byte(`{"snapshot_id":"` + id + `"}`)
	}
	return prefix
}

// Listing 14 snapshots read their sidecars one at a time, each a signing
// request and a bucket read in turn, and asked for the epochs once per
// surface: from a host far from the bucket it took doctor's whole 10
// seconds. One epochs listing, one signing request, a listing per epoch.
func TestListingSnapshotsSignsTheirSidecarsInOneRequest(t *testing.T) {
	f := newFakeRepoHosted(t)
	var want []string
	for i, surface := range []string{"orders", "users"} {
		var ids []string
		for j := 0; j < 7; j++ {
			ids = append(ids, fmt.Sprintf("snap-202610%02d-000000-%06x", j+1, i*16+j))
		}
		f.addEpoch(t, surface, fmt.Sprintf("e202610-0000000%d", i+1), ids...)
		want = append(want, ids...)
	}
	rows, err := repoSnapshots(context.Background(), f.repo())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.Meta.SnapshotID)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("listed %v, want %v", got, want)
	}
	if f.epochLists != 1 || f.objectLists != 2 || f.downloads != 1 || f.gets != 14 {
		t.Fatalf("asked for the epochs %d times, listed %d epochs, signed %d times, read %d objects; want 1, 2, 1, 14",
			f.epochLists, f.objectLists, f.downloads, f.gets)
	}
}

// list read the sidecar of every repository snapshot in the organization's
// hosted storage, thousands of objects for an organization a year old, to
// print rows the remote server's record already held. A snapshot the record
// has is not read; one it lacks still is.
func TestListingTakesRecordedSnapshotsFromTheRecord(t *testing.T) {
	f := newFakeRepoHosted(t)
	var ids []string
	for j := 0; j < 7; j++ {
		ids = append(ids, fmt.Sprintf("snap-202610%02d-000000-%06x", j+1, j))
	}
	f.addEpoch(t, "orders", "e202610-00000001", ids...)
	recorded := map[string]*model.SnapshotMetadata{}
	for _, id := range ids[:6] {
		recorded[id] = &model.SnapshotMetadata{SnapshotID: id, NodeID: "node-1", Status: model.SnapshotStatusVerified}
	}
	rows, err := repoSnapshotsKnown(context.Background(), f.repo(), func(id string) *model.SnapshotMetadata { return recorded[id] })
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 7 {
		t.Fatalf("listed %d snapshots, want 7", len(rows))
	}
	for i, r := range rows {
		if r.Meta == nil || r.Meta.SnapshotID != ids[i] {
			t.Fatalf("row %d is %+v, want %s", i, r.Meta, ids[i])
		}
		if i < 6 && r.Meta.Status != model.SnapshotStatusVerified {
			t.Errorf("row %d is described by its sidecar, not the record", i)
		}
	}
	if f.gets != 1 {
		t.Fatalf("read %d sidecars; want 1, for the one snapshot the record lacks", f.gets)
	}
}

// A drill on SafeGrd found its snapshot by reading its sidecar from every
// epoch of every surface in the organization, and each miss was a signing
// request the remote server answered with 404: hundreds a drill on
// production. The epoch the remote server recorded is tried first.
func TestFindingASnapshotTriesTheRecordedEpochFirst(t *testing.T) {
	f := newFakeRepoHosted(t)
	for i := 0; i < 5; i++ {
		f.addEpoch(t, fmt.Sprintf("s%d", i), fmt.Sprintf("e202610-0000000%d", i), fmt.Sprintf("snap-20261001-000000-00000%d", i))
	}
	rs, err := findRepoSnapshot(context.Background(), f.repo(), "snap-20261001-000000-000004", "e202610-00000004")
	if err != nil || rs == nil {
		t.Fatalf("found %v, %v", rs, err)
	}
	if rs.SurfaceID != "s4" || f.downloads != 1 || f.gets != 1 {
		t.Fatalf("found it in %s after %d signing requests and %d reads; want s4, 1, 1", rs.SurfaceID, f.downloads, f.gets)
	}
	// Without a record every epoch is still searched, and it is found.
	f.downloads, f.gets = 0, 0
	if rs, err := findRepoSnapshot(context.Background(), f.repo(), "snap-20261001-000000-000004", ""); err != nil || rs == nil || rs.SurfaceID != "s4" {
		t.Fatalf("without the recorded epoch: %v, %v", rs, err)
	}
}

// doctor counts the snapshots and reads one sidecar to show the bucket
// reads, where it read every sidecar in the organization.
func TestDoctorsCountReadsOneSidecar(t *testing.T) {
	f := newFakeRepoHosted(t)
	for i, surface := range []string{"orders", "users"} {
		var ids []string
		for j := 0; j < 7; j++ {
			ids = append(ids, fmt.Sprintf("snap-202610%02d-000000-%06x", j+1, i*16+j))
		}
		f.addEpoch(t, surface, fmt.Sprintf("e202610-0000000%d", i+1), ids...)
	}
	h := f.repo()
	_, ids, err := repoSnapshotIDs(context.Background(), h)
	if err != nil || len(ids) != 14 {
		t.Fatalf("listed %d snapshots: %v", len(ids), err)
	}
	if f.downloads != 0 || f.gets != 0 {
		t.Fatalf("listing alone signed %d and read %d objects", f.downloads, f.gets)
	}
}
