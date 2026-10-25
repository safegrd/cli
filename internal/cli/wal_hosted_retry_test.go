package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A WAL segment's upload is retried while the bucket answers 503 (MinIO's
// "please reduce your request rate", S3's SlowDown) and is not retried for
// an answer that will not change.
func TestAWALSegmentUploadOutlastsABusyBucket(t *testing.T) {
	for _, c := range []struct {
		name     string
		answers  []int
		wantPuts int32
		wantErr  string
	}{
		{"busy twice, then written", []int{503, 503, 200}, 3, ""},
		{"refused", []int{400}, 1, "400"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var puts, uploaded int32
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/wal/sign":
					_ = json.NewEncoder(w).Encode(map[string]any{"objects": []map[string]any{{"key": "seg", "url": srv.URL + "/bucket/seg"}}})
				case r.URL.Path == "/bucket/seg" && r.Method == http.MethodPut:
					n := atomic.AddInt32(&puts, 1)
					code := c.answers[min(int(n), len(c.answers))-1]
					w.WriteHeader(code)
					if code == 503 {
						_, _ = w.Write([]byte(`<Error><Code>RequestTimeout</Code><Message>A timeout occurred while trying to lock a resource, please reduce your request rate</Message></Error>`))
					}
				case r.URL.Path == "/wal/uploaded":
					atomic.AddInt32(&uploaded, 1)
					_, _ = w.Write([]byte(`{}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			saved := hostedRetryPause
			hostedRetryPause = time.Millisecond
			defer func() { hostedRetryPause = saved }()

			h := &walHostedStore{p: &hostedProvider{client: &hostedClient{base: srv.URL, token: "t", api: srv.Client(), bucket: srv.Client()}}}
			_, err := h.putSmall(context.Background(), "seg", []byte("wal bytes"), "")
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("upload: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("upload: %v, want an error naming %s", err, c.wantErr)
			}
			if got := atomic.LoadInt32(&puts); got != c.wantPuts {
				t.Errorf("%d uploads, want %d", got, c.wantPuts)
			}
			if want := int32(map[bool]int{true: 1, false: 0}[c.wantErr == ""]); atomic.LoadInt32(&uploaded) != want {
				t.Errorf("the server was told of the segment %d times, want %d", uploaded, want)
			}
		})
	}
}
