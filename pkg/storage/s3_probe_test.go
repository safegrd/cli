package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// A stand-in bucket that allows or denies the two kinds of delete, and
// records what it was asked.
func probeBucket(t *testing.T, allowDelete, allowVersions bool) (*S3StorageProvider, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		versioned := r.URL.Query().Get("versionId") != ""
		if (versioned && !allowVersions) || (!versioned && !allowDelete) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`))
			return
		}
		if !versioned {
			w.Header().Set("x-amz-delete-marker", "true")
			w.Header().Set("x-amz-version-id", "marker-1")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AWS_ACCESS_KEY_ID", "probe")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "probe")
	p, err := NewS3Storage(context.Background(), config.StorageConfig{
		Type: config.StorageTypeS3, Bucket: "b", Region: "us-east-1", Endpoint: srv.URL, Prefix: "safegrd",
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, &seen
}

func TestTheDeleteProbeReadsTheBucketsAnswer(t *testing.T) {
	for _, c := range []struct {
		name               string
		allowDel, allowVer bool
		wantDel, wantVer   bool
		wantMarker         bool
	}{
		{"denied", false, false, false, false, false},
		{"markers only", true, false, true, false, true},
		{"everything", true, true, true, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, seen := probeBucket(t, c.allowDel, c.allowVer)
			del, ver, marker, err := p.DeleteProbe(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if del != c.wantDel || ver != c.wantVer || (marker != "") != c.wantMarker {
				t.Errorf("DeleteProbe = %v %v %q, want %v %v marker=%v", del, ver, marker, c.wantDel, c.wantVer, c.wantMarker)
			}
			for _, req := range *seen {
				if req != "DELETE /b/safegrd/.safegrd-delete-probe?versionId=null&x-id=DeleteObject" &&
					req != "DELETE /b/safegrd/.safegrd-delete-probe?x-id=DeleteObject" &&
					req != "DELETE /b/safegrd/.safegrd-delete-probe?versionId=marker-1&x-id=DeleteObject" {
					t.Errorf("the probe asked for something other than its own key: %s", req)
				}
			}
		})
	}
}
