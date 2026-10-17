package storage

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// storage_class is set on the archive only: its manifest is read by every
// list and drill, and a cold class charges for each read.
func TestTheStorageClassIsSetOnTheArchiveOnly(t *testing.T) {
	var mu sync.Mutex
	classes := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			mu.Lock()
			classes[r.URL.Path] = r.Header.Get("X-Amz-Storage-Class")
			mu.Unlock()
			w.Header().Set("ETag", `"etag"`)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AWS_ACCESS_KEY_ID", "class")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "class")
	p, err := NewS3Storage(context.Background(), config.StorageConfig{
		Type: config.StorageTypeS3, Bucket: "b", Region: "us-east-1", Endpoint: srv.URL, Prefix: "safegrd",
		WORMMode: config.WORMModeNone, StorageClass: "standard_ia",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UploadSnapshot(context.Background(), "snap-class", bytes.NewReader([]byte("ciphertext")), 10, time.Time{}); err != nil {
		t.Fatalf("UploadSnapshot: %v", err)
	}
	if err := p.UploadMetadata(context.Background(), "snap-class", &model.SnapshotMetadata{SnapshotID: "snap-class"}); err != nil {
		t.Fatalf("UploadMetadata: %v", err)
	}
	var archive, manifest string
	for path, class := range classes {
		switch {
		case strings.HasSuffix(path, ".safegrd"):
			archive = class
		case strings.HasSuffix(path, ".meta.json"):
			manifest = class
		}
	}
	if archive != "STANDARD_IA" || manifest != "" {
		t.Errorf("archive class %q, manifest class %q; want STANDARD_IA and none", archive, manifest)
	}
}

func TestAStorageClassADrillCannotReadIsRefused(t *testing.T) {
	for class, ok := range map[string]bool{"": true, "STANDARD": true, "glacier_ir": true, "DEEP_ARCHIVE": false, "GLACIER": false, "ONEZONE": false} {
		_, err := (&config.StorageConfig{StorageClass: class}).ResolveStorageClass()
		if (err == nil) != ok {
			t.Errorf("storage_class %q: err = %v, want accepted = %v", class, err, ok)
		}
	}
}
