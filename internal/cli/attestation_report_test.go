package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

// captureStderr runs fn and returns what it wrote to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 16<<10)
		n, _ := r.Read(buf)
		done <- string(buf[:n])
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

// A backup the remote server never recorded must not look like one it did.
//
// Every failure in sendMetadataToServer used to return silently, so a node with
// a stale token, or a config missing node_id, printed "Backup Completed
// Successfully" while the console showed a node that had never backed up. This
// product sells the proof rather than the copy; an attestation nobody received
// is not a proof, and the host is the only place that can notice.
func TestARejectedAttestationIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"node token does not match node_id"}`))
	}))
	defer srv.Close()

	out := captureStderr(t, func() {
		sendMetadataToServer(context.Background(), srv.URL, "sg_tok_stale",
			&model.SnapshotMetadata{SnapshotID: "snap-1", NodeID: "node-1"}, true)
	})

	if !strings.Contains(out, "NOT RECORDED") {
		t.Fatalf("a 403 from the remote server was not reported at all; output was %q", out)
	}
	for _, want := range []string{"403", "node token does not match node_id"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q, so nobody can act on it: %q", want, out)
		}
	}
}

// The two misconfigurations that produced exactly this on a production host: a config
// with no node_id, and one with no server_token. Both must say so before a
// request is even attempted.
func TestMissingNodeIdentityIsReportedWithoutCallingTheServer(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	t.Run("no node_id", func(t *testing.T) {
		out := captureStderr(t, func() {
			sendMetadataToServer(context.Background(), srv.URL, "sg_tok_fine",
				&model.SnapshotMetadata{SnapshotID: "snap-2"}, true)
		})
		if !strings.Contains(out, "no node_id") {
			t.Errorf("a config with no node_id was not reported: %q", out)
		}
	})

	t.Run("no server_token", func(t *testing.T) {
		out := captureStderr(t, func() {
			sendMetadataToServer(context.Background(), srv.URL, "",
				&model.SnapshotMetadata{SnapshotID: "snap-3", NodeID: "node-1"}, true)
		})
		if !strings.Contains(out, "no server_token") {
			t.Errorf("a config with no server_token was not reported: %q", out)
		}
	})

	if called {
		t.Error("a request was sent despite the config being incomplete")
	}
}

// A successful report stays quiet on stderr; warnings indicate failures.
func TestASuccessfulAttestationWarnsAboutNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"snapshot_id":"snap-4"}`))
	}))
	defer srv.Close()

	out := captureStderr(t, func() {
		sendMetadataToServer(context.Background(), srv.URL, "sg_tok_fine",
			&model.SnapshotMetadata{SnapshotID: "snap-4", NodeID: "node-1"}, true)
	})
	if strings.Contains(out, "NOT RECORDED") {
		t.Errorf("a successful report produced a failure warning: %q", out)
	}
}

// A standalone host (no token) is told it is standalone, not warned on
// every backup, and nothing is sent anywhere. `init` writes a node_id
// without enrolling, so a node id is not a sign of enrolment; a token the
// remote server refuses is (TestARejectedAttestationIsReported).
func TestAStandaloneHostIsNotWarnedAndSendsNothing(t *testing.T) {
	contacted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted = true
	}))
	defer srv.Close()

	for _, meta := range []*model.SnapshotMetadata{{SnapshotID: "snap-1"}, {SnapshotID: "snap-2", NodeID: "node-from-init"}} {
		out := captureStderr(t, func() {
			sendMetadataToServer(context.Background(), srv.URL, "", meta, true)
		})
		if strings.Contains(out, "NOT RECORDED") || contacted {
			t.Errorf("standalone backup of %+v was warned (%q) or contacted the server (%t)", meta, out, contacted)
		}
	}
}
