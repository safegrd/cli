package cli

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

// A backup the remote server never recorded must not look like one it did.
//
// Every failure in sendMetadataToServer used to return silently, so a node with
// a stale token, or a config missing node_id, printed "Backup Completed
// Successfully" while the console showed a node that had never backed up. This
// product sells the proof rather than the copy; an attestation nobody received
// is not a proof, and the host is the only place that can notice.
func TestARejectedAttestationIsReported(t *testing.T) {
	api := newFakeAPI(t, "sg_tok_stale", map[string]http.HandlerFunc{
		"POST /api/v1/snapshots": jsonReply(http.StatusForbidden, `{"error":"node token does not match node_id"}`),
	})

	var reason string
	out := captureStderr(t, func() {
		reason = sendMetadataToServer(context.Background(), api.URL(), "sg_tok_stale",
			&model.SnapshotMetadata{SnapshotID: "snap-1", NodeID: "node-1"}, true)
	})
	// The daemon carries this in its last error, which is how a host running
	// as a service tells the console its backup was never recorded.
	if !strings.Contains(reason, "403") || !strings.Contains(reason, "node token does not match node_id") {
		t.Errorf("the reason returned for the daemon is %q", reason)
	}

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
// with no node.id, and one with no server.token. Both must say so before a
// request is even attempted.
func TestMissingNodeIdentityIsReportedWithoutCallingTheServer(t *testing.T) {
	api := newFakeAPI(t, "sg_tok_fine", map[string]http.HandlerFunc{"POST /api/v1/snapshots": jsonReply(http.StatusCreated, `{}`)})

	t.Run("no node.id", func(t *testing.T) {
		out := captureStderr(t, func() {
			sendMetadataToServer(context.Background(), api.URL(), "sg_tok_fine",
				&model.SnapshotMetadata{SnapshotID: "snap-2"}, true)
		})
		if !strings.Contains(out, "no node.id") {
			t.Errorf("a config with no node.id was not reported: %q", out)
		}
	})

	t.Run("no server.token", func(t *testing.T) {
		out := captureStderr(t, func() {
			sendMetadataToServer(context.Background(), api.URL(), "",
				&model.SnapshotMetadata{SnapshotID: "snap-3", NodeID: "node-1"}, true)
		})
		if !strings.Contains(out, "no server.token") {
			t.Errorf("a config with no server.token was not reported: %q", out)
		}
	})

	if n := len(api.Calls("/api/v1/snapshots")); n != 0 {
		t.Errorf("%d requests were sent despite the config being incomplete", n)
	}
}

// A successful report stays quiet on stderr; warnings indicate failures.
func TestASuccessfulAttestationWarnsAboutNothing(t *testing.T) {
	api := newFakeAPI(t, "sg_tok_fine", map[string]http.HandlerFunc{
		"POST /api/v1/snapshots": jsonReply(http.StatusCreated, `{"snapshot_id":"snap-4"}`),
	})

	var reason string
	out := captureStderr(t, func() {
		reason = sendMetadataToServer(context.Background(), api.URL(), "sg_tok_fine",
			&model.SnapshotMetadata{SnapshotID: "snap-4", NodeID: "node-1"}, true)
	})
	if out != "" || reason != "" {
		t.Errorf("a successful report produced a warning: %q, reason %q", out, reason)
	}
	calls := api.Calls("/api/v1/snapshots")
	if len(calls) != 1 || !strings.Contains(string(calls[0].Body), `"snapshot_id":"snap-4"`) {
		t.Errorf("the record was sent %d times: %+v", len(calls), calls)
	}
}

// A report the remote server records but marks as outside the project's
// storage is said on the host: the console shows the project's storage, and
// this backup is somewhere else.
func TestABackupOutsideTheProjectsStorageIsSaid(t *testing.T) {
	api := newFakeAPI(t, "sg_tok_fine", map[string]http.HandlerFunc{
		"POST /api/v1/snapshots": jsonReply(http.StatusCreated, `{"snapshot_id":"snap-5","outside_project_storage":true}`),
	})

	meta := &model.SnapshotMetadata{SnapshotID: "snap-5", NodeID: "node-1", StorageURI: "file:///var/backups/snap-5"}
	var reason string
	out := captureStderr(t, func() {
		reason = sendMetadataToServer(context.Background(), api.URL(), "sg_tok_fine", meta, false)
	})
	if !strings.Contains(out, "OUTSIDE THE PROJECT'S STORAGE") || !strings.Contains(out, "file:///var/backups/snap-5") {
		t.Errorf("a backup outside the project's storage was not said: %q", out)
	}
	if reason != "" || !meta.OutsideProjectStorage {
		t.Errorf("recorded, so no reason (got %q), and the mark is kept on the metadata (got %v)", reason, meta.OutsideProjectStorage)
	}
}

// A standalone host (no token) is told it is standalone, not warned on
// every backup, and nothing is sent anywhere. `init` writes a node_id
// without enrolling, so a node id is not a sign of enrolment; a token the
// remote server refuses is (TestARejectedAttestationIsReported).
func TestAStandaloneHostIsNotWarnedAndSendsNothing(t *testing.T) {
	api := newFakeAPI(t, "sg_tok_any", map[string]http.HandlerFunc{"POST /api/v1/snapshots": jsonReply(http.StatusCreated, `{}`)})

	for _, meta := range []*model.SnapshotMetadata{{SnapshotID: "snap-1"}, {SnapshotID: "snap-2", NodeID: "node-from-init"}} {
		out := captureStderr(t, func() {
			sendMetadataToServer(context.Background(), api.URL(), "", meta, true)
		})
		if strings.Contains(out, "NOT RECORDED") || len(api.Calls("/api/v1/snapshots")) != 0 {
			t.Errorf("standalone backup of %+v was warned (%q) or contacted the server (%d requests)", meta, out, len(api.Calls("/api/v1/snapshots")))
		}
	}
}
