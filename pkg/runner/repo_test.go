package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/write"
)

func repoSnapshotForTest(t *testing.T) (RepoDrill, string) {
	t.Helper()
	id, _ := age.GenerateX25519Identity()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(src, "d"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "d", "b.bin"), make([]byte, 700<<10), 0o600)
	st, _ := sink.NewDir(t.TempDir(), "n")
	b := sink.NewDirect(st)
	var meta *model.SnapshotMetadata
	res, err := write.Run(context.Background(), b, write.Options{
		SurfaceID: "s", Roots: []string{src}, StateDir: t.TempDir(), Recipient: id.Recipient().String(),
		Retention: policy.Retention{Days: 7}, Tier: format.TierBase, Planned: time.Now().Add(7 * 24 * time.Hour), SnapshotID: "snap-1",
		Sidecar: func(r *write.Result) ([]byte, error) {
			meta = &model.SnapshotMetadata{SnapshotID: "snap-1", SurfaceType: model.SurfaceTypeFiles, Status: model.SnapshotStatusCompleted,
				Sha256Checksum: r.Snapshot.ContentRoot, Format: model.SnapshotFormatRepo, EpochID: r.Epoch.EpochID, ObjectClass: r.Class,
				FileStats: &model.FileStatsSummary{TotalFiles: r.Snapshot.Stats.Files}}
			meta.CalculateTotals()
			return json.Marshal(meta)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	es, _ := b.Epochs(context.Background(), "s")
	_ = res
	return RepoDrill{Backend: b, Epoch: es[0], Meta: meta}, id.String()
}

func repoRecordServer(t *testing.T, rec model.SnapshotMetadata, got *[]model.VerificationReport) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/snapshots/"):
			_ = json.NewEncoder(w).Encode(rec)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/verifications":
			var rep model.VerificationReport
			_ = json.NewDecoder(r.Body).Decode(&rep)
			*got = append(*got, rep)
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestARepoSnapshotIsNeverCalledLegacyOrTampered(t *testing.T) {
	d, key := repoSnapshotForTest(t)
	// The record carries the content root and, by design, no ciphertext
	// digest.
	rec := *d.Meta
	rec.EncryptedSha256 = ""
	var reports []model.VerificationReport
	srv := repoRecordServer(t, rec, &reports)
	defer srv.Close()
	v := NewVerifier(nil, srv.URL)
	v.SetServerToken("tok")
	report, err := v.RunRepoDrill(context.Background(), d, key)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != model.VerificationStatusPassed {
		t.Fatalf("drill failed: %s %+v", report.ErrorMessage, report.Assertions)
	}
	for _, a := range report.Assertions {
		low := strings.ToLower(a.Message + a.Actual)
		if strings.Contains(low, "legacy") || strings.Contains(low, "tamper") || strings.Contains(low, "predates") {
			t.Fatalf("assertion %s calls a repository snapshot legacy or tampered: %s", a.Name, a.Message)
		}
	}
	if len(reports) != 1 || reports[0].Status != model.VerificationStatusPassed {
		t.Fatalf("reported %+v", reports)
	}
	// The stream path refuses a repository snapshot by name, never with the
	// legacy explanation.
	msg := v.checkDigests(&model.VerificationReport{}, d.Meta, snapshotRecord{record: &rec}, &crypto.StreamMetrics{RawSha256: "x"})
	if !strings.Contains(msg, "incremental repository") || strings.Contains(strings.ToLower(msg), "legacy") {
		t.Fatalf("checkDigests on a repository snapshot: %q", msg)
	}
}

func TestARepoDrillFailsWhenTheRecordedRootDiffers(t *testing.T) {
	d, key := repoSnapshotForTest(t)
	rec := *d.Meta
	rec.Sha256Checksum = strings.Repeat("0", 64)
	var reports []model.VerificationReport
	srv := repoRecordServer(t, rec, &reports)
	defer srv.Close()
	v := NewVerifier(nil, srv.URL)
	v.SetServerToken("tok")
	report, err := v.RunRepoDrill(context.Background(), d, key)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status == model.VerificationStatusPassed {
		t.Fatal("a drill passed against a different recorded root")
	}
	if len(reports) != 1 || reports[0].Status != model.VerificationStatusFailed {
		t.Fatalf("the failure was not reported: %+v", reports)
	}
}
