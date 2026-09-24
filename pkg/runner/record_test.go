package runner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
)

func recordServer(t *testing.T, status int, rec *model.SnapshotMetadata) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(rec)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func assertion(r *model.VerificationReport, name string) *model.AssertionResult {
	for i := range r.Assertions {
		if r.Assertions[i].Name == name {
			return &r.Assertions[i]
		}
	}
	return nil
}

func TestTheStreamIsHeldToTheRemoteServerRecordNotTheSidecar(t *testing.T) {
	original := &model.SnapshotMetadata{SnapshotID: "snap-1", Sha256Checksum: "plain-orig", EncryptedSha256: "cipher-orig"}
	// What an attacker who can write the bucket leaves behind: a different
	// archive, encrypted to the public recipient, with a sidecar to match.
	swappedSidecar := &model.SnapshotMetadata{SnapshotID: "snap-1", Sha256Checksum: "plain-swap"}
	swappedStream := &crypto.StreamMetrics{RawSha256: "plain-swap", EncryptedSha256: "cipher-swap"}
	intactStream := &crypto.StreamMetrics{RawSha256: "plain-orig", EncryptedSha256: "cipher-orig"}

	v := NewVerifier(nil, recordServer(t, http.StatusOK, original).URL)
	v.SetServerToken("tok")
	rec := v.fetchRecord(t.Context(), "snap-1")
	if rec.record == nil {
		t.Fatalf("record not fetched: %s", rec.why)
	}

	t.Run("a swapped snapshot fails", func(t *testing.T) {
		report := &model.VerificationReport{}
		msg := v.checkDigests(report, swappedSidecar, rec, swappedStream)
		if msg == "" {
			t.Fatal("a snapshot replaced together with its sidecar verified")
		}
		if a := assertion(report, "DigestIntegrity"); a == nil || a.Passed || a.Expected != "plain-orig" {
			t.Errorf("DigestIntegrity: %+v", a)
		}
	})
	t.Run("an altered sidecar over intact data fails", func(t *testing.T) {
		report := &model.VerificationReport{}
		if msg := v.checkDigests(report, swappedSidecar, rec, intactStream); !strings.Contains(msg, "sidecar") {
			t.Fatalf("an altered sidecar was not reported: %q", msg)
		}
	})
	t.Run("a ciphertext that is not the one written fails", func(t *testing.T) {
		report := &model.VerificationReport{}
		stream := &crypto.StreamMetrics{RawSha256: "plain-orig", EncryptedSha256: "cipher-other"}
		if msg := v.checkDigests(report, original, rec, stream); !strings.Contains(msg, "ciphertext") {
			t.Fatalf("a different ciphertext was not reported: %q", msg)
		}
	})
	t.Run("the intact snapshot passes and says what it was checked against", func(t *testing.T) {
		report := &model.VerificationReport{}
		if msg := v.checkDigests(report, original, rec, intactStream); msg != "" {
			t.Fatal(msg)
		}
		if a := assertion(report, "RemoteServerRecord"); a == nil || !a.Passed {
			t.Errorf("RemoteServerRecord: %+v", a)
		}
	})
	t.Run("a record from before the ciphertext digest was kept still checks the data", func(t *testing.T) {
		old := *original
		old.EncryptedSha256 = ""
		oldRec := snapshotRecord{record: &old}
		report := &model.VerificationReport{}
		if msg := v.checkDigests(report, swappedSidecar, oldRec, swappedStream); msg == "" {
			t.Fatal("a swap verified against a record with no ciphertext digest")
		}
	})
}

func TestWithoutARecordTheSidecarIsUsedAndABlankOneIsNoWayPast(t *testing.T) {
	for name, v := range map[string]*Verifier{
		"no remote server": NewVerifier(nil, ""),
		"no record": func() *Verifier {
			v := NewVerifier(nil, recordServer(t, http.StatusNotFound, nil).URL)
			v.SetServerToken("tok")
			return v
		}(),
		"refused": func() *Verifier {
			v := NewVerifier(nil, recordServer(t, http.StatusForbidden, nil).URL)
			v.SetServerToken("tok")
			return v
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			rec := v.fetchRecord(t.Context(), "snap-1")
			if rec.record != nil || rec.why == "" {
				t.Fatalf("expected no record and a reason, got %+v", rec)
			}
			stream := &crypto.StreamMetrics{RawSha256: "plain", EncryptedSha256: "cipher"}

			report := &model.VerificationReport{}
			if msg := v.checkDigests(report, &model.SnapshotMetadata{Sha256Checksum: "plain"}, rec, stream); msg != "" {
				t.Fatalf("the sidecar fallback failed an intact snapshot: %s", msg)
			}
			if assertion(report, "RemoteServerRecord") != nil {
				t.Error("claimed a remote server check that did not happen")
			}

			report = &model.VerificationReport{}
			if msg := v.checkDigests(report, &model.SnapshotMetadata{}, rec, stream); msg == "" {
				t.Error("a sidecar with its digest blanked out verified")
			}
		})
	}
}
