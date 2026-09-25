package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
)

// The sidecar beside a snapshot, and the manifest sealed inside it, are both
// things an attacker who can write the bucket can produce: the Age recipient
// is public, so a replacement archive encrypted to it decrypts cleanly, and a
// sidecar to match is a JSON file. Checked only against those, `verify`
// passed a snapshot swapped out wholesale. The digests the remote server
// recorded when the backup ran are the one copy that attacker cannot rewrite
// (the server keeps them write-once), so they are what the stream is held to
// whenever a remote server can be asked.

// snapshotRecord is what the remote server said about a snapshot, or why it
// could not be asked. record is nil when it was not consulted.
type snapshotRecord struct {
	record *model.SnapshotMetadata
	why    string
}

// fetchRecord asks the remote server for its record of snapshotID. It never
// fails the run: protection does not depend on the remote server.
// It reports why the record is unavailable, and the caller says so out loud.
func (v *Verifier) fetchRecord(ctx context.Context, snapshotID string) snapshotRecord {
	if v.serverURL == "" {
		return snapshotRecord{why: "no remote server is configured"}
	}
	if v.serverToken == "" {
		return snapshotRecord{why: "no server_token in this config"}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.serverURL+"/api/v1/snapshots/"+url.PathEscape(snapshotID), nil)
	if err != nil {
		return snapshotRecord{why: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+v.serverToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return snapshotRecord{why: fmt.Sprintf("the remote server could not be reached (%v)", err)}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return snapshotRecord{why: "the remote server has no record of this snapshot"}
	default:
		return snapshotRecord{why: fmt.Sprintf("the remote server refused the lookup (HTTP %d)", resp.StatusCode)}
	}
	var rec model.SnapshotMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rec); err != nil {
		return snapshotRecord{why: fmt.Sprintf("the remote server's record could not be read (%v)", err)}
	}
	if rec.SnapshotID != snapshotID {
		return snapshotRecord{why: "the remote server answered with a different snapshot"}
	}
	if rec.Sha256Checksum == "" {
		return snapshotRecord{why: "the remote server's record carries no digest"}
	}
	return snapshotRecord{record: &rec}
}

// checkDigests holds the decrypted stream to the recorded digest, appending
// its assertions to report. It returns a failure message, or "" when every
// digest the run could consult agrees.
//
// With a record: the plaintext digest must match the record, the sidecar must
// agree with the record, and the ciphertext must match the record where one
// was kept. Without one, the sidecar is all there is, and the run says so on
// stderr and by the absence of the RemoteServerRecord assertion.
func (v *Verifier) checkDigests(report *model.VerificationReport, meta *model.SnapshotMetadata, rec snapshotRecord, dec *crypto.StreamMetrics) string {
	if dec == nil {
		return "the decrypted stream produced no digest"
	}
	expected, source := meta.Sha256Checksum, "backup manifest (sidecar)"
	if rec.record != nil {
		expected, source = rec.record.Sha256Checksum, "remote server record"
	}
	if expected == "" {
		// A blanked digest must not be a way past the check.
		report.Assertions = append(report.Assertions, model.AssertionResult{
			Name:     "DigestIntegrity",
			Passed:   false,
			Expected: "a recorded SHA-256 for this snapshot",
			Actual:   dec.RawSha256,
			Message:  "Neither the sidecar nor the remote server holds a digest, so the data cannot be verified",
		})
		return "no digest is recorded for this snapshot anywhere this run could consult (" + rec.why + "), so it cannot be verified"
	}
	if dec.RawSha256 != expected {
		report.Assertions = append(report.Assertions, model.AssertionResult{
			Name:     "DigestIntegrity",
			Passed:   false,
			Expected: expected,
			Actual:   dec.RawSha256,
			Message:  "Decrypted stream SHA-256 does not match the " + source,
		})
		return legacyDigestExplanation(dec, expected, source)
	}
	report.Assertions = append(report.Assertions, model.AssertionResult{
		Name:     "DigestIntegrity",
		Passed:   true,
		Expected: expected,
		Actual:   dec.RawSha256,
		Message:  "Decrypted stream SHA-256 matches the " + source + " exactly",
	})

	if rec.record == nil {
		fmt.Fprintf(os.Stderr, "\n[!] Digest checked against the sidecar only: %s.\n"+
			"    Whoever can write the bucket can replace a snapshot and its sidecar together.\n"+
			"    Verify with a remote server configured to hold it to the digest recorded at backup time.\n", rec.why)
		return ""
	}

	r := rec.record
	switch {
	case meta.Sha256Checksum != r.Sha256Checksum:
		report.Assertions = append(report.Assertions, model.AssertionResult{
			Name:     "RemoteServerRecord",
			Passed:   false,
			Expected: r.Sha256Checksum,
			Actual:   meta.Sha256Checksum,
			Message:  "The sidecar beside the snapshot does not carry the digest recorded at backup time",
		})
		return fmt.Sprintf("the sidecar's digest (%s) is not the one the remote server recorded at backup time (%s): the sidecar at the sink has been changed", meta.Sha256Checksum, r.Sha256Checksum)
	case r.EncryptedSha256 != "" && dec.EncryptedSha256 != r.EncryptedSha256:
		report.Assertions = append(report.Assertions, model.AssertionResult{
			Name:     "RemoteServerRecord",
			Passed:   false,
			Expected: r.EncryptedSha256,
			Actual:   dec.EncryptedSha256,
			Message:  "The object at the sink is not the ciphertext written at backup time",
		})
		return fmt.Sprintf("the ciphertext read from the sink (%s) is not the one written at backup time (%s)", dec.EncryptedSha256, r.EncryptedSha256)
	}
	msg := "Sidecar and decrypted stream match the digest recorded at backup time"
	if r.EncryptedSha256 != "" {
		msg = "Sidecar, ciphertext and decrypted stream match the digests recorded at backup time"
	}
	report.Assertions = append(report.Assertions, model.AssertionResult{
		Name:     "RemoteServerRecord",
		Passed:   true,
		Expected: r.Sha256Checksum,
		Actual:   dec.RawSha256,
		Message:  msg,
	})
	return ""
}

// RecordedDigests returns the remote server's record of snapshotID.
// rec is nil when the record could not be consulted, and why explains what happened.
func RecordedDigests(ctx context.Context, serverURL, serverToken, snapshotID string) (rec *model.SnapshotMetadata, why string) {
	v := &Verifier{serverURL: serverURL, serverToken: serverToken}
	r := v.fetchRecord(ctx, snapshotID)
	return r.record, r.why
}
