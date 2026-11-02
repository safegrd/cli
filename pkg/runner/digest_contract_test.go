package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
)

// The digest contract: what a backup records is what verification compares
// the restored stream against. The manifest's Sha256Checksum is the digest of
// the PLAINTEXT; EncryptedSha256 is the object as stored. The metadata is
// filled by StreamMetrics.RecordInto, the call every backup path makes, and
// checked by checkDigests, the comparison every stream drill makes.
func TestTheManifestDigestIsOfThePlaintext(t *testing.T) {
	plaintext := []byte(strings.Repeat("safegrd sample data rows;", 500))

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	var sealed bytes.Buffer
	encMetrics, err := crypto.EncryptStream(bytes.NewReader(plaintext), &sealed, kp.PublicKey)
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	if encMetrics.RawSha256 == encMetrics.EncryptedSha256 {
		t.Fatal("the plaintext and ciphertext digests are equal, so this test proves nothing")
	}

	meta := &model.SnapshotMetadata{SnapshotID: "snap-digest-contract"}
	encMetrics.RecordInto(meta)

	var restored bytes.Buffer
	decMetrics, err := crypto.DecryptStream(bytes.NewReader(sealed.Bytes()), &restored, kp.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(restored.Bytes(), plaintext) {
		t.Fatal("the round trip did not return the plaintext")
	}

	report := &model.VerificationReport{}
	v := NewVerifier(nil, "")
	if msg := v.checkDigests(report, meta, snapshotRecord{why: "no remote server in this test"}, decMetrics); msg != "" {
		t.Fatalf("a drill of a freshly written snapshot fails its digest check: %s\n"+
			"  manifest sha256_checksum = %s\n  digest of restored data  = %s", msg, meta.Sha256Checksum, decMetrics.RawSha256)
	}
	if a := assertion(report, "DigestIntegrity"); a == nil || !a.Passed {
		t.Fatalf("DigestIntegrity: %+v", a)
	}
	if meta.EncryptedSha256 != decMetrics.EncryptedSha256 || meta.EncryptedSizeBytes != int64(sealed.Len()) || meta.RawSizeBytes != int64(len(plaintext)) {
		t.Errorf("the recorded object does not describe what was stored: sha %s (read back %s), %d of %d bytes, raw %d",
			meta.EncryptedSha256, decMetrics.EncryptedSha256, meta.EncryptedSizeBytes, sealed.Len(), meta.RawSizeBytes)
	}
}

// A snapshot written before the fix must be reported as old, not as tampered
// with. Its owner's data is intact and telling them otherwise is a false alarm.
func TestAPreFixManifestIsExplainedRatherThanCalledTampering(t *testing.T) {
	dec := &crypto.StreamMetrics{
		RawSha256:       "aaaa",
		EncryptedSha256: "bbbb",
	}
	// The old behaviour: the manifest carries the ciphertext digest.
	legacy := &model.SnapshotMetadata{Sha256Checksum: "bbbb"}
	msg := legacyDigestExplanation(dec, legacy.Sha256Checksum, "sidecar")
	if strings.Contains(msg, "mismatch") {
		t.Errorf("a pre-fix snapshot is reported as a digest mismatch: %q", msg)
	}
	if !strings.Contains(msg, "intact") {
		t.Errorf("the explanation does not say the backup is fine: %q", msg)
	}

	// A genuinely wrong digest must still be reported as a mismatch.
	corrupt := &model.SnapshotMetadata{Sha256Checksum: "cccc"}
	msg = legacyDigestExplanation(dec, corrupt.Sha256Checksum, "sidecar")
	if !strings.Contains(msg, "mismatch") {
		t.Errorf("a real digest mismatch was explained away: %q", msg)
	}
}
