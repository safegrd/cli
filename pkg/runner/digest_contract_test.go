package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
)

// The digest contract, asserted end to end through real streaming encryption.
//
// The manifest Sha256Checksum records the PLAINTEXT stream digest, and
// verification compares it against the decrypted PLAINTEXT digest.
// This test asserts that an encrypted stream produces a manifest
// whose digest matches the restored stream.
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

	// What `safegrd backup` records.
	meta := &model.SnapshotMetadata{
		SnapshotID:      "snap-digest-contract",
		Sha256Checksum:  encMetrics.RawSha256,
		EncryptedSha256: encMetrics.EncryptedSha256,
	}

	if meta.Sha256Checksum == meta.EncryptedSha256 {
		t.Fatal("the plaintext and ciphertext digests are equal, so this test proves nothing")
	}

	// What verification computes on the way back.
	var restored bytes.Buffer
	decMetrics, err := crypto.DecryptStream(bytes.NewReader(sealed.Bytes()), &restored, kp.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(restored.Bytes(), plaintext) {
		t.Fatal("the round trip did not return the plaintext")
	}

	if decMetrics.RawSha256 != meta.Sha256Checksum {
		t.Errorf("a Fire Drill on a freshly written snapshot would FAIL:\n"+
			"  manifest sha256_checksum = %s\n"+
			"  digest of restored data  = %s\n"+
			"  These must be the same stream, or verification can never pass.",
			meta.Sha256Checksum, decMetrics.RawSha256)
	}

	// The at-rest digest must stay the other one, or it answers no question.
	if decMetrics.EncryptedSha256 != meta.EncryptedSha256 {
		t.Errorf("encrypted_sha256 does not describe the object as stored: manifest %s, read back %s",
			meta.EncryptedSha256, decMetrics.EncryptedSha256)
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
