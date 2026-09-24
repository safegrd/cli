package runner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
)

func TestFireDrillCertificateGeneration(t *testing.T) {
	report := &model.VerificationReport{
		VerificationID: "verif-1234",
		SnapshotID:     "snap-test-01",
		NodeID:         "node-test",
		TablesRestored: 42,
		RowsRestored:   150000,
		CompletedAt:    time.Now(),
	}

	hash := computeCertificateHash(report)
	if !strings.HasPrefix(hash, "cert_sg_") {
		t.Errorf("expected certificate hash to start with 'cert_sg_', got %s", hash)
	}
}

func TestFireDrillMissingSnapshotHandling(t *testing.T) {
	tempDir := t.TempDir()
	store, err := storage.NewLocalStorage(filepath.Join(tempDir, "worm-store"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	verifier := NewVerifier(store, "")
	ctx := context.Background()

	// Run drill on non-existent snapshot
	report, err := verifier.RunFireDrill(ctx, "non-existent-snap", "dummy-key", "postgres://localhost/test")
	if err == nil {
		t.Fatal("expected error for non-existent snapshot metadata, got nil")
	}
	if report != nil && report.Status == model.VerificationStatusPassed {
		t.Errorf("expected report not to be marked passed")
	}
}

func TestVerifier_RunDryRestore_Roundtrip(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	store, err := storage.NewLocalStorage(filepath.Join(tempDir, "worm-store"))
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}

	// 1. Generate Age keypair
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed generating keypair: %v", err)
	}
	pubKey, privKey := kp.PublicKey, kp.PrivateKey

	snapshotID := "snap-dry-verify-01"

	// 2. Prepare metadata
	meta := &model.SnapshotMetadata{
		SnapshotID:   snapshotID,
		NodeID:       "node-alpha-01",
		DatabaseName: "finance_prod",
		SchemaSource: "pg_dump 18.6",
		CreatedAt:    time.Now().UTC(),
		Status:       model.SnapshotStatusCompleted,
		TotalTables:  1,
		TotalRows:    2,
		Extensions:   []string{"uuid-ossp"},
		TableStats: []model.TableStat{
			{Schema: "public", TableName: "invoices", RowCount: 2, SizeBytes: 180},
		},
	}
	if err := store.UploadMetadata(ctx, snapshotID, meta); err != nil {
		t.Fatalf("failed uploading metadata: %v", err)
	}

	// 3. Build tar archive
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)

	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	schemaSQL := `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE IF NOT EXISTS "public"."invoices" (
  "id" integer NOT NULL,
  "amount" numeric(10,2) NOT NULL
);
`
	// Build PGCOPY binary for 2 invoices
	var copyBuf bytes.Buffer
	copyBuf.Write([]byte{0x50, 0x47, 0x43, 0x4F, 0x50, 0x59, 0x0A, 0xFF, 0x0D, 0x0A, 0x00}) // sig
	_ = binary.Write(&copyBuf, binary.BigEndian, uint32(0))                                 // flags
	_ = binary.Write(&copyBuf, binary.BigEndian, uint32(0))                                 // extLen

	// Row 1
	_ = binary.Write(&copyBuf, binary.BigEndian, int16(2))
	_ = binary.Write(&copyBuf, binary.BigEndian, int32(1))
	copyBuf.WriteString("1")
	_ = binary.Write(&copyBuf, binary.BigEndian, int32(5))
	copyBuf.WriteString("99.50")

	// Row 2
	_ = binary.Write(&copyBuf, binary.BigEndian, int16(2))
	_ = binary.Write(&copyBuf, binary.BigEndian, int32(1))
	copyBuf.WriteString("2")
	_ = binary.Write(&copyBuf, binary.BigEndian, int32(6))
	copyBuf.WriteString("149.00")

	// Trailer
	_ = binary.Write(&copyBuf, binary.BigEndian, int16(-1))

	writeEntry := func(name string, data []byte) {
		hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}
		_ = tw.WriteHeader(hdr)
		_, _ = tw.Write(data)
	}

	writeEntry("pre-data.sql", []byte(schemaSQL))
	writeEntry("data/public/invoices.copy", copyBuf.Bytes())
	writeEntry("sequences.sql", []byte("-- none\n"))
	writeEntry("manifest.json", metaBytes)
	_ = tw.Close()

	// 4. Encrypt stream with Age public key
	var cipherBuf bytes.Buffer
	metrics, err := crypto.EncryptStream(&tarBuf, &cipherBuf, pubKey)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	// Record the digest the backup would have: with none anywhere, verify
	// refuses to call the data verified.
	meta.Sha256Checksum = metrics.RawSha256
	if err := store.UploadMetadata(ctx, snapshotID, meta); err != nil {
		t.Fatalf("failed uploading metadata: %v", err)
	}

	// 5. Upload ciphertext to storage
	retentionUntil := time.Now().Add(14 * 24 * time.Hour)
	_, err = store.UploadSnapshot(ctx, snapshotID, &cipherBuf, int64(cipherBuf.Len()), retentionUntil)
	if err != nil {
		t.Fatalf("upload snapshot failed: %v", err)
	}

	// 6. Execute RunDryRestore
	verifier := NewVerifier(store, "")
	report, dryResult, err := verifier.RunDryRestore(ctx, snapshotID, privKey)
	if err != nil {
		t.Fatalf("dry restore failed: %v", err)
	}

	if report.Status != model.VerificationStatusPassed {
		t.Fatalf("expected report to pass, but failed: %s", report.ErrorMessage)
	}
	if report.TablesRestored != 1 {
		t.Errorf("expected 1 table restored, got %d", report.TablesRestored)
	}
	if report.RowsRestored != 2 {
		t.Errorf("expected 2 rows restored, got %d", report.RowsRestored)
	}
	if !strings.HasPrefix(report.CertificateHash, "cert_sg_") {
		t.Errorf("expected certificate hash starting with 'cert_sg_', got %s", report.CertificateHash)
	}
	if dryResult == nil || !dryResult.Passed {
		t.Fatalf("expected dry result passed")
	}

	// 7. Test invalid private key -> fails decryption
	kp2, _ := crypto.GenerateKeyPair()
	badReport, _, err := verifier.RunDryRestore(ctx, snapshotID, kp2.PrivateKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if badReport.Status == model.VerificationStatusPassed {
		t.Fatalf("expected verification with wrong private key to fail")
	}
}

func TestVerifier_RunDryRestore_Files(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create test file tree
	srcDir := filepath.Join(tempDir, "source")
	if err := os.MkdirAll(filepath.Join(srcDir, "docs"), 0755); err != nil {
		t.Fatalf("failed creating src dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "hello.txt"), []byte("Hello SafeGrd"), 0644); err != nil {
		t.Fatalf("failed writing file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "docs", "manual.pdf"), []byte("%PDF-1.4 dummy pdf"), 0644); err != nil {
		t.Fatalf("failed writing file: %v", err)
	}

	store, err := storage.NewLocalStorage(filepath.Join(tempDir, "worm-store"))
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed generating keypair: %v", err)
	}

	snapshotID := "snap-files-verify-01"

	collector := dump.NewFileCollector(dump.FileCollectorConfig{
		RootDir:     srcDir,
		ArchiveTime: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	})

	tarStream, meta, err := collector.ScanAndStream(ctx)
	if err != nil {
		t.Fatalf("failed collecting files: %v", err)
	}

	var cipherBuf bytes.Buffer
	metrics, err := crypto.EncryptStream(tarStream, &cipherBuf, kp.PublicKey)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	meta.SnapshotID = snapshotID
	meta.NodeID = "node-files-01"
	meta.RawSizeBytes = metrics.RawBytes
	meta.EncryptedSizeBytes = metrics.EncryptedBytes
	meta.Sha256Checksum = metrics.RawSha256
	meta.CalculateTotals()

	if err := store.UploadMetadata(ctx, snapshotID, meta); err != nil {
		t.Fatalf("failed uploading metadata: %v", err)
	}
	if _, err := store.UploadSnapshot(ctx, snapshotID, &cipherBuf, int64(cipherBuf.Len()), time.Now().Add(14*24*time.Hour)); err != nil {
		t.Fatalf("failed uploading snapshot: %v", err)
	}

	verifier := NewVerifier(store, "")

	// Test Fire Drill fails for file surface
	_, err = verifier.RunFireDrill(ctx, snapshotID, kp.PrivateKey, "postgres://localhost/test")
	if err == nil {
		t.Fatal("expected RunFireDrill to reject file surface snapshot, but got nil error")
	}

	// Test Dry Restore succeeds for file surface
	report, _, err := verifier.RunDryRestore(ctx, snapshotID, kp.PrivateKey)
	if err != nil {
		t.Fatalf("dry restore failed: %v", err)
	}

	if report.Status != model.VerificationStatusPassed {
		t.Fatalf("expected report passed, got %s: %s", report.Status, report.ErrorMessage)
	}
	if report.SurfaceType != model.SurfaceTypeFiles {
		t.Errorf("expected surface files, got %s", report.SurfaceType)
	}
	if report.TotalItems != 2 {
		t.Errorf("expected 2 files restored, got %d", report.TotalItems)
	}
	if !strings.HasPrefix(report.CertificateHash, "cert_sg_") {
		t.Errorf("expected valid cert hash, got %s", report.CertificateHash)
	}
}

type mockRunnerEmailSource struct{}

func (m *mockRunnerEmailSource) Connect(ctx context.Context) error { return nil }
func (m *mockRunnerEmailSource) ListFolders(ctx context.Context) ([]string, error) {
	return []string{"INBOX"}, nil
}
func (m *mockRunnerEmailSource) FetchFolderMessages(ctx context.Context, folder string) ([]dump.FetchedEmail, error) {
	body := []byte("From: security@safegrd.dev\r\nSubject: Multi-Surface Shield\r\nDate: Sat, 19 Sep 2026 12:00:00 +0000\r\n\r\nVerified.")
	h := sha256.Sum256(body)
	return []dump.FetchedEmail{
		{
			Folder:    "INBOX",
			UID:       1,
			MessageID: "<msg-1@safegrd.dev>",
			Subject:   "Multi-Surface Shield",
			From:      "security@safegrd.dev",
			Date:      time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC),
			Body:      body,
			Sha256:    hex.EncodeToString(h[:]),
		},
	}, nil
}
func (m *mockRunnerEmailSource) Close() error { return nil }

func TestVerifier_RunDryRestore_Email(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	store, err := storage.NewLocalStorage(filepath.Join(tempDir, "worm-store"))
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed generating keypair: %v", err)
	}

	snapshotID := "snap-email-verify-01"

	collector := dump.NewEmailCollector(dump.EmailCollectorConfig{
		Host:        "imap.example.com",
		Username:    "user@example.com",
		ArchiveTime: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	})

	tarStream, meta, err := collector.ScanAndStream(ctx, &mockRunnerEmailSource{})
	if err != nil {
		t.Fatalf("failed collecting email: %v", err)
	}

	var cipherBuf bytes.Buffer
	metrics, err := crypto.EncryptStream(tarStream, &cipherBuf, kp.PublicKey)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	meta.SnapshotID = snapshotID
	meta.NodeID = "node-email-01"
	meta.RawSizeBytes = metrics.RawBytes
	meta.EncryptedSizeBytes = metrics.EncryptedBytes
	meta.Sha256Checksum = metrics.RawSha256
	meta.CalculateTotals()

	if err := store.UploadMetadata(ctx, snapshotID, meta); err != nil {
		t.Fatalf("failed uploading metadata: %v", err)
	}
	if _, err := store.UploadSnapshot(ctx, snapshotID, &cipherBuf, int64(cipherBuf.Len()), time.Now().Add(14*24*time.Hour)); err != nil {
		t.Fatalf("failed uploading snapshot: %v", err)
	}

	verifier := NewVerifier(store, "")

	// Test Fire Drill fails for email surface
	_, err = verifier.RunFireDrill(ctx, snapshotID, kp.PrivateKey, "postgres://localhost/test")
	if err == nil {
		t.Fatal("expected RunFireDrill to reject email surface snapshot, but got nil error")
	}

	// Test Dry Restore succeeds for email surface
	report, _, err := verifier.RunDryRestore(ctx, snapshotID, kp.PrivateKey)
	if err != nil {
		t.Fatalf("dry restore failed: %v", err)
	}

	if report.Status != model.VerificationStatusPassed {
		t.Fatalf("expected report passed, got %s: %s", report.Status, report.ErrorMessage)
	}
	if report.SurfaceType != model.SurfaceTypeEmail {
		t.Errorf("expected surface email, got %s", report.SurfaceType)
	}
	if report.TotalItems != 1 {
		t.Errorf("expected 1 email restored, got %d", report.TotalItems)
	}
	if !strings.HasPrefix(report.CertificateHash, "cert_sg_") {
		t.Errorf("expected valid cert hash, got %s", report.CertificateHash)
	}
}

// The certificate digest is the full SHA-256, not a prefix.
//
// It was hex.EncodeToString(h[:12]) — 96 bits, a ~48-bit birthday bound — and
// it is the value PrevHash links against, so it is the narrowest margin in the
// chain. This asserts the width rather than only the prefix, because every
// other test here checks "cert_sg_" and would pass at any length.
func TestTheCertificateDigestIsAWholeSHA256(t *testing.T) {
	report := &model.VerificationReport{
		VerificationID: "ver-width-01",
		SnapshotID:     "snap-width-01",
		NodeID:         "node-width-01",
		TablesRestored: 7,
		RowsRestored:   1234,
		CompletedAt:    time.Unix(1750000000, 0).UTC(),
	}

	hash := computeCertificateHash(report)
	const prefix = "cert_sg_"
	digest := strings.TrimPrefix(hash, prefix)
	if len(digest) != sha256.Size*2 {
		t.Fatalf("certificate digest is %d hex chars (%d bits), want %d (%d bits) — "+
			"a truncated digest is the one value the whole attestation chain is built out of",
			len(digest), len(digest)*4, sha256.Size*2, sha256.Size*8)
	}

	// And it is actually the digest of the payload, not merely the right length.
	want := sha256.Sum256([]byte(fmt.Sprintf("CERT:%s:%s:%s:%d:%d:%d",
		report.VerificationID, report.SnapshotID, report.NodeID,
		report.TablesRestored, report.RowsRestored, report.CompletedAt.Unix())))
	if digest != hex.EncodeToString(want[:]) {
		t.Fatalf("certificate digest does not match SHA-256 of its payload:\n got %s\nwant %s",
			digest, hex.EncodeToString(want[:]))
	}

	// Changing any covered field must change the digest.
	other := *report
	other.RowsRestored = 1235
	if computeCertificateHash(&other) == hash {
		t.Fatal("row count is covered by the certificate but did not change the digest")
	}
}
