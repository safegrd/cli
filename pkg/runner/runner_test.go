package runner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	var se *StorageError
	if !errors.As(err, &se) || !strings.Contains(err.Error(), "failed to fetch snapshot metadata") {
		t.Fatalf("a drill of a snapshot the store does not hold: %v, want the metadata fetch to fail", err)
	}
	if report != nil {
		t.Errorf("a drill that found no snapshot returned a report: %+v", report)
	}
}

// The verifier's dry restore over an archive laid out by hand: it decrypts
// with the right key, counts what the manifest records, and fails with the
// wrong key. The archive is not what the dumper writes; the round trip from a
// real database through the dumper and this dry restore is
// TestANativeSnapshotPassesTheDryRestoreAndRestoresItsRows, in the tests that
// run against PostgreSQL.
func TestVerifier_RunDryRestore_HandBuiltArchive(t *testing.T) {
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

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	schemaSQL := `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE IF NOT EXISTS "public"."invoices" (
  "id" integer NOT NULL,
  "note" text NOT NULL
);
`
	// PGCOPY binary for 2 invoices, each field in PostgreSQL's binary
	// encoding: an int4 is 4 bytes big-endian, text is its bytes.
	var copyBuf bytes.Buffer
	copyBuf.Write([]byte{0x50, 0x47, 0x43, 0x4F, 0x50, 0x59, 0x0A, 0xFF, 0x0D, 0x0A, 0x00}) // sig
	_ = binary.Write(&copyBuf, binary.BigEndian, uint32(0))                                 // flags
	_ = binary.Write(&copyBuf, binary.BigEndian, uint32(0))                                 // extLen

	for i, note := range []string{"first", "second"} {
		_ = binary.Write(&copyBuf, binary.BigEndian, int16(2))
		_ = binary.Write(&copyBuf, binary.BigEndian, int32(4))
		_ = binary.Write(&copyBuf, binary.BigEndian, int32(i+1))
		_ = binary.Write(&copyBuf, binary.BigEndian, int32(len(note)))
		copyBuf.WriteString(note)
	}

	// Trailer
	_ = binary.Write(&copyBuf, binary.BigEndian, int16(-1))

	writeEntry := func(name string, data []byte) {
		hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}

	writeEntry("pre-data.sql", []byte(schemaSQL))
	writeEntry("data/public/invoices.copy", copyBuf.Bytes())
	writeEntry("sequences.sql", []byte("-- none\n"))
	writeEntry("manifest.json", metaBytes)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

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
	if err == nil || !strings.Contains(err.Error(), "requires a database snapshot") {
		t.Fatalf("a sandbox drill of a file snapshot: %v, want it refused as not a database", err)
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
	if err == nil || !strings.Contains(err.Error(), "requires a database snapshot") {
		t.Fatalf("a sandbox drill of a email snapshot: %v, want it refused as not a database", err)
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
// It was previously hex.EncodeToString(h[:12]) (96 bits) and
// it is the value PrevHash links against. This asserts the width rather
// than only the prefix.
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
		t.Fatalf("certificate digest is %d hex chars (%d bits), want %d (%d bits)",
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

// A MariaDB snapshot is restored into MariaDB, and its drill record says so;
// it read "ephemeral-mysql-sandbox" because its surface type is mysql.
func TestAMariaDBDrillNamesItsEngine(t *testing.T) {
	maria := &model.SnapshotMetadata{ServerVersion: "11.4.13-MariaDB-ubu2404"}
	if got := sandboxEngineName(model.SurfaceTypeMySQL, maria); got != "ephemeral-mariadb-sandbox" {
		t.Errorf("MariaDB: %s", got)
	}
	if got := sandboxEngineName(model.SurfaceTypeMySQL, &model.SnapshotMetadata{ServerVersion: "8.4.11"}); got != "ephemeral-mysql-sandbox" {
		t.Errorf("MySQL: %s", got)
	}
	if got := sandboxEngineName(model.SurfaceTypeMongoDB, nil); got != "ephemeral-mongodb-sandbox" {
		t.Errorf("MongoDB: %s", got)
	}
}
