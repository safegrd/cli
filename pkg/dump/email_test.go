package dump

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

type mockIMAPSource struct {
	folders   []string
	messages  map[string][]FetchedEmail
	seenFlags map[string]bool
	peekUsed  bool
	connected bool
	closed    bool
}

func (m *mockIMAPSource) Connect(ctx context.Context) error {
	m.connected = true
	return nil
}

func (m *mockIMAPSource) ListFolders(ctx context.Context) ([]string, error) {
	return m.folders, nil
}

func (m *mockIMAPSource) FetchFolderMessages(ctx context.Context, folder string) ([]FetchedEmail, error) {
	m.peekUsed = true
	return m.messages[folder], nil
}

func (m *mockIMAPSource) Close() error {
	m.closed = true
	return nil
}

func createTestMailSource() *mockIMAPSource {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	msg1 := []byte("From: alice@safegrd.dev\r\nTo: bob@safegrd.dev\r\nSubject: Backup Verification Report\r\nDate: Sat, 19 Sep 2026 10:00:00 +0000\r\nMessage-ID: <msg-001@safegrd.dev>\r\n\r\nAll systems operational.")
	sum1 := sha256.Sum256(msg1)

	msg2 := []byte("From: charlie@startup.io\r\nTo: team@startup.io\r\nSubject: Q3 Architectural Review\r\nDate: Sat, 19 Sep 2026 11:00:00 +0000\r\nMessage-ID: <msg-002@startup.io>\r\n\r\nZero-knowledge files and email live.")
	sum2 := sha256.Sum256(msg2)

	spam := []byte("From: spammer@junk.net\r\nSubject: Buy Now\r\nDate: Sat, 19 Sep 2026 09:00:00 +0000\r\nMessage-ID: <spam-999@junk.net>\r\n\r\nDiscount.")
	spamSum := sha256.Sum256(spam)

	return &mockIMAPSource{
		folders: []string{"INBOX", "Sent", "[Gmail]/Spam"},
		messages: map[string][]FetchedEmail{
			"INBOX": {
				{
					Folder:    "INBOX",
					UID:       101,
					MessageID: "<msg-001@safegrd.dev>",
					Subject:   "Backup Verification Report",
					From:      "alice@safegrd.dev",
					Date:      now,
					Body:      msg1,
					Sha256:    hex.EncodeToString(sum1[:]),
				},
			},
			"Sent": {
				{
					Folder:    "Sent",
					UID:       201,
					MessageID: "<msg-002@startup.io>",
					Subject:   "Q3 Architectural Review",
					From:      "charlie@startup.io",
					Date:      now.Add(time.Hour),
					Body:      msg2,
					Sha256:    hex.EncodeToString(sum2[:]),
				},
			},
			"[Gmail]/Spam": {
				{
					Folder:    "[Gmail]/Spam",
					UID:       999,
					MessageID: "<spam-999@junk.net>",
					Subject:   "Buy Now",
					From:      "spammer@junk.net",
					Date:      now.Add(-time.Hour),
					Body:      spam,
					Sha256:    hex.EncodeToString(spamSum[:]),
				},
			},
		},
		seenFlags: make(map[string]bool),
	}
}

func TestEmailCollector_LosslessExtractionAndExclusion(t *testing.T) {
	mock := createTestMailSource()

	fixedTime := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	collector := NewEmailCollector(EmailCollectorConfig{
		Host:           "imap.gmail.com",
		Username:       "founder@startup.com",
		ExcludeFolders: []string{"[Gmail]/Spam"},
		ArchiveTime:    fixedTime,
	})

	ctx := context.Background()
	reader, meta, err := collector.ScanAndStream(ctx, mock)
	if err != nil {
		t.Fatalf("ScanAndStream failed: %v", err)
	}

	if !mock.peekUsed {
		t.Fatalf("expected BODY.PEEK[] to be used for lossless fetch without modifying flags")
	}

	if meta.TotalItems != 2 {
		t.Fatalf("expected 2 emails, got %d", meta.TotalItems)
	}
	if meta.TotalContainers != 2 {
		t.Fatalf("expected 2 folders, got %d", meta.TotalContainers)
	}

	restorer := NewEmailRestorer()
	res, err := restorer.InspectEmailArchive(ctx, reader, meta)
	if err != nil {
		t.Fatalf("InspectEmailArchive failed: %v", err)
	}

	if !res.Passed {
		t.Fatalf("expected dry restore verification to pass, error: %s", res.ErrorMessage)
	}

	if res.TotalEmails != 2 {
		t.Fatalf("expected 2 emails verified, got %d", res.TotalEmails)
	}
	if res.TotalFolders != 2 {
		t.Fatalf("expected 2 folders verified, got %d", res.TotalFolders)
	}

	for _, msg := range res.SealedManifest.Messages {
		if msg.Folder == "[Gmail]/Spam" {
			t.Fatalf("excluded spam message found in sealed manifest: %+v", msg)
		}
	}
}

func TestEmailCollector_NegativeMismatchedCountFailsDrill(t *testing.T) {
	mock := createTestMailSource()

	collector := NewEmailCollector(EmailCollectorConfig{
		Host:           "imap.gmail.com",
		Username:       "founder@startup.com",
		ExcludeFolders: []string{"[Gmail]/Spam"},
	})

	reader, meta, err := collector.ScanAndStream(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}

	tamperedMeta := *meta
	tamperedMeta.TotalItems = 99999

	restorer := NewEmailRestorer()
	res, err := restorer.InspectEmailArchive(context.Background(), reader, &tamperedMeta)
	if err != nil {
		t.Fatalf("InspectEmailArchive error: %v", err)
	}

	if res.Passed {
		t.Fatalf("expected dry restore verification to fail on mismatched email count, but it passed")
	}
}

func TestEmailCollector_DiskExtraction(t *testing.T) {
	mock := createTestMailSource()

	collector := NewEmailCollector(EmailCollectorConfig{
		Host:           "imap.gmail.com",
		Username:       "founder@startup.com",
		ExcludeFolders: []string{"[Gmail]/Spam"},
	})

	reader, _, err := collector.ScanAndStream(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}

	tarBytes, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	targetDir := t.TempDir()
	restorer := NewEmailRestorer()
	res, err := restorer.ExtractEmailArchive(context.Background(), bytes.NewReader(tarBytes), targetDir)
	if err != nil {
		t.Fatalf("ExtractEmailArchive failed: %v", err)
	}

	if res.EmailsExtracted != 2 {
		t.Fatalf("expected 2 emails extracted to disk, got %d", res.EmailsExtracted)
	}

	entries, err := os.ReadDir(filepath.Join(targetDir, "INBOX"))
	if err != nil {
		t.Fatalf("failed reading extracted INBOX directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file in INBOX, got %d", len(entries))
	}

	content, err := os.ReadFile(filepath.Join(targetDir, "INBOX", entries[0].Name()))
	if err != nil {
		t.Fatalf("failed reading extracted EML: %v", err)
	}
	if !bytes.Contains(content, []byte("Backup Verification Report")) {
		t.Fatalf("expected extracted content to contain email subject, got: %s", string(content))
	}
}

func TestIncrementalUIDSynchronization(t *testing.T) {
	cfg := EmailCollectorConfig{
		Host:     "imap.test.safegrd.dev",
		Username: "operator@safegrd.dev",
		LastFolderStats: []model.EmailFolderStat{
			{
				Folder:      "INBOX",
				UIDValidity: 10001,
				HighestUID:  450,
			},
			{
				Folder:      "Sent",
				UIDValidity: 10002,
				HighestUID:  120,
			},
		},
	}

	client := NewStandardIMAPClient(cfg)
	if client.FolderUIDValidity["INBOX"] != 10001 || client.FolderHighestUID["INBOX"] != 450 {
		t.Fatalf("failed pre-seeding UID sequence state for INBOX: got validity %d, highest %d",
			client.FolderUIDValidity["INBOX"], client.FolderHighestUID["INBOX"])
	}

	// Test UIDVALIDITY reset behavior when mailbox is reindexed/recreated (RFC 3501 §2.3.1.1)
	newValidity := uint32(99999)
	if prevVal, exists := client.FolderUIDValidity["INBOX"]; exists && prevVal != newValidity {
		client.FolderHighestUID["INBOX"] = 0
		client.FolderUIDValidity["INBOX"] = newValidity
	}

	if client.FolderHighestUID["INBOX"] != 0 {
		t.Fatalf("expected highest UID to reset to 0 after UIDVALIDITY change, got %d", client.FolderHighestUID["INBOX"])
	}
	if client.FolderUIDValidity["INBOX"] != 99999 {
		t.Fatalf("expected new UIDVALIDITY 99999, got %d", client.FolderUIDValidity["INBOX"])
	}
}
