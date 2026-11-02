package dump

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// mockIMAPSource hands the collector fetched messages directly. It stands in
// for the IMAP client, so nothing it does says how the client fetches: the
// scripted server tests in email_imap_test.go record the commands sent.
type mockIMAPSource struct {
	folders   []string
	messages  map[string][]FetchedEmail
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

	// 2 emails expected (INBOX + Sent, excluding Spam)
	if meta.TotalItems != 2 {
		t.Fatalf("expected 2 emails, got %d", meta.TotalItems)
	}
	if meta.TotalContainers != 2 {
		t.Fatalf("expected 2 folders, got %d", meta.TotalContainers)
	}

	// In-memory dry restore verification
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
	collect := func() ([]byte, *model.SnapshotMetadata) {
		t.Helper()
		collector := NewEmailCollector(EmailCollectorConfig{
			Host:           "imap.gmail.com",
			Username:       "founder@startup.com",
			ExcludeFolders: []string{"[Gmail]/Spam"},
		})
		reader, meta, err := collector.ScanAndStream(context.Background(), createTestMailSource())
		if err != nil {
			t.Fatal(err)
		}
		archive, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		return archive, meta
	}
	archive, meta := collect()
	restorer := NewEmailRestorer()

	// The same archive with its own record passes: what fails below is the
	// count alone.
	res, err := restorer.InspectEmailArchive(context.Background(), bytes.NewReader(archive), meta)
	if err != nil || !res.Passed {
		t.Fatalf("the untampered archive did not pass: %+v, %v", res, err)
	}

	tamperedMeta := *meta
	tamperedMeta.TotalItems = 99999
	res, err = restorer.InspectEmailArchive(context.Background(), bytes.NewReader(archive), &tamperedMeta)
	if err != nil {
		t.Fatalf("InspectEmailArchive error: %v", err)
	}
	if res.Passed {
		t.Fatalf("expected dry restore verification to fail on mismatched email count, but it passed")
	}
	if a := assertion(t, res.Assertions, "Archive Email Count Matches Manifest"); a.Passed {
		t.Fatalf("the count assertion passed over a record of 99999 emails: %+v", a)
	}
	if !strings.Contains(res.ErrorMessage, "the snapshot record says 99999") {
		t.Fatalf("the failure does not name the count it disagreed with: %q", res.ErrorMessage)
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

	// Every message that was not excluded comes back byte for byte, in its
	// folder, and the excluded one does not.
	src := createTestMailSource()
	for _, folder := range []string{"INBOX", "Sent"} {
		entries, err := os.ReadDir(filepath.Join(targetDir, folder))
		if err != nil {
			t.Fatalf("reading the extracted %s directory: %v", folder, err)
		}
		if len(entries) != len(src.messages[folder]) {
			t.Fatalf("%s: %d files extracted, the source holds %d", folder, len(entries), len(src.messages[folder]))
		}
		content, err := os.ReadFile(filepath.Join(targetDir, folder, entries[0].Name()))
		if err != nil {
			t.Fatalf("reading the extracted message: %v", err)
		}
		if !bytes.Equal(content, src.messages[folder][0].Body) {
			t.Fatalf("%s/%s is not the message the server held:\n%s", folder, entries[0].Name(), content)
		}
	}
	if _, err := os.Stat(filepath.Join(targetDir, "[Gmail]")); !os.IsNotExist(err) {
		t.Fatalf("the excluded spam folder was extracted (%v)", err)
	}
}

// An incremental backup fetches each folder from the UID after the highest
// it holds. When the server reports a new UIDVALIDITY (the mailbox was
// recreated, RFC 3501 2.3.1.1), the old UIDs mean nothing and the folder is
// fetched whole. Every fetch is BODY.PEEK[], which leaves \Seen unset.
func TestIncrementalUIDSynchronization(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	srv := startScriptedIMAP(t, serverTLS, func(verb, args string) string {
		switch verb {
		case "LOGIN":
			return "TAG OK Logged in\r\n"
		case "CAPABILITY":
			return "* CAPABILITY IMAP4rev1 UIDPLUS\r\nTAG OK\r\n"
		case "LIST":
			return "* LIST (\\HasNoChildren) \"/\" INBOX\r\n* LIST (\\HasNoChildren) \"/\" Archive\r\nTAG OK List completed\r\n"
		case "SELECT":
			return "* 1 EXISTS\r\n* OK [UIDVALIDITY 7] UIDs valid\r\nTAG OK [READ-WRITE] Select completed\r\n"
		case "UID FETCH":
			m := eml("<m@example.com>", "a message")
			return fmt.Sprintf("* 1 FETCH (UID 500 BODY[] {%d}\r\n%s)\r\n", len(m), m) + "TAG OK Fetch completed\r\n"
		}
		return "TAG BAD unexpected\r\n"
	})
	host, port, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	collector := NewEmailCollector(EmailCollectorConfig{
		Host: host, Port: p, Username: "u@example.com", Password: "pw", TLSConfig: clientTLS,
		Warn: func(string) {},
		LastFolderStats: []model.EmailFolderStat{
			// INBOX was recreated: the server now says UIDVALIDITY 7.
			{Folder: "INBOX", UIDValidity: 10001, HighestUID: 450},
			// Archive is the mailbox it was.
			{Folder: "Archive", UIDValidity: 7, HighestUID: 120},
		},
	})
	stream, _, err := collector.ScanAndStream(context.Background(), nil)
	if err != nil {
		t.Fatalf("ScanAndStream: %v", err)
	}
	if _, err := io.ReadAll(stream); err != nil {
		t.Fatal(err)
	}
	fetches := map[string]string{}
	var selected string
	for _, c := range srv.recorded() {
		_, rest, _ := strings.Cut(c, " ")
		switch {
		case strings.HasPrefix(rest, "SELECT "):
			selected = strings.Trim(strings.TrimPrefix(rest, "SELECT "), `"`)
		case strings.HasPrefix(rest, "UID FETCH "):
			fetches[selected] = rest
		}
	}
	for folder, want := range map[string]string{"INBOX": "UID FETCH 1:* ", "Archive": "UID FETCH 121:* "} {
		got, ok := fetches[folder]
		if !ok {
			t.Fatalf("%s was never fetched; commands sent: %v", folder, fetches)
		}
		if !strings.HasPrefix(got, want) {
			t.Errorf("%s fetched with %q, want %q", folder, got, want)
		}
		if !strings.Contains(got, "BODY.PEEK[]") {
			t.Errorf("%s fetched with %q: without BODY.PEEK[] the server marks every message read", folder, got)
		}
	}
}

func TestParseListLineSkipsMailboxesThatCannotBeSelected(t *testing.T) {
	cases := []struct {
		line   string
		folder string
		ok     bool
	}{
		{`* LIST (\HasNoChildren) "/" "INBOX"`, "INBOX", true},
		{`* LIST (\HasChildren \Noselect) "/" "[Gmail]"`, "", false},
		{`* LIST (\HasNoChildren \All) "/" "[Gmail]/All Mail"`, "[Gmail]/All Mail", true},
		{`* LIST (\NoSelect) "." "Archive"`, "", false},
		{`* LIST (\NonExistent) "/" "Gone"`, "", false},
		{`* LIST (\HasNoChildren) NIL "Flat"`, "Flat", true},
		{`* LIST () "." Drafts`, "Drafts", true},
		{`* OK done`, "", false},
	}
	for _, c := range cases {
		folder, _, ok := parseListLine(c.line)
		if folder != c.folder || ok != c.ok {
			t.Errorf("parseListLine(%q) = %q, %v; want %q, %v", c.line, folder, ok, c.folder, c.ok)
		}
	}
}
