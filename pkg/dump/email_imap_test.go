package dump

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// selfSignedTLS returns a server config for 127.0.0.1 and a client config
// that trusts it.
func selfSignedTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "imap.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	server := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	client := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	return server, client
}

// scriptedIMAP answers each command with respond(verb, args), with "TAG"
// in the reply replaced by the command's tag. Commands are recorded.
type scriptedIMAP struct {
	addr     string
	commands chan string
}

func startScriptedIMAP(t *testing.T, cfg *tls.Config, respond func(verb, args string) string) *scriptedIMAP {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &scriptedIMAP{addr: ln.Addr().String(), commands: make(chan string, 64)}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		_, _ = io.WriteString(conn, "* OK scripted IMAP ready\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			s.commands <- line
			parts := strings.SplitN(line, " ", 3)
			tag, verb, args := parts[0], "", ""
			if len(parts) > 1 {
				verb = strings.ToUpper(parts[1])
			}
			if len(parts) > 2 {
				args = parts[2]
			}
			if verb == "UID" {
				sub := strings.SplitN(args, " ", 2)
				verb, args = "UID "+strings.ToUpper(sub[0]), sub[1]
			}
			if verb == "LOGOUT" {
				_, _ = io.WriteString(conn, "* BYE\r\n"+tag+" OK LOGOUT\r\n")
				return
			}
			_, _ = io.WriteString(conn, strings.ReplaceAll(respond(verb, args), "TAG", tag))
		}
	}()
	return s
}

func (s *scriptedIMAP) recorded() []string {
	var out []string
	for {
		select {
		case c := <-s.commands:
			out = append(out, c)
		default:
			return out
		}
	}
}

func eml(id, subject string) []byte {
	return []byte("From: a@example.com\r\nSubject: " + subject + "\r\nDate: Mon, 28 Sep 2026 10:00:00 +0000\r\nMessage-ID: " + id + "\r\n\r\nbody of " + subject)
}

// gmailScript answers like imap.gmail.com: X-GM-EXT-1, a \Noselect [Gmail]
// container, a localized \All mailbox, and labels on either side of the body.
func gmailScript(t *testing.T, allMailListed bool, msg1, msg2 []byte) func(verb, args string) string {
	return func(verb, args string) string {
		switch verb {
		case "LOGIN":
			return "TAG OK LOGIN completed\r\n"
		case "CAPABILITY":
			return "* CAPABILITY IMAP4rev1 UNSELECT IDLE NAMESPACE QUOTA ID XLIST CHILDREN X-GM-EXT-1 UIDPLUS\r\nTAG OK Thats all she wrote!\r\n"
		case "LIST":
			out := "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n" +
				"* LIST (\\HasChildren \\Noselect) \"/\" \"[Google Mail]\"\r\n" +
				"* LIST (\\HasNoChildren \\Sent) \"/\" \"[Google Mail]/Sent Mail\"\r\n" +
				"* LIST (\\HasNoChildren) \"/\" \"Work stuff\"\r\n"
			if allMailListed {
				out += "* LIST (\\All \\HasNoChildren) \"/\" \"[Google Mail]/All Mail\"\r\n"
			}
			return out + "TAG OK Success\r\n"
		case "SELECT":
			if allMailListed && args != `"[Google Mail]/All Mail"` {
				t.Errorf("selected %s; with All Mail listed only All Mail should be selected", args)
			}
			return "* FLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen)\r\n* 2 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 7] UIDs valid.\r\nTAG OK [READ-WRITE] Success\r\n"
		case "UID FETCH":
			if !strings.Contains(args, "X-GM-LABELS") {
				t.Errorf("FETCH %s did not ask for X-GM-LABELS", args)
			}
			return fmt.Sprintf("* 1 FETCH (X-GM-LABELS (\\Inbox \"Work stuff\" \"UID 99\" \"say \\\"hi\\\"\") UID 11 BODY[] {%d}\r\n%s)\r\n", len(msg1), msg1) +
				fmt.Sprintf("* 2 FETCH (UID 12 BODY[] {%d}\r\n%s X-GM-LABELS (\"\\\\Sent\"))\r\n", len(msg2), msg2) +
				"TAG OK Success\r\n"
		}
		return "TAG BAD unexpected\r\n"
	}
}

func TestGmailIsBackedUpFromAllMailOnceWithItsLabels(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	// A Gmail Message-ID with + and =, which the verifier used to miss.
	msg1 := eml("<CAB+x=y_1@mail.gmail.com>", "first")
	msg2 := eml("<sent-2@example.com>", "second")
	srv := startScriptedIMAP(t, serverTLS, gmailScript(t, true, msg1, msg2))

	host, port, _ := net.SplitHostPort(srv.addr)
	var p int
	fmt.Sscan(port, &p)
	var warnings []string
	collector := NewEmailCollector(EmailCollectorConfig{
		Host: host, Port: p, Username: "u@example.com", Password: "pw",
		ExcludeFolders: []string{"[Gmail]/Spam", "[Gmail]/Trash"},
		TLSConfig:      clientTLS,
		Warn:           func(m string) { warnings = append(warnings, m) },
	})
	stream, meta, err := collector.ScanAndStream(context.Background(), nil)
	if err != nil {
		t.Fatalf("ScanAndStream: %v", err)
	}
	archive, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if meta.TotalItems != 2 || meta.TotalContainers != 1 {
		t.Fatalf("snapshot counts %d messages in %d folders, want 2 in 1", meta.TotalItems, meta.TotalContainers)
	}
	for _, c := range srv.recorded() {
		if strings.Contains(c, "SELECT") && !strings.Contains(c, "All Mail") {
			t.Errorf("sent %q; only All Mail should be selected", c)
		}
	}

	// The drill passes on what the collector wrote.
	res, err := NewEmailRestorer().InspectEmailArchive(context.Background(), bytes.NewReader(archive), meta)
	if err != nil || !res.Passed {
		t.Fatalf("drill did not pass: %+v, %v", res, err)
	}
	if !res.SealedManifest.GmailAllMail {
		t.Error("sealed manifest does not say it holds Gmail's All Mail")
	}

	// A restore writes the manifest, and the labels read back from it.
	dir := t.TempDir()
	ext, err := NewEmailRestorer().ExtractEmailArchive(context.Background(), bytes.NewReader(archive), dir)
	if err != nil {
		t.Fatal(err)
	}
	if ext.EmailsExtracted != 2 || !ext.GmailLabels || ext.ManifestPath == "" {
		t.Fatalf("extraction: %+v", ext)
	}
	data, err := os.ReadFile(ext.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var sealed SealedEmailManifest
	if err := json.Unmarshal(data, &sealed); err != nil {
		t.Fatal(err)
	}
	want := map[uint32][]string{
		11: {`\Inbox`, "Work stuff", "UID 99", `say "hi"`},
		12: {`\Sent`},
	}
	for _, m := range sealed.Messages {
		if !reflect.DeepEqual(m.Labels, want[m.UID]) {
			t.Errorf("UID %d labels = %q, want %q", m.UID, m.Labels, want[m.UID])
		}
		body, err := os.ReadFile(filepath.Join(dir, m.Path))
		if err != nil {
			t.Errorf("restored %s: %v", m.Path, err)
			continue
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != m.Sha256 {
			t.Errorf("restored %s does not match its sealed digest", m.Path)
		}
	}
	if len(sealed.Messages) != 2 {
		t.Fatalf("manifest lists %d messages, want 2", len(sealed.Messages))
	}
}

func TestGmailWithoutAllMailFallsBackToFoldersAndSaysSo(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	msg1, msg2 := eml("<a@x>", "a"), eml("<b@x>", "b")
	srv := startScriptedIMAP(t, serverTLS, gmailScript(t, false, msg1, msg2))
	host, port, _ := net.SplitHostPort(srv.addr)
	var p int
	fmt.Sscan(port, &p)
	var warnings []string
	collector := NewEmailCollector(EmailCollectorConfig{
		Host: host, Port: p, Username: "u", Password: "pw", TLSConfig: clientTLS,
		Warn: func(m string) { warnings = append(warnings, m) },
	})
	stream, meta, err := collector.ScanAndStream(context.Background(), nil)
	if err != nil {
		t.Fatalf("ScanAndStream: %v", err)
	}
	_, _ = io.Copy(io.Discard, stream)
	if meta.TotalContainers != 3 {
		t.Errorf("backed up %d folders, want the 3 selectable ones", meta.TotalContainers)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "All Mail") {
		t.Errorf("warnings = %q, want one naming All Mail", warnings)
	}
}

func TestEmailDrillFailsWhenArchiveAndManifestDisagree(t *testing.T) {
	body := eml("<m@x>", "m")
	sum := sha256.Sum256(body)
	build := func(manifestPath, entryPath string) []byte {
		man, _ := json.Marshal(SealedEmailManifest{TotalEmails: 1, Messages: []EmailMessageManifest{
			{Path: manifestPath, Folder: "INBOX", UID: 1, Sha256: hex.EncodeToString(sum[:])},
		}})
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: ".safegrd-email-manifest.json", Mode: 0600, Size: int64(len(man)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(man)
		_ = tw.WriteHeader(&tar.Header{Name: entryPath, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
		_ = tw.Close()
		return buf.Bytes()
	}

	ok, err := NewEmailRestorer().InspectEmailArchive(context.Background(), bytes.NewReader(build("INBOX/1-m.eml", "INBOX/1-m.eml")), nil)
	if err != nil || !ok.Passed {
		t.Fatalf("matching archive did not pass: %+v, %v", ok, err)
	}
	bad, err := NewEmailRestorer().InspectEmailArchive(context.Background(), bytes.NewReader(build("INBOX/1-m.eml", "INBOX/1-other.eml")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if bad.Passed || !strings.Contains(bad.ErrorMessage, "not in the sealed manifest") {
		t.Fatalf("an entry the manifest does not list passed the drill: %+v", bad)
	}
}
