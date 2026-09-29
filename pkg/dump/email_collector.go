package dump

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// EmailMessageManifest records individual email details sealed inside the archive.
type EmailMessageManifest struct {
	// Path is the message's entry in the archive. The verifier looks entries
	// up by it rather than rebuilding the name from the Message-ID.
	Path      string    `json:"path"`
	Folder    string    `json:"folder"`
	UID       uint32    `json:"uid"`
	MessageID string    `json:"message_id"`
	Subject   string    `json:"subject"`
	From      string    `json:"from"`
	Date      time.Time `json:"date"`
	SizeBytes int64     `json:"size_bytes"`
	Sha256    string    `json:"sha256"`
	// Labels are the message's Gmail labels (X-GM-LABELS) as the server sent
	// them, system labels such as \Inbox included. Empty for other providers.
	Labels []string `json:"labels,omitempty"`
}

// SealedEmailManifest is stored as .safegrd-email-manifest.json inside the sealed archive.
type SealedEmailManifest struct {
	Version      string    `json:"version"`
	Account      string    `json:"account"`
	Host         string    `json:"host"`
	CreatedAt    time.Time `json:"created_at"`
	TotalEmails  int64     `json:"total_emails"`
	TotalFolders int       `json:"total_folders"`
	RawSizeBytes int64     `json:"raw_size_bytes"`
	// GmailAllMail is set when the archive holds only Gmail's All Mail, one
	// copy per message, and each message's labels stand in for its folders.
	GmailAllMail bool                    `json:"gmail_all_mail,omitempty"`
	Folders      []model.EmailFolderStat `json:"folders"`
	Messages     []EmailMessageManifest  `json:"messages"`
}

// EmailCollectorConfig configures Universal IMAP extraction.
type EmailCollectorConfig struct {
	// Warn reports a condition that does not fail the backup. Defaults to stderr.
	Warn           func(msg string)
	Host           string
	Port           int
	Username       string
	Password       string
	IncludeFolders []string
	ExcludeFolders []string
	ArchiveTime    time.Time
	// LastFolderStats carries previous UID sequence metadata for incremental sync
	LastFolderStats []model.EmailFolderStat
	TLSConfig       *tls.Config
}

// EmailCollector extracts emails via IMAP into an encrypted streaming EML tarball.
type EmailCollector struct {
	cfg EmailCollectorConfig
}

// NewEmailCollector creates a new EmailCollector.
func NewEmailCollector(cfg EmailCollectorConfig) *EmailCollector {
	if cfg.Port == 0 {
		cfg.Port = 993
	}
	if cfg.Warn == nil {
		cfg.Warn = func(msg string) { fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg) }
	}
	return &EmailCollector{cfg: cfg}
}

// FetchedEmail represents a single retrieved RFC 5322 MIME message.
type FetchedEmail struct {
	Folder    string
	UID       uint32
	MessageID string
	Subject   string
	From      string
	Date      time.Time
	Body      []byte
	Sha256    string
	Labels    []string
}

// IMAPSource abstracts the IMAP connection to enable hermetic testing and modularity.
type IMAPSource interface {
	Connect(ctx context.Context) error
	ListFolders(ctx context.Context) ([]string, error)
	FetchFolderMessages(ctx context.Context, folder string) ([]FetchedEmail, error)
	Close() error
}

// GmailSource is implemented by an IMAPSource that can tell whether it is
// talking to Gmail.
type GmailSource interface {
	// GmailAllMail reports whether the server advertises X-GM-EXT-1, and the
	// mailbox it flags \All, if it lists one. Valid after ListFolders.
	GmailAllMail() (allMail string, gmail bool)
}

// StandardIMAPClient implements pure Go RFC 3501 IMAP client over TLS.
type StandardIMAPClient struct {
	cfg               EmailCollectorConfig
	conn              *tls.Conn
	reader            *bufio.Reader
	tagSeq            int
	FolderUIDValidity map[string]uint32
	FolderHighestUID  map[string]uint32
	gmail             bool
	allMail           string
}

func NewStandardIMAPClient(cfg EmailCollectorConfig) *StandardIMAPClient {
	c := &StandardIMAPClient{
		cfg:               cfg,
		FolderUIDValidity: make(map[string]uint32),
		FolderHighestUID:  make(map[string]uint32),
	}
	for _, f := range cfg.LastFolderStats {
		if f.UIDValidity > 0 {
			c.FolderUIDValidity[f.Folder] = f.UIDValidity
			c.FolderHighestUID[f.Folder] = f.HighestUID
		}
	}
	return c
}

func (c *StandardIMAPClient) nextTag() string {
	c.tagSeq++
	return fmt.Sprintf("A%04d", c.tagSeq)
}

func (c *StandardIMAPClient) Connect(ctx context.Context) error {
	tlsCfg := c.cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			ServerName: c.cfg.Host,
			MinVersion: tls.VersionTLS12,
		}
	}

	addr := fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port)
	dialer := &tls.Dialer{Config: tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed connecting to IMAP server over TLS (%s): %w", addr, err)
	}

	c.conn = conn.(*tls.Conn)
	c.reader = bufio.NewReader(c.conn)

	// Read greeting banner
	greeting, err := c.reader.ReadString('\n')
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("failed reading IMAP greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		c.conn.Close()
		return fmt.Errorf("unexpected IMAP greeting: %s", strings.TrimSpace(greeting))
	}

	// Login
	tag := c.nextTag()
	loginCmd := fmt.Sprintf("%s LOGIN %s %s\r\n", tag, quoteIMAP(c.cfg.Username), quoteIMAP(c.cfg.Password))
	if _, err := c.conn.Write([]byte(loginCmd)); err != nil {
		c.conn.Close()
		return fmt.Errorf("failed sending LOGIN: %w", err)
	}

	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			c.conn.Close()
			return fmt.Errorf("error waiting for LOGIN response: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" OK") {
			break
		}
		if strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
			c.conn.Close()
			return fmt.Errorf("IMAP authentication failed: %s", line)
		}
	}

	// Capabilities can change once authenticated, so ask again now.
	caps, err := c.capabilities()
	if err != nil {
		c.conn.Close()
		return err
	}
	c.gmail = caps["X-GM-EXT-1"]
	return nil
}

func (c *StandardIMAPClient) capabilities() (map[string]bool, error) {
	tag := c.nextTag()
	if _, err := c.conn.Write([]byte(tag + " CAPABILITY\r\n")); err != nil {
		return nil, fmt.Errorf("failed sending CAPABILITY: %w", err)
	}
	caps := make(map[string]bool)
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed reading CAPABILITY response: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" OK") {
			return caps, nil
		}
		if strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
			return nil, fmt.Errorf("CAPABILITY rejected: %s", line)
		}
		if rest, ok := strings.CutPrefix(line, "* CAPABILITY "); ok {
			for _, capability := range strings.Fields(rest) {
				caps[strings.ToUpper(capability)] = true
			}
		}
	}
}

// GmailAllMail implements GmailSource.
func (c *StandardIMAPClient) GmailAllMail() (string, bool) {
	return c.allMail, c.gmail
}

func quoteIMAP(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func (c *StandardIMAPClient) ListFolders(ctx context.Context) ([]string, error) {
	tag := c.nextTag()
	cmd := fmt.Sprintf("%s LIST \"\" \"*\"\r\n", tag)
	if _, err := c.conn.Write([]byte(cmd)); err != nil {
		return nil, fmt.Errorf("failed sending LIST: %w", err)
	}

	var folders []string

	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed reading LIST response: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")

		if strings.HasPrefix(line, tag+" OK") {
			break
		}
		if strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
			return nil, fmt.Errorf("LIST command rejected: %s", line)
		}

		if folder, flags, ok := parseListLine(line); ok {
			folders = append(folders, folder)
			if hasFlag(flags, `\All`) {
				c.allMail = folder
			}
		}
	}

	return folders, nil
}

var listLineRegex = regexp.MustCompile(`^\*\s+LIST\s+\((.*?)\)\s+(?:"(?:[^"\\]|\\.)*"|NIL)\s+(.*)$`)

// parseListLine returns the mailbox named by one untagged LIST response and
// its flags, or false when the line is not one or names a mailbox that cannot
// be selected. Gmail's "[Gmail]" is such a container (\Noselect); selecting it
// fails with NONEXISTENT.
func parseListLine(line string) (string, []string, bool) {
	matches := listLineRegex.FindStringSubmatch(line)
	if len(matches) != 3 {
		return "", nil, false
	}
	flags := strings.Fields(matches[1])
	if hasFlag(flags, `\Noselect`) || hasFlag(flags, `\NonExistent`) {
		return "", nil, false
	}
	folder := strings.Trim(strings.TrimSpace(matches[2]), `"`)
	return folder, flags, folder != ""
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, want) {
			return true
		}
	}
	return false
}

// cutGmailLabels removes the X-GM-LABELS list from a FETCH response and
// returns its labels, unquoted, and the response without it. Labels are
// atoms (\Inbox, Work) or quoted strings with \" and \\ escapes.
func cutGmailLabels(s string) ([]string, string) {
	start := strings.Index(strings.ToUpper(s), "X-GM-LABELS (")
	if start < 0 {
		return nil, s
	}
	i := start + len("X-GM-LABELS (")
	labels := []string{}
	for i < len(s) {
		switch s[i] {
		case ' ':
			i++
		case ')':
			return labels, s[:start] + s[i+1:]
		case '"':
			var b strings.Builder
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				b.WriteByte(s[i])
				i++
			}
			i++
			labels = append(labels, b.String())
		default:
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != ')' {
				j++
			}
			labels = append(labels, s[i:j])
			i = j
		}
	}
	return nil, s
}

func (c *StandardIMAPClient) FetchFolderMessages(ctx context.Context, folder string) ([]FetchedEmail, error) {
	selectTag := c.nextTag()
	cmd := fmt.Sprintf("%s SELECT %s\r\n", selectTag, quoteIMAP(folder))
	if _, err := c.conn.Write([]byte(cmd)); err != nil {
		return nil, fmt.Errorf("failed sending SELECT %s: %w", folder, err)
	}

	var messageCount int64
	existsRegex := regexp.MustCompile(`^\*\s+(\d+)\s+EXISTS`)
	uidvalidityRegex := regexp.MustCompile(`\[UIDVALIDITY\s+(\d+)\]`)

	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed reading SELECT response: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")

		if matches := existsRegex.FindStringSubmatch(line); len(matches) == 2 {
			count, _ := strconv.ParseInt(matches[1], 10, 64)
			messageCount = count
		}
		if matches := uidvalidityRegex.FindStringSubmatch(line); len(matches) == 2 {
			val, _ := strconv.ParseUint(matches[1], 10, 32)
			newValidity := uint32(val)
			if prevVal, exists := c.FolderUIDValidity[folder]; exists && prevVal != newValidity {
				c.FolderHighestUID[folder] = 0
			}
			c.FolderUIDValidity[folder] = newValidity
		}

		if strings.HasPrefix(line, selectTag+" OK") {
			break
		}
		if strings.HasPrefix(line, selectTag+" NO") || strings.HasPrefix(line, selectTag+" BAD") {
			return nil, fmt.Errorf("SELECT %s failed: %s", folder, line)
		}
	}

	if messageCount == 0 {
		return nil, nil
	}

	lastHighest := c.FolderHighestUID[folder]
	fetchTag := c.nextTag()
	items := "UID BODY.PEEK[]"
	if c.gmail {
		items = "UID X-GM-LABELS BODY.PEEK[]"
	}
	fetchCmd := fmt.Sprintf("%s UID FETCH %d:* (%s)\r\n", fetchTag, lastHighest+1, items)
	if _, err := c.conn.Write([]byte(fetchCmd)); err != nil {
		return nil, fmt.Errorf("failed sending UID FETCH: %w", err)
	}

	var messages []FetchedEmail
	uidRegex := regexp.MustCompile(`(?:^|[\s(])UID\s+(\d+)`)
	// Only a literal that follows BODY[] is the message. Gmail does not keep
	// the requested item order, so UID and labels may sit on either side of it.
	bodyLiteralRegex := regexp.MustCompile(`BODY\[\]\s+\{(\d+)\}$`)

	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed reading FETCH response: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")

		if strings.HasPrefix(line, fetchTag+" OK") {
			break
		}
		if strings.HasPrefix(line, fetchTag+" NO") || strings.HasPrefix(line, fetchTag+" BAD") {
			return nil, fmt.Errorf("FETCH command failed: %s", line)
		}

		if strings.HasPrefix(line, "* ") && strings.Contains(line, "FETCH") {

			if matches := bodyLiteralRegex.FindStringSubmatch(line); len(matches) == 2 {
				litSize, _ := strconv.ParseInt(matches[1], 10, 64)
				body := make([]byte, litSize)
				if _, err := io.ReadFull(c.reader, body); err != nil {
					return nil, fmt.Errorf("failed reading message body literal (%d bytes): %w", litSize, err)
				}
				// The rest of the response: ")" or the items after the body.
				rest, err := c.reader.ReadString('\n')
				if err != nil {
					return nil, fmt.Errorf("failed reading FETCH response: %w", err)
				}
				labels, others := cutGmailLabels(line + " " + strings.TrimRight(rest, "\r\n"))

				var uid uint32
				if matches := uidRegex.FindStringSubmatch(others); len(matches) == 2 {
					val, _ := strconv.ParseUint(matches[1], 10, 32)
					uid = uint32(val)
				}

				if uid > c.FolderHighestUID[folder] {
					c.FolderHighestUID[folder] = uid
				}
				if lastHighest > 0 && uid <= lastHighest {
					continue
				}

				sum := sha256.Sum256(body)
				sumHex := hex.EncodeToString(sum[:])

				var (
					msgID   = fmt.Sprintf("<%d@safegrd.generated>", uid)
					subject = "(no subject)"
					from    = "(unknown)"
					date    = time.Now().UTC()
				)

				msg, err := mail.ReadMessage(strings.NewReader(string(body)))
				if err == nil {
					if id := msg.Header.Get("Message-ID"); id != "" {
						msgID = id
					}
					if s := msg.Header.Get("Subject"); s != "" {
						subject = s
					}
					if f := msg.Header.Get("From"); f != "" {
						from = f
					}
					if d, err := msg.Header.Date(); err == nil {
						date = d.UTC()
					}
				}

				messages = append(messages, FetchedEmail{
					Folder:    folder,
					UID:       uid,
					MessageID: msgID,
					Subject:   subject,
					From:      from,
					Date:      date,
					Body:      body,
					Sha256:    sumHex,
					Labels:    labels,
				})
			}
		}
	}

	return messages, nil
}

func (c *StandardIMAPClient) Close() error {
	if c.conn != nil {
		tag := c.nextTag()
		_, _ = c.conn.Write([]byte(tag + " LOGOUT\r\n"))
		return c.conn.Close()
	}
	return nil
}

// ScanAndStream collects all folders and emails, and streams an encrypted POSIX tarball of EML files.
func (ec *EmailCollector) ScanAndStream(ctx context.Context, source IMAPSource) (io.Reader, *model.SnapshotMetadata, error) {
	if source == nil {
		source = NewStandardIMAPClient(ec.cfg)
	}

	if err := source.Connect(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed connecting to IMAP mailbox: %w", err)
	}

	folders, err := source.ListFolders(ctx)
	if err != nil {
		_ = source.Close()
		return nil, nil, fmt.Errorf("failed listing folders: %w", err)
	}

	var targetFolders []string
	for _, f := range folders {
		if MatchesExclude(f, ec.cfg.ExcludeFolders) {
			continue
		}
		if len(ec.cfg.IncludeFolders) > 0 && !MatchesExclude(f, ec.cfg.IncludeFolders) {
			continue
		}
		targetFolders = append(targetFolders, f)
	}
	sort.Strings(targetFolders)

	// Gmail shows each label as a folder, so a message with three labels would
	// be fetched and stored three times. All Mail holds every message once
	// (Spam and Trash aside, which are left out anyway) and X-GM-LABELS carries
	// the labels, so back up that mailbox alone. A surface that names its
	// folders keeps them.
	//
	// If another provider turns out to show one message in several folders,
	// do not add a second provider branch here. Deduplicate by content
	// instead: store each body once, keyed by the SHA-256 already taken for
	// every message, and list in the manifest every folder that holds it.
	// That still downloads each copy, but it works for any server.
	gmailAllMail := false
	if gs, ok := source.(GmailSource); ok && len(ec.cfg.IncludeFolders) == 0 {
		switch allMail, gmail := gs.GmailAllMail(); {
		case gmail && allMail != "":
			targetFolders = []string{allMail}
			gmailAllMail = true
		case gmail:
			ec.cfg.Warn(fmt.Sprintf("%s lists no All Mail folder over IMAP, so each label is backed up as its own folder "+
				"and a message with several labels is stored once per label. Turn on \"Show in IMAP\" for All Mail "+
				"in Gmail's settings (Labels tab).", ec.cfg.Host))
		}
	}

	var (
		allEmails     []FetchedEmail
		folderStats   []model.EmailFolderStat
		totalRawBytes int64
		oldestDate    *time.Time
		newestDate    *time.Time
	)

	for _, folder := range targetFolders {
		msgs, err := source.FetchFolderMessages(ctx, folder)
		if err != nil {
			_ = source.Close()
			return nil, nil, fmt.Errorf("failed fetching messages from %s: %w", folder, err)
		}

		var fBytes int64
		for _, m := range msgs {
			fBytes += int64(len(m.Body))
			totalRawBytes += int64(len(m.Body))

			if oldestDate == nil || m.Date.Before(*oldestDate) {
				t := m.Date
				oldestDate = &t
			}
			if newestDate == nil || m.Date.After(*newestDate) {
				t := m.Date
				newestDate = &t
			}
			allEmails = append(allEmails, m)
		}

		var uidVal, highUID uint32
		if std, ok := source.(*StandardIMAPClient); ok {
			uidVal = std.FolderUIDValidity[folder]
			highUID = std.FolderHighestUID[folder]
		}
		folderStats = append(folderStats, model.EmailFolderStat{
			Folder:       folder,
			MessageCount: int64(len(msgs)),
			SizeBytes:    fBytes,
			UIDValidity:  uidVal,
			HighestUID:   highUID,
		})
	}
	_ = source.Close()

	sort.Slice(allEmails, func(i, j int) bool {
		if allEmails[i].Folder != allEmails[j].Folder {
			return allEmails[i].Folder < allEmails[j].Folder
		}
		return allEmails[i].UID < allEmails[j].UID
	})

	archiveTime := ec.cfg.ArchiveTime
	if archiveTime.IsZero() {
		archiveTime = time.Now().UTC().Truncate(time.Second)
	}

	var manifestMessages []EmailMessageManifest
	for _, em := range allEmails {
		manifestMessages = append(manifestMessages, EmailMessageManifest{
			Path:      emailEntryName(em),
			Folder:    em.Folder,
			UID:       em.UID,
			MessageID: em.MessageID,
			Subject:   em.Subject,
			From:      em.From,
			Date:      em.Date,
			SizeBytes: int64(len(em.Body)),
			Sha256:    em.Sha256,
			Labels:    em.Labels,
		})
	}

	sealedManifest := SealedEmailManifest{
		Version:      "1.0",
		Account:      ec.cfg.Username,
		Host:         ec.cfg.Host,
		CreatedAt:    archiveTime,
		TotalEmails:  int64(len(allEmails)),
		TotalFolders: len(targetFolders),
		RawSizeBytes: totalRawBytes,
		GmailAllMail: gmailAllMail,
		Folders:      folderStats,
		Messages:     manifestMessages,
	}

	sealedBytes, err := json.MarshalIndent(sealedManifest, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshaling sealed email manifest: %w", err)
	}

	meta := &model.SnapshotMetadata{
		SurfaceType:     model.SurfaceTypeEmail,
		TotalItems:      int64(len(allEmails)),
		TotalContainers: len(targetFolders),
		RawSizeBytes:    totalRawBytes,
		EmailStats: &model.EmailStatsSummary{
			TotalEmails:  int64(len(allEmails)),
			TotalFolders: len(targetFolders),
			Folders:      folderStats,
			OldestDate:   oldestDate,
			NewestDate:   newestDate,
		},
		CreatedAt: archiveTime,
	}

	pr, pw := io.Pipe()

	go func() {
		tw := tar.NewWriter(pw)
		var writeErr error

		defer func() {
			if writeErr != nil {
				_ = pw.CloseWithError(writeErr)
			} else {
				_ = tw.Close()
				_ = pw.Close()
			}
		}()

		manHeader := &tar.Header{
			Name:     ".safegrd-email-manifest.json",
			Mode:     0600,
			Size:     int64(len(sealedBytes)),
			ModTime:  archiveTime,
			Format:   tar.FormatPAX,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(manHeader); err != nil {
			writeErr = fmt.Errorf("failed writing sealed email manifest header: %w", err)
			return
		}
		if _, err := tw.Write(sealedBytes); err != nil {
			writeErr = fmt.Errorf("failed writing sealed email manifest body: %w", err)
			return
		}

		for _, f := range targetFolders {
			dirHdr := &tar.Header{
				Name:     filepath.ToSlash(f) + "/",
				Mode:     0755,
				ModTime:  archiveTime,
				Format:   tar.FormatPAX,
				Typeflag: tar.TypeDir,
			}
			if err := tw.WriteHeader(dirHdr); err != nil {
				writeErr = fmt.Errorf("failed writing folder header for %s: %w", f, err)
				return
			}
		}

		for _, em := range allEmails {
			select {
			case <-ctx.Done():
				writeErr = ctx.Err()
				return
			default:
			}

			entryName := emailEntryName(em)

			msgHdr := &tar.Header{
				Name:     entryName,
				Mode:     0644,
				Size:     int64(len(em.Body)),
				ModTime:  em.Date,
				Format:   tar.FormatPAX,
				Typeflag: tar.TypeReg,
			}
			if err := tw.WriteHeader(msgHdr); err != nil {
				writeErr = fmt.Errorf("failed writing email header for %s: %w", entryName, err)
				return
			}
			if _, err := tw.Write(em.Body); err != nil {
				writeErr = fmt.Errorf("failed writing email body for %s: %w", entryName, err)
				return
			}
		}
	}()

	return pr, meta, nil
}

var entryNameUnsafe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// emailEntryName is a message's path in the archive: its folder, then its UID
// and up to 32 characters of its Message-ID.
func emailEntryName(em FetchedEmail) string {
	id := entryNameUnsafe.ReplaceAllString(em.MessageID, "_")
	if len(id) > 32 {
		id = id[:32]
	}
	return fmt.Sprintf("%s/%d-%s.eml", filepath.ToSlash(em.Folder), em.UID, id)
}
