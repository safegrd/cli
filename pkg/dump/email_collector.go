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
	Folder    string    `json:"folder"`
	UID       uint32    `json:"uid"`
	MessageID string    `json:"message_id"`
	Subject   string    `json:"subject"`
	From      string    `json:"from"`
	Date      time.Time `json:"date"`
	SizeBytes int64     `json:"size_bytes"`
	Sha256    string    `json:"sha256"`
}

// SealedEmailManifest is stored as .safegrd-email-manifest.json inside the sealed archive.
type SealedEmailManifest struct {
	Version      string                  `json:"version"`
	Account      string                  `json:"account"`
	Host         string                  `json:"host"`
	CreatedAt    time.Time               `json:"created_at"`
	TotalEmails  int64                   `json:"total_emails"`
	TotalFolders int                     `json:"total_folders"`
	RawSizeBytes int64                   `json:"raw_size_bytes"`
	Folders      []model.EmailFolderStat `json:"folders"`
	Messages     []EmailMessageManifest  `json:"messages"`
}

// EmailCollectorConfig configures Universal IMAP extraction.
type EmailCollectorConfig struct {
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
}

// IMAPSource abstracts the IMAP connection to enable hermetic testing and modularity.
type IMAPSource interface {
	Connect(ctx context.Context) error
	ListFolders(ctx context.Context) ([]string, error)
	FetchFolderMessages(ctx context.Context, folder string) ([]FetchedEmail, error)
	Close() error
}

// StandardIMAPClient implements pure Go RFC 3501 IMAP client over TLS.
type StandardIMAPClient struct {
	cfg               EmailCollectorConfig
	conn              *tls.Conn
	reader            *bufio.Reader
	tagSeq            int
	FolderUIDValidity map[string]uint32
	FolderHighestUID  map[string]uint32
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

	return nil
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
	listRegex := regexp.MustCompile(`^\*\s+LIST\s+\(.*?\)\s+"(.*?)"\s+(.*)$`)

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

		if matches := listRegex.FindStringSubmatch(line); len(matches) == 3 {
			folder := strings.Trim(strings.TrimSpace(matches[2]), `"`)
			if folder != "" {
				folders = append(folders, folder)
			}
		}
	}

	return folders, nil
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
	var fetchCmd string
	if lastHighest > 0 {
		fetchCmd = fmt.Sprintf("%s UID FETCH %d:* (UID BODY.PEEK[])\r\n", fetchTag, lastHighest+1)
	} else {
		fetchCmd = fmt.Sprintf("%s UID FETCH 1:* (UID BODY.PEEK[])\r\n", fetchTag)
	}
	if _, err := c.conn.Write([]byte(fetchCmd)); err != nil {
		return nil, fmt.Errorf("failed sending UID FETCH: %w", err)
	}

	var messages []FetchedEmail
	uidRegex := regexp.MustCompile(`UID\s+(\d+)`)
	literalRegex := regexp.MustCompile(`\{(\d+)\}$`)

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
			var uid uint32
			if matches := uidRegex.FindStringSubmatch(line); len(matches) == 2 {
				val, _ := strconv.ParseUint(matches[1], 10, 32)
				uid = uint32(val)
			}

			// Check for literal size {N}
			if matches := literalRegex.FindStringSubmatch(line); len(matches) == 2 {
				litSize, _ := strconv.ParseInt(matches[1], 10, 64)
				body := make([]byte, litSize)
				if _, err := io.ReadFull(c.reader, body); err != nil {
					return nil, fmt.Errorf("failed reading message body literal (%d bytes): %w", litSize, err)
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
			Folder:    em.Folder,
			UID:       em.UID,
			MessageID: em.MessageID,
			Subject:   em.Subject,
			From:      em.From,
			Date:      em.Date,
			SizeBytes: int64(len(em.Body)),
			Sha256:    em.Sha256,
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

		cleanRegex := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
		for _, em := range allEmails {
			select {
			case <-ctx.Done():
				writeErr = ctx.Err()
				return
			default:
			}

			cleanMsgID := cleanRegex.ReplaceAllString(em.MessageID, "_")
			if len(cleanMsgID) > 32 {
				cleanMsgID = cleanMsgID[:32]
			}
			entryName := fmt.Sprintf("%s/%d-%s.eml", filepath.ToSlash(em.Folder), em.UID, cleanMsgID)

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
