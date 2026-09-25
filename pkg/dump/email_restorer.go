package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// EmailDryRestoreResult captures the verification assertions of an email snapshot in memory.
type EmailDryRestoreResult struct {
	TotalEmails    int64                   `json:"total_emails"`
	TotalFolders   int                     `json:"total_folders"`
	TotalRawBytes  int64                   `json:"total_raw_bytes"`
	SealedManifest *SealedEmailManifest    `json:"sealed_manifest,omitempty"`
	Passed         bool                    `json:"passed"`
	Assertions     []model.AssertionResult `json:"assertions"`
	DurationMs     int64                   `json:"duration_ms"`
	ErrorMessage   string                  `json:"error_message,omitempty"`
}

// EmailExtractionResult tracks results when extracting to disk.
type EmailExtractionResult struct {
	EmailsExtracted      int64 `json:"emails_extracted"`
	DirectoriesExtracted int   `json:"directories_extracted"`
	TotalBytesWritten    int64 `json:"total_bytes_written"`
}

// EmailRestorer provides in-memory verification and EML folder extraction for email backups.
type EmailRestorer struct{}

// NewEmailRestorer creates a new EmailRestorer.
func NewEmailRestorer() *EmailRestorer {
	return &EmailRestorer{}
}

// InspectEmailArchive inspects a decrypted email tarball in memory without disk writes.
func (er *EmailRestorer) InspectEmailArchive(ctx context.Context, src io.Reader, outerMeta *model.SnapshotMetadata) (*EmailDryRestoreResult, error) {
	startTime := time.Now()

	result := &EmailDryRestoreResult{
		Passed: true,
	}

	tarReader := tar.NewReader(src)

	var (
		manifestFound  bool
		sealed         SealedEmailManifest
		emailsFound    int64
		dirsFound      int
		bytesFound     int64
		checksumsOK    = true
		checksumErr    string
		mimeParsedOK   = true
		mimeErr        string
		expectedHashes = make(map[string]string)
		folderCounts   = make(map[string]int64)
	)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Passed = false
			result.ErrorMessage = fmt.Sprintf("corrupt email archive tar stream: %v", err)
			return result, nil
		}

		cleanName := filepath.ToSlash(filepath.Clean(hdr.Name))

		if cleanName == ".safegrd-email-manifest.json" {
			manifestFound = true
			data, err := io.ReadAll(tarReader)
			if err != nil {
				result.Passed = false
				result.ErrorMessage = fmt.Sprintf("failed reading sealed email manifest: %v", err)
				return result, nil
			}
			if err := json.Unmarshal(data, &sealed); err != nil {
				result.Passed = false
				result.ErrorMessage = fmt.Sprintf("failed parsing sealed email manifest: %v", err)
				return result, nil
			}
			result.SealedManifest = &sealed
			for _, msg := range sealed.Messages {
				cleanRegex := strings.NewReplacer("<", "_", ">", "_", "@", "_", ".", "_")
				sanitized := cleanRegex.Replace(msg.MessageID)
				if len(sanitized) > 32 {
					sanitized = sanitized[:32]
				}
				key := fmt.Sprintf("%s/%d-%s.eml", filepath.ToSlash(msg.Folder), msg.UID, sanitized)
				expectedHashes[key] = msg.Sha256
			}
			continue
		}

		if hdr.Typeflag == tar.TypeDir {
			dirsFound++
			continue
		}

		if hdr.Typeflag == tar.TypeReg && strings.HasSuffix(cleanName, ".eml") {
			emailsFound++
			bytesFound += hdr.Size

			dir := filepath.Dir(cleanName)
			folderCounts[dir]++

			body, err := io.ReadAll(tarReader)
			if err != nil {
				result.Passed = false
				result.ErrorMessage = fmt.Sprintf("failed reading email entry %s: %v", cleanName, err)
				return result, nil
			}

			sum := sha256.Sum256(body)
			sumHex := hex.EncodeToString(sum[:])
			if exp, ok := expectedHashes[cleanName]; ok {
				if sumHex != exp {
					checksumsOK = false
					checksumErr = fmt.Sprintf("hash mismatch for %s: got %s, want %s", cleanName, sumHex, exp)
				}
			}

			if _, err := mail.ReadMessage(bytes.NewReader(body)); err != nil {
				mimeParsedOK = false
				mimeErr = fmt.Sprintf("invalid RFC 5322 MIME structure in %s: %v", cleanName, err)
			}
		}
	}

	result.TotalEmails = emailsFound
	result.TotalFolders = dirsFound
	result.TotalRawBytes = bytesFound
	result.DurationMs = elapsedMilliseconds(startTime)

	// Assertion 1: Sealed Manifest Present
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "Sealed Email Manifest Verified",
		Passed:   manifestFound,
		Expected: "present",
		Actual: func() string {
			if manifestFound {
				return "present"
			}
			return "missing"
		}(),
		Message: fmt.Sprintf("Found sealed manifest for %s with %d messages", sealed.Account, len(sealed.Messages)),
	})
	if !manifestFound {
		result.Passed = false
		result.ErrorMessage = "sealed manifest .safegrd-email-manifest.json missing from archive"
	}

	// Assertion 2: Email Count Assertion
	emailCountMatch := manifestFound && (emailsFound == sealed.TotalEmails)
	if manifestFound && outerMeta != nil && outerMeta.TotalItems > 0 && emailsFound != outerMeta.TotalItems {
		emailCountMatch = false
	}
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "Archive Email Count Matches Manifest",
		Passed:   emailCountMatch,
		Expected: fmt.Sprintf("%d emails", sealed.TotalEmails),
		Actual:   fmt.Sprintf("%d emails", emailsFound),
		Message:  fmt.Sprintf("Archive contains %d emails (sealed: %d)", emailsFound, sealed.TotalEmails),
	})
	if !emailCountMatch {
		result.Passed = false
		if result.ErrorMessage == "" {
			result.ErrorMessage = fmt.Sprintf("email count mismatch: archive has %d, manifest has %d", emailsFound, sealed.TotalEmails)
		}
	}

	// Assertion 3: RFC 5322 MIME Structure Valid
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "RFC 5322 MIME Header Integrity Verified",
		Passed:   mimeParsedOK,
		Expected: "every message parses",
		Actual: func() string {
			if mimeParsedOK {
				return "every message parses"
			}
			return "a message does not parse"
		}(),
		Message: func() string {
			if mimeParsedOK {
				return "All EML messages parse cleanly under net/mail standard library"
			}
			return mimeErr
		}(),
	})
	if !mimeParsedOK {
		result.Passed = false
		if result.ErrorMessage == "" {
			result.ErrorMessage = mimeErr
		}
	}

	// Assertion 4: SHA-256 Message Integrity
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "Message SHA-256 Hashes Verified",
		Passed:   checksumsOK,
		Expected: "every message's digest as sealed",
		Actual: func() string {
			if checksumsOK {
				return "every message's digest as sealed"
			}
			return "a digest differs"
		}(),
		Message: func() string {
			if checksumsOK {
				return "All message digests match sealed manifest"
			}
			return checksumErr
		}(),
	})
	if !checksumsOK {
		result.Passed = false
		if result.ErrorMessage == "" {
			result.ErrorMessage = checksumErr
		}
	}

	return result, nil
}

// ExtractEmailArchive extracts the archive into an organized directory tree of EML files.
func (er *EmailRestorer) ExtractEmailArchive(ctx context.Context, src io.Reader, targetDir string) (*EmailExtractionResult, error) {
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("invalid target directory: %w", err)
	}

	if err := os.MkdirAll(absTarget, 0700); err != nil {
		return nil, fmt.Errorf("failed creating target directory %s: %w", absTarget, err)
	}
	if real, err := filepath.EvalSymlinks(absTarget); err == nil {
		absTarget = real
	}

	tarReader := tar.NewReader(src)
	res := &EmailExtractionResult{}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed reading archive stream: %w", err)
		}

		cleanRel := filepath.Clean(hdr.Name)
		if cleanRel == ".safegrd-email-manifest.json" {
			continue
		}

		destPath := filepath.Join(absTarget, cleanRel)
		relToTarget, err := filepath.Rel(absTarget, destPath)
		if err != nil || strings.HasPrefix(relToTarget, "..") || strings.HasPrefix(destPath, "..") {
			return nil, fmt.Errorf("path traversal attempt in email archive entry: %s", hdr.Name)
		}
		if relToTarget == "." {
			continue
		}
		// As for files: never write through a symlink already in the target.
		if err := refuseSymlinkPath(absTarget, relToTarget, false); err != nil {
			return nil, fmt.Errorf("refusing email archive entry %s: %w", hdr.Name, err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			// Mail is private: folders and messages are the owner's alone. They
			// were restored 0755 and 0644, readable by every user on the host.
			if err := os.MkdirAll(destPath, 0700); err != nil {
				return nil, fmt.Errorf("failed creating folder %s: %w", destPath, err)
			}
			res.DirectoriesExtracted++

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
				return nil, fmt.Errorf("failed creating folder for email %s: %w", destPath, err)
			}

			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return nil, fmt.Errorf("failed creating email file %s: %w", destPath, err)
			}

			copied, err := io.Copy(outFile, tarReader)
			outFile.Close()
			if err != nil {
				return nil, fmt.Errorf("failed writing email %s: %w", destPath, err)
			}

			if !hdr.ModTime.IsZero() {
				_ = os.Chtimes(destPath, hdr.ModTime, hdr.ModTime)
			}

			res.EmailsExtracted++
			res.TotalBytesWritten += copied
		}
	}

	return res, nil
}
