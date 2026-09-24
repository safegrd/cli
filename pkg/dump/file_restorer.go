package dump

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// FileDryRestoreResult captures the verification assertions of a file snapshot in memory.
type FileDryRestoreResult struct {
	TotalFiles       int64                   `json:"total_files"`
	TotalDirectories int                     `json:"total_directories"`
	TotalRawBytes    int64                   `json:"total_raw_bytes"`
	SealedManifest   *SealedFileManifest     `json:"sealed_manifest,omitempty"`
	Passed           bool                    `json:"passed"`
	Assertions       []model.AssertionResult `json:"assertions"`
	DurationMs       int64                   `json:"duration_ms"`
	ErrorMessage     string                  `json:"error_message,omitempty"`
}

// FileExtractionResult tracks results when extracting to disk.
type FileExtractionResult struct {
	FilesExtracted       int64 `json:"files_extracted"`
	DirectoriesExtracted int   `json:"directories_extracted"`
	SymlinksExtracted    int   `json:"symlinks_extracted"`
	TotalBytesWritten    int64 `json:"total_bytes_written"`
	// OwnershipRestored is true when owners recorded in the sealed manifest
	// were reapplied, which needs root. OwnershipNote says why they were
	// not, for the restore to print.
	OwnershipRestored bool   `json:"ownership_restored"`
	OwnershipNote     string `json:"ownership_note,omitempty"`
	// Skipped lists archive entries of a type this restore does not create,
	// as "path (type)". Nothing is left out silently.
	Skipped []string `json:"skipped,omitempty"`
}

// FileRestorer provides in-memory verification and disk extraction for file backups.
type FileRestorer struct{}

// NewFileRestorer creates a new FileRestorer.
func NewFileRestorer() *FileRestorer {
	return &FileRestorer{}
}

// InspectFileArchive reads a decrypted file tarball in-memory, verifying its sealed manifest and file digests.
func (fr *FileRestorer) InspectFileArchive(ctx context.Context, src io.Reader, outerMeta *model.SnapshotMetadata) (*FileDryRestoreResult, error) {
	startTime := time.Now()

	result := &FileDryRestoreResult{
		Passed: true,
	}

	tarReader := tar.NewReader(src)

	var (
		manifestFound bool
		sealed        SealedFileManifest
		filesFound    int64
		dirsFound     int
		bytesFound    int64
		checksumsOK   = true
		checksumErr   string
	)

	expectedHashes := make(map[string]string)

	// Every archive entry is held to the sealed manifest, not only the regular
	// files' digests. Before this, a symlink repointed at /etc/shadow passed
	// verification: the manifest recorded where the link pointed and nothing
	// compared it, and an entry the manifest never mentioned was only noticed
	// if it happened to change a count.
	sealedByPath := make(map[string]FileEntryManifest)
	seen := make(map[string]bool)
	var structural []string
	mismatch := func(format string, args ...any) {
		structural = append(structural, fmt.Sprintf(format, args...))
	}
	// checkSealed compares one archive entry with its sealed record and
	// returns the record, or false when there is none to compare against.
	checkSealed := func(name, kind string) (FileEntryManifest, bool) {
		if !manifestFound {
			mismatch("%s %s precedes the sealed manifest", kind, name)
			return FileEntryManifest{}, false
		}
		entry, ok := sealedByPath[name]
		if !ok {
			mismatch("%s %s is in the archive but not in the sealed manifest", kind, name)
			return FileEntryManifest{}, false
		}
		if seen[name] {
			mismatch("%s %s appears in the archive more than once", kind, name)
		}
		seen[name] = true
		sealedKind := "file"
		switch {
		case entry.IsDir:
			sealedKind = "directory"
		case entry.IsSymlink:
			sealedKind = "symlink"
		}
		if sealedKind != kind {
			mismatch("%s is a %s in the archive but was sealed as a %s", name, kind, sealedKind)
		}
		return entry, true
	}

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
			result.ErrorMessage = fmt.Sprintf("corrupt tar archive stream: %v", err)
			return result, nil
		}

		cleanName := filepath.ToSlash(filepath.Clean(hdr.Name))

		// Check for sealed manifest
		if cleanName == ".safegrd-manifest.json" {
			manifestFound = true
			data, err := io.ReadAll(tarReader)
			if err != nil {
				result.Passed = false
				result.ErrorMessage = fmt.Sprintf("failed reading sealed manifest: %v", err)
				return result, nil
			}
			if err := json.Unmarshal(data, &sealed); err != nil {
				result.Passed = false
				result.ErrorMessage = fmt.Sprintf("failed parsing sealed manifest JSON: %v", err)
				return result, nil
			}
			result.SealedManifest = &sealed
			for _, entry := range sealed.Entries {
				sealedByPath[filepath.ToSlash(filepath.Clean(entry.Path))] = entry
				if !entry.IsDir && entry.Sha256 != "" {
					expectedHashes[entry.Path] = entry.Sha256
				}
			}
			continue
		}

		if hdr.Typeflag == tar.TypeDir {
			dirsFound++
			checkSealed(cleanName, "directory")
			continue
		}

		// Counted as an item, contributing no bytes -- the same convention the
		// collector seals into the manifest. Before this arm existed a symlink
		// was counted by neither branch, so archive and manifest disagreed.
		if hdr.Typeflag == tar.TypeSymlink {
			filesFound++
			if entry, ok := checkSealed(cleanName, "symlink"); ok && entry.IsSymlink && hdr.Linkname != entry.LinkTarget {
				mismatch("symlink %s points at %q in the archive but was sealed pointing at %q",
					cleanName, hdr.Linkname, entry.LinkTarget)
			}
			continue
		}

		if hdr.Typeflag != tar.TypeReg {
			// The collector writes directories, symlinks and regular files and
			// nothing else. A hard link, device or FIFO in the archive is not
			// something this backup produced, and skipping it silently is how
			// an entry goes unverified.
			mismatch("%s has tar type %q, which a SafeGrd file backup never writes", cleanName, string(hdr.Typeflag))
			continue
		}

		if hdr.Typeflag == tar.TypeReg {
			filesFound++
			checkSealed(cleanName, "file")
			bytesFound += hdr.Size

			// Stream regular file through sha256 to assert digest in memory
			h := sha256.New()
			copied, err := io.Copy(h, tarReader)
			if err != nil {
				result.Passed = false
				result.ErrorMessage = fmt.Sprintf("failed streaming archive entry %s: %v", cleanName, err)
				return result, nil
			}
			if copied != hdr.Size {
				result.Passed = false
				result.ErrorMessage = fmt.Sprintf("short read on archive entry %s: got %d, want %d", cleanName, copied, hdr.Size)
				return result, nil
			}

			sum := hex.EncodeToString(h.Sum(nil))
			if expected, ok := expectedHashes[cleanName]; ok {
				if sum != expected {
					checksumsOK = false
					checksumErr = fmt.Sprintf("checksum mismatch for %s: got %s, want %s", cleanName, sum, expected)
				}
			}
		}
	}

	result.TotalFiles = filesFound
	result.TotalDirectories = dirsFound
	result.TotalRawBytes = bytesFound
	result.DurationMs = time.Since(startTime).Milliseconds()

	// Assertion 1: Sealed manifest presence
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "Sealed Manifest Verified",
		Passed:   manifestFound,
		Expected: "present",
		Actual: func() string {
			if manifestFound {
				return "present"
			}
			return "missing"
		}(),
		Message: fmt.Sprintf("Found sealed manifest with %d declared entries", len(sealed.Entries)),
	})
	if !manifestFound {
		result.Passed = false
		result.ErrorMessage = "sealed manifest .safegrd-manifest.json missing from archive"
	}

	// Assertion 2: File count assertion
	fileCountMatch := manifestFound && (filesFound == sealed.TotalFiles)
	if manifestFound && outerMeta != nil && outerMeta.TotalItems > 0 && filesFound != outerMeta.TotalItems {
		fileCountMatch = false
	}
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "Archive File Count Matches Manifest",
		Passed:   fileCountMatch,
		Expected: fmt.Sprintf("%d files", sealed.TotalFiles),
		Actual:   fmt.Sprintf("%d files", filesFound),
		Message:  fmt.Sprintf("Archive contains %d files (sealed: %d)", filesFound, sealed.TotalFiles),
	})
	if !fileCountMatch {
		result.Passed = false
		if result.ErrorMessage == "" {
			result.ErrorMessage = fmt.Sprintf("file count mismatch: archive has %d, manifest has %d", filesFound, sealed.TotalFiles)
		}
	}

	// Assertion 3: Byte volume assertion
	byteVolumeMatch := manifestFound && (bytesFound == sealed.RawSizeBytes)
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "Archive Byte Volume Matches Manifest",
		Passed:   byteVolumeMatch,
		Expected: fmt.Sprintf("%d bytes", sealed.RawSizeBytes),
		Actual:   fmt.Sprintf("%d bytes", bytesFound),
		Message:  fmt.Sprintf("Archive contains %d bytes (sealed: %d)", bytesFound, sealed.RawSizeBytes),
	})
	if !byteVolumeMatch {
		result.Passed = false
		if result.ErrorMessage == "" {
			result.ErrorMessage = fmt.Sprintf("byte volume mismatch: archive has %d, manifest has %d", bytesFound, sealed.RawSizeBytes)
		}
	}

	// Assertion 4: every entry matches its sealed record, in both directions
	if manifestFound {
		for _, entry := range sealed.Entries {
			if name := filepath.ToSlash(filepath.Clean(entry.Path)); !seen[name] {
				mismatch("%s is in the sealed manifest but missing from the archive", name)
			}
		}
	}
	entriesMatch := len(structural) == 0
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "Archive Entries Match Sealed Manifest",
		Passed:   entriesMatch,
		Expected: fmt.Sprintf("%d entries as sealed", len(sealed.Entries)),
		Actual:   fmt.Sprintf("%d mismatched", len(structural)),
		Message: func() string {
			if entriesMatch {
				return "Every entry, type and symlink target matches the sealed manifest"
			}
			if len(structural) > 5 {
				return strings.Join(structural[:5], "; ") + fmt.Sprintf("; and %d more", len(structural)-5)
			}
			return strings.Join(structural, "; ")
		}(),
	})
	if !entriesMatch {
		result.Passed = false
		if result.ErrorMessage == "" {
			result.ErrorMessage = structural[0]
		}
	}

	// Assertion 5: Per-file SHA-256 integrity
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "File-Level SHA-256 Digests Verified",
		Passed:   checksumsOK,
		Expected: "every file's digest as sealed",
		Actual: func() string {
			if checksumsOK {
				return "every file's digest as sealed"
			}
			return "a digest differs"
		}(),
		Message: func() string {
			if checksumsOK {
				return "All file digests match sealed manifest"
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

// ExtractArchive extracts tar archive entries to targetDir on disk.
//
// It never writes outside targetDir. The name check alone was lexical, so an
// archive holding a symlink "a -> /etc" and then a file "a/passwd" wrote
// /etc/passwd, and a symlink "x -> /etc/passwd" followed by a file "x" did the
// same through O_TRUNC. The public key is public: anyone who can write to the
// bucket can produce an archive that decrypts. Every entry's parent chain and
// the entry itself are checked for symlinks first, and a restore that meets
// one refuses rather than skipping.
//
// Modes are set explicitly (creation modes pass through the umask, and an
// existing file's mode was never updated), and directories get theirs, with
// their times, in a last pass deepest first — earlier, a 0500 directory
// would block its own children, and writing the children resets its mtime.
// Every directory used to come back 0755, so a 0700 ~/.ssh was restored
// readable by everyone.
func (fr *FileRestorer) ExtractArchive(ctx context.Context, src io.Reader, targetDir string) (*FileExtractionResult, error) {
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("invalid target directory: %w", err)
	}

	if err := os.MkdirAll(absTarget, 0755); err != nil {
		return nil, fmt.Errorf("failed creating target directory %s: %w", absTarget, err)
	}
	// The target itself may be reached through a symlink (/tmp on macOS);
	// what matters is that nothing inside it is one.
	if real, err := filepath.EvalSymlinks(absTarget); err == nil {
		absTarget = real
	}

	tarReader := tar.NewReader(src)
	res := &FileExtractionResult{}

	var sealed *SealedFileManifest
	owners := map[string]FileEntryManifest{}
	chown := canChown()

	type dirFix struct {
		path  string
		mode  os.FileMode
		mtime time.Time
		entry string
	}
	var dirs []dirFix

	applyOwner := func(dest, name string) error {
		e, ok := owners[name]
		if !chown || !ok || e.UID == nil || e.GID == nil {
			return nil
		}
		if err := os.Lchown(dest, *e.UID, *e.GID); err != nil {
			return fmt.Errorf("failed restoring the owner of %s: %w", dest, err)
		}
		return nil
	}

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
		if cleanRel == ".safegrd-manifest.json" {
			// Not extracted into the target, but read: it carries the owners.
			var m SealedFileManifest
			if err := json.NewDecoder(tarReader).Decode(&m); err == nil {
				sealed = &m
				for _, e := range m.Entries {
					owners[filepath.Clean(filepath.FromSlash(e.Path))] = e
				}
			}
			continue
		}

		// Security: path traversal protection (zip-slip prevention)
		destPath := filepath.Join(absTarget, cleanRel)
		relToTarget, err := filepath.Rel(absTarget, destPath)
		if err != nil || relToTarget == ".." || strings.HasPrefix(relToTarget, ".."+string(filepath.Separator)) || filepath.IsAbs(cleanRel) {
			return nil, fmt.Errorf("path traversal attempt detected in archive entry: %s", hdr.Name)
		}
		if relToTarget == "." {
			continue // the root itself: the target directory already exists
		}
		if err := refuseSymlinkPath(absTarget, relToTarget, hdr.Typeflag == tar.TypeSymlink); err != nil {
			return nil, fmt.Errorf("refusing archive entry %s: %w", hdr.Name, err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0700); err != nil {
				return nil, fmt.Errorf("failed creating directory %s: %w", destPath, err)
			}
			dirs = append(dirs, dirFix{path: destPath, mode: hdr.FileInfo().Mode().Perm(), mtime: hdr.ModTime, entry: cleanRel})
			res.DirectoriesExtracted++

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
				return nil, fmt.Errorf("failed creating parent directory for %s: %w", destPath, err)
			}

			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return nil, fmt.Errorf("failed creating file %s: %w", destPath, err)
			}

			copied, err := io.Copy(outFile, tarReader)
			closeErr := outFile.Close()
			if err != nil {
				return nil, fmt.Errorf("failed writing file %s: %w", destPath, err)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("failed writing file %s: %w", destPath, closeErr)
			}
			if err := applyOwner(destPath, cleanRel); err != nil {
				return nil, err
			}
			// After the owner: a chown may clear permission bits.
			if err := os.Chmod(destPath, hdr.FileInfo().Mode().Perm()); err != nil {
				return nil, fmt.Errorf("failed setting the mode of %s: %w", destPath, err)
			}
			if !hdr.ModTime.IsZero() {
				if err := os.Chtimes(destPath, hdr.ModTime, hdr.ModTime); err != nil {
					return nil, fmt.Errorf("failed setting the time of %s: %w", destPath, err)
				}
			}

			res.FilesExtracted++
			res.TotalBytesWritten += copied

		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
				return nil, fmt.Errorf("failed creating parent directory for symlink %s: %w", destPath, err)
			}
			if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed replacing %s with a symlink: %w", destPath, err)
			}
			if err := os.Symlink(hdr.Linkname, destPath); err != nil {
				return nil, fmt.Errorf("failed creating symlink %s -> %s: %w", destPath, hdr.Linkname, err)
			}
			if err := applyOwner(destPath, cleanRel); err != nil {
				return nil, err
			}
			res.SymlinksExtracted++

		default:
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s (%s)", hdr.Name, tarTypeName(hdr.Typeflag)))
		}
	}

	// Directories last, deepest first.
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i].path) > len(dirs[j].path) })
	for _, d := range dirs {
		if err := applyOwner(d.path, d.entry); err != nil {
			return nil, err
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return nil, fmt.Errorf("failed setting the mode of %s: %w", d.path, err)
		}
		if !d.mtime.IsZero() {
			if err := os.Chtimes(d.path, d.mtime, d.mtime); err != nil {
				return nil, fmt.Errorf("failed setting the time of %s: %w", d.path, err)
			}
		}
	}

	switch {
	case sealed == nil || !manifestHasOwners(sealed):
		res.OwnershipNote = "this snapshot predates recorded ownership, so files belong to whoever ran the restore"
	case !chown:
		res.OwnershipNote = "owners were recorded but not reapplied: that needs root, so files belong to whoever ran the restore"
	default:
		res.OwnershipRestored = true
	}

	return res, nil
}

// refuseSymlinkPath fails when any existing component between root and rel
// is a symlink — writing through it would land outside root. The entry
// itself may be an existing symlink only when the archive entry replaces it
// with a symlink.
func refuseSymlinkPath(root, rel string, entryIsSymlink bool) error {
	parts := strings.Split(rel, string(filepath.Separator))
	cur := root
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil // nothing below a missing component exists yet
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if i == len(parts)-1 && entryIsSymlink {
			return nil
		}
		return fmt.Errorf("%s is a symlink, and writing through it could leave the restore directory", cur)
	}
	return nil
}

func manifestHasOwners(m *SealedFileManifest) bool {
	for _, e := range m.Entries {
		if e.UID != nil {
			return true
		}
	}
	return false
}

// tarTypeName names a tar entry type for the list of what was not restored.
func tarTypeName(t byte) string {
	switch t {
	case tar.TypeLink:
		return "hard link"
	case tar.TypeChar:
		return "character device"
	case tar.TypeBlock:
		return "block device"
	case tar.TypeFifo:
		return "named pipe"
	default:
		return fmt.Sprintf("tar type %q", t)
	}
}
