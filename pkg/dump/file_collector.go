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

// FileEntryManifest records individual file details sealed inside the archive.
type FileEntryManifest struct {
	Path       string      `json:"path"`
	Size       int64       `json:"size"`
	Mode       os.FileMode `json:"mode"`
	ModTime    time.Time   `json:"mod_time"`
	Sha256     string      `json:"sha256"`
	IsDir      bool        `json:"is_dir"`
	IsSymlink  bool        `json:"is_symlink"`
	LinkTarget string      `json:"link_target,omitempty"`
	// Owner, recorded here rather than in the tar header: the header's uid
	// and gid are zeroed so the archive bytes do not depend on who ran the
	// backup, and ownership was simply lost. Absent (nil) in manifests
	// written before 2026-09-24; a restore then leaves ownership alone.
	UID *int `json:"uid,omitempty"`
	GID *int `json:"gid,omitempty"`
}

// SealedFileManifest is stored as .safegrd-manifest.json inside the sealed archive.
type SealedFileManifest struct {
	Version          string              `json:"version"`
	RootPath         string              `json:"root_path"`
	CreatedAt        time.Time           `json:"created_at"`
	TotalFiles       int64               `json:"total_files"`
	TotalDirectories int                 `json:"total_directories"`
	RawSizeBytes     int64               `json:"raw_size_bytes"`
	Entries          []FileEntryManifest `json:"entries"`
}

// FileCollectorConfig configures directory traversal and packaging.
type FileCollectorConfig struct {
	RootDir        string
	Excludes       []string
	FollowSymlinks bool
	ArchiveTime    time.Time // Optional fixed timestamp for reproducible byte-stable archive generation
}

// FileCollector traverses a filesystem tree and produces a streaming POSIX tar archive.
type FileCollector struct {
	cfg     FileCollectorConfig
	skipped []string
}

// Skipped lists what the last scan left out because it is not a file, a
// directory or a symlink — FIFOs, sockets and device nodes — as
// "path (kind)". A backup that leaves something out must say so; the caller
// prints it.
func (fc *FileCollector) Skipped() []string {
	return fc.skipped
}

// NewFileCollector creates a new FileCollector.
func NewFileCollector(cfg FileCollectorConfig) *FileCollector {
	return &FileCollector{cfg: cfg}
}

// MatchesExclude checks whether a relative path or filename matches any exclusion pattern.
func MatchesExclude(relPath string, patterns []string) bool {
	cleanRel := filepath.ToSlash(filepath.Clean(relPath))
	baseName := filepath.Base(cleanRel)
	for _, p := range patterns {
		cleanPattern := filepath.ToSlash(filepath.Clean(p))
		if cleanPattern == "" {
			continue
		}
		if matched, _ := filepath.Match(cleanPattern, cleanRel); matched {
			return true
		}
		if matched, _ := filepath.Match(cleanPattern, baseName); matched {
			return true
		}
		dirPattern := strings.TrimSuffix(cleanPattern, "/*")
		if cleanRel == dirPattern || strings.HasPrefix(cleanRel, dirPattern+"/") {
			return true
		}
	}
	return false
}

type collectedItem struct {
	relPath  string
	fullPath string
	info     os.FileInfo
	isDir    bool
	isSym    bool
	linkDest string
}

// ScanAndStream walks the root directory, constructs the sealed manifest, and streams the tarball.
// The sealed manifest (.safegrd-manifest.json) is written as the very first entry of the tar.
func (fc *FileCollector) ScanAndStream(ctx context.Context) (io.Reader, *model.SnapshotMetadata, error) {
	absRoot, err := filepath.Abs(fc.cfg.RootDir)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid root directory: %w", err)
	}

	rootInfo, err := os.Stat(absRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("failed stating root directory %s: %w", absRoot, err)
	}
	if !rootInfo.IsDir() {
		return nil, nil, fmt.Errorf("root path is not a directory: %s", absRoot)
	}

	// 1. Traverse and discover files, failing on permission errors
	fc.skipped = nil
	var items []collectedItem
	visitedRealDirs := make(map[string]bool)

	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err == nil {
		visitedRealDirs[realRoot] = true
	}

	err = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, walkErr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Fail loudly on any access error: a directory skipped for permissions
		// is a hole in the backup, not a warning.
		if walkErr != nil {
			return fmt.Errorf("access error reading %s: %w", path, walkErr)
		}

		if path == absRoot {
			return nil
		}

		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return fmt.Errorf("failed computing relative path: %w", err)
		}
		relSlash := filepath.ToSlash(rel)

		if MatchesExclude(relSlash, fc.cfg.Excludes) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("failed reading file info for %s: %w", path, err)
		}

		isSym := (info.Mode() & os.ModeSymlink) != 0
		// A FIFO, socket or device node is not data to back up, and each one
		// broke the backup differently: hashing a FIFO blocked forever, which
		// hangs the agent; tar refuses sockets, which failed the whole run; a
		// character device such as /dev/zero reads without end.
		if !isSym && !d.IsDir() && !info.Mode().IsRegular() {
			fc.skipped = append(fc.skipped, relSlash+" ("+specialKind(info.Mode())+")")
			return nil
		}
		var linkDest string
		if isSym {
			dest, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("failed reading symlink %s: %w", path, err)
			}
			linkDest = dest
			// A symlink is recorded, never followed, so it cannot form a
			// loop. The check that stood here failed the whole backup for any
			// link to a directory already walked — "latest -> releases/42",
			// or a link back to the root — which is an ordinary tree.
		}

		if d.IsDir() {
			realDir, err := filepath.EvalSymlinks(path)
			if err == nil {
				if visitedRealDirs[realDir] {
					return fmt.Errorf("symlink directory loop detected at %s", path)
				}
				visitedRealDirs[realDir] = true
			}
		}

		items = append(items, collectedItem{
			relPath:  relSlash,
			fullPath: path,
			info:     info,
			isDir:    d.IsDir(),
			isSym:    isSym,
			linkDest: linkDest,
		})

		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	// 2. Sort items deterministically for byte-stable reproducible tar output
	sort.Slice(items, func(i, j int) bool {
		return items[i].relPath < items[j].relPath
	})

	// 3. Precompute file hashes and build SealedFileManifest
	var (
		totalFiles       int64
		totalDirectories int
		totalRawBytes    int64
		manifestEntries  []FileEntryManifest
		extCounts        = make(map[string]int64)
		extBytes         = make(map[string]int64)
	)

	for _, item := range items {
		if item.isDir {
			totalDirectories++
			uid, gid := ownerOf(item.info)
			manifestEntries = append(manifestEntries, FileEntryManifest{
				Path:    item.relPath,
				Mode:    item.info.Mode(),
				ModTime: item.info.ModTime().UTC().Truncate(time.Second),
				IsDir:   true,
				UID:     uid,
				GID:     gid,
			})
			continue
		}

		totalFiles++

		// A symlink is an item, not a payload. os.Lstat reports its "size" as
		// the length of the target string, but the archive stores a symlink as
		// a header with no data blocks at all, so counting those bytes sealed a
		// manifest claiming bytes the archive does not contain. Verification
		// then failed on every tree containing a symlink -- a good backup that
		// could never be proven, which is the product's whole claim. The count
		// still includes it, because it is backed up and it is restored.
		size := item.info.Size()
		if item.isSym {
			size = 0
		}
		totalRawBytes += size

		ext := strings.ToLower(filepath.Ext(item.relPath))
		if ext == "" {
			ext = "(no extension)"
		}
		extCounts[ext]++
		extBytes[ext] += size

		var hashStr string
		if !item.isSym {
			h := sha256.New()
			f, err := os.Open(item.fullPath)
			if err != nil {
				return nil, nil, fmt.Errorf("failed opening file %s for hashing: %w", item.fullPath, err)
			}
			if _, err := io.Copy(h, f); err != nil {
				f.Close()
				return nil, nil, fmt.Errorf("failed hashing file %s: %w", item.fullPath, err)
			}
			f.Close()
			hashStr = hex.EncodeToString(h.Sum(nil))
		}

		uid, gid := ownerOf(item.info)
		manifestEntries = append(manifestEntries, FileEntryManifest{
			UID:        uid,
			GID:        gid,
			Path:       item.relPath,
			Size:       size,
			Mode:       item.info.Mode(),
			ModTime:    item.info.ModTime().UTC().Truncate(time.Second),
			Sha256:     hashStr,
			IsDir:      false,
			IsSymlink:  item.isSym,
			LinkTarget: item.linkDest,
		})
	}

	archiveTime := fc.cfg.ArchiveTime
	if archiveTime.IsZero() {
		archiveTime = time.Now().UTC().Truncate(time.Second)
	}

	sealedManifest := SealedFileManifest{
		Version:          "1.0",
		RootPath:         absRoot,
		CreatedAt:        archiveTime,
		TotalFiles:       totalFiles,
		TotalDirectories: totalDirectories,
		RawSizeBytes:     totalRawBytes,
		Entries:          manifestEntries,
	}

	sealedBytes, err := json.MarshalIndent(sealedManifest, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshaling sealed manifest: %w", err)
	}

	// Prepare aggregate top extensions for public metadata
	var topExts []model.ExtensionStat
	for ext, count := range extCounts {
		topExts = append(topExts, model.ExtensionStat{
			Extension: ext,
			Count:     count,
			SizeBytes: extBytes[ext],
		})
	}
	sort.Slice(topExts, func(i, j int) bool {
		return topExts[i].SizeBytes > topExts[j].SizeBytes
	})
	if len(topExts) > 10 {
		topExts = topExts[:10]
	}

	meta := &model.SnapshotMetadata{
		SurfaceType:     model.SurfaceTypeFiles,
		TotalItems:      totalFiles,
		TotalContainers: totalDirectories,
		RawSizeBytes:    totalRawBytes,
		FileStats: &model.FileStatsSummary{
			TotalFiles:       totalFiles,
			TotalDirectories: totalDirectories,
			TopExtensions:    topExts,
		},
		CreatedAt: archiveTime,
	}

	// 4. Create streaming pipe
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

		// Write sealed manifest as the very first entry
		manifestHeader := &tar.Header{
			Name:     ".safegrd-manifest.json",
			Mode:     0600,
			Size:     int64(len(sealedBytes)),
			ModTime:  time.Unix(0, 0).UTC(),
			Format:   tar.FormatPAX,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(manifestHeader); err != nil {
			writeErr = fmt.Errorf("failed writing manifest header: %w", err)
			return
		}
		if _, err := tw.Write(sealedBytes); err != nil {
			writeErr = fmt.Errorf("failed writing manifest body: %w", err)
			return
		}

		// Write all items
		for _, item := range items {
			select {
			case <-ctx.Done():
				writeErr = ctx.Err()
				return
			default:
			}

			hdr, err := tar.FileInfoHeader(item.info, item.linkDest)
			if err != nil {
				writeErr = fmt.Errorf("failed creating tar header for %s: %w", item.relPath, err)
				return
			}

			hdr.Name = item.relPath
			hdr.Format = tar.FormatPAX
			hdr.Uid = 0
			hdr.Gid = 0
			hdr.Uname = ""
			hdr.Gname = ""
			hdr.ModTime = item.info.ModTime().UTC().Truncate(time.Second)
			// On Linux FileInfoHeader also fills atime and ctime, which PAX
			// then writes out. Hashing the file for the manifest reads it and
			// moves its atime, so two archives of an unchanged tree differed
			// on every run. Only mtime is restored, so only mtime is kept.
			hdr.AccessTime = time.Time{}
			hdr.ChangeTime = time.Time{}

			if item.isDir {
				hdr.Typeflag = tar.TypeDir
				if !strings.HasSuffix(hdr.Name, "/") {
					hdr.Name += "/"
				}
				if err := tw.WriteHeader(hdr); err != nil {
					writeErr = fmt.Errorf("failed writing dir header for %s: %w", item.relPath, err)
					return
				}
				continue
			}

			if item.isSym {
				hdr.Typeflag = tar.TypeSymlink
				hdr.Linkname = item.linkDest
				if err := tw.WriteHeader(hdr); err != nil {
					writeErr = fmt.Errorf("failed writing symlink header for %s: %w", item.relPath, err)
					return
				}
				continue
			}

			hdr.Typeflag = tar.TypeReg
			hdr.Size = item.info.Size()
			if err := tw.WriteHeader(hdr); err != nil {
				writeErr = fmt.Errorf("failed writing file header for %s: %w", item.relPath, err)
				return
			}

			file, err := os.Open(item.fullPath)
			if err != nil {
				writeErr = fmt.Errorf("failed opening file %s for tar streaming: %w", item.fullPath, err)
				return
			}

			copied, err := io.Copy(tw, file)
			file.Close()
			if err != nil {
				writeErr = fmt.Errorf("failed streaming file content for %s: %w", item.relPath, err)
				return
			}
			if copied != hdr.Size {
				writeErr = fmt.Errorf("file size mismatch for %s: header=%d, copied=%d", item.relPath, hdr.Size, copied)
				return
			}
		}
	}()

	return pr, meta, nil
}

// specialKind names a file type the collector does not archive.
func specialKind(m os.FileMode) string {
	switch {
	case m&os.ModeNamedPipe != 0:
		return "named pipe"
	case m&os.ModeSocket != 0:
		return "socket"
	case m&os.ModeCharDevice != 0:
		return "character device"
	case m&os.ModeDevice != 0:
		return "block device"
	case m&os.ModeIrregular != 0:
		return "irregular file"
	default:
		return "special file"
	}
}
