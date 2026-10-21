package wal

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A cluster with data checksums has every page checked as pg_basebackup
// reads it. PostgreSQL reads a page that fails a second time before it
// reports it, so a page being written as it was read is not counted; what
// it reports did fail twice. It sends the whole backup anyway and then ends
// it with an error, and pg_basebackup exits non-zero over a backup it wrote
// in full.

var (
	checksumBlockRe = regexp.MustCompile(`checksum verification failed in file "([^"]+)", block (\d+)`)
	checksumTotalRe = regexp.MustCompile(`file "([^"]+)" has a total of (\d+) checksum verification failures?`)
)

// checksumFailures reads pg_basebackup's stderr for pages that failed their
// checksum, by file. ok is false when it reports none.
func checksumFailures(stderr string) (byFile map[string]int, ok bool) {
	byFile = map[string]int{}
	for _, m := range checksumBlockRe.FindAllStringSubmatch(stderr, -1) {
		byFile[cleanRelPath(m[1])]++
	}
	// The per-file total counts the failures past the fifth, which are
	// not reported one by one.
	for _, m := range checksumTotalRe.FindAllStringSubmatch(stderr, -1) {
		if n, err := strconv.Atoi(m[2]); err == nil && n > byFile[cleanRelPath(m[1])] {
			byFile[cleanRelPath(m[1])] = n
		}
	}
	ended := strings.Contains(stderr, "checksum error occurred") || strings.Contains(stderr, "checksum verification failure during base backup")
	return byFile, len(byFile) > 0 || ended
}

func cleanRelPath(p string) string { return strings.TrimPrefix(p, "./") }

// ChecksumWords says how many of the base's pages failed their checksum,
// in which files, at most five named: "1 page in base/5/16384 (1)".
func (b BaseInfo) ChecksumWords() string { return checksumWords(b.ChecksumFiles) }

func checksumWords(byFile map[string]int) string {
	files := make([]string, 0, len(byFile))
	total := 0
	for f, n := range byFile {
		files = append(files, f)
		total += n
	}
	sort.Strings(files)
	var parts []string
	for i, f := range files {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("and %d more files", len(files)-5))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", f, byFile[f]))
	}
	pages := "pages"
	if total == 1 {
		pages = "page"
	}
	return fmt.Sprintf("%d %s in %s", total, pages, strings.Join(parts, ", "))
}
