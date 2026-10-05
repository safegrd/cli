package dump

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// runDumpTool starts cmd, copies its stdout into w, and waits for it. It
// returns what the tool wrote on stderr, trimmed, so the caller can pass on
// warnings a tool prints while exiting 0; whether that is a warning is the
// caller's to decide, per tool. A tool that fails is reported with the first
// 500 bytes of its stderr.
func runDumpTool(cmd *exec.Cmd, tool fmt.Stringer, w io.Writer) (string, error) {
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("starting %s: %w", tool, err)
	}
	_, copyErr := io.Copy(w, stdout)
	waitErr := cmd.Wait()
	msg := toolMessage(stderr.String())
	if waitErr != nil {
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return "", fmt.Errorf("%s failed: %v: %s", tool, waitErr, msg)
	}
	if copyErr != nil {
		return "", fmt.Errorf("writing the dump to the archive: %w", copyErr)
	}
	return msg, nil
}

var (
	// toolURLPasswordRe finds the password in any URL a tool echoes back:
	// mongodump's connection error repeats the whole connection string.
	toolURLPasswordRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]*:)[^\s@]*@`)
	// toolLogStampRe is the timestamp mongodump and mongorestore put at the
	// start of every line they log.
	toolLogStampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T[0-9:.]+(Z|[+-]\d{2}:?\d{2})\s+`)
)

// toolMessage is what a dump tool wrote on stderr, made fit to print and to
// store: passwords in any URL replaced, log timestamps dropped and the lines
// joined, so the one line a console shows holds the reason. mongodump's
// "Failed: …" came on the line after the CLI's own, so the console showed
// "exit status 1:" and nothing else, and the line it did write carried the
// connection string's password.
func toolMessage(stderr string) string {
	var lines []string
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(toolLogStampRe.ReplaceAllString(strings.TrimSpace(line), ""))
		if line != "" {
			lines = append(lines, line)
		}
	}
	msg := strings.Join(lines, "; ")
	msg = toolURLPasswordRe.ReplaceAllString(msg, "${1}xxxxx@")
	return urlQueryPasswordRe.ReplaceAllString(msg, "${1}xxxxx")
}

// finishArchive totals meta, stamps its duration from start, writes it as the
// archive's manifest entry and closes the archive.
func finishArchive(tw *tar.Writer, meta *model.SnapshotMetadata, start time.Time) error {
	meta.CalculateTotals()
	meta.DurationMs = elapsedMilliseconds(start)
	manifest, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := writeTarEntry(tw, entryManifest, manifest); err != nil {
		return fmt.Errorf("failed writing the manifest to the archive: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to close the archive: %w", err)
	}
	return nil
}
