package dump

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
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
	msg := strings.TrimSpace(stderr.String())
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
