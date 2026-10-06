package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/safegrd/cli/pkg/repo/wprun"
)

// restoreRepoWordPress restores a WordPress site's snapshot: the database
// into an empty MySQL or MariaDB database, the files into an empty
// directory. Every file is checked against its SHA-256 as it is read, and the
// content root against the one recorded at backup time before anything is
// written.
func restoreRepoWordPress(ctx context.Context, rs *repoSnapshot, privateKey, targetURL, targetDir string) error {
	ids, err := unseal.Identities(privateKey)
	if err != nil {
		return err
	}
	id := rs.Meta.SnapshotID
	r := read.Open(rs.Backend, rs.Epoch, ids)
	snap, err := r.Snapshot(ctx, id)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", id, err)
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", id, err)
	}
	root, _, err := r.ContentRoot(ctx, idx, snap)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", id, err)
	}
	if err := checkRepoContentRoot(ctx, rs.Meta, id, root); err != nil {
		return err
	}
	run, err := wprun.Files(ctx, r, idx, snap)
	if err != nil {
		return err
	}
	started := time.Now()
	pr, pw := io.Pipe()
	archived := make(chan error, 1)
	go func() {
		err := wprun.Archive(ctx, r, idx, run, pw)
		_ = pw.CloseWithError(err)
		archived <- err
	}()
	res, err := dump.RestoreWordPress(ctx, pr, targetURL, targetDir)
	_, _ = io.Copy(io.Discard, pr) // the rest of the run, checked to its end
	if aerr := <-archived; err == nil && aerr != nil {
		err = fmt.Errorf("reading the snapshot back: %w", aerr)
	}
	if err != nil {
		return fmt.Errorf("WordPress restore failed: %w", err)
	}
	fmt.Printf("\nRestore complete\n")
	fmt.Printf("   Duration:       %s\n", time.Since(started).Round(time.Millisecond))
	printWordPressRestore(res, targetDir)
	return nil
}

// printWordPressRestore says what a WordPress restore wrote, and what is left
// to put the site back together.
func printWordPressRestore(res *dump.WordPressRestoreResult, targetDir string) {
	if res == nil || res.Manifest == nil {
		return
	}
	fmt.Printf("   Tables:         %d\n", res.Manifest.TotalTables)
	fmt.Printf("   Rows:           %d\n", res.Manifest.TotalRows)
	fmt.Printf("   Files:          %d\n", res.FilesWritten)
	fmt.Printf("   Bytes written:  %d\n", res.BytesWritten)
	fmt.Printf("   Destination:    %s\n", targetDir)
	if wp := res.Manifest.WordPress; wp != nil {
		if wp.WordPressVersion != "" {
			fmt.Printf("   WordPress:      %s (core is not in the snapshot: install this version, then copy the restored files over it)\n", wp.WordPressVersion)
		}
		if wp.SiteURL != "" {
			fmt.Printf("   Site URL:       %s\n", wp.SiteURL)
			fmt.Printf("   On another domain, run: wp search-replace '%s' 'https://new.example' --all-tables\n", wp.SiteURL)
		}
	}
	fmt.Printf("   wp-config.php still names the old database; point DB_NAME, DB_USER, DB_PASSWORD and DB_HOST at the restored one.\n")
}
