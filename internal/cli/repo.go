package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/safegrd/cli/pkg/repo/write"
	"github.com/safegrd/cli/pkg/runner"
	"github.com/safegrd/cli/pkg/storage"
)

// Files surfaces are stored in one of two formats.
const (
	formatTar  = "tar"
	formatRepo = "repo"
)

// fileFormat resolves a format flag or setting. Unset is repo: incremental
// backups are the default for files; format: tar keeps one archive per backup.
func fileFormat(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", formatRepo:
		return formatRepo, nil
	case formatTar:
		return formatTar, nil
	}
	return "", fmt.Errorf("format %q is not tar or repo", v)
}

// repoSurfaceID names the repository of an ad-hoc `backup --files`: the
// same roots always land in the same repository, so each run uploads only
// what changed since the last.
func repoSurfaceID(roots []string) string {
	clean := make([]string, len(roots))
	for i, r := range roots {
		if abs, err := filepath.Abs(r); err == nil {
			r = abs
		}
		clean[i] = filepath.ToSlash(filepath.Clean(r))
	}
	sort.Strings(clean)
	sum := sha256.Sum256([]byte(strings.Join(clean, "\n")))
	return "files-" + hex.EncodeToString(sum[:])[:12]
}

// repoBackend opens where a repository's objects go for this storage.
func repoBackend(ctx context.Context, c *config.CLIConfig, storageCfg config.StorageConfig) (sink.Backend, error) {
	node := strings.TrimSpace(storageCfg.NodeID)
	switch storageCfg.Type {
	case config.StorageTypeLocal, "":
		p := storageCfg.LocalPath
		if p == "" {
			p = "./safegrd-storage"
		}
		d, err := sink.NewDir(p, node)
		if err != nil {
			return nil, err
		}
		return sink.NewDirect(d), nil
	case config.StorageTypeS3:
		if hostedLayout(storageCfg) {
			if node == "" {
				return nil, errors.New("storage.layout: hosted needs storage.node_id to name one host's repositories")
			}
			bs, err := hostedLayoutRepos(ctx, storageCfg, node)
			if err != nil {
				return nil, err
			}
			return bs[0], nil
		}
		prov, err := storage.NewS3Storage(ctx, storageCfg)
		if err != nil {
			return nil, err
		}
		client, bucket, prefix, mode := prov.ObjectStore()
		return sink.NewDirect(&sink.S3{Client: client, Bucket: bucket, Prefix: prefix, Mode: mode}), nil
	case config.StorageTypeHosted:
		return newHostedRepo(c, storageCfg)
	}
	return nil, fmt.Errorf("storage type %q holds no repository", storageCfg.Type)
}

// epochURI names where an epoch's objects are, as a snapshot report gives it.
func epochURI(b sink.Backend, e format.Epoch, surfaceID string) string {
	if u, ok := b.(interface{ EpochURI(format.Epoch) string }); ok {
		return u.EpochURI(e)
	}
	// A directory on this host is named as an archive in one is, file://,
	// which is how guard tells that nothing locks it.
	if d, ok := b.(*sink.Direct); ok {
		if dir, ok := d.S.(*sink.Dir); ok {
			return "file://" + filepath.Join(dir.Describe(), "repo", surfaceID, e.EpochID)
		}
	}
	return b.Describe() + "/" + path.Join("repo", surfaceID, e.EpochID)
}

// repoParams are one repository backup.
type repoParams struct {
	SurfaceID  string
	Roots      []string
	Excludes   []string
	OneFS      *bool
	StorageCfg config.StorageConfig
	NodeID     string
	Recipient  string
	Retention  policy.Retention
	Tier       string
	Planned    time.Time
	NewEpoch   bool
	Rescan     bool
	SnapshotID string
	StateDir   string
	// Out receives the progress lines; stderr gets warnings either way.
	Out io.Writer
	// RecoverySealTo seals the recovery document to this recipient; ""
	// writes it as text.
	RecoverySealTo string
}

func reasonText(reason string) string {
	switch reason {
	case format.ReasonFirst:
		return "first backup"
	case format.ReasonMonth:
		return "the month turned"
	case format.ReasonCacheLost:
		return "this host's cache of the last epoch is gone"
	case format.ReasonRetentionIncreased:
		return "retention was increased"
	case format.ReasonFormat:
		return "the repository format changed"
	case format.ReasonRequested:
		return "--new-epoch"
	case format.ReasonRecipient:
		return "the public key changed"
	}
	return reason
}

func shortDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	case d < time.Minute:
		return d.Round(time.Second).String()
	default:
		return strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
	}
}

func pluralWord(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// runRepoBackup writes one snapshot of a files surface into its repository
// and returns the metadata it recorded in the sidecar. Reporting it to the
// remote server is the caller's: a manual backup and the daemon differ there.
func runRepoBackup(ctx context.Context, p repoParams) (*model.SnapshotMetadata, *write.Result, error) {
	out := p.Out
	if out == nil {
		out = io.Discard
	}
	b, err := repoBackend(ctx, cfg, p.StorageCfg)
	if err != nil {
		return nil, nil, err
	}
	label := "[" + p.SurfaceID + "]"
	locked := repoLocked(p.StorageCfg)
	var skip []string
	if p.StorageCfg.Type == config.StorageTypeLocal || p.StorageCfg.Type == "" {
		lp := p.StorageCfg.LocalPath
		if lp == "" {
			lp = "./safegrd-storage"
		}
		skip = append(skip, lp)
	}
	skip = append(skip, filepath.Join(p.StateDir, "cache"))
	started := time.Now()
	var meta *model.SnapshotMetadata
	host, _ := os.Hostname()
	res, err := write.Run(ctx, b, write.Options{
		SurfaceID: p.SurfaceID, Roots: p.Roots, Excludes: p.Excludes, OneFilesystem: p.OneFS, SkipPaths: skip,
		StateDir: p.StateDir, Recipient: p.Recipient, Retention: p.Retention, Tier: p.Tier, Planned: p.Planned,
		NewEpoch: p.NewEpoch, Rescan: p.Rescan, Host: host, SnapshotID: p.SnapshotID,
		OnStart: func(r *write.Result) {
			if r.Opened {
				fmt.Fprintf(out, "%s Epoch %s opened (%s). Every file is uploaded once this month.\n", label, r.Epoch.EpochID, reasonText(r.Reason))
			}
			if r.Resumed {
				fmt.Fprintf(out, "%s Resuming epoch %s: %d %s (%s) already uploaded are reused.\n", label, r.Epoch.EpochID,
					r.AdoptedPacks, pluralWord(int64(r.AdoptedPacks), "pack", "packs"), formatBytes(r.AdoptedBytes))
			}
			if !r.Opened && !r.Resumed {
				fmt.Fprintf(out, "%s Incremental, in epoch %s: only what changed since the last run is uploaded.\n", label, r.Epoch.EpochID)
			}
		},
		RecoveryDoc: repoRecoveryDoc(p.StorageCfg, p.NodeID, p.SurfaceID, p.RecoverySealTo, func() *model.SnapshotMetadata { return meta }),
		Sidecar: func(r *write.Result) ([]byte, error) {
			now := time.Now().UTC()
			meta = &model.SnapshotMetadata{
				SnapshotID:         p.SnapshotID,
				NodeID:             p.NodeID,
				SurfaceType:        model.SurfaceTypeFiles,
				CreatedAt:          r.Snapshot.CreatedAt,
				CompletedAt:        &now,
				Status:             model.SnapshotStatusCompleted,
				RawSizeBytes:       r.Snapshot.Stats.LogicalBytes,
				EncryptedSizeBytes: r.WrittenBytes,
				Sha256Checksum:     r.Snapshot.ContentRoot,
				StorageURI:         epochURI(b, r.Epoch, p.SurfaceID),
				FileStats:          &model.FileStatsSummary{TotalFiles: r.Snapshot.Stats.Files, TotalDirectories: int(r.Snapshot.Stats.Dirs)},
				DurationMs:         backupMilliseconds(started),
				Format:             model.SnapshotFormatRepo,
				EpochID:            r.Epoch.EpochID,
				ObjectClass:        r.Class,
			}
			recordRetention(meta, p.StorageCfg, repoKeptUntil(r, repoLocked(p.StorageCfg)))
			meta.Unlocked = repoLocked(p.StorageCfg) && !repoRunLocked(r, true)
			meta.CalculateTotals()
			return json.MarshalIndent(meta, "", "  ")
		},
	})
	if err != nil {
		return nil, nil, err
	}
	snap := res.Snapshot
	if len(snap.Skipped) > 0 {
		var s []string
		for _, sk := range snap.Skipped {
			s = append(s, sk.Path+" ("+sk.Reason+")")
		}
		warnSkipped(s)
	}
	for _, p := range snap.Inconsistent {
		fmt.Fprintf(os.Stderr, "Warning: %s /%s changed while it was read, twice. The second read is stored, and the next run reads it again.\n", label, p)
	}
	if res.CacheWarning != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s %s\n", label, res.CacheWarning)
	}
	if res.RecoveryWarning != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s %s\n", label, res.RecoveryWarning)
	}
	if res.Excluded > 0 && len(p.Excludes) > 0 {
		fmt.Fprintf(out, "%s Left out %s %s matching the exclusions given (%s).\n", label, formatNumber(res.Excluded),
			pluralWord(res.Excluded, "entry", "entries"), strings.Join(p.Excludes, ", "))
	}
	took := shortDuration(time.Since(started))
	if res.Class == format.ClassOpening {
		fmt.Fprintf(out, "%s %s files, %s read, %s stored in %d %s, %s.\n", label, formatNumber(snap.Stats.Files),
			formatBytes(res.ReadBytes), formatBytes(res.WrittenBytes), snap.Stats.NewPacks, pluralWord(snap.Stats.NewPacks, "pack", "packs"), took)
	} else {
		fmt.Fprintf(out, "%s %s files, %s changed, %s read, %s stored in %d %s, %s.\n", label, formatNumber(snap.Stats.Files),
			formatNumber(res.ChangedFiles), formatBytes(res.ReadBytes), formatBytes(res.WrittenBytes), snap.Stats.NewPacks,
			pluralWord(snap.Stats.NewPacks, "pack", "packs"), took)
	}
	printRepoKept(out, label, res, locked)
	return meta, res, nil
}

// repoLocked reports whether a repository on this storage is under Object
// Lock: hosted storage always is, a local directory never, and a bucket
// unless worm_mode is NONE.
func repoLocked(sc config.StorageConfig) bool {
	switch sc.Type {
	case config.StorageTypeHosted:
		return true
	case config.StorageTypeLocal, "":
		return false
	}
	mode, err := sc.ResolveWORMMode()
	return err != nil || mode != config.WORMModeNone
}

// repoKeptUntil is the date a run's snapshot is recorded and printed with.
// Under Object Lock it is the lock every object of the run carries, which
// is the epoch's lock for the run's class: the planned retention can be
// shorter (two days for a one-off backup), but nothing can delete the
// objects before the lock ends, and the record said "locked until" the
// shorter date while the bucket held them for weeks. Without a lock it is
// how long the snapshot is kept.
func repoKeptUntil(res *write.Result, locked bool) time.Time {
	if res.Decision.Known {
		return res.Decision.Until().UTC()
	}
	if locked {
		if lock := res.Epoch.RetainUntil(res.Class); !lock.IsZero() {
			return lock.UTC()
		}
	}
	return res.Snapshot.RetainUntil.UTC()
}

// repoRunLocked reports whether the run's objects are under a lock: the
// storage's lock, unless the remote server wrote this run unlocked.
func repoRunLocked(res *write.Result, locked bool) bool {
	if res.Decision.Known {
		return locked && res.Decision.Locked
	}
	return locked
}

// printRepoKept prints the line that closes a run: how long its snapshot is
// kept, and whether it is locked for that long.
func printRepoKept(out io.Writer, label string, res *write.Result, locked bool) {
	snap := res.Snapshot
	until := repoKeptUntil(res, locked).Format("2006-01-02")
	switch {
	case res.Decision.Known && !res.Decision.Locked:
		fmt.Fprintf(out, "%s Snapshot %s complete. Kept until %s, not locked: this project locks the day's first backup and the weekly and monthly copies.\n",
			label, snap.SnapshotID, until)
	case res.Decision.Known && res.Decision.Scheduled:
		fmt.Fprintf(out, "%s Snapshot %s complete. Locked until %s (daily copy).\n", label, snap.SnapshotID, until)
	case !locked:
		fmt.Fprintf(out, "%s Snapshot %s complete. Not locked: this storage applies no Object Lock; it is kept until %s.\n",
			label, snap.SnapshotID, until)
	case res.Class == format.ClassOpening && res.Epoch.OpeningTier == format.TierMonthly:
		fmt.Fprintf(out, "%s Snapshot %s complete. Immutable until %s: the month's first backup is kept as its monthly copy. Later backups follow the surface's retention.\n",
			label, snap.SnapshotID, until)
	default:
		fmt.Fprintf(out, "%s Snapshot %s complete. Immutable until %s.\n", label, snap.SnapshotID, until)
	}
	// A capped lock is said once, as the reason, not as a second date: "Kept
	// until 2026-10-19, not 2027-01-04" named a date nobody chose on a
	// trial's first backup (ADR-0041 ends a trial's hosted locks with the
	// trial, which is what capped it).
	if res.Capped {
		fmt.Fprintf(out, "%s The lock ends with this repository's month of objects, or with a trial, whichever comes first.\n", label)
	}
}

// repoSnapshot is a repository snapshot found in storage.
type repoSnapshot struct {
	Backend   sink.Backend
	Epoch     sink.EpochInfo
	SurfaceID string
	Meta      *model.SnapshotMetadata
}

// lister is a backend that can enumerate its surfaces.
type lister interface {
	Surfaces(ctx context.Context) ([]string, error)
}

// findRepoSnapshot looks for snapshotID among the repositories in storage.
// It returns nil, nil when there is none of that id.
func findRepoSnapshot(ctx context.Context, b sink.Backend, snapshotID string) (*repoSnapshot, error) {
	if sink.ValidSnapshotName(snapshotID) != nil {
		return nil, nil
	}
	l, ok := b.(lister)
	if !ok {
		return nil, nil
	}
	surfaces, err := l.Surfaces(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range surfaces {
		es, err := b.Epochs(ctx, s)
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			key, _ := sink.ObjectKey(e.Prefix, sink.KindMeta, snapshotID)
			body, err := b.Get(ctx, key)
			if errors.Is(err, sink.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			var m model.SnapshotMetadata
			if err := json.Unmarshal(body, &m); err != nil {
				return nil, fmt.Errorf("the sidecar of %s does not parse: %w", snapshotID, err)
			}
			return &repoSnapshot{Backend: b, Epoch: e, SurfaceID: s, Meta: &m}, nil
		}
	}
	return nil, nil
}

// repoSnapshots lists every repository snapshot in storage with its sidecar.
func repoSnapshots(ctx context.Context, b sink.Backend) ([]repoSnapshot, error) {
	l, ok := b.(lister)
	if !ok {
		return nil, nil
	}
	surfaces, err := l.Surfaces(ctx)
	if err != nil {
		return nil, err
	}
	var out []repoSnapshot
	for _, s := range surfaces {
		es, err := b.Epochs(ctx, s)
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			ids, err := check.Snapshots(ctx, b, e)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				key, _ := sink.ObjectKey(e.Prefix, sink.KindMeta, id)
				body, err := b.Get(ctx, key)
				if err != nil {
					return nil, err
				}
				var m model.SnapshotMetadata
				if err := json.Unmarshal(body, &m); err != nil {
					return nil, fmt.Errorf("the sidecar of %s does not parse: %w", id, err)
				}
				out = append(out, repoSnapshot{Backend: b, Epoch: e, SurfaceID: s, Meta: &m})
			}
		}
	}
	return out, nil
}

// restoreRepoSnapshot restores a repository snapshot, all of it or the paths
// selected. The content root recomputed from the snapshot's trees is held to
// the one recorded at backup time before anything is written, and every file
// to its SHA-256 in the tree before it takes its place.
func restoreRepoSnapshot(ctx context.Context, rs *repoSnapshot, privateKey, targetDir string, paths []string) error {
	ids, err := unseal.Identities(privateKey)
	if err != nil {
		return err
	}
	snapshotID := rs.Meta.SnapshotID
	r := read.Open(rs.Backend, rs.Epoch, ids)
	snap, err := r.Snapshot(ctx, snapshotID)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", snapshotID, err)
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", snapshotID, err)
	}
	started := time.Now()
	root, _, err := r.ContentRoot(ctx, idx, snap)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", snapshotID, err)
	}
	if err := checkRepoContentRoot(ctx, rs.Meta, snapshotID, root); err != nil {
		return err
	}
	// A snapshot of one directory restores that directory's contents into
	// the target, as an archive of it does. One of several roots, or of /,
	// restores at its paths from /.
	base := ""
	if len(snap.Roots) == 1 && snap.Roots[0] != "/" {
		base = strings.TrimPrefix(snap.Roots[0], "/")
	}
	res, err := r.Restore(ctx, snap, idx, read.RestoreOptions{Target: targetDir, Paths: paths, Base: base})
	if err != nil {
		return fmt.Errorf("restore failed, and %s is as it was: %w", targetDir, err)
	}
	switch {
	case len(paths) > 0:
		fmt.Printf("   Restored %s, from the backup of %s, into %s.\n", strings.Join(paths, ", "), snap.Roots[0], targetDir)
	case base != "":
		fmt.Printf("   Restored the contents of %s into %s.\n", snap.Roots[0], targetDir)
	}
	fmt.Printf("Restored %s %s (%s) from %s in %s. Every file matched its SHA-256.\n", formatNumber(res.Files),
		pluralWord(res.Files, "file", "files"), formatBytes(res.Bytes), snapshotID, shortDuration(time.Since(started)))
	if res.Symlinks > 0 || res.Dirs > 0 {
		fmt.Printf("   Also %d %s and %d %s.\n", res.Dirs, pluralWord(res.Dirs, "directory", "directories"), res.Symlinks, pluralWord(res.Symlinks, "symlink", "symlinks"))
	}
	fmt.Printf("   Destination:    %s\n", targetDir)
	printFileRestoreLimits(&dump.FileExtractionResult{OwnershipRestored: res.OwnershipRestored, OwnershipNote: res.OwnershipNote})
	return nil
}

// checkRepoContentRoot holds a repository snapshot's content root to the one
// recorded at backup time: the remote server's record when it can be asked,
// the sidecar when not.
func checkRepoContentRoot(ctx context.Context, meta *model.SnapshotMetadata, snapshotID, root string) error {
	expected, source := meta.Sha256Checksum, "sidecar"
	rec, why := runner.RecordedDigests(ctx, cfg.ServerURL, cfg.ServerToken, snapshotID)
	if rec != nil {
		expected, source = rec.Sha256Checksum, "remote server's record"
	}
	switch {
	case expected == "":
		return fmt.Errorf("no content root is recorded for %s (%s), so nothing proves it is what was backed up; nothing was restored", snapshotID, why)
	case root != expected:
		return fmt.Errorf("snapshot %s has content root %s, the %s says %s: it is not the snapshot that was backed up; nothing was restored", snapshotID, root, source, expected)
	case rec == nil:
		fmt.Fprintf(os.Stderr, "Warning: content root checked against the sidecar only: %s.\n"+
			"    It was not compared with SafeGrd's record from backup time; run this on an enrolled host to compare.\n", why)
	default:
		if meta.Sha256Checksum != rec.Sha256Checksum {
			return fmt.Errorf("the sidecar of %s records content root %s, the remote server %s: the sidecar was changed; nothing was restored", snapshotID, meta.Sha256Checksum, rec.Sha256Checksum)
		}
		fmt.Println("   Content root:   matches the remote server's record from backup time")
	}
	return nil
}

// verifyRepoSnapshot runs the repository drill on one snapshot and prints it
// the way verify prints every drill.
func verifyRepoSnapshot(ctx context.Context, rs *repoSnapshot, privateKey string) error {
	verifier := runner.NewVerifier(nil, cfg.ServerURL)
	if cfg.ServerToken != "" {
		verifier.SetServerToken(cfg.ServerToken)
	}
	how := "restoring every file"
	if runner.IsRepoWordPress(rs.Meta) {
		how = "reading the site back in memory"
	}
	fmt.Printf("Verifying %s (epoch %s, %s): checking the packs, %s, recomputing the content root.\n",
		rs.Meta.SnapshotID, rs.Epoch.Epoch.EpochID, rs.SurfaceID, how)
	report, err := verifier.RunRepoDrill(ctx, runner.RepoDrill{Backend: rs.Backend, Epoch: rs.Epoch, Meta: rs.Meta,
		Scratch: drillScratch()}, privateKey)
	if err != nil {
		return err
	}
	for _, a := range report.Assertions {
		status := "PASS"
		if !a.Passed {
			status = "FAIL"
		}
		fmt.Printf("   [%s] %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Expected, a.Actual)
	}
	if report.Status != model.VerificationStatusPassed {
		return fmt.Errorf("verification of %s failed: %s", rs.Meta.SnapshotID, report.ErrorMessage)
	}
	if runner.IsRepoWordPress(rs.Meta) {
		fmt.Printf("Dry restore verified: %d tables, %s rows, every file and attachment, in %s\n", report.TablesRestored, formatNumber(report.RowsRestored),
			time.Duration(report.DurationMs*int64(time.Millisecond)).Round(time.Millisecond))
	} else {
		fmt.Printf("Restore verified: %s files, %d directories, in %s\n", formatNumber(report.RowsRestored), report.TablesRestored,
			time.Duration(report.DurationMs*int64(time.Millisecond)).Round(time.Millisecond))
	}
	fmt.Printf("   Verification ID: %s\n", report.VerificationID)
	fmt.Printf("   Certificate:     %s\n", report.CertificateHash)
	return nil
}

// drillScratch is where a drill restores to: under the state directory, so
// a large tree does not land in a small /tmp.
func drillScratch() string { return drillScratchIn(resolveStateDir("", cfg)) }

// stateDirOf is the state directory a config names, or the default.
func stateDirOf(c *config.CLIConfig) string { return resolveStateDir("", c) }

// drillScratchIn makes a fresh scratch directory under stateDir/drill.
func drillScratchIn(stateDir string) string {
	dir := filepath.Join(stateDir, "drill")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	d, err := os.MkdirTemp(dir, "restore-")
	if err != nil {
		return ""
	}
	return d
}

// repoBackendsAll opens the repository of every node filed under this
// storage: the host's own first, then each surface the daemon files under a
// node of its own, then any other a recovery machine may be looking for.
func repoBackendsAll(ctx context.Context, storageCfg config.StorageConfig) ([]sink.Backend, error) {
	// Hosted storage's bucket holds the whole organization; read every node.
	if hostedLayout(storageCfg) {
		return hostedLayoutRepos(ctx, storageCfg, "")
	}
	primary, err := repoBackend(ctx, cfg, storageCfg)
	if err != nil {
		return nil, err
	}
	out := []sink.Backend{primary}
	// Hosted storage answers for the whole organization at once.
	if h, ok := primary.(*hostedRepo); ok {
		h.allNodes = true
		return out, nil
	}
	d, ok := primary.(*sink.Direct)
	if !ok {
		return out, nil
	}
	base := storageCfg
	base.NodeID = ""
	bb, err := repoBackend(ctx, cfg, base)
	if err != nil {
		return out, nil
	}
	bd, ok := bb.(*sink.Direct)
	if !ok {
		return out, nil
	}
	ch, ok := bd.S.(sink.Children)
	if !ok {
		return out, nil
	}
	nodes, err := ch.Children(ctx, bd.S.Root())
	if err != nil {
		return nil, err
	}
	if names, _ := ch.Children(ctx, path.Join(bd.S.Root(), "repo")); len(names) > 0 && d.S.Root() != bd.S.Root() {
		out = append(out, bb)
	}
	for _, n := range nodes {
		if n == "repo" || n == strings.TrimSpace(storageCfg.NodeID) {
			continue
		}
		if names, _ := ch.Children(ctx, path.Join(bd.S.Root(), n, "repo")); len(names) == 0 {
			continue
		}
		nc := storageCfg
		nc.NodeID = n
		nb, err := repoBackend(ctx, cfg, nc)
		if err != nil {
			return nil, err
		}
		out = append(out, nb)
	}
	return out, nil
}

// locateRepoSnapshot finds snapshotID in any repository under this storage.
func locateRepoSnapshot(ctx context.Context, storageCfg config.StorageConfig, snapshotID string) (*repoSnapshot, error) {
	bs, err := repoBackendsAll(ctx, storageCfg)
	if err != nil {
		return nil, err
	}
	for _, b := range bs {
		rs, err := findRepoSnapshot(ctx, b, snapshotID)
		if err != nil || rs != nil {
			return rs, err
		}
	}
	return nil, nil
}
