package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/storage"
)

// A surface's copies are up to two more S3 buckets every backup is written
// to, each under its own key, lock and retention: copies: in the config, or
// the buckets the project names on the remote server, which replace them.
// An archive is written to every bucket from one stream (storage.Tee); a run
// of an incremental repository is copied after it commits. Whatever a bucket
// did not take, the catch-up writes later. A copy that fails never fails the
// backup: it is said on stderr and on the record.

// resolvedCopy is one bucket a surface writes to beside its own storage.
type resolvedCopy struct {
	name string
	cfg  config.StorageConfig
}

// projectCopiesSaid is the hosts' configs whose copies: were said to be
// replaced by the project's, so the warning is printed once a run.
var projectCopiesSaid sync.Map

// surfaceCopies is the buckets surface s writes to beside primary: the
// project's, when the remote server names any, else the config's. A config
// whose copies: does not validate is said, and the backup goes on to its
// own storage alone.
func surfaceCopies(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string, primary config.StorageConfig) []resolvedCopy {
	var out []resolvedCopy
	if server := projectCopies(ctx, c, primary); len(server) > 0 {
		if len(c.Copies) > 0 {
			if _, said := projectCopiesSaid.LoadOrStore(c, true); !said {
				var names, buckets []string
				for _, cp := range c.Copies {
					names = append(names, cp.Name)
				}
				for _, cp := range server {
					buckets = append(buckets, cp.cfg.Bucket)
				}
				fmt.Fprintf(os.Stderr, "Warning: the project's storage replaces the copies in this config (%s); backups are copied to %s\n",
					strings.Join(names, ", "), strings.Join(buckets, ", "))
			}
		}
		out = server
	} else {
		if err := c.ValidateCopies(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v. This backup is written to its own storage only.\n", err)
			return nil
		}
		for _, cp := range c.CopiesOf(s) {
			cfg := cp.StorageConfig
			for _, f := range []*string{&cfg.AccessKeyID, &cfg.SecretAccessKey} {
				v, err := resolveConfigSecret("copies "+cp.Name+" key", *f)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: copy %s is not written: %v\n", cp.Name, err)
					cfg.Bucket = ""
					break
				}
				*f = v
			}
			if cfg.Bucket == "" {
				continue
			}
			out = append(out, resolvedCopy{name: cp.Name, cfg: cfg})
		}
	}
	for i := range out {
		out[i].cfg.NodeID = nodeID
		if out[i].cfg.RetentionDays == 0 {
			out[i].cfg.RetentionDays = primary.RetentionDays
		}
	}
	return out
}

// projectCopies is the buckets the project on the remote server names beside
// its own, with the keys it holds for them.
func projectCopies(ctx context.Context, c *config.CLIConfig, primary config.StorageConfig) []resolvedCopy {
	if !canReport(c) || c.NodeID == "" {
		return nil
	}
	sinkResp, err := fetchNodeSink(ctx, c.ServerURL, c.NodeID, c.ServerToken)
	if err != nil || len(sinkResp.Copies) == 0 {
		return nil
	}
	keys := map[string]config.StorageConfig{}
	if creds, err := fetchNodeCredentials(ctx, c.ServerURL, c.NodeID, c.ServerToken); err == nil {
		for _, k := range creds.Copies {
			keys[k.Name] = config.StorageConfig{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}
		}
	} else {
		fmt.Fprintf(os.Stderr, "Warning: could not fetch the keys of the project's other buckets (%v)\n", err)
	}
	var out []resolvedCopy
	for _, sc := range sinkResp.Copies {
		cfg := config.StorageConfig{Type: config.StorageTypeS3, Bucket: sc.Bucket, Region: sc.Region, Endpoint: sc.Endpoint,
			Prefix: sc.Prefix, ForcePathStyle: sc.ForcePathStyle, WORMMode: config.WORMMode(sc.WORMMode),
			RetentionDays: sc.RetentionDays, StorageClass: sc.StorageClass, AccessKeyID: sc.AccessKeyID}
		if k, ok := keys[sc.Name]; ok {
			cfg.AccessKeyID, cfg.SecretAccessKey = k.AccessKeyID, k.SecretAccessKey
		}
		if cfg.SecretAccessKey == "" {
			fmt.Fprintf(os.Stderr, "Warning: the project's bucket %s (%s) has no key on this host and the remote server holds none; it is not written\n", sc.Name, sc.Bucket)
			continue
		}
		out = append(out, resolvedCopy{name: sc.Name, cfg: cfg})
	}
	return out
}

// openCopies opens each copy's bucket. One that cannot be opened is said
// and left out of this backup; the catch-up writes it later.
func openCopies(ctx context.Context, copies []resolvedCopy) []storage.NamedCopy {
	var out []storage.NamedCopy
	for _, rc := range copies {
		p, err := storage.NewProvider(ctx, rc.cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: copy to %s failed: opening the bucket: %v; the catch-up will retry\n", rc.name, err)
			continue
		}
		if rc.cfg.NodeID != "" {
			if s, ok := p.(interface{ SetNodeID(string) }); ok {
				s.SetNodeID(rc.cfg.NodeID)
			}
		}
		out = append(out, storage.NamedCopy{Name: rc.name, Provider: p, WORMMode: string(rc.cfg.WORMMode), RetentionDays: rc.cfg.RetentionDays})
	}
	return out
}

// teeCopies wraps a surface's storage so each archive is written to its
// copies too. It returns the provider unchanged for a surface with none.
func teeCopies(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string, primaryCfg config.StorageConfig, p storage.StorageProvider) (storage.StorageProvider, int) {
	copies := surfaceCopies(ctx, c, s, nodeID, primaryCfg)
	if len(copies) == 0 {
		return p, 0
	}
	return storage.NewTee(p, openCopies(ctx, copies)...), len(copies)
}

// noteTeeCopies records what the copies of an archive came to on its record,
// and says each: where it is and its lock, or why it failed.
func noteTeeCopies(provider storage.StorageProvider, meta *model.SnapshotMetadata) {
	tee, ok := provider.(*storage.Tee)
	if !ok {
		return
	}
	for _, r := range tee.Results(meta.SnapshotID) {
		sc := model.SnapshotCopy{SnapshotID: meta.SnapshotID, Bucket: r.Name, StorageURI: r.StorageURI, WORMMode: r.WORMMode, State: model.CopyHeld}
		if !r.RetainUntil.IsZero() {
			until := r.RetainUntil
			sc.RetainUntil = &until
		}
		if r.Err != nil {
			sc.State, sc.Error, sc.StorageURI = model.CopyFailed, r.Err.Error(), ""
			fmt.Fprintf(os.Stderr, "Warning: copy to %s failed: %v; the catch-up will retry\n", r.Name, r.Err)
		} else {
			fmt.Printf("   Copy %s:%s%s, %s\n", r.Name, strings.Repeat(" ", max(1, 11-len(r.Name))), r.StorageURI, copyLockWords(sc))
		}
		meta.Copies = append(meta.Copies, sc)
	}
}

// copyLockWords says a copy's lock: never "locked" over a bucket under
// worm_mode NONE.
func copyLockWords(sc model.SnapshotCopy) string {
	switch {
	case sc.WORMMode == string(config.WORMModeNone):
		if sc.RetainUntil != nil {
			return "kept until " + sc.RetainUntil.UTC().Format("2006-01-02") + ", not locked (worm_mode NONE)"
		}
		return "not locked (worm_mode NONE)"
	case sc.RetainUntil != nil:
		return "locked until " + sc.RetainUntil.UTC().Format("2006-01-02 15:04 UTC")
	}
	return "no lock date"
}

// copyBehind is one copy's state after a catch-up.
type copyBehind struct {
	name    string
	missing int
	err     error
}

// syncCopies is the catch-up: for each of the surface's copies, every
// snapshot its own storage holds within the copy's retention and the copy
// does not, written primary to copy. An archive is checked for before it is
// written (a second write of a key under Object Lock is a new locked version
// nobody can delete) and held to its digest; a run of an incremental
// repository is copied object by object, an object already there skipped,
// the epoch's descriptor last. only names one copy, or all when empty.
// dryRun counts what is missing and writes nothing.
func syncCopies(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID, only string, dryRun bool) ([]copyBehind, []model.SnapshotCopy, error) {
	primaryCfg, err := surfaceStorageConfig(ctx, c, s, nodeID)
	if err != nil {
		return nil, nil, err
	}
	copies := surfaceCopies(ctx, c, s, nodeID, primaryCfg)
	if only != "" {
		var keep []resolvedCopy
		for _, rc := range copies {
			if rc.name == only {
				keep = append(keep, rc)
			}
		}
		if len(keep) == 0 {
			return nil, nil, fmt.Errorf("surface %s writes to no copy named %s", s.ID, only)
		}
		copies = keep
	}
	if len(copies) == 0 {
		return nil, nil, nil
	}
	primary, err := openStorage(ctx, c, primaryCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("opening the surface's own storage: %w", err)
	}
	var behind []copyBehind
	var reported []model.SnapshotCopy
	for _, rc := range copies {
		b := copyBehind{name: rc.name}
		dst, err := storage.NewProvider(ctx, rc.cfg)
		if err != nil {
			b.err = fmt.Errorf("opening the bucket: %w", err)
			behind = append(behind, b)
			continue
		}
		setNode(dst, nodeID, nodeID)
		missing, wrote, err := syncArchives(ctx, primary, dst, rc, dryRun)
		b.missing += missing
		reported = append(reported, wrote...)
		if err != nil {
			b.err = err
		}
		rmissing, rwrote, err := syncRepos(ctx, c, primaryCfg, rc, s.ID, nodeID, dryRun)
		b.missing += rmissing
		reported = append(reported, rwrote...)
		if err != nil && b.err == nil {
			b.err = err
		}
		behind = append(behind, b)
	}
	return behind, reported, nil
}

// syncArchives copies the archives the primary holds and the copy lacks.
func syncArchives(ctx context.Context, primary, dst storage.StorageProvider, rc resolvedCopy, dryRun bool) (missing int, wrote []model.SnapshotCopy, err error) {
	ids, err := primary.ListSnapshots(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("listing the surface's own storage: %w", err)
	}
	window := rc.cfg.RetentionDays
	if window <= 0 {
		window = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -window)
	sort.Strings(ids)
	for _, id := range ids {
		taken, ok := snapshotIDTime(id)
		if !ok || taken.Before(since) {
			continue
		}
		// ListSnapshots reads the whole prefix; only this surface's node is
		// copied, under its own node.
		if here, err := primary.SnapshotExists(ctx, id); err != nil || !here {
			continue
		}
		there, xerr := dst.SnapshotExists(ctx, id)
		if xerr != nil {
			return missing, wrote, fmt.Errorf("the bucket could not be read: %w", xerr)
		}
		if there {
			continue
		}
		missing++
		if dryRun {
			continue
		}
		sc, cerr := copyArchive(ctx, primary, dst, id, rc, taken)
		wrote = append(wrote, sc)
		if cerr != nil {
			err = cerr
			continue
		}
		missing--
	}
	return missing, wrote, err
}

// copyArchive writes one archive and its manifest into a copy, locked from
// when the snapshot was taken for the copy's retention, and holds it to the
// digest recorded at backup time.
func copyArchive(ctx context.Context, src, dst storage.StorageProvider, id string, rc resolvedCopy, taken time.Time) (model.SnapshotCopy, error) {
	sc := model.SnapshotCopy{SnapshotID: id, Bucket: rc.name, WORMMode: string(rc.cfg.WORMMode), State: model.CopyFailed}
	until := taken.AddDate(0, 0, rc.cfg.RetentionDays)
	if !until.After(time.Now().Add(time.Minute)) {
		until = time.Time{}
	} else {
		sc.RetainUntil = &until
	}
	meta, err := src.DownloadMetadata(ctx, id)
	if err != nil {
		sc.Error = "reading its manifest: " + err.Error()
		return sc, fmt.Errorf("%s: %s", id, sc.Error)
	}
	body, err := src.DownloadSnapshot(ctx, id)
	if err != nil {
		sc.Error = "reading it: " + err.Error()
		return sc, fmt.Errorf("%s: %s", id, sc.Error)
	}
	defer body.Close()
	uri, err := dst.UploadSnapshot(ctx, id, body, -1, until)
	if err != nil {
		sc.Error = "writing it: " + err.Error()
		return sc, fmt.Errorf("%s: %s", id, sc.Error)
	}
	m := *meta
	m.StorageURI = uri
	if !until.IsZero() {
		m.WORMRetentionUntil = until
	}
	if err := dst.UploadMetadata(ctx, id, &m); err != nil {
		sc.Error = "writing its manifest: " + err.Error()
		return sc, fmt.Errorf("%s: %s", id, sc.Error)
	}
	sc.State, sc.StorageURI = model.CopyHeld, uri
	return sc, nil
}

// syncRepos copies the epochs of the surface's incremental repository the
// copy does not hold in full.
func syncRepos(ctx context.Context, c *config.CLIConfig, primaryCfg config.StorageConfig, rc resolvedCopy, surfaceID, nodeID string, dryRun bool) (missing int, wrote []model.SnapshotCopy, err error) {
	src, err := repoBackend(ctx, c, primaryCfg)
	if err != nil {
		return 0, nil, nil // no repository here
	}
	epochs, err := src.Epochs(ctx, surfaceID)
	if err != nil || len(epochs) == 0 {
		return 0, nil, nil
	}
	dcfg := rc.cfg
	dcfg.NodeID = nodeID
	dstB, err := repoBackend(ctx, c, dcfg)
	if err != nil {
		return 0, nil, fmt.Errorf("opening the copy's repository: %w", err)
	}
	dst, ok := dstB.(*sink.Direct)
	if !ok {
		return 0, nil, fmt.Errorf("a copy of a repository is written to a bucket")
	}
	rows, _ := repoSnapshots(ctx, src)
	for _, e := range epochs {
		objs, lerr := src.List(ctx, e, "")
		if lerr != nil {
			return missing, wrote, lerr
		}
		have := map[string]int64{}
		prefix := sink.EpochPrefix(dst.S.Root(), surfaceID, e.Epoch.EpochID)
		if existing, lerr := dst.S.List(ctx, prefix+"/"); lerr == nil {
			for _, o := range existing {
				have[o.Key] = o.Size
			}
		}
		lacking := 0
		for _, o := range objs {
			if size, ok := have[prefix+strings.TrimPrefix(o.Key, e.Prefix)]; !ok || size != o.Size {
				lacking++
			}
		}
		if lacking == 0 {
			continue
		}
		var snaps []string
		for _, r := range rows {
			if r.SurfaceID == surfaceID && r.Epoch.Epoch.EpochID == e.Epoch.EpochID {
				snaps = append(snaps, r.Meta.SnapshotID)
			}
		}
		missing += max(len(snaps), 1)
		if dryRun {
			continue
		}
		_, _, cerr := exportEpoch(ctx, src, e, dst, surfaceID)
		state, msg := model.CopyHeld, ""
		if cerr != nil {
			state, msg, err = model.CopyFailed, cerr.Error(), cerr
		} else {
			missing -= max(len(snaps), 1)
		}
		until := e.Epoch.OpeningRetainUntil
		for _, id := range snaps {
			sc := model.SnapshotCopy{SnapshotID: id, Bucket: rc.name, WORMMode: string(rc.cfg.WORMMode), State: state, Error: msg,
				StorageURI: copyRepoURI(rc.cfg, prefix)}
			if !until.IsZero() && rc.cfg.WORMMode != config.WORMModeNone {
				u := until
				sc.RetainUntil = &u
			}
			wrote = append(wrote, sc)
		}
	}
	return missing, wrote, err
}

func copyRepoURI(cfg config.StorageConfig, prefix string) string {
	return "s3://" + cfg.Bucket + "/" + strings.TrimLeft(prefix, "/")
}

// snapshotIDTime reads when a snapshot was taken from its id,
// snap-YYYYMMDD-HHMMSS-xxxxxx.
func snapshotIDTime(id string) (time.Time, bool) {
	parts := strings.SplitN(strings.TrimPrefix(id, "snap-"), "-", 3)
	if len(parts) < 2 {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102150405", parts[0]+parts[1])
	return t.UTC(), err == nil
}

// surfaceStorageConfig is the storage a surface backs up to, resolved as its
// backup resolves it, keys included.
func surfaceStorageConfig(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string) (config.StorageConfig, error) {
	storageCfg := c.Storage
	if s.Storage != nil {
		storageCfg = *s.Storage
		if err := checkSurfaceStorage(ctx, c, &storageCfg); err != nil {
			return storageCfg, err
		}
	} else if err := routeProjectSink(ctx, c, &storageCfg, false, false); err != nil {
		return storageCfg, err
	}
	if nodeID != "" && storageCfg.NodeID == "" {
		storageCfg.NodeID = nodeID
	}
	storageCfg.RetentionDays = surfaceRetentionDays(c, s)
	if _, err := resolveHostedStorage(ctx, c, &storageCfg, false); err != nil {
		return storageCfg, err
	}
	applyHeldSinkKey(ctx, c, &storageCfg)
	return storageCfg, nil
}

// reportCopies tells the remote server what the copies of a surface's
// snapshots came to. A failure is said: the copies are in the buckets either
// way, and the next catch-up reports again.
func reportCopies(ctx context.Context, c *config.CLIConfig, nodeID string, copies []model.SnapshotCopy) {
	if len(copies) == 0 || !canReport(c) || nodeID == "" {
		return
	}
	if status, err := postJSON(ctx, c, "/api/v1/nodes/"+url.PathEscape(nodeID)+"/copies", model.CopiesReport{Copies: copies}, nil); err != nil {
		noteServerStatus(status)
		fmt.Fprintf(os.Stderr, "Warning: the remote server was not told about %d copies of this surface's snapshots: %v\n", len(copies), err)
	}
}

// copyBehindOf is the heartbeat's view of a catch-up.
func copyBehindOf(prev []model.CopyBehind, behind []copyBehind, now time.Time) []model.CopyBehind {
	since := map[string]*time.Time{}
	for _, p := range prev {
		since[p.Name] = p.Since
	}
	var out []model.CopyBehind
	for _, b := range behind {
		if b.missing == 0 && b.err == nil {
			continue
		}
		cb := model.CopyBehind{Name: b.name, Missing: b.missing, Since: since[b.name]}
		if cb.Since == nil {
			t := now
			cb.Since = &t
		}
		if b.err != nil {
			cb.Error = b.err.Error()
		}
		out = append(out, cb)
	}
	return out
}

// copySyncEvery is how often the daemon's catch-up runs for a surface with a
// copy behind. Each run lists the surface's own storage and the copy's.
const copySyncEvery = 30 * time.Minute

// afterBackupCopies brings a surface's copies level after a backup: a run of
// a repository is copied now, and an archive a copy did not take is left to
// the catch-up's next turn, which the heartbeat says is due.
func afterBackupCopies(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string, meta *model.SnapshotMetadata, st *SurfaceState) {
	st.HasCopies = st.hasCopies
	if !st.hasCopies || meta == nil {
		return
	}
	// A copy that could not even be opened is not on the record at all.
	failed := len(meta.Copies) < st.copiesWanted
	for _, cp := range meta.Copies {
		if cp.State != model.CopyHeld {
			failed = true
		}
	}
	if meta.EpochID == "" && !failed && len(meta.Copies) > 0 {
		st.CopiesBehind = nil
		return
	}
	runCopySync(ctx, c, s, nodeID, st)
}

// runCopySync is one turn of the catch-up for a surface: it writes what the
// copies lack, reports it, and records which are still behind.
func runCopySync(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string, st *SurfaceState) {
	st.LastCopySync = time.Now().UTC()
	behind, wrote, err := syncCopies(ctx, c, s, nodeID, "", false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: the copies could not be caught up: %v\n", s.ID, err)
		st.CopiesBehind = copyBehindOf(st.CopiesBehind, []copyBehind{{name: "all", err: err}}, time.Now().UTC())
		return
	}
	reportCopies(ctx, c, nodeID, wrote)
	for _, w := range wrote {
		if w.State == model.CopyHeld {
			fmt.Printf("Surface %s: copied %s to %s, %s\n", s.ID, w.SnapshotID, w.Bucket, copyLockWords(w))
		}
	}
	for _, b := range behind {
		if b.err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Surface %s: copy to %s is behind by %d: %v; the catch-up will retry\n", s.ID, b.name, b.missing, b.err)
		}
	}
	st.CopiesBehind = copyBehindOf(st.CopiesBehind, behind, time.Now().UTC())
}

// copySyncDue reports whether a surface's catch-up should run this tick: a
// copy is behind and the last turn was a while ago.
func copySyncDue(st *SurfaceState, now time.Time) bool {
	return len(st.CopiesBehind) > 0 && now.Sub(st.LastCopySync) >= copySyncEvery
}

// storageOrCopy is the storage a reading command uses: routed as backup
// routes it, or the copy named, which holds the same keys under its own
// prefix and so reads the same way.
func storageOrCopy(ctx context.Context, name string) (config.StorageConfig, error) {
	if name == "" {
		return resolveStorageRouting(ctx, cfg, "", "", "", "", false)
	}
	var known []string
	for _, rc := range projectCopies(ctx, cfg, cfg.Storage) {
		if rc.name == name {
			rc.cfg.NodeID = cfg.NodeID
			return rc.cfg, nil
		}
		known = append(known, rc.name)
	}
	for _, cp := range cfg.Copies {
		if cp.Name != name {
			known = append(known, cp.Name)
			continue
		}
		st := cp.StorageConfig
		for _, f := range []*string{&st.AccessKeyID, &st.SecretAccessKey} {
			v, err := resolveConfigSecret("copies "+cp.Name+" key", *f)
			if err != nil {
				return st, err
			}
			*f = v
		}
		st.NodeID = cfg.NodeID
		return st, nil
	}
	if len(known) == 0 {
		return config.StorageConfig{}, fmt.Errorf("--from-bucket %s: this config has no copies: and the project names no other bucket", name)
	}
	return config.StorageConfig{}, fmt.Errorf("--from-bucket %s: no copy by that name; there is %s", name, strings.Join(known, ", "))
}
