package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/format"
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
// own storage alone. ignored names the config's copies of s that the
// project's buckets replace, for the heartbeat to say.
func surfaceCopies(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string, primary config.StorageConfig) (out []resolvedCopy, ignored []string) {
	if server := projectCopies(ctx, c, primary); len(server) > 0 {
		for _, cp := range c.CopiesOf(s) {
			ignored = append(ignored, cp.Name)
		}
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
			return nil, nil
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
	return out, ignored
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
		out = append(out, storage.NamedCopy{Name: rc.name, Provider: p, WORMMode: string(rc.cfg.WORMMode), RetentionDays: rc.cfg.RetentionDays, Config: rc.cfg})
	}
	return out
}

// teeCopies wraps a surface's storage so each archive is written to its
// copies too, and returns the copies so a repository run writes them as it
// goes. It returns the provider unchanged for a surface with none.
func teeCopies(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string, primaryCfg config.StorageConfig, p storage.StorageProvider) (storage.StorageProvider, []resolvedCopy, []string) {
	copies, ignored := surfaceCopies(ctx, c, s, nodeID, primaryCfg)
	if len(copies) == 0 {
		return p, nil, ignored
	}
	return storage.NewTee(p, openCopies(ctx, copies)...), copies, ignored
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
			if r.DocErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: the recovery document beside copy %s was not written: %v. The copy holds the backup and its manifest.\n", r.Name, r.DocErr)
			}
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
	copies, _ := surfaceCopies(ctx, c, s, nodeID, primaryCfg)
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
	// Each copy gets its own recovery document, naming its own bucket,
	// sealed to the surface's recipient where the surface seals them.
	pubKey := surfacePublicKey(c, s)
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
		missing, wrote, err := syncArchives(ctx, primary, dst, rc, nodeID, recoveryDocSealTo(s, pubKey), dryRun)
		b.missing += missing
		reported = append(reported, wrote...)
		if err != nil {
			b.err = err
		}
		rmissing, rwrote, err := syncRepos(ctx, c, primaryCfg, rc, s.ID, nodeID, pubKey, dryRun)
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
// sealTo is the recipient each copy's recovery document is sealed to, or ""
// to write it as text.
func syncArchives(ctx context.Context, primary, dst storage.StorageProvider, rc resolvedCopy, nodeID, sealTo string, dryRun bool) (missing int, wrote []model.SnapshotCopy, err error) {
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
		sc, cerr := copyArchive(ctx, primary, dst, id, rc, nodeID, sealTo, taken)
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
// digest recorded at backup time. The copy's manifest and recovery document
// name the copy's bucket and its own lock, not the primary's. A recovery
// document that cannot be written is said and leaves the copy held: the
// copy restores without it.
func copyArchive(ctx context.Context, src, dst storage.StorageProvider, id string, rc resolvedCopy, nodeID, sealTo string, taken time.Time) (model.SnapshotCopy, error) {
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
	if rc.cfg.WORMMode != "" {
		m.WORMMode = string(rc.cfg.WORMMode)
	}
	if !until.IsZero() {
		m.WORMRetentionUntil = until
	}
	if rc.cfg.WORMMode == config.WORMModeNone {
		m.WORMRetentionUntil = time.Time{}
	}
	if err := dst.UploadMetadata(ctx, id, &m); err != nil {
		sc.Error = "writing its manifest: " + err.Error()
		return sc, fmt.Errorf("%s: %s", id, sc.Error)
	}
	sc.State, sc.StorageURI = model.CopyHeld, uri
	doc, sealed, derr := renderRecoveryDoc(&m, recoveryLocation(rc.cfg, nodeID), sealTo)
	if derr == nil {
		derr = dst.UploadRecoveryDoc(ctx, id, doc, sealed, until)
	}
	if derr != nil {
		fmt.Fprintf(os.Stderr, "Warning: the recovery document of %s beside copy %s was not written: %v. The copy holds the backup and its manifest.\n", id, rc.name, derr)
	}
	return sc, nil
}

// syncRepos copies the epochs of the surface's incremental repository the
// copy does not hold in full. Each snapshot's recovery document is rendered
// for the copy, naming its bucket, instead of copied from the primary;
// pubKey seals the one the primary holds sealed.
func syncRepos(ctx context.Context, c *config.CLIConfig, primaryCfg config.StorageConfig, rc resolvedCopy, surfaceID, nodeID, pubKey string, dryRun bool) (missing int, wrote []model.SnapshotCopy, err error) {
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
		var snaps []string
		metas := map[string]*model.SnapshotMetadata{}
		for _, r := range rows {
			if r.SurfaceID == surfaceID && r.Epoch.Epoch.EpochID == e.Epoch.EpochID {
				snaps = append(snaps, r.Meta.SnapshotID)
				metas[r.Meta.SnapshotID] = r.Meta
			}
		}
		docs := recoveryDocKeys(e.Prefix, snaps)
		have := map[string]int64{}
		prefix := sink.EpochPrefix(dst.S.Root(), surfaceID, e.Epoch.EpochID)
		if existing, lerr := dst.S.List(ctx, prefix+"/"); lerr == nil {
			for _, o := range existing {
				have[o.Key] = o.Size
			}
		}
		lacking := 0
		for _, o := range objs {
			size, ok := have[prefix+strings.TrimPrefix(o.Key, e.Prefix)]
			// A copy's recovery document is its own, so its size is not
			// the primary's.
			if _, doc := docs[o.Key]; !ok || (!doc && size != o.Size) {
				lacking++
			}
		}
		if lacking == 0 {
			continue
		}
		missing += max(len(snaps), 1)
		if dryRun {
			continue
		}
		// Every snapshot of the epoch is taken by its planned end, so the
		// copy keeps each for its own retention from then, and never for
		// less than the epoch is locked in the surface's own storage.
		until := e.Epoch.PlannedEnd.AddDate(0, 0, rc.cfg.RetentionDays)
		if until.Before(e.Epoch.OpeningRetainUntil) {
			until = e.Epoch.OpeningRetainUntil
		}
		_, _, cerr := exportEpochObjects(ctx, src, e, dst, surfaceID, until, func(key string) func() ([]byte, error) {
			d, ok := docs[key]
			if !ok {
				return nil
			}
			return func() ([]byte, error) {
				sealTo, err := "", error(nil)
				if d.sealed {
					if sealTo = pubKey; pubKey == "" {
						err = fmt.Errorf("the surface has no public key to seal it to")
					}
				}
				var body []byte
				if err == nil {
					body, err = copyRepoDoc(rc.cfg, nodeID, surfaceID, e.Epoch, until, metas[d.id], sealTo)
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: the recovery document of %s beside copy %s was not written: %v. The copy holds the backup and its manifest.\n", d.id, rc.name, err)
				}
				return body, err
			}
		})
		state, msg := model.CopyHeld, ""
		if cerr != nil {
			state, msg, err = model.CopyFailed, cerr.Error(), cerr
		} else {
			missing -= max(len(snaps), 1)
		}
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
	// Every copy took this backup, archive or run, and none was behind
	// before it: nothing to catch up.
	if !failed && len(meta.Copies) > 0 && len(st.CopiesBehind) == 0 {
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

// runCopies wraps a repository run's backend so the run is written to each
// copy as it goes. It returns b unchanged when there is no copy, or when b
// is not a store this host writes itself (hosted storage): the catch-up
// copies those runs after they commit.
func runCopies(ctx context.Context, b sink.Backend, copies []resolvedCopy) (sink.Backend, *sink.Multi) {
	d, ok := b.(*sink.Direct)
	if !ok || len(copies) == 0 {
		return b, nil
	}
	var named []sink.Named
	for _, rc := range copies {
		cb, err := repoBackend(ctx, cfg, rc.cfg)
		if err == nil {
			if cd, ok := cb.(*sink.Direct); ok {
				named = append(named, sink.Named{Name: rc.name, D: cd, RetentionDays: rc.cfg.RetentionDays})
				continue
			}
			err = fmt.Errorf("a copy of a repository is written to a bucket")
		}
		fmt.Fprintf(os.Stderr, "Warning: copy to %s failed: opening the bucket: %v; the catch-up will retry\n", rc.name, err)
	}
	if len(named) == 0 {
		return b, nil
	}
	m := sink.NewMulti(d, named...)
	return m, m
}

// setRunCopyDocs has each copy of a run get its own recovery document,
// naming the copy's bucket, its address of the epoch and its own lock.
func setRunCopyDocs(m *sink.Multi, copies []resolvedCopy, nodeID, surfaceID, sealTo string, meta func() *model.SnapshotMetadata) {
	if m == nil {
		return
	}
	cfgs := map[string]config.StorageConfig{}
	for _, rc := range copies {
		cfgs[rc.name] = rc.cfg
	}
	m.SetCopyRecoveryDoc(func(name string, e format.Epoch, until time.Time) ([]byte, error) {
		return copyRepoDoc(cfgs[name], nodeID, surfaceID, e, until, meta(), sealTo)
	})
}

// copyRepoDoc is the recovery document of a snapshot in a run of a
// repository, beside its copy in cfg's bucket: that bucket's address of the
// epoch and its own lock until until, never a lock under worm_mode NONE.
func copyRepoDoc(cfg config.StorageConfig, nodeID, surfaceID string, e format.Epoch, until time.Time, mm *model.SnapshotMetadata, sealTo string) ([]byte, error) {
	if mm == nil {
		return nil, fmt.Errorf("the run recorded no metadata")
	}
	c := *mm
	loc := recoveryLocation(cfg, nodeID)
	loc.Prefix = path.Join(loc.Prefix, "repo", surfaceID, e.EpochID)
	c.StorageURI, c.WORMMode, c.WORMRetentionUntil = copyRepoURI(cfg, loc.Prefix), string(cfg.WORMMode), time.Time{}
	if cfg.WORMMode != config.WORMModeNone {
		c.WORMRetentionUntil = until
	}
	doc, _, err := renderRecoveryDoc(&c, loc, sealTo)
	return doc, err
}

// recoveryDoc names a recovery document's snapshot and whether it is sealed.
type recoveryDoc struct {
	id     string
	sealed bool
}

// recoveryDocKeys is where each snapshot's recovery document sits in an
// epoch at prefix, in either form.
func recoveryDocKeys(prefix string, ids []string) map[string]recoveryDoc {
	out := map[string]recoveryDoc{}
	for _, id := range ids {
		if k, err := sink.ObjectKey(prefix, sink.KindRecovery, id); err == nil {
			out[k] = recoveryDoc{id: id}
		}
		if k, err := sink.ObjectKey(prefix, sink.KindRecoverySealed, id); err == nil {
			out[k] = recoveryDoc{id: id, sealed: true}
		}
	}
	return out
}

// surfacePublicKey is the recipient a surface's backups are sealed to.
func surfacePublicKey(c *config.CLIConfig, s *config.SurfaceConfig) string {
	if s != nil && s.Encryption != nil && s.Encryption.PublicKey != "" {
		return s.Encryption.PublicKey
	}
	return c.Encryption.PublicKey
}

// noteRunCopies records on a run's record what each copy came to, and says
// each: where it is and its lock, or why it failed. A copy that lacks
// earlier objects of the epoch is left to the catch-up, which reports it.
func noteRunCopies(m *sink.Multi, copies []resolvedCopy, meta *model.SnapshotMetadata) {
	if m == nil || meta == nil {
		return
	}
	mode := map[string]config.StorageConfig{}
	for _, rc := range copies {
		mode[rc.name] = rc.cfg
	}
	for _, r := range m.Results() {
		if r.Behind {
			continue
		}
		cc := mode[r.Name]
		sc := model.SnapshotCopy{SnapshotID: meta.SnapshotID, Bucket: r.Name, WORMMode: string(cc.WORMMode), State: model.CopyHeld,
			StorageURI: copyRepoURI(cc, r.Prefix)}
		if !r.RetainUntil.IsZero() && cc.WORMMode != config.WORMModeNone {
			until := r.RetainUntil
			sc.RetainUntil = &until
		}
		if r.Err != nil || !r.Held {
			why := r.Err
			if why == nil {
				why = fmt.Errorf("the run was not published there")
			}
			sc.State, sc.Error, sc.StorageURI = model.CopyFailed, why.Error(), ""
			fmt.Fprintf(os.Stderr, "Warning: copy to %s failed: %v; the catch-up will retry\n", r.Name, why)
		} else {
			fmt.Printf("   Copy %s:%s%s, %s\n", r.Name, strings.Repeat(" ", max(1, 11-len(r.Name))), sc.StorageURI, copyLockWords(sc))
		}
		meta.Copies = append(meta.Copies, sc)
	}
}

// hostCopies is every bucket this host writes to beside its own, with its
// key: the project's, when the remote server names any, else the config's.
// A config copy whose key cannot be resolved is said and left out.
func hostCopies(ctx context.Context, c *config.CLIConfig) []resolvedCopy {
	out := projectCopies(ctx, c, c.Storage)
	if len(out) == 0 {
		for _, cp := range c.Copies {
			st := cp.StorageConfig
			ok := true
			for _, f := range []*string{&st.AccessKeyID, &st.SecretAccessKey} {
				v, err := resolveConfigSecret("copies "+cp.Name+" key", *f)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: copy %s: %v\n", cp.Name, err)
					ok = false
					break
				}
				*f = v
			}
			if ok {
				out = append(out, resolvedCopy{name: cp.Name, cfg: st})
			}
		}
	}
	for i := range out {
		out[i].cfg.NodeID = c.NodeID
	}
	return out
}
