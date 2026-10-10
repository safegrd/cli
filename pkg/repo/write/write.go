// Package write is the archiver: it walks a host's roots and writes one
// snapshot into the surface's current epoch, uploading only the chunks the
// epoch does not already hold. It takes a recipient and never an identity, and
// it does not import the reading half of the encryption, so nothing here can
// read back what it wrote.
package write

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/repo/cache"
	"github.com/safegrd/cli/pkg/repo/chunk"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
	"github.com/safegrd/cli/pkg/repo/seal"
	"github.com/safegrd/cli/pkg/repo/sink"
)

// Options configure one run.
type Options struct {
	SurfaceID string
	// Roots are the directories backed up. Each must be absolute; none may
	// be inside another.
	Roots    []string
	Excludes []string
	// OneFilesystem keeps the walk on each root's filesystem. Nil means yes
	// when a root is "/", no otherwise.
	OneFilesystem *bool
	// SkipPaths are never walked: the cache directory, a local sink.
	SkipPaths []string
	// StateDir holds the cache, under cache/<surface-id>/.
	StateDir  string
	Recipient string
	Retention policy.Retention
	// Tier and Planned are this run's retention tier and retain-until as the
	// surface's schedule decides them at the run's start.
	Tier    string
	Planned time.Time
	// NewEpoch asks for a new epoch now.
	NewEpoch bool
	// Rescan reads every file, ignoring the files cache. Every RescanEvery
	// runs one rescans anyway; zero means 7.
	Rescan      bool
	RescanEvery int
	// Concurrency is how many packs upload at once; zero means 4.
	Concurrency int
	// PackTargetBytes is the pack size a new epoch closes packs at; zero
	// means 32 MiB.
	PackTargetBytes int
	// Chunker is the chunk size bounds a new epoch is cut with; nil keeps
	// format.DefaultChunker.
	Chunker    *format.ChunkerParams
	Host       string
	SnapshotID string
	Now        func() time.Time
	// Logf receives progress lines a person reads while the run goes on.
	Logf func(format string, args ...any)
	// OnStart is called once the epoch is decided, before the walk: Opened,
	// Reason, Class, Resumed and the adopted packs are set.
	OnStart func(*Result)
	// Sidecar returns the plaintext metadata sidecar for the finished run,
	// written last: the snapshot exists once it does.
	Sidecar func(*Result) ([]byte, error)
	// RecoveryDoc, when set, returns the recovery document written beside
	// the sidecar, and whether it is sealed. It is written after the
	// sidecar and before the commit; a failure is Result.RecoveryWarning,
	// never the run's: the snapshot already exists.
	RecoveryDoc func(*Result) (body []byte, sealed bool, err error)
	// Source, when set, supplies the snapshot's files as streams in place of
	// a walk of Roots, which must then be empty. Its files are the top of
	// the snapshot's tree and its one root is "/".
	Source Source
	// State, when set, returns what this run leaves for the next one of the
	// surface, kept in the cache with the run and handed to the next run as
	// Result.PriorState. It is called once the run is published.
	State func(*Result) ([]byte, error)
}

// Source supplies a snapshot's files as streams: a database dump, one entry
// per section and per table, that never touches the host's disk. It calls
// emit once per file, in any order, and emit reads the file to its end
// before it returns.
type Source func(ctx context.Context, emit func(Entry) error) error

// Entry is one file of a Source.
type Entry struct {
	// Path is slash-separated and relative: "data/public/users.copy".
	Path   string
	Reader io.Reader
	// Carry stores the file as this epoch last stored it, without reading
	// it: the source knows it has not changed. Reader is ignored. emit
	// returns ErrNotCarried when the epoch does not hold it, which
	// Result.CanCarry said beforehand.
	Carry bool
}

// ErrNotCarried is returned by emit for an Entry to carry that the epoch
// cannot carry.
var ErrNotCarried = errors.New("the repository cannot carry this file forward unread")

// Result is what a finished run wrote.
type Result struct {
	Snapshot format.Snapshot
	Epoch    format.Epoch
	// Opened is set when this run opened the epoch, with the reason.
	Opened bool
	Reason string
	Class  string
	// Tier is the retention tier the snapshot was kept at. It is the
	// epoch's opening tier for an opening run, which a resumed run keeps
	// whatever Options.Tier asked, and Options.Tier otherwise. A caller
	// that hands out tiers by schedule should count a slot as taken only
	// when this is the tier it offered.
	Tier string
	// Planned is the retain-until the schedule asked for; Capped says the
	// class lock shortened it to Snapshot.RetainUntil.
	Planned time.Time
	Capped  bool
	// Resumed is set when the run adopted packs an interrupted run uploaded.
	Resumed      bool
	AdoptedPacks int
	AdoptedBytes int64
	// ReadBytes is what the run read from disk; WrittenBytes is everything it
	// uploaded, packs and metadata.
	ReadBytes    int64
	WrittenBytes int64
	ChangedFiles int64
	// Excluded counts the entries the exclude patterns left out, each
	// directory once with everything in it.
	Excluded  int64
	Rescanned bool
	// NewBytes is, for a run of a Source, the bytes of chunks each file added
	// to the epoch, before compression: zero for a file that did not change.
	NewBytes map[string]int64
	// PriorState is what the surface's last finished run left through
	// Options.State, or nil; set before OnStart.
	PriorState []byte
	// CanCarry reports whether the epoch holds every chunk of path as it
	// was last stored, so a Source may emit it with Carry; set before
	// OnStart.
	CanCarry func(path string) bool
	// StateSaved is set when the cache recorded this run with the state
	// Options.State returned.
	StateSaved bool
	// Keys are the objects this run wrote, sidecar included.
	Keys       []string
	SidecarKey string
	// Decision is the backend's word on this run's lock, when it gave one.
	Decision sink.RunDecision
	// CacheWarning is set when the run succeeded but could not tidy the
	// cache; the next run still works.
	CacheWarning string
	// RecoveryWarning is set when the run succeeded but its recovery
	// document was not written.
	RecoveryWarning string
}

// sourceStateKey is where the cache keeps Options.State.
const sourceStateKey = "source"

// DefaultExcludesForSlash are left out when a root is "/": kernel and
// runtime filesystems, scratch space and swap.
var DefaultExcludesForSlash = []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/swapfile", "/swap.img", "/var/lib/swap"}

type statInfo struct {
	ok       bool
	dev, ino uint64
	ctimeNs  int64
	uid, gid *uint32
}

// Run writes one snapshot of the roots into the surface's current epoch.
func Run(ctx context.Context, b sink.Backend, o Options) (*Result, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.RescanEvery <= 0 {
		o.RescanEvery = 7
	}
	if err := sink.ValidSurfaceID(o.SurfaceID); err != nil {
		return nil, err
	}
	if err := sink.ValidSnapshotName(o.SnapshotID); err != nil {
		return nil, err
	}
	var roots []string
	var err error
	if o.Source != nil {
		if len(o.Roots) > 0 {
			return nil, fmt.Errorf("a run takes a source or roots, not both")
		}
		roots = []string{"/"}
	} else if roots, err = CleanRoots(o.Roots); err != nil {
		return nil, err
	}
	rec, err := seal.Recipient(o.Recipient)
	if err != nil {
		return nil, err
	}
	started := o.Now().UTC()

	// 1. The epoch, and the retain-until.
	dir := cache.Dir(o.StateDir, o.SurfaceID)
	cur, lost, err := cache.Current(dir, o.SurfaceID)
	if err != nil {
		return nil, err
	}
	var current *policy.Current
	if cur != nil {
		current = &policy.Current{Epoch: cur.Epoch(), OpeningDone: cur.OpeningDone()}
	} else if !lost {
		// No cache at all: a first run, or a rebuilt host. The epoch list is
		// plaintext and says which, without reading anything sealed.
		if es, err := b.Epochs(ctx, o.SurfaceID); err == nil && len(es) > 0 {
			lost = true
		}
	}
	decision := policy.Decide(started, current, o.Retention, lost, o.NewEpoch, o.Recipient)
	tier := o.Tier
	if !policy.ValidTier(tier) {
		tier = format.TierBase
	}
	if !decision.Open && current != nil && !current.OpeningDone {
		// A resumed opening run keeps the tier it was opened at.
		tier = current.Epoch.OpeningTier
	}
	opened, err := b.OpenEpoch(ctx, sink.OpenRequest{
		SurfaceID: o.SurfaceID, Current: current, Decision: decision, OpeningTier: tier,
		Retention: o.Retention, Recipient: o.Recipient, Now: started, PackTargetBytes: o.PackTargetBytes,
		Chunker: o.Chunker,
	})
	if err != nil {
		if cur != nil {
			cur.Close()
		}
		return nil, err
	}
	res := &Result{Epoch: opened.Epoch, Opened: opened.New, Reason: opened.Epoch.Reason}
	if cur != nil {
		// Kept across a new epoch: the source's state names who it is, not
		// what this epoch holds.
		if res.PriorState, err = cur.State(sourceStateKey); err != nil {
			cur.Close()
			return nil, fmt.Errorf("reading the local cache: %w", err)
		}
	}
	if cur != nil && cur.Epoch().EpochID != opened.Epoch.EpochID {
		cur.Close()
		cur = nil
	}
	if cur == nil {
		if !opened.New && opened.OpeningDone {
			// The remote server continues an epoch this host has no cache
			// for. Writing into it would need the cache; ask for a new one.
			return nil, fmt.Errorf("epoch %s continues on the remote server but this host has no cache for it; run again with --new-epoch", opened.Epoch.EpochID)
		}
		if cur, err = cache.Create(dir, opened.Epoch); err != nil {
			return nil, fmt.Errorf("creating the local cache: %w", err)
		}
	}
	defer cur.Close()
	if opened.OpeningDone && !cur.OpeningDone() {
		if err := cur.MarkOpeningDone(); err != nil {
			return nil, err
		}
	}
	e := opened.Epoch
	res.Class, res.Tier = format.ClassLater, tier
	if !cur.OpeningDone() {
		res.Class, res.Tier = format.ClassOpening, e.OpeningTier
	}
	planned := o.Planned
	if res.Class == format.ClassOpening {
		planned = policy.TierUntil(started, e.OpeningTier, o.Retention)
	}
	if planned.IsZero() {
		planned = started.Add(time.Duration(o.Retention.Days) * 24 * time.Hour)
	}
	res.Planned = planned
	retain, capped := policy.RetainUntil(planned.UTC(), res.Class, e)
	retain = retain.UTC()
	res.Capped = capped

	adopted, err := cur.Resume()
	if err != nil {
		return nil, fmt.Errorf("reading the local cache: %w", err)
	}
	if len(adopted) > 0 {
		res.Resumed, res.AdoptedPacks = true, len(adopted)
		for _, p := range adopted {
			res.AdoptedBytes += p.Bytes
		}
	}
	res.CanCarry = func(p string) bool {
		row, err := cur.File(p)
		if err != nil || row == nil {
			return false
		}
		for _, id := range row.Blobs {
			if known, err := cur.Known(id); err != nil || !known {
				return false
			}
		}
		return true
	}
	if o.OnStart != nil {
		o.OnStart(res)
	}
	runID := format.NewRandomID()
	if rs, ok := b.(sink.RunStarter); ok {
		dec, err := rs.StartRun(ctx, e, runID)
		if err != nil {
			return nil, fmt.Errorf("starting the run: %w", err)
		}
		if dec.Known {
			res.Decision = dec
			retain = dec.Until().UTC()
		}
	}
	if err := cur.BeginRun(runID, o.SnapshotID, res.Class, started); err != nil {
		return nil, err
	}
	// The catalog lists every path in the opening run, and again after a
	// run that may have published a snapshot without finishing: the cache
	// does not hold what that run saw, so a delta against it would miss
	// what changed since.
	unfinished, err := cur.UnfinishedRun()
	if err != nil {
		return nil, err
	}
	completeCatalog := res.Class == format.ClassOpening || unfinished
	ch, err := chunk.New(cur.Polynomial(), e.Chunker)
	if err != nil {
		return nil, err
	}
	res.Rescanned = o.Rescan || cur.RunsSinceRescan()+1 >= o.RescanEvery

	// 2–4. Walk, chunk, pack, upload.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	up := newUploader(runCtx, cancel, b, cur, e, res.Class, runID, o.Concurrency)
	w := &walker{
		ctx: runCtx, cache: cur, ch: ch, up: up, runID: runID,
		data:    newPacker(format.BlobData, e.PackTargetBytes, rec),
		trees:   newPacker(format.BlobTree, e.PackTargetBytes, rec),
		inRun:   map[format.ID]bool{},
		rescan:  res.Rescanned || res.Class == format.ClassOpening,
		exclude: o.Excludes,
		skip:    map[string]bool{},
		buf:     make([]byte, 0, 1<<20),
	}
	oneFS := false
	for _, r := range roots {
		if r == "/" {
			oneFS = true
			w.exclude = append(append([]string{}, DefaultExcludesForSlash...), w.exclude...)
		}
	}
	if o.OneFilesystem != nil {
		oneFS = *o.OneFilesystem
	}
	w.oneFS = oneFS
	for _, p := range append([]string{dir}, o.SkipPaths...) {
		if abs, err := filepath.Abs(p); err == nil {
			w.skip[abs] = true
			if real, err := filepath.EvalSymlinks(abs); err == nil {
				w.skip[real] = true
			}
		}
	}
	var rootTree format.ID
	var walkErr error
	if o.Source != nil {
		rootTree, walkErr = w.source(o.Source, started)
	} else {
		rootTree, walkErr = w.walkRoots(roots)
	}
	if walkErr == nil {
		walkErr = w.flush()
	}
	upErr := up.close()
	if walkErr != nil {
		if upErr != nil && errors.Is(walkErr, context.Canceled) {
			return nil, upErr
		}
		return nil, walkErr
	}
	if upErr != nil {
		return nil, upErr
	}
	res.ReadBytes = w.readBytes
	res.ChangedFiles = w.changed
	res.Excluded = w.excludedN
	res.NewBytes = w.newBytes

	// 5–6. Index, catalog, snapshot, sidecar, in that order.
	if err := cur.Commit(); err != nil {
		return nil, err
	}
	cr := format.NewContentRoot()
	if err := cur.Entries(func(en cache.Entry) error {
		cr.Add(en.Type, en.Value, en.Path)
		return nil
	}); err != nil {
		return nil, err
	}
	contentRoot, err := cr.Sum()
	if err != nil {
		return nil, err
	}
	packs, runs, err := cur.Referenced(runID)
	if err != nil {
		return nil, fmt.Errorf("the snapshot would name data that is not uploaded: %w", err)
	}
	unindexed, err := cur.Unindexed()
	if err != nil {
		return nil, err
	}
	index := format.Index{Version: format.Version, EpochID: e.EpochID, RunID: runID, Packs: unindexed}
	if index.Packs == nil {
		index.Packs = []format.IndexPack{}
	}
	if err := index.Validate(); err != nil {
		return nil, fmt.Errorf("the index this run built: %w", err)
	}
	deltas, err := cur.Deltas(completeCatalog)
	if err != nil {
		return nil, err
	}
	catalog := format.Catalog{Version: format.Version, EpochID: e.EpochID, RunID: runID, SnapshotID: o.SnapshotID,
		Complete: completeCatalog, Entries: make([]format.CatalogEntry, 0, len(deltas))}
	for _, d := range deltas {
		ce := format.CatalogEntry{Path: d.Path, Event: d.Event, Type: string(d.Type)}
		if d.Event != format.EventDeleted {
			if d.Type == format.ContentFile {
				ce.SHA256, ce.Size = d.Value, d.Size
			}
			mt := time.Unix(0, d.MTimeNs).UTC()
			ce.MTime, ce.Mode = &mt, d.Mode
		}
		catalog.Entries = append(catalog.Entries, ce)
	}
	snap := format.Snapshot{
		Version: format.Version, SnapshotID: o.SnapshotID, EpochID: e.EpochID, RunID: runID, Class: res.Class,
		CreatedAt: started, Host: o.Host, Roots: roots, RootTree: rootTree.String(), ContentRoot: contentRoot,
		Runs: runs, Packs: packs, Skipped: w.skipped, Inconsistent: w.inconsistent, RetainUntil: retain,
		Unlocked: res.Decision.Known && !res.Decision.Locked,
		Stats:    format.SnapshotStats{Files: w.files, Dirs: w.dirs, LogicalBytes: w.logical, NewPacks: up.packs},
	}
	if snap.Skipped == nil {
		snap.Skipped = []format.Skipped{}
	}
	if snap.Inconsistent == nil {
		snap.Inconsistent = []format.RawPath{}
	}
	if snap.Packs == nil {
		snap.Packs = []string{}
	}

	indexBody, err := seal.Object(index, rec)
	if err != nil {
		return nil, err
	}
	catalogBody, err := seal.Object(catalog, rec)
	if err != nil {
		return nil, err
	}
	if err := up.putOne(ctx, sink.KindIndex, runID, indexBody); err != nil {
		return nil, fmt.Errorf("writing the index: %w", err)
	}
	if err := up.putOne(ctx, sink.KindCatalog, runID, catalogBody); err != nil {
		return nil, fmt.Errorf("writing the catalog: %w", err)
	}
	snap.Stats.NewBytes = up.bytes
	snap.CompletedAt = o.Now().UTC()
	snapBody, err := seal.Object(snap, rec)
	if err != nil {
		return nil, err
	}
	if err := up.putOne(ctx, sink.KindSnapshot, o.SnapshotID, snapBody); err != nil {
		return nil, fmt.Errorf("writing the snapshot: %w", err)
	}
	res.Snapshot = snap
	res.WrittenBytes = up.bytes
	res.Keys = up.keys
	if o.Sidecar == nil {
		return nil, fmt.Errorf("no sidecar")
	}
	sidecar, err := o.Sidecar(res)
	if err != nil {
		return nil, err
	}
	// From the sidecar on the snapshot exists for every reader. The cache
	// notes that first, so a run that dies between here and FinishRun is
	// known to the next one, which then lists every path in its catalog.
	if err := cur.MarkPublishing(runID); err != nil {
		return nil, err
	}
	if err := up.putOne(ctx, sink.KindMeta, o.SnapshotID, sidecar); err != nil {
		return nil, fmt.Errorf("writing the snapshot's metadata: %w", err)
	}
	res.Keys = up.keys
	res.SidecarKey = up.keys[len(up.keys)-1]
	if o.RecoveryDoc != nil {
		doc, sealed, err := o.RecoveryDoc(res)
		kind := sink.KindRecovery
		if sealed {
			kind = sink.KindRecoverySealed
		}
		if err == nil {
			err = up.putOne(ctx, kind, o.SnapshotID, doc)
		}
		if err != nil {
			res.RecoveryWarning = fmt.Sprintf("the recovery document for %s was not written: %v", o.SnapshotID, err)
		}
		res.Keys = up.keys
	}
	if err := b.Commit(ctx, e, sink.RunCommit{SnapshotID: o.SnapshotID, RunID: runID, Class: res.Class, Keys: res.Keys,
		Refs: referencedKeys(res.Keys, snap), RetainUntil: retain, Unlocked: snap.Unlocked}); err != nil {
		return nil, fmt.Errorf("recording the run: %w", err)
	}
	var state map[string][]byte
	if o.State != nil {
		b, err := o.State(res)
		if err != nil {
			res.CacheWarning = fmt.Sprintf("this run's state for the next could not be built (%v); the next run reads everything", err)
		} else {
			state = map[string][]byte{sourceStateKey: b}
		}
	}
	if err := cur.FinishRun(runID, res.Rescanned, state); err != nil {
		res.CacheWarning = fmt.Sprintf("the local cache did not record this run (%v); the next run re-indexes what it uploaded", err)
	} else if res.StateSaved = state != nil; res.Class == format.ClassOpening {
		if err := cache.RemoveOthers(dir, e.EpochID); err != nil {
			res.CacheWarning = fmt.Sprintf("could not delete the caches of earlier epochs in %s: %v", dir, err)
		}
	}
	return res, nil
}

// referencedKeys is every object the snapshot reads that this run did not
// write: the packs of earlier runs it references and the index of each run
// it reads. Every key of an epoch shares the prefix of the keys written, so
// the prefix is read off one of them.
func referencedKeys(written []string, snap format.Snapshot) []string {
	if len(written) == 0 {
		return nil
	}
	prefix := path.Dir(path.Dir(written[0]))
	own := make(map[string]bool, len(written))
	for _, k := range written {
		own[k] = true
	}
	var refs []string
	add := func(k string) {
		if !own[k] {
			refs = append(refs, k)
		}
	}
	for _, p := range snap.Packs {
		add(prefix + "/packs/" + p)
	}
	for _, r := range snap.Runs {
		add(prefix + "/index/" + r + ".age")
	}
	return refs
}

// CleanRoots resolves each root to the real directory it names and refuses
// one inside another.
func CleanRoots(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("no root to back up")
	}
	var out []string
	for _, r := range in {
		if !filepath.IsAbs(r) {
			abs, err := filepath.Abs(r)
			if err != nil {
				return nil, err
			}
			r = abs
		}
		real, err := filepath.EvalSymlinks(filepath.Clean(r))
		if err != nil {
			return nil, fmt.Errorf("root %s: %w", r, err)
		}
		fi, err := os.Stat(real)
		if err != nil {
			return nil, fmt.Errorf("root %s: %w", r, err)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("root %s is not a directory", r)
		}
		out = append(out, filepath.ToSlash(real))
	}
	sort.Strings(out)
	for i := 0; i < len(out); i++ {
		for j := 0; j < len(out); j++ {
			if i == j {
				continue
			}
			if out[i] == out[j] {
				return nil, fmt.Errorf("root %s is listed twice", out[i])
			}
			if out[i] == "/" || strings.HasPrefix(out[j], out[i]+"/") {
				return nil, fmt.Errorf("root %s is inside root %s; list only %s", out[j], out[i], out[i])
			}
		}
	}
	return out, nil
}

// uploader uploads closed packs, a few at a time, and records each in the
// cache before and after.
type uploader struct {
	ctx    context.Context
	cancel context.CancelFunc
	b      sink.Backend
	c      *cache.Cache
	e      format.Epoch
	class  string
	runID  string
	queue  chan *sealedPack
	wg     sync.WaitGroup
	mu     sync.Mutex
	err    error
	bytes  int64
	packs  int64
	keys   []string
}

func newUploader(ctx context.Context, cancel context.CancelFunc, b sink.Backend, c *cache.Cache, e format.Epoch, class, runID string, n int) *uploader {
	u := &uploader{ctx: ctx, cancel: cancel, b: b, c: c, e: e, class: class, runID: runID, queue: make(chan *sealedPack, 1)}
	for i := 0; i < n; i++ {
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			for p := range u.queue {
				if err := u.upload(p); err != nil {
					u.fail(err)
				}
			}
		}()
	}
	return u
}

func (u *uploader) fail(err error) {
	u.mu.Lock()
	if u.err == nil {
		u.err = err
	}
	u.mu.Unlock()
	u.cancel()
}

func (u *uploader) failed() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.err
}

func (u *uploader) send(p *sealedPack) error {
	select {
	case u.queue <- p:
		return nil
	case <-u.ctx.Done():
		if err := u.failed(); err != nil {
			return err
		}
		return u.ctx.Err()
	}
}

func (u *uploader) upload(p *sealedPack) error {
	if u.ctx.Err() != nil {
		return nil
	}
	slots, err := u.b.Reserve(u.ctx, u.e, u.class, []sink.ObjectSpec{{Kind: sink.KindPack, Name: p.id, Size: int64(len(p.body)), MD5: p.md5}})
	if err != nil {
		return fmt.Errorf("reserving pack %s: %w", p.id, err)
	}
	slot := slots[0]
	if err := u.c.SealPack(p.id, slot.Key, u.runID, int64(len(p.body)), p.entries); err != nil {
		return fmt.Errorf("recording pack %s in the cache: %w", p.id, err)
	}
	if err := u.b.Put(u.ctx, slot, p.body); err != nil {
		return fmt.Errorf("uploading pack %s: %w", p.id, err)
	}
	if err := u.c.MarkUploaded(p.id); err != nil {
		return fmt.Errorf("recording pack %s in the cache: %w", p.id, err)
	}
	if err := u.b.Uploaded(u.ctx, u.e, []string{slot.Key}); err != nil {
		return fmt.Errorf("confirming pack %s: %w", p.id, err)
	}
	u.mu.Lock()
	u.bytes += int64(len(p.body))
	u.packs++
	u.keys = append(u.keys, slot.Key)
	u.mu.Unlock()
	return nil
}

// close waits for every queued pack.
func (u *uploader) close() error {
	close(u.queue)
	u.wg.Wait()
	return u.failed()
}

// putOne writes one metadata object after the packs.
func (u *uploader) putOne(ctx context.Context, kind sink.Kind, name string, body []byte) error {
	slots, err := u.b.Reserve(ctx, u.e, u.class, []sink.ObjectSpec{{Kind: kind, Name: name, Size: int64(len(body)), MD5: md5.Sum(body)}})
	if err != nil {
		return err
	}
	if err := u.b.Put(ctx, slots[0], body); err != nil {
		return err
	}
	if err := u.b.Uploaded(ctx, u.e, []string{slots[0].Key}); err != nil {
		return err
	}
	u.bytes += int64(len(body))
	u.keys = append(u.keys, slots[0].Key)
	return nil
}

// walker walks the roots depth first in byte order, emitting each
// directory's tree blob when the directory is finished.
type walker struct {
	// excludedN counts the entries the exclude patterns left out.
	excludedN    int64
	ctx          context.Context
	cache        *cache.Cache
	ch           *chunk.Chunker
	up           *uploader
	runID        string
	data, trees  *packer
	inRun        map[format.ID]bool
	rescan       bool
	exclude      []string
	root         string
	skip         map[string]bool
	oneFS        bool
	buf          []byte
	files, dirs  int64
	logical      int64
	readBytes    int64
	changed      int64
	skipped      []format.Skipped
	inconsistent []format.RawPath
	newBytes     map[string]int64
}

type rootNode struct {
	children map[string]*rootNode
	isRoot   bool
}

func (w *walker) walkRoots(roots []string) (format.ID, error) {
	top := &rootNode{children: map[string]*rootNode{}}
	for _, r := range roots {
		n := top
		if r == "/" {
			n.isRoot = true
			continue
		}
		for _, part := range strings.Split(strings.TrimPrefix(r, "/"), "/") {
			child, ok := n.children[part]
			if !ok {
				child = &rootNode{children: map[string]*rootNode{}}
				n.children[part] = child
			}
			n = child
		}
		n.isRoot = true
	}
	fi, err := os.Lstat("/")
	if err != nil {
		return format.ID{}, err
	}
	return w.synth("/", "", top, fi)
}

// synth stores a directory on the way to a root: its own mode, owner and
// time, holding only the entries that lead to roots.
func (w *walker) synth(abs, rel string, n *rootNode, fi os.FileInfo) (format.ID, error) {
	if n.isRoot {
		w.root = abs
		return w.dir(abs, rel, sysStat(fi).dev)
	}
	names := make([]string, 0, len(n.children))
	for name := range n.children {
		names = append(names, name)
	}
	sort.Strings(names)
	var t format.Tree
	for _, name := range names {
		childAbs := path.Join(abs, name)
		childRel := joinRel(rel, name)
		cfi, err := os.Lstat(childAbs)
		if err != nil {
			return format.ID{}, fmt.Errorf("reading %s: %w", childAbs, err)
		}
		sub, err := w.synth(childAbs, childRel, n.children[name], cfi)
		if err != nil {
			return format.ID{}, err
		}
		t.Entries = append(t.Entries, w.dirNode(name, cfi, sub))
		// The roots and the directories above them are not counted: the
		// count is what lies below the roots, as a restore reports it.
		w.dirs--
		if err := w.entry(childRel, format.ContentDir, "-", cfi, 0); err != nil {
			return format.ID{}, err
		}
	}
	return w.storeTree(t)
}

func joinRel(rel, name string) string {
	if rel == "" {
		return name
	}
	return rel + "/" + name
}

func (w *walker) dirNode(name string, fi os.FileInfo, sub format.ID) format.Node {
	st := sysStat(fi)
	w.dirs++
	return format.Node{Name: name, Type: format.NodeDir, Mode: uint32(fi.Mode().Perm()), UID: st.uid, GID: st.gid,
		ModTime: fi.ModTime().UTC(), Subtree: sub}
}

func (w *walker) entry(rel string, typ byte, value string, fi os.FileInfo, size int64) error {
	return w.cache.AddEntry(cache.Entry{Path: rel, Type: typ, Value: value, Size: size,
		MTimeNs: fi.ModTime().UnixNano(), Mode: uint32(fi.Mode().Perm())})
}

// excluded applies the exclude patterns. A pattern starting with "/" is
// matched against the absolute path; any other is matched against the path
// relative to the root being walked and against the base name, and "dir/*"
// leaves out dir and everything in it.
func (w *walker) excluded(abs string) bool {
	if w.skip[abs] {
		return true
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(abs, w.root), "/")
	for _, p := range w.exclude {
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "/") {
			p = path.Clean(p)
			if ok, _ := path.Match(p, abs); ok || abs == p {
				return true
			}
			if d := strings.TrimSuffix(p, "/*"); d != p && abs == d {
				return true
			}
			continue
		}
		p = path.Clean(filepath.ToSlash(p))
		if ok, _ := path.Match(p, rel); ok {
			return true
		}
		if ok, _ := path.Match(p, path.Base(rel)); ok {
			return true
		}
		d := strings.TrimSuffix(p, "/*")
		if rel == d || strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

func specialKind(m fs.FileMode) string {
	switch {
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeCharDevice != 0:
		return "character device"
	case m&fs.ModeDevice != 0:
		return "device"
	}
	return "special file"
}

// dir walks one directory and returns its tree's id.
func (w *walker) dir(abs, rel string, dev uint64) (format.ID, error) {
	if err := w.ctx.Err(); err != nil {
		return format.ID{}, err
	}
	des, err := os.ReadDir(abs)
	if err != nil {
		// A directory left out for permissions is a hole in the backup.
		return format.ID{}, fmt.Errorf("reading directory %s: %w", abs, err)
	}
	var t format.Tree
	for _, de := range des {
		name := de.Name()
		childAbs := path.Join(abs, name)
		childRel := joinRel(rel, name)
		if w.excluded(childAbs) {
			if !w.skip[childAbs] {
				w.excludedN++
			}
			continue
		}
		fi, err := os.Lstat(childAbs)
		if errors.Is(err, fs.ErrNotExist) {
			continue // removed since the directory was read
		}
		if err != nil {
			return format.ID{}, fmt.Errorf("reading %s: %w", childAbs, err)
		}
		m := fi.Mode()
		switch {
		case m.IsDir():
			if w.oneFS {
				if st := sysStat(fi); st.ok && st.dev != dev {
					w.skipped = append(w.skipped, format.Skipped{Path: childRel, Reason: "another filesystem"})
					continue
				}
			}
			sub, err := w.dir(childAbs, childRel, dev)
			if err != nil {
				return format.ID{}, err
			}
			t.Entries = append(t.Entries, w.dirNode(name, fi, sub))
			if err := w.entry(childRel, format.ContentDir, "-", fi, 0); err != nil {
				return format.ID{}, err
			}
		case m&fs.ModeSymlink != 0:
			target, err := os.Readlink(childAbs)
			if err != nil {
				return format.ID{}, fmt.Errorf("reading symlink %s: %w", childAbs, err)
			}
			st := sysStat(fi)
			t.Entries = append(t.Entries, format.Node{Name: name, Type: format.NodeSymlink, Mode: uint32(m.Perm()),
				UID: st.uid, GID: st.gid, ModTime: fi.ModTime().UTC(), Target: target})
			if err := w.entry(childRel, format.ContentSymlink, format.ContentValue(format.ContentSymlink, "", target), fi, 0); err != nil {
				return format.ID{}, err
			}
		case m.IsRegular():
			n, ok, err := w.file(childAbs, childRel, fi)
			if err != nil {
				return format.ID{}, err
			}
			if !ok {
				continue
			}
			t.Entries = append(t.Entries, n)
		default:
			// A FIFO hangs a read, a socket cannot be read, a device reads
			// without end. They are listed, never stored.
			w.skipped = append(w.skipped, format.Skipped{Path: childRel, Reason: specialKind(m)})
		}
	}
	return w.storeTree(t)
}

func (w *walker) storeTree(t format.Tree) (format.ID, error) {
	if t.Entries == nil {
		t.Entries = []format.Node{}
	}
	plain, err := format.EncodeTree(t)
	if err != nil {
		return format.ID{}, err
	}
	id := format.Hash(plain)
	if err := w.store(w.trees, id, plain); err != nil {
		return format.ID{}, err
	}
	return id, nil
}

// store adds a blob unless the epoch or this run already holds it, and
// records that the snapshot references it.
func (w *walker) store(p *packer, id format.ID, plain []byte) error {
	_, err := w.storeNew(p, id, plain)
	return err
}

// storeNew is store, saying whether the blob was new to the epoch.
func (w *walker) storeNew(p *packer, id format.ID, plain []byte) (bool, error) {
	if err := w.cache.Ref(id); err != nil {
		return false, err
	}
	if w.inRun[id] {
		return false, nil
	}
	known, err := w.cache.Known(id)
	if err != nil {
		return false, err
	}
	if known {
		return false, nil
	}
	w.inRun[id] = true
	if err := p.add(id, plain); err != nil {
		return true, err
	}
	if p.full() {
		sp, err := p.finish()
		if err != nil {
			return true, err
		}
		return true, w.up.send(sp)
	}
	return true, nil
}

func (w *walker) flush() error {
	for _, p := range []*packer{w.data, w.trees} {
		sp, err := p.finish()
		if err != nil {
			return err
		}
		if sp != nil {
			if err := w.up.send(sp); err != nil {
				return err
			}
		}
	}
	return nil
}

func sameStat(a, b os.FileInfo) bool {
	if a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	sa, sb := sysStat(a), sysStat(b)
	return sa.ctimeNs == sb.ctimeNs
}

// file stores one regular file, or reuses what the cache knows of it when
// its (device, inode, size, mtime, ctime) are unchanged and the epoch holds
// every blob. ok is false when the file vanished before it could be read.
func (w *walker) file(abs, rel string, fi os.FileInfo) (n format.Node, ok bool, err error) {
	st := sysStat(fi)
	n = format.Node{Name: path.Base(abs), Type: format.NodeFile, Mode: uint32(fi.Mode().Perm()), UID: st.uid, GID: st.gid,
		ModTime: fi.ModTime().UTC()}
	if !w.rescan {
		row, err := w.cache.File(rel)
		if err != nil {
			return n, false, err
		}
		if row != nil && row.Size == fi.Size() && row.MTimeNs == fi.ModTime().UnixNano() && row.CTimeNs == st.ctimeNs &&
			row.Dev == st.dev && row.Ino == st.ino {
			reuse := true
			for _, id := range row.Blobs {
				if w.inRun[id] {
					continue
				}
				known, err := w.cache.Known(id)
				if err != nil {
					return n, false, err
				}
				if !known {
					reuse = false
					break
				}
			}
			if reuse {
				for _, id := range row.Blobs {
					if err := w.cache.Ref(id); err != nil {
						return n, false, err
					}
				}
				n.Size, n.SHA256, n.Content = row.Size, row.SHA256, row.Blobs
				n.ModTime = time.Unix(0, row.MTimeNs).UTC()
				if err := w.counted(rel, n, fi); err != nil {
					return n, false, err
				}
				return n, true, nil
			}
		}
	}

	var pre, post os.FileInfo
	for attempt := 0; attempt < 2; attempt++ {
		var content []format.ID
		var size int64
		var sum string
		content, size, sum, pre, post, err = w.read(abs)
		if errors.Is(err, fs.ErrNotExist) {
			return n, false, nil
		}
		if err != nil {
			return n, false, err
		}
		n.Content, n.Size, n.SHA256 = content, size, sum
		n.ModTime = pre.ModTime().UTC()
		n.Mode = uint32(pre.Mode().Perm())
		if sameStat(pre, post) && post.Size() == size {
			break
		}
		if attempt == 1 {
			// It changed during both reads: keep the second, and say so.
			n.Inconsistent = true
			w.inconsistent = append(w.inconsistent, format.RawPath(rel))
		}
	}
	w.changed++
	pst := sysStat(pre)
	if !n.Inconsistent {
		row := cache.FileRow{Path: rel, Dev: pst.dev, Ino: pst.ino, Size: pre.Size(), MTimeNs: pre.ModTime().UnixNano(),
			CTimeNs: pst.ctimeNs, Mode: n.Mode, SHA256: n.SHA256, Blobs: n.Content}
		if err := w.cache.PutFile(row, w.runID); err != nil {
			return n, false, err
		}
	}
	if err := w.counted(rel, n, pre); err != nil {
		return n, false, err
	}
	return n, true, nil
}

func (w *walker) counted(rel string, n format.Node, fi os.FileInfo) error {
	w.files++
	w.logical += n.Size
	return w.cache.AddEntry(cache.Entry{Path: rel, Type: format.ContentFile, Value: n.SHA256, Size: n.Size,
		MTimeNs: n.ModTime.UnixNano(), Mode: n.Mode})
}

// read chunks one file, storing every chunk the epoch lacks, and returns the
// file's stat before and after the read.
func (w *walker) read(abs string) (content []format.ID, size int64, sum string, pre, post os.FileInfo, err error) {
	f, err := openNoFollow(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, "", nil, nil, err
		}
		return nil, 0, "", nil, nil, fmt.Errorf("opening %s: %w", abs, err)
	}
	defer f.Close()
	pre, err = f.Stat()
	if err != nil {
		return nil, 0, "", nil, nil, err
	}
	if !pre.Mode().IsRegular() {
		return nil, 0, "", nil, nil, fmt.Errorf("%s stopped being a regular file during the backup", abs)
	}
	h := sha256.New()
	w.ch.Reset(f)
	for {
		if err := w.ctx.Err(); err != nil {
			return nil, 0, "", nil, nil, err
		}
		b, err := w.ch.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, "", nil, nil, fmt.Errorf("reading %s: %w", abs, err)
		}
		h.Write(b)
		size += int64(len(b))
		w.readBytes += int64(len(b))
		id := format.Hash(b)
		content = append(content, id)
		// Sealing copies the bytes before the chunker reuses its buffer.
		if err := w.store(w.data, id, b); err != nil {
			return nil, 0, "", nil, nil, err
		}
	}
	post, err = f.Stat()
	if err != nil {
		return nil, 0, "", nil, nil, err
	}
	return content, size, hex.EncodeToString(h.Sum(nil)), pre, post, nil
}
