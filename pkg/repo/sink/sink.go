// Package sink is where a repository's objects go. The engine talks only to
// Backend; a backend that writes straight to a bucket or a directory is Direct
// over a Store, and the hosted backend, whose remote server names every key
// and signs every request, implements Backend itself.
package sink

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
)

// Kind is what an object is.
type Kind string

const (
	KindEpoch    Kind = "epoch"
	KindPack     Kind = "pack"
	KindIndex    Kind = "index"
	KindCatalog  Kind = "catalog"
	KindSnapshot Kind = "snapshot"
	KindMeta     Kind = "meta"
	// KindRecovery is the recovery document beside a snapshot's sidecar,
	// plain text; KindRecoverySealed is the same page encrypted to the
	// epoch's recipient.
	KindRecovery       Kind = "recovery"
	KindRecoverySealed Kind = "recovery-sealed"
)

// ObjectSpec is one object a run is about to write.
type ObjectSpec struct {
	Kind Kind
	// Name is the pack id, run id or snapshot id the key is built from.
	// Ignored for the epoch descriptor.
	Name string
	Size int64
	MD5  [16]byte
}

// Slot is where one object goes, and the lock it carries.
type Slot struct {
	Kind        Kind
	Key         string
	EpochID     string
	Class       string
	RetainUntil time.Time
	// Unlocked is an object written with no lock: a recent run's, in a
	// project that locks only the copies it keeps. RetainUntil is then how
	// long the run is kept, not a lock.
	Unlocked bool
	// URL and Headers are set when the remote server signed the request:
	// the body must be PUT there with exactly these headers.
	URL     string
	Headers map[string]string
}

// RunDecision is what a backend decided about a run before it wrote: whether
// its objects are locked when written, and until when they are locked or
// kept. Known is false when the backend made no decision, and the epoch's
// class lock applies as it always has.
type RunDecision struct {
	Known     bool
	Scheduled bool
	Locked    bool
	LockUntil time.Time
	KeptUntil time.Time
	Slot      string
}

// Until is the date the run's snapshot is kept or locked until.
func (d RunDecision) Until() time.Time {
	if d.Locked {
		return d.LockUntil
	}
	return d.KeptUntil
}

// RunStarter is a backend that decides a run's lock before the run writes.
// The writer asks once per run, right after the epoch is open.
type RunStarter interface {
	StartRun(ctx context.Context, e format.Epoch, runID string) (RunDecision, error)
}

// OpenRequest is what a run knows when it starts.
type OpenRequest struct {
	SurfaceID string
	// Current is the epoch the writer's cache holds, nil when it holds none.
	Current *policy.Current
	// Decision is the writer's own: continue Current, or open with a reason.
	Decision    policy.Decision
	OpeningTier string
	Retention   policy.Retention
	Recipient   string
	Now         time.Time
	// PackTargetBytes overrides the size a pack is closed at; zero keeps
	// the default.
	PackTargetBytes int
	// Chunker is the chunk size bounds a new epoch is cut with; nil keeps
	// format.DefaultChunker. A continuing epoch keeps its own.
	Chunker *format.ChunkerParams
}

// Opened is the epoch a run writes into.
type Opened struct {
	Epoch format.Epoch
	// New is true when this call opened it.
	New bool
	// OpeningDone is true once the epoch's first snapshot is complete, so
	// this run writes objects of the later class.
	OpeningDone bool
}

// RunCommit is what a finished run tells the backend.
type RunCommit struct {
	SnapshotID string
	RunID      string
	Class      string
	// Keys is every object the run wrote; Refs every object its snapshot
	// reads that an earlier run wrote (packs, and the index of each run it
	// reads). Together they are what a kept copy of the run has to hold.
	Keys        []string
	Refs        []string
	RetainUntil time.Time
	// Unlocked says the run's objects carry no lock.
	Unlocked bool
}

// ObjectInfo is one object in a listing.
type ObjectInfo struct {
	Key  string
	Size int64
}

// EpochInfo is an epoch found on the read side.
type EpochInfo struct {
	Epoch  format.Epoch
	Prefix string
}

// Backend is everything the engine needs from where objects are kept.
type Backend interface {
	// OpenEpoch returns the epoch to write into: the writer's current one, or
	// a new one when its decision, or the remote server, says so.
	OpenEpoch(ctx context.Context, req OpenRequest) (Opened, error)
	// Reserve returns where each object goes. The class is the epoch's,
	// as the backend sees it.
	Reserve(ctx context.Context, e format.Epoch, class string, objs []ObjectSpec) ([]Slot, error)
	// Put writes one object to its slot, with the slot's lock. It fails if
	// the key already holds an object.
	Put(ctx context.Context, slot Slot, body []byte) error
	// Uploaded confirms finished objects, so the remote server can stop
	// counting them as outstanding. A no-op elsewhere.
	Uploaded(ctx context.Context, e format.Epoch, keys []string) error
	// Commit records a finished run.
	Commit(ctx context.Context, e format.Epoch, c RunCommit) error

	// Epochs lists every epoch of a surface that is still in the store.
	Epochs(ctx context.Context, surfaceID string) ([]EpochInfo, error)
	// List lists the objects of an epoch under sub ("packs", "snapshots", …).
	List(ctx context.Context, e EpochInfo, sub string) ([]ObjectInfo, error)
	Get(ctx context.Context, key string) ([]byte, error)
	GetRange(ctx context.Context, key string, off, n int64) ([]byte, error)

	// Describe says where objects go, for messages.
	Describe() string
}

// ErrNotFound is returned by Get for a key that holds nothing.
var ErrNotFound = errors.New("not found")

// PerKey hands out one lock per key, so that concurrent first reads of one
// object (a pack's header, a signed URL) share one request instead of each
// making their own.
type PerKey struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// Lock takes the key's lock and returns what releases it.
func (p *PerKey) Lock(key string) func() {
	p.mu.Lock()
	if p.locks == nil {
		p.locks = map[string]*sync.Mutex{}
	}
	l, ok := p.locks[key]
	if !ok {
		l = &sync.Mutex{}
		p.locks[key] = l
	}
	p.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// Store is a flat object store a Direct backend writes through.
type Store interface {
	// Put writes body at key with the lock until retainUntil (where the
	// store locks). It must fail rather than overwrite.
	Put(ctx context.Context, key string, body []byte, md5 [16]byte, retainUntil time.Time) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	GetRange(ctx context.Context, key string, off, n int64) ([]byte, error)
	// List returns the current objects under prefix, recursively.
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
	// Root is the key prefix every repository key starts with.
	Root() string
	Describe() string
}

// Layout of a repository's keys under its root:
//
//	repo/<surface-id>/<epoch-id>/
//	  epoch.json
//	  packs/<pack-id>
//	  index/<run-id>.age
//	  catalog/<run-id>.age
//	  snapshots/<snapshot-id>.age
//	  snapshots/<snapshot-id>.meta.json
//	  snapshots/<snapshot-id>.RECOVERY.md (or .RECOVERY.md.age)

// EpochPrefix is the key prefix of one epoch, below the store's root.
func EpochPrefix(root, surfaceID, epochID string) string {
	return path.Join(root, "repo", surfaceID, epochID)
}

// ObjectKey is the key of one object of an epoch.
func ObjectKey(epochPrefix string, kind Kind, name string) (string, error) {
	switch kind {
	case KindEpoch:
		return path.Join(epochPrefix, "epoch.json"), nil
	case KindPack:
		if !format.ValidRandomID(name) {
			return "", fmt.Errorf("pack id %q is malformed", name)
		}
		return path.Join(epochPrefix, "packs", name), nil
	case KindIndex:
		if !format.ValidRandomID(name) {
			return "", fmt.Errorf("run id %q is malformed", name)
		}
		return path.Join(epochPrefix, "index", name+".age"), nil
	case KindCatalog:
		if !format.ValidRandomID(name) {
			return "", fmt.Errorf("run id %q is malformed", name)
		}
		return path.Join(epochPrefix, "catalog", name+".age"), nil
	case KindSnapshot, KindMeta, KindRecovery, KindRecoverySealed:
		if err := ValidSnapshotName(name); err != nil {
			return "", err
		}
		switch kind {
		case KindMeta:
			return path.Join(epochPrefix, "snapshots", name+".meta.json"), nil
		case KindRecovery:
			return path.Join(epochPrefix, "snapshots", name+".RECOVERY.md"), nil
		case KindRecoverySealed:
			return path.Join(epochPrefix, "snapshots", name+".RECOVERY.md.age"), nil
		}
		return path.Join(epochPrefix, "snapshots", name+".age"), nil
	}
	return "", fmt.Errorf("object kind %q is unknown", kind)
}

// ValidSnapshotName refuses a snapshot id that could leave its directory.
func ValidSnapshotName(name string) error {
	if name == "" || len(name) > 128 {
		return fmt.Errorf("snapshot id %q is empty or too long", name)
	}
	for _, c := range name {
		ok := c == '-' || c == '_' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return fmt.Errorf("snapshot id %q holds %q", name, c)
		}
	}
	if name[0] == '.' {
		return fmt.Errorf("snapshot id %q starts with a dot", name)
	}
	return nil
}

// ValidSurfaceID refuses a surface id that cannot be a key segment.
func ValidSurfaceID(id string) error {
	if err := ValidSnapshotName(id); err != nil {
		return fmt.Errorf("surface id %q: letters, digits, '-', '_' and '.' only", id)
	}
	return nil
}
