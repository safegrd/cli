package format

import (
	"encoding/base64"
	"fmt"
	"time"
	"unicode/utf8"
)

// Object classes. Objects written by an epoch's opening run, which stores the
// whole tree, are of the opening class and are locked longest; objects of every
// later run are of the later class.
const (
	ClassOpening = "opening"
	ClassLater   = "later"
)

// Reasons an epoch opens.
const (
	ReasonFirst              = "first"
	ReasonMonth              = "month"
	ReasonCacheLost          = "cache-lost"
	ReasonRetentionIncreased = "retention-increased"
	ReasonFormat             = "format"
	ReasonRequested          = "requested"
	// ReasonRecipient: the surface's public key changed. Packs are wrapped
	// to one recipient per epoch, so a new key starts a new epoch.
	ReasonRecipient = "recipient-changed"
)

// Retention tiers an opening snapshot can be declared at.
const (
	TierBase    = "base"
	TierDaily   = "daily"
	TierWeekly  = "weekly"
	TierMonthly = "monthly"
)

// ChunkerParams are the chunk size bounds an epoch was cut with. The
// polynomial is never stored in the repository: only the writer needs it.
type ChunkerParams struct {
	Algorithm string `json:"algorithm"`
	Min       int    `json:"min"`
	Avg       int    `json:"avg"`
	Max       int    `json:"max"`
}

// ChunkerAlgorithm names the content-defined chunker.
const ChunkerAlgorithm = "rabin-restic"

// DefaultChunker is 512 KiB minimum, about 1 MiB on average, 8 MiB maximum.
var DefaultChunker = ChunkerParams{Algorithm: ChunkerAlgorithm, Min: 512 << 10, Avg: 1 << 20, Max: 8 << 20}

// DatabaseChunker is 32 KiB minimum, about 64 KiB on average, 512 KiB
// maximum: a database's tables change a few rows at a time all over, and a
// smaller chunk re-uploads less of a table for each scattered change.
var DatabaseChunker = ChunkerParams{Algorithm: ChunkerAlgorithm, Min: 32 << 10, Avg: 64 << 10, Max: 512 << 10}

// DefaultPackTarget is the size at which a pack is closed.
const DefaultPackTarget = 32 << 20

// Epoch is the plaintext epoch descriptor, epoch.json:
//
//	format, version, epoch_id, surface_id, opened_at, planned_end, reason,
//	t_mid_days, opening_tier, opening_retain_until, later_retain_until,
//	recipient, chunker {algorithm, min, avg, max}, pack_target_bytes
type Epoch struct {
	Format             string        `json:"format"`
	Version            int           `json:"version"`
	EpochID            string        `json:"epoch_id"`
	SurfaceID          string        `json:"surface_id"`
	OpenedAt           time.Time     `json:"opened_at"`
	PlannedEnd         time.Time     `json:"planned_end"`
	Reason             string        `json:"reason"`
	TMidDays           int           `json:"t_mid_days"`
	OpeningTier        string        `json:"opening_tier"`
	OpeningRetainUntil time.Time     `json:"opening_retain_until"`
	LaterRetainUntil   time.Time     `json:"later_retain_until"`
	Recipient          string        `json:"recipient"`
	Chunker            ChunkerParams `json:"chunker"`
	PackTargetBytes    int           `json:"pack_target_bytes"`
}

// RetainUntil is the lock every object of class carries.
func (e Epoch) RetainUntil(class string) time.Time {
	if class == ClassOpening {
		return e.OpeningRetainUntil
	}
	return e.LaterRetainUntil
}

// Validate refuses a descriptor of another format or version, or one whose
// dates contradict each other.
func (e Epoch) Validate() error {
	if e.Format != FormatName {
		return fmt.Errorf("epoch descriptor: format %q is not %s", e.Format, FormatName)
	}
	if e.Version != Version {
		return fmt.Errorf("epoch %s: repository format version %d is not one this release reads (it reads version %d); upgrade safegrd", e.EpochID, e.Version, Version)
	}
	if !ValidEpochID(e.EpochID) {
		return fmt.Errorf("epoch descriptor: epoch id %q is malformed", e.EpochID)
	}
	if e.SurfaceID == "" {
		return fmt.Errorf("epoch %s: no surface id", e.EpochID)
	}
	if !e.PlannedEnd.After(e.OpenedAt) {
		return fmt.Errorf("epoch %s: planned end %s is not after it opened", e.EpochID, e.PlannedEnd)
	}
	if e.LaterRetainUntil.Before(e.PlannedEnd) || e.OpeningRetainUntil.Before(e.LaterRetainUntil) {
		return fmt.Errorf("epoch %s: lock dates out of order (later %s, opening %s)", e.EpochID, e.LaterRetainUntil, e.OpeningRetainUntil)
	}
	if e.Recipient == "" {
		return fmt.Errorf("epoch %s: no recipient", e.EpochID)
	}
	c := e.Chunker
	if c.Algorithm != ChunkerAlgorithm || c.Min <= 0 || c.Min > c.Avg || c.Avg > c.Max {
		return fmt.Errorf("epoch %s: chunker %+v is not one this release knows", e.EpochID, c)
	}
	return nil
}

// IndexPack is one pack an index names, with every blob of it the run first
// stored.
type IndexPack struct {
	PackID string      `json:"pack_id"`
	Bytes  int64       `json:"bytes"`
	Blobs  []BlobEntry `json:"blobs"`
}

// Index lists every blob first stored by one run.
type Index struct {
	Version int         `json:"version"`
	EpochID string      `json:"epoch_id"`
	RunID   string      `json:"run_id"`
	Packs   []IndexPack `json:"packs"`
}

// Validate checks an index's shape.
func (x Index) Validate() error {
	if x.Version != Version {
		return fmt.Errorf("index %s: format version %d is not one this release reads (it reads version %d)", x.RunID, x.Version, Version)
	}
	if !ValidEpochID(x.EpochID) || !ValidRandomID(x.RunID) {
		return fmt.Errorf("index: epoch %q or run %q is malformed", x.EpochID, x.RunID)
	}
	if x.Packs == nil {
		return fmt.Errorf("index %s: no packs list", x.RunID)
	}
	for _, p := range x.Packs {
		if !ValidRandomID(p.PackID) {
			return fmt.Errorf("index %s: pack id %q is malformed", x.RunID, p.PackID)
		}
		if p.Blobs == nil {
			return fmt.Errorf("index %s: pack %s has no blobs list", x.RunID, p.PackID)
		}
		for _, b := range p.Blobs {
			if err := b.Validate(); err != nil {
				return fmt.Errorf("index %s, pack %s: %w", x.RunID, p.PackID, err)
			}
			if b.Offset+b.Length > p.Bytes {
				return fmt.Errorf("index %s, pack %s: blob %s ends past the pack's %d bytes", x.RunID, p.PackID, b.ID, p.Bytes)
			}
		}
	}
	return nil
}

// SnapshotStats are what one run saw and wrote.
type SnapshotStats struct {
	Files        int64 `json:"files"`
	Dirs         int64 `json:"dirs"`
	LogicalBytes int64 `json:"logical_bytes"`
	NewBytes     int64 `json:"new_bytes"`
	NewPacks     int64 `json:"new_packs"`
}

// Skipped is a path the walk did not store, and why. A path that is not
// valid UTF-8 is written as path_b64.
type Skipped struct {
	Path   string
	Reason string
}

type wireSkipped struct {
	Path    string `json:"path,omitempty"`
	PathB64 string `json:"path_b64,omitempty"`
	Reason  string `json:"reason"`
}

func (k Skipped) MarshalJSON() ([]byte, error) {
	w := wireSkipped{Reason: k.Reason}
	w.Path, w.PathB64 = rawString(k.Path)
	return Marshal(w)
}

func (k *Skipped) UnmarshalJSON(b []byte) error {
	var w wireSkipped
	if err := Unmarshal(b, &w); err != nil {
		return err
	}
	p, err := fromRawString(w.Path, w.PathB64)
	if err != nil {
		return fmt.Errorf("skipped path: %w", err)
	}
	*k = Skipped{Path: p, Reason: w.Reason}
	return nil
}

// RawPath is a path that keeps its raw bytes through JSON: a string when
// valid UTF-8, {"b64": …} otherwise. The snapshot's inconsistent list uses it.
type RawPath string

func (p RawPath) MarshalJSON() ([]byte, error) {
	plain, b64 := rawString(string(p))
	if b64 == "" {
		return Marshal(plain)
	}
	return Marshal(map[string]string{"b64": b64})
}

func (p *RawPath) UnmarshalJSON(b []byte) error {
	var s string
	if err := Unmarshal(b, &s); err == nil {
		*p = RawPath(s)
		return nil
	}
	var w struct {
		B64 string `json:"b64"`
	}
	if err := Unmarshal(b, &w); err != nil {
		return err
	}
	raw, err := fromRawString("", w.B64)
	if err != nil {
		return err
	}
	*p = RawPath(raw)
	return nil
}

// Snapshot is the Age-encrypted snapshot object.
type Snapshot struct {
	Version      int           `json:"version"`
	SnapshotID   string        `json:"snapshot_id"`
	EpochID      string        `json:"epoch_id"`
	RunID        string        `json:"run_id"`
	Class        string        `json:"class"`
	CreatedAt    time.Time     `json:"created_at"`
	CompletedAt  time.Time     `json:"completed_at"`
	Host         string        `json:"host"`
	Roots        []string      `json:"roots"`
	RootTree     string        `json:"root_tree"`
	ContentRoot  string        `json:"content_root"`
	Runs         []string      `json:"runs"`
	Packs        []string      `json:"packs"`
	Stats        SnapshotStats `json:"stats"`
	Skipped      []Skipped     `json:"skipped"`
	Inconsistent []RawPath     `json:"inconsistent"`
	RetainUntil  time.Time     `json:"retain_until"`
}

// Validate checks a snapshot object's shape.
func (s Snapshot) Validate() error {
	if s.Version != Version {
		return fmt.Errorf("snapshot %s: format version %d is not one this release reads (it reads version %d); upgrade safegrd", s.SnapshotID, s.Version, Version)
	}
	if !ValidEpochID(s.EpochID) || !ValidRandomID(s.RunID) {
		return fmt.Errorf("snapshot %s: epoch %q or run %q is malformed", s.SnapshotID, s.EpochID, s.RunID)
	}
	if s.Class != ClassOpening && s.Class != ClassLater {
		return fmt.Errorf("snapshot %s: class %q is not opening or later", s.SnapshotID, s.Class)
	}
	if _, err := ParseID(s.RootTree); err != nil {
		return fmt.Errorf("snapshot %s: root tree: %w", s.SnapshotID, err)
	}
	if len(s.ContentRoot) != 64 || !lowerHex.MatchString(s.ContentRoot) {
		return fmt.Errorf("snapshot %s: content root %q is malformed", s.SnapshotID, s.ContentRoot)
	}
	if len(s.Roots) == 0 {
		return fmt.Errorf("snapshot %s: no roots", s.SnapshotID)
	}
	for _, r := range append(append([]string{}, s.Runs...), s.Packs...) {
		if !ValidRandomID(r) {
			return fmt.Errorf("snapshot %s: run or pack id %q is malformed", s.SnapshotID, r)
		}
	}
	return nil
}

// Catalog events.
const (
	EventPresent = "present"
	EventAdded   = "added"
	EventChanged = "changed"
	EventDeleted = "deleted"
)

// CatalogEntry is one path a run saw added, changed or deleted, or, in an
// opening run, present. Path is relative to / with no leading slash, as raw
// bytes: a path that is not valid UTF-8 is written as path_b64, like a tree's
// names, because a JSON string cannot carry it.
type CatalogEntry struct {
	Path   string
	Event  string
	Type   string
	SHA256 string
	Size   int64
	MTime  *time.Time
	Mode   uint32
}

type wireCatalogEntry struct {
	Path    string     `json:"path,omitempty"`
	PathB64 string     `json:"path_b64,omitempty"`
	Event   string     `json:"event"`
	Type    string     `json:"type"`
	SHA256  string     `json:"sha256,omitempty"`
	Size    int64      `json:"size,omitempty"`
	MTime   *time.Time `json:"mtime,omitempty"`
	Mode    uint32     `json:"mode,omitempty"`
}

func (e CatalogEntry) MarshalJSON() ([]byte, error) {
	w := wireCatalogEntry{Event: e.Event, Type: e.Type, SHA256: e.SHA256, Size: e.Size, MTime: e.MTime, Mode: e.Mode}
	w.Path, w.PathB64 = rawString(e.Path)
	return Marshal(w)
}

func (e *CatalogEntry) UnmarshalJSON(b []byte) error {
	var w wireCatalogEntry
	if err := Unmarshal(b, &w); err != nil {
		return err
	}
	p, err := fromRawString(w.Path, w.PathB64)
	if err != nil {
		return fmt.Errorf("catalog entry: %w", err)
	}
	*e = CatalogEntry{Path: p, Event: w.Event, Type: w.Type, SHA256: w.SHA256, Size: w.Size, MTime: w.MTime, Mode: w.Mode}
	return nil
}

// rawString splits raw bytes into a JSON string field and a base64 one:
// the string when they are valid UTF-8, the base64 otherwise.
func rawString(s string) (plain, b64 string) {
	if utf8.ValidString(s) {
		return s, ""
	}
	return "", base64.StdEncoding.EncodeToString([]byte(s))
}

func fromRawString(plain, b64 string) (string, error) {
	switch {
	case plain != "" && b64 != "":
		return "", fmt.Errorf("both a string and its base64")
	case b64 != "":
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return "", err
		}
		if utf8.Valid(raw) {
			return "", fmt.Errorf("base64 of valid UTF-8, which is written as a string")
		}
		return string(raw), nil
	}
	return plain, nil
}

// Catalog is one run's catalog delta.
type Catalog struct {
	Version    int            `json:"version"`
	EpochID    string         `json:"epoch_id"`
	RunID      string         `json:"run_id"`
	SnapshotID string         `json:"snapshot_id"`
	Complete   bool           `json:"complete"`
	Entries    []CatalogEntry `json:"entries"`
}

// Validate checks a catalog delta's shape.
func (c Catalog) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("catalog %s: format version %d is not one this release reads (it reads version %d)", c.RunID, c.Version, Version)
	}
	if !ValidEpochID(c.EpochID) || !ValidRandomID(c.RunID) {
		return fmt.Errorf("catalog: epoch %q or run %q is malformed", c.EpochID, c.RunID)
	}
	for _, e := range c.Entries {
		switch e.Event {
		case EventPresent:
			if !c.Complete {
				return fmt.Errorf("catalog %s: a present entry in a delta", c.RunID)
			}
		case EventAdded, EventChanged, EventDeleted:
			if c.Complete {
				return fmt.Errorf("catalog %s: a %s entry in a complete catalog", c.RunID, e.Event)
			}
		default:
			return fmt.Errorf("catalog %s: event %q", c.RunID, e.Event)
		}
		if e.Type != "f" && e.Type != "d" && e.Type != "l" {
			return fmt.Errorf("catalog %s: type %q", c.RunID, e.Type)
		}
	}
	return nil
}
