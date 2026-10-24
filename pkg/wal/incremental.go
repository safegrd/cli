package wal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// An incremental base backup (PostgreSQL 17 and newer) holds only the blocks
// changed since a full base, and is rebuilt with pg_combinebackup. It is
// always taken from the newest full, never from another incremental, and it
// is locked until exactly the date its full is locked until: once the full
// expires the incremental cannot be rebuilt, so it must not outlive it.

// ErrChainRefused is a store that will not lock an incremental base to the
// full it names: hosted storage, when the full is not there or is locked
// short of the window.
var ErrChainRefused = errors.New("the storage refused to lock an incremental base to its full")

// ChainLocker is a store that sets an incremental base's lock itself, to the
// date of the full it names.
type ChainLocker interface {
	PutChained(ctx context.Context, key string, body io.Reader, fullID string) (time.Time, error)
}

// NoBackupError is a pg_basebackup that stopped before it sent a byte, so
// nothing was uploaded.
type NoBackupError struct {
	Stderr string
	Err    error
}

func (e *NoBackupError) Error() string {
	return fmt.Sprintf("pg_basebackup wrote no backup: %v\n%s", e.Err, e.Stderr)
}

// Reason is PostgreSQL's own words for the refusal, or the error.
func (e *NoBackupError) Reason() string {
	for _, line := range strings.Split(e.Stderr, "\n") {
		if i := strings.Index(line, "ERROR:"); i >= 0 {
			return strings.TrimSpace(line[i+len("ERROR:"):])
		}
	}
	if e.Stderr != "" {
		return e.Stderr
	}
	return e.Err.Error()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// put writes one of a base's objects: an incremental's through the store's
// own chained lock when it has one.
func (a *Archive) put(ctx context.Context, key string, body io.Reader, info BaseInfo) (time.Time, error) {
	if cl, ok := a.Store.(ChainLocker); ok && info.IncrementalFrom != "" {
		return cl.PutChained(ctx, key, body, info.IncrementalFrom)
	}
	return a.Store.Put(ctx, key, body, info.LockedUntil)
}

// writeBaseRecord writes base.json and its copy, locked as the base is.
func (a *Archive) writeBaseRecord(ctx context.Context, info BaseInfo) (time.Time, error) {
	body, err := SealRecord(info)
	if err != nil {
		return time.Time{}, err
	}
	key := a.baseKey(info.BaseID, "base.json")
	got, err := a.put(ctx, key, bytes.NewReader(body), info)
	if err != nil {
		return got, err
	}
	if _, err := a.put(ctx, key+copySuffix, bytes.NewReader(body), info); err != nil {
		return got, fmt.Errorf("writing its second copy: %w", err)
	}
	return got, nil
}

var (
	labelIncrLSNRe = regexp.MustCompile(`(?m)^INCREMENTAL FROM LSN: ([0-9A-F]+/[0-9A-F]+)\s*$`)
	labelIncrTLIRe = regexp.MustCompile(`(?m)^INCREMENTAL FROM TLI: (\d+)\s*$`)
)

// checkIncrementalLabel records where an incremental's backup_label says
// its full starts, and refuses one that is not the full it was taken from.
func checkIncrementalLabel(info *BaseInfo, label string, from *BaseInfo) error {
	lm, tm := labelIncrLSNRe.FindStringSubmatch(label), labelIncrTLIRe.FindStringSubmatch(label)
	if from == nil {
		if lm != nil {
			return errors.New("pg_basebackup sent an incremental base where a full one was asked for")
		}
		return nil
	}
	if lm == nil || tm == nil {
		return fmt.Errorf("the base's backup_label names no full it was taken from, though it was asked for as an incremental from %s", from.BaseID)
	}
	lsn, err := ParseLSN(lm[1])
	if err != nil {
		return err
	}
	tli, err := strconv.ParseUint(tm[1], 10, 32)
	if err != nil {
		return err
	}
	info.IncrementalFromLSN, info.IncrementalFromTLI = lsn.String(), uint32(tli)
	if !sameStart(*from, lsn, uint32(tli)) {
		return fmt.Errorf("the incremental base is from %s on timeline %d, and full base %s starts at %s on timeline %d", lsn, tli, from.BaseID, from.StartLSN, from.Timeline)
	}
	return nil
}

// sameStart says full starts at lsn on timeline tli.
func sameStart(full BaseInfo, lsn LSN, tli uint32) bool {
	start, err := ParseLSN(full.StartLSN)
	if err != nil {
		return false
	}
	return start == lsn && full.Timeline == tli
}

// manifestPath is where this host keeps a full base's backup_manifest.
func (a *Archive) manifestPath(baseID string) string {
	return filepath.Join(a.ManifestDir, a.SystemID, baseID)
}

// keepManifest keeps a full base's backup_manifest on this host, for the
// incrementals taken from it, and drops the older fulls' ones.
func (a *Archive) keepManifest(info BaseInfo, manifest []byte) error {
	if a.ManifestDir == "" {
		return nil
	}
	dir := filepath.Join(a.ManifestDir, a.SystemID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".manifest-")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(manifest)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), a.manifestPath(info.BaseID))
	}
	if werr != nil {
		os.Remove(tmp.Name())
		return werr
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if e.Name() != info.BaseID && baseIDRe.MatchString(e.Name()) {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return nil
}

// BasePlan is the base backup to take next: an incremental from From, or a
// full when From is nil, with Why saying what stood in the way of an
// incremental.
type BasePlan struct {
	From     *BaseInfo
	Manifest string
	Why      string
}

// PlanBase works out whether the next base of srv can be an incremental.
// It can when the server is PostgreSQL 17 or newer with summarize_wal on,
// the archive's newest full is on the server's timeline, inside its
// interval and locked at least to now plus the window plus the slack, and
// this host holds that full's manifest.
func (a *Archive) PlanBase(ctx context.Context, srv Server) (BasePlan, error) {
	a.SystemID = srv.SystemID
	full := func(why string, args ...any) (BasePlan, error) {
		return BasePlan{Why: fmt.Sprintf(why, args...)}, nil
	}
	if srv.VersionNum < 170000 {
		return full("PostgreSQL %d takes no incremental base backups; 17 and newer do", srv.VersionNum/10000)
	}
	if !srv.SummarizeWAL {
		return full("summarize_wal is off on the server. Set summarize_wal = on to take incremental base backups")
	}
	bases, _, err := a.Bases(ctx)
	if err != nil {
		return BasePlan{}, err
	}
	var last *BaseInfo
	for i := range bases {
		if !bases[i].Incremental() {
			last = &bases[i]
		}
	}
	if last == nil {
		return full("the archive holds no full base backup of this cluster yet")
	}
	now := a.now()
	if age := now.Sub(last.StartedAt); age >= a.BaseEvery {
		return full("full base %s is %s old, and a full one is due every %d days (wal.base_every_days)", last.BaseID, age.Round(time.Hour), int(a.BaseEvery/(24*time.Hour)))
	}
	if a.Store.Locks() && !last.LockedUntil.IsZero() && last.LockedUntil.Before(now.Add(a.Window+lockSlack)) {
		return full("full base %s is locked until %s, short of the recovery window from now (it was raised since that base was taken), and an incremental is locked no longer than its full", last.BaseID, stamp(last.LockedUntil))
	}
	if last.Timeline != srv.Timeline {
		return full("full base %s is on timeline %d and the server is on timeline %d", last.BaseID, last.Timeline, srv.Timeline)
	}
	if a.ManifestDir == "" {
		return full("this host keeps no base manifests")
	}
	p := a.manifestPath(last.BaseID)
	b, err := os.ReadFile(p)
	if err != nil {
		return full("this host does not hold full base %s's manifest (the full was taken on another host, or this host's state directory is new)", last.BaseID)
	}
	if last.ManifestSha256 != "" && sha256Hex(b) != last.ManifestSha256 {
		return full("this host's copy of full base %s's manifest does not match the base's record", last.BaseID)
	}
	return BasePlan{From: last, Manifest: p}, nil
}

// BrokenBase is an incremental base a restore cannot rebuild.
type BrokenBase struct {
	BaseID, FullID, Why string
}

// chainFull is the full an incremental base was taken from, or why it cannot
// be rebuilt. A full base has no chain: nil, nil.
func chainFull(bases []BaseInfo, b BaseInfo) (*BaseInfo, error) {
	if !b.Incremental() {
		return nil, nil
	}
	for i := range bases {
		if bases[i].BaseID != b.IncrementalFrom {
			continue
		}
		f := bases[i]
		if f.Incremental() {
			return nil, fmt.Errorf("base %s is incremental on %s, which is an incremental too", b.BaseID, f.BaseID)
		}
		if lsn, err := ParseLSN(b.IncrementalFromLSN); err != nil || !sameStart(f, lsn, b.IncrementalFromTLI) {
			return nil, fmt.Errorf("base %s is incremental on %s from %s, and %s starts at %s", b.BaseID, f.BaseID, b.IncrementalFromLSN, f.BaseID, f.StartLSN)
		}
		return &f, nil
	}
	return nil, fmt.Errorf("base %s is incremental on full base %s, which the archive no longer holds", b.BaseID, b.IncrementalFrom)
}

// usableBases are the bases a restore can start from, and the incrementals
// whose full is gone.
func usableBases(bases []BaseInfo) ([]BaseInfo, []BrokenBase) {
	var ok []BaseInfo
	var broken []BrokenBase
	for _, b := range bases {
		if _, err := chainFull(bases, b); err != nil {
			broken = append(broken, BrokenBase{BaseID: b.BaseID, FullID: b.IncrementalFrom, Why: err.Error()})
			continue
		}
		ok = append(ok, b)
	}
	return ok, broken
}

// ChainBytes is how much a restore from b unpacks: the base, and its full
// when it is an incremental.
func ChainBytes(bases []BaseInfo, b BaseInfo) int64 {
	n := b.TarBytes
	if f, err := chainFull(bases, b); err == nil && f != nil {
		n += f.TarBytes
	}
	return n
}

// unpackChain writes the data directory base b restores into dir: the base
// itself, or for an incremental its full and itself unpacked side by side
// in a work directory next to dir and combined into dir with
// pg_combinebackup.
func (a *Archive) unpackChain(ctx context.Context, bases []BaseInfo, b BaseInfo, dir string) error {
	full, err := chainFull(bases, b)
	if err != nil {
		return err
	}
	if full == nil {
		return a.unpackBase(ctx, b, dir)
	}
	bin, err := FindPgTool(ctx, "pg_combinebackup", b.Major(), true)
	if err != nil {
		return fmt.Errorf("base %s is incremental and is rebuilt with pg_combinebackup: %w", b.BaseID, err)
	}
	work, err := os.MkdirTemp(filepath.Dir(filepath.Clean(dir)), "."+filepath.Base(dir)+".combine-")
	if err != nil {
		return fmt.Errorf("making a work directory beside %s to combine the incremental base in: %w", dir, err)
	}
	defer os.RemoveAll(work)
	fullDir, incrDir := filepath.Join(work, "full"), filepath.Join(work, "incremental")
	for _, d := range []string{fullDir, incrDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return err
		}
	}
	if err := a.unpackBase(ctx, *full, fullDir); err != nil {
		return err
	}
	if err := a.unpackBase(ctx, b, incrDir); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, bin, fullDir, incrDir, "-o", dir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_combinebackup could not rebuild base %s from full base %s: %w\n%s", b.BaseID, full.BaseID, err, strings.TrimSpace(string(out)))
	}
	return nil
}
