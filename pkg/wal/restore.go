package wal

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/crypto"
)

// RestoreOptions are one point-in-time restore.
type RestoreOptions struct {
	// Target is the moment to replay to. With TargetName set it only picks
	// the base backup: the newest one that ended before it. With neither,
	// the replay runs to the end of the archive and the newest base is used.
	Target time.Time
	// TargetName is a restore point to replay to.
	TargetName string
	// TargetLSN ("16/B374D848") and TargetXID are a position in the WAL and
	// a transaction to replay to, instead of a time.
	TargetLSN string
	TargetXID string
	// Exclusive stops just before the target instead of just after it.
	Exclusive bool
	// Timeline is the timeline to follow: "latest" (PostgreSQL's default),
	// "current", or a number the archive holds the history of.
	Timeline string
	PGData   string
	// FetchCommand is restore_command, with %f and %p for PostgreSQL to
	// fill in.
	FetchCommand string
}

// RestoreResult is what a restore wrote.
type RestoreResult struct {
	Base BaseInfo
	// ArchiveEnd is when the newest WAL file in the archive was pushed.
	ArchiveEnd time.Time
	// NoConf is a base with no postgresql.conf in it: the cluster kept its
	// configuration outside the data directory, as Debian and Ubuntu do.
	NoConf bool
	// CheckpointKept says why pg_control's checkpoint was left as the base
	// had it, so the cluster could start without its backup_label; "" when
	// it was cleared.
	CheckpointKept string
}

// Restore unpacks the newest complete base backup that ends before the
// target into an empty directory and sets PostgreSQL up to replay the
// archive to the target and promote. Starting PostgreSQL does the replay.
func (a *Archive) Restore(ctx context.Context, o RestoreOptions) (RestoreResult, error) {
	var res RestoreResult
	bases, _, err := a.Bases(ctx)
	if err != nil {
		return res, err
	}
	if len(bases) == 0 {
		return res, fmt.Errorf("the archive at %s holds no complete base backup. Take one with 'safegrd wal base'", a.Describe())
	}
	pick, err := a.pickBase(ctx, bases, o)
	if err != nil {
		return res, err
	}
	if err := a.checkTimeline(ctx, *pick, o.Timeline); err != nil {
		return res, err
	}
	have, err := a.archivedNames(ctx)
	if err != nil {
		return res, err
	}
	for _, t := range have {
		if t.After(res.ArchiveEnd) {
			res.ArchiveEnd = t
		}
	}
	// Push times are whole seconds; a target within the last push's second
	// is still inside the archive.
	if o.TargetName == "" && !o.Target.IsZero() && o.Target.After(res.ArchiveEnd.Add(time.Second)) {
		return res, fmt.Errorf("the archive reaches %s, and %s is after it: the WAL since then is not archived yet. Restore to a time before it", stamp(res.ArchiveEnd), stamp(o.Target))
	}
	// A missing WAL file ends the replay where restore_command first finds
	// nothing, and PostgreSQL promotes there: a replay to the end of the
	// archive would say nothing, and one to a later time stops with
	// "recovery ended before configured recovery target was reached".
	// Refused here, before anything is unpacked, with the file named.
	st, err := a.Status(ctx)
	if err != nil {
		return res, err
	}
	for _, g := range st.Gaps {
		// The same second of slack as the archive's end above: push times
		// are whole seconds.
		if !slices.Contains(g.Breaks, pick.BaseID) || (!o.Target.IsZero() && !o.Target.After(g.Before.Add(time.Second))) {
			continue
		}
		return res, fmt.Errorf("the archive is missing %s, so a replay from base %s stops at %s. Restore to a time before that, or take a base backup (safegrd wal base) to start an unbroken window after it",
			g.First, pick.BaseID, stamp(g.Before))
	}
	if err := emptyDir(o.PGData); err != nil {
		return res, err
	}
	if err := a.unpackBase(ctx, *pick, o.PGData); err != nil {
		return res, err
	}
	if _, err := os.Stat(filepath.Join(o.PGData, "backup_label")); err != nil {
		return res, fmt.Errorf("base %s holds no backup_label, and a cluster restored from it would start from the wrong checkpoint: %w", pick.BaseID, err)
	}
	switch err := InvalidateCheckpoint(o.PGData); {
	case errors.Is(err, ErrControlUnknown):
		res.CheckpointKept = err.Error()
	case err != nil:
		return res, fmt.Errorf("clearing the checkpoint in pg_control, so the cluster starts only from its backup_label: %w", err)
	}
	if err := writeRecovery(o.PGData, o.FetchCommand, o); err != nil {
		return res, err
	}
	res.Base = *pick
	if _, err := os.Stat(filepath.Join(o.PGData, "postgresql.conf")); errors.Is(err, os.ErrNotExist) {
		res.NoConf = true
	}
	return res, nil
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

// emptyDir makes dir, or accepts it when it exists and holds nothing.
func emptyDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if len(ents) > 0 {
		return fmt.Errorf("%s is not empty; a restore writes a whole data directory and needs an empty one", dir)
	}
	return os.Chmod(dir, 0o700)
}

func (a *Archive) unpackBase(ctx context.Context, b BaseInfo, dir string) error {
	rc, err := a.Store.Get(ctx, a.baseKey(b.BaseID, "base.tar.zst.age"))
	if err != nil {
		return fmt.Errorf("reading base %s: %w", b.BaseID, err)
	}
	defer rc.Close()
	pr, pw := io.Pipe()
	type decrypted struct {
		m   *crypto.StreamMetrics
		err error
	}
	done := make(chan decrypted, 1)
	go func() {
		m, err := crypto.DecryptStream(rc, pw, a.Identity)
		pw.CloseWithError(err)
		done <- decrypted{m, err}
	}()
	untarErr := untar(pr, dir)
	if untarErr == nil {
		_, untarErr = io.Copy(io.Discard, pr) // the tar's trailing blocks
	}
	pr.CloseWithError(io.ErrClosedPipe)
	d := <-done
	if d.err != nil {
		return fmt.Errorf("decrypting base %s: %w", b.BaseID, d.err)
	}
	if untarErr != nil {
		return fmt.Errorf("unpacking base %s: %w", b.BaseID, untarErr)
	}
	if d.m.RawSha256 != b.TarSha256 {
		return fmt.Errorf("base %s decrypts to other bytes than were written (%s, wrote %s)", b.BaseID, d.m.RawSha256[:16], b.TarSha256[:16])
	}
	return nil
}

func untar(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	manifestRead := false
	for {
		h, err := tr.Next()
		if err == io.EOF || (errors.Is(err, io.ErrUnexpectedEOF) && manifestRead) {
			// PostgreSQL 13 and 14 end the tar right after the manifest's
			// last byte (scanTar).
			return nil
		}
		if err != nil {
			return err
		}
		manifestRead = false
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." {
			continue
		}
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("the base holds %q, outside the data directory", h.Name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(h.Mode)&0o700|0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			manifestRead = name == "backup_manifest"
		case tar.TypeSymlink:
			// pg_basebackup -Ft writes pg_wal as a directory and refuses
			// tablespaces on stdout, so a link here is not PostgreSQL's.
			return fmt.Errorf("the base holds a symbolic link %q; pg_basebackup writes none into a tar on stdout, so this is not one of its backups", h.Name)
		default:
			return fmt.Errorf("the base holds %q of tar type %q", h.Name, h.Typeflag)
		}
	}
}

// writeRecovery sets the unpacked cluster up to replay the archive to the
// target and promote. Archiving is turned off on it: a restored cluster
// that archived would push a new timeline into the archive it came from.
func writeRecovery(dir, fetch string, o RestoreOptions) error {
	if err := os.WriteFile(filepath.Join(dir, "recovery.signal"), nil, 0o600); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "postgresql.auto.conf"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	target := ""
	switch {
	case o.TargetName != "":
		target = "recovery_target_name = " + confQuote(o.TargetName) + "\n"
	case o.TargetLSN != "":
		target = "recovery_target_lsn = " + confQuote(o.TargetLSN) + "\n"
	case o.TargetXID != "":
		target = "recovery_target_xid = " + confQuote(o.TargetXID) + "\n"
	case !o.Target.IsZero():
		target = "recovery_target_time = " + confQuote(o.Target.UTC().Format("2006-01-02 15:04:05.999999")+"+00") + "\n"
	}
	if target != "" && o.Exclusive {
		target += "recovery_target_inclusive = 'off'\n"
	}
	if o.Timeline != "" {
		target += "recovery_target_timeline = " + confQuote(o.Timeline) + "\n"
	}
	_, err = fmt.Fprintf(f, "\n# Written by safegrd wal restore\nrestore_command = %s\n%srecovery_target_action = 'promote'\narchive_mode = 'off'\n",
		confQuote(fetch), target)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// confQuote quotes a value for postgresql.conf.
func confQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// pickBase is the base a restore starts from. For a time, the newest that
// ended before it; for a WAL position, the newest that ended at or before
// it; for a transaction id, which no base records, the oldest whose WAL
// reaches the end of the archive unbroken, so the transaction is after it
// wherever in the window it is.
func (a *Archive) pickBase(ctx context.Context, bases []BaseInfo, o RestoreOptions) (*BaseInfo, error) {
	var pick *BaseInfo
	switch {
	case o.TargetLSN != "":
		target, err := ParseLSN(o.TargetLSN)
		if err != nil {
			return nil, err
		}
		for i := range bases {
			end, err := ParseLSN(bases[i].EndLSN)
			if err == nil && end <= target {
				pick = &bases[i]
			}
		}
		if pick == nil {
			return nil, fmt.Errorf("no base backup ends at or before %s; the oldest ends at %s. Restore to a later position", target, bases[0].EndLSN)
		}
	case o.TargetXID != "":
		if _, err := strconv.ParseUint(strings.TrimSpace(o.TargetXID), 10, 64); err != nil {
			return nil, fmt.Errorf("--to-xid %q is not a transaction id", o.TargetXID)
		}
		st, err := a.Status(ctx)
		if err != nil {
			return nil, err
		}
		broken := map[string]bool{}
		for _, g := range st.Gaps {
			for _, b := range g.Breaks {
				broken[b] = true
			}
		}
		for i := range bases {
			if !broken[bases[i].BaseID] {
				pick = &bases[i]
				break
			}
		}
		if pick == nil {
			return nil, fmt.Errorf("every base backup's WAL stops at a missing file, so no restore can be sure to reach transaction %s. Restore to a time instead", o.TargetXID)
		}
	default:
		for i := range bases {
			if o.Target.IsZero() || bases[i].EndedAt.Before(o.Target) {
				pick = &bases[i]
			}
		}
		if pick == nil {
			return nil, fmt.Errorf("no base backup ends before %s; the oldest ends at %s", stamp(o.Target), stamp(bases[0].EndedAt))
		}
	}
	return pick, nil
}

// checkTimeline holds a timeline asked for to the archive's history before
// anything is written: a numbered timeline other than the base's needs its
// history file in the archive, and the base's timeline among its parents,
// branched off after the base ended.
func (a *Archive) checkTimeline(ctx context.Context, b BaseInfo, timeline string) error {
	switch timeline {
	case "", "latest", "current":
		return nil
	}
	n, err := strconv.ParseUint(timeline, 10, 32)
	if err != nil || n == 0 {
		return fmt.Errorf("--timeline %q is not latest, current or a timeline number", timeline)
	}
	if uint32(n) == b.Timeline {
		return nil
	}
	name := fmt.Sprintf("%08X.history", n)
	var hist bytes.Buffer
	if err := a.Fetch(ctx, name, &hist); err != nil {
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("the archive holds no history for timeline %d (%s), so PostgreSQL could not follow it. Base %s is on timeline %d", n, name, b.BaseID, b.Timeline)
		}
		return fmt.Errorf("reading %s: %w", name, err)
	}
	end, err := ParseLSN(b.EndLSN)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(hist.String(), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		parent, err1 := strconv.ParseUint(f[0], 10, 32)
		switchAt, err2 := ParseLSN(f[1])
		if err1 != nil || err2 != nil || uint32(parent) != b.Timeline {
			continue
		}
		if switchAt < end {
			return fmt.Errorf("timeline %d branched off timeline %d at %s, before base %s ended at %s, so no replay from it reaches timeline %d", n, b.Timeline, switchAt, b.BaseID, end, n)
		}
		return nil
	}
	return fmt.Errorf("timeline %d does not descend from timeline %d, which base %s is on (%s)", n, b.Timeline, b.BaseID, name)
}
