package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/wal"
)

const (
	// walRetry is how long a failed base backup or bundle waits before the
	// daemon tries it again.
	walRetry = time.Hour
	// walBundleEvery is how often the unlocked WAL is bundled whatever its
	// size: it is what anyone with delete permission in the bucket could
	// remove.
	walBundleEvery = 24 * time.Hour
	// walSizeEvery is how often the unlocked WAL is measured against
	// wal.bundle_mb, which costs a listing.
	walSizeEvery = 10 * time.Minute
)

var (
	// walArchiverSaid is the archive_command failure last said for each
	// surface, so it is said when it starts, when it moves to another file,
	// and when it ends.
	walArchiverSaid = map[string]string{}
	walSizeChecked  = map[string]time.Time{}
	// walHeldChecked is when the archiver of a surface whose credential the
	// remote server holds, or a command prints, was last read. Each read
	// fetches the credential, which the remote server audits, so it is read
	// hourly and not on every tick.
	walHeldChecked = map[string]time.Time{}
)

// walHeldEvery is how often such a surface's archiver is read.
const walHeldEvery = time.Hour

// checkWALArchiver reads pg_stat_archiver and says when archive_command
// starts or stops failing, and returns false while it fails. A database
// that does not answer is the probe's to report.
func checkWALArchiver(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, st *SurfaceState) bool {
	dbURL, ok := probeDatabaseURL(ctx, c, s)
	if !ok {
		switch s.CredentialFrom() {
		case config.CredentialFromSafeGrd, config.CredentialFromCommand:
		default:
			return true
		}
		if time.Since(walHeldChecked[s.ID]) < walHeldEvery {
			return walArchiverSaid[s.ID] == ""
		}
		walHeldChecked[s.ID] = time.Now()
		u, err := walDBURL(ctx, c, s, st)
		if err != nil {
			return walArchiverSaid[s.ID] == ""
		}
		dbURL = u
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	ar, err := wal.ReadArchiver(pctx, dbURL)
	cancel()
	if err != nil {
		return true
	}
	now, before := "", walArchiverSaid[s.ID]
	if ar.Failing() {
		now = ar.LastFailed
	}
	if st != nil {
		w := walState(st)
		w.ArchiverFailing, w.ArchiverFailures = now, 0
		if now != "" {
			w.ArchiverFailures = ar.FailedCount
		}
	}
	if now != before {
		walArchiverSaid[s.ID] = now
		if now == "" {
			fmt.Printf("Surface %s: archive_command works again (last archived %s).\n", s.ID, ar.LastArchived)
		} else {
			last := "never"
			if !ar.ArchivedAt.IsZero() {
				last = ar.ArchivedAt.Format("2006-01-02 15:04 UTC")
			}
			fmt.Fprintf(os.Stderr, "Error: Surface %s: archive_command is failing on %s (%d failures; last archived %s). "+
				"PostgreSQL keeps every WAL file it cannot archive, so pg_wal grows until this is fixed or the disk is full. "+
				"PostgreSQL's log has the reason.\n", s.ID, ar.LastFailed, ar.FailedCount, last)
		}
	}
	return now == ""
}

// runWALWork takes the surface's base backup when one is due and bundles its
// WAL when that is due. It returns false when either failed; each failure
// is said, and tried again an hour later.
func runWALWork(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, st *SurfaceState, lockDir string, now time.Time) bool {
	baseEvery := walDays(s.WAL.BaseEveryDays)
	baseDue := now.Sub(st.WALLastBase) >= baseEvery && now.Sub(st.WALBaseFailedAt) >= walRetry
	bundleDue := now.Sub(st.WALLastBundle) >= walBundleEvery && now.Sub(st.WALBundleFailedAt) >= walRetry
	drillDue := walDrillDue(s, st, now)
	statusDue := now.Sub(st.WALCheckedAt) >= walStatusEvery
	if !baseDue && !bundleDue && !drillDue && !statusDue && now.Sub(walSizeChecked[s.ID]) < walSizeEvery {
		return true
	}
	release, err := acquireLock(filepath.Join(lockDir, s.ID+".wal.lock"), s.ID, "")
	if err != nil {
		return true // another process is at it
	}
	defer release()
	a, _, err := walArchive(ctx, c, s.ID, "")
	if err != nil {
		if baseDue || bundleDue {
			st.WALBaseFailedAt, st.WALBundleFailedAt = now, now
			fmt.Fprintf(os.Stderr, "Error: Surface %s: WAL archive: %v\n", s.ID, err)
			return false
		}
		return true
	}
	ok := true
	if !bundleDue && now.Sub(walSizeChecked[s.ID]) >= walSizeEvery {
		walSizeChecked[s.ID] = now
		bundleDue = walUnlockedBytes(ctx, a) >= int64(walBundleMB(s))<<20 && now.Sub(st.WALBundleFailedAt) >= walRetry
	}
	if bundleDue {
		walDaemonPoint(ctx, c, a, s, st)
		if err := walDaemonBundle(ctx, a); err != nil {
			st.WALBundleFailedAt = now
			fmt.Fprintf(os.Stderr, "Error: Surface %s: bundling WAL: %v. The daemon tries again in an hour.\n", s.ID, err)
			ok = false
		} else {
			st.WALLastBundle, st.WALBundleFailedAt = now, time.Time{}
		}
	}
	if baseDue {
		if err := walDaemonBase(ctx, c, a, s, st, now); err != nil {
			st.WALBaseFailedAt = now
			fmt.Fprintf(os.Stderr, "Error: Surface %s: base backup: %v. The daemon tries again in an hour.\n", s.ID, err)
			ok = false
		}
	}
	if drillDue {
		if sys, err := newestSystem(ctx, a); err == nil {
			a.SystemID = sys
			st.WALLastDrill = now
			fmt.Printf("Surface %s: point-in-time drill.\n", s.ID)
			d := runWALDrill(ctx, c, a, s, st, resolveStateDir("", c))
			walState(st).Drill = d
			sayWALDrill(s, d)
			if !d.Passed && d.Blocked == "" {
				ok = false
			}
		}
	}
	if bundleDue || baseDue || drillDue || statusDue {
		walRefreshStatus(ctx, a, st, now)
	}
	return ok
}

// walStatusEvery is how often the daemon reads the archive's window for the
// heartbeat when nothing else made it read the archive.
const walStatusEvery = time.Hour

// walState is the surface's WAL report, made when first needed.
func walState(st *SurfaceState) *model.WALStatus {
	if st.WAL == nil {
		st.WAL = &model.WALStatus{}
	}
	return st.WAL
}

// walReport is what the heartbeat says about the archive: nothing for a
// surface without one.
func walReport(s *config.SurfaceConfig, st *SurfaceState) *model.WALStatus {
	if s.WAL == nil || st == nil {
		return nil
	}
	return st.WAL
}

// walDrillDue says a point-in-time drill is due: every drill_every_days, and
// a day after one that failed or could not run.
func walDrillDue(s *config.SurfaceConfig, st *SurfaceState, now time.Time) bool {
	every := walDays(s.WAL.DrillEveryDays)
	if st.WAL != nil && st.WAL.Drill != nil && !st.WAL.Drill.Passed && every > 24*time.Hour {
		every = 24 * time.Hour
	}
	return now.Sub(st.WALLastDrill) >= every
}

// walRefreshStatus reads the newest cluster's window into the report.
func walRefreshStatus(ctx context.Context, a *wal.Archive, st *SurfaceState, now time.Time) {
	sys, err := newestSystem(ctx, a)
	if err != nil {
		return
	}
	a.SystemID = sys
	status, err := a.Status(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: could not read the WAL archive's window: %v\n", a.SurfaceID, err)
		return
	}
	st.WALCheckedAt = now
	w := walState(st)
	w.CheckedAt, w.WindowFrom, w.WindowTo, w.LockedTo, w.Gap = now, nil, nil, nil, ""
	if status.HasWindow {
		from, to := status.WindowFrom, status.WindowTo
		w.WindowFrom, w.WindowTo = &from, &to
	}
	if !status.LockedTo.IsZero() {
		locked := status.LockedTo
		w.LockedTo = &locked
	}
	if len(status.Gaps) > 0 {
		w.Gap = status.Gaps[0].First
	}
}

// walDaemonPoint marks a restore point before a bundle, so the bundle holds
// the WAL a drill replays to it. A role that may not create one is said
// once a day, with the grant, and the bundle goes ahead.
func walDaemonPoint(ctx context.Context, c *config.CLIConfig, a *wal.Archive, s *config.SurfaceConfig, st *SurfaceState) {
	sys, err := newestSystem(ctx, a)
	if err != nil {
		return
	}
	a.SystemID = sys
	dbURL, err := walDBURL(ctx, c, s, st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: no restore point before the bundle: %v\n", s.ID, err)
		return
	}
	rp, err := a.CreateRestorePoint(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: no restore point before the bundle: %v\n", s.ID, err)
		return
	}
	fmt.Printf("Surface %s: restore point %s, %d tables counted.\n", s.ID, rp.Name, len(rp.Tables))
}

func walBundleMB(s *config.SurfaceConfig) int {
	if s.WAL.BundleMB > 0 {
		return s.WAL.BundleMB
	}
	return 1024
}

// walUnlockedBytes is the size of the surface's unlocked WAL, every cluster
// together. A listing that fails counts as nothing; the daily bundle still
// comes.
func walUnlockedBytes(ctx context.Context, a *wal.Archive) int64 {
	systems, err := wal.Systems(ctx, a.Store, a.SurfaceID)
	if err != nil {
		return 0
	}
	var n int64
	for _, sys := range systems {
		a.SystemID = sys
		pushed, err := a.Pushed(ctx)
		if err != nil {
			return n
		}
		for _, p := range pushed {
			n += p.Size
		}
	}
	return n
}

// walDaemonBundle bundles every cluster's WAL. An archive nothing has been
// pushed to yet has nothing to bundle.
func walDaemonBundle(ctx context.Context, a *wal.Archive) error {
	systems, err := wal.Systems(ctx, a.Store, a.SurfaceID)
	if err != nil {
		return err
	}
	if len(systems) == 0 {
		return nil
	}
	fmt.Printf("Surface %s: bundling WAL.\n", a.SurfaceID)
	return walBundleAll(ctx, a, systems)
}

// walDaemonBase takes a base backup unless the archive already holds one
// newer than the interval: one taken by hand counts.
func walDaemonBase(ctx context.Context, c *config.CLIConfig, a *wal.Archive, s *config.SurfaceConfig, st *SurfaceState, now time.Time) error {
	if a.Recipient == "" {
		return errors.New("encryption.public_key is not set, and the base backup is encrypted to it")
	}
	connURL, srv, err := walServer(ctx, c, s)
	if err != nil {
		return err
	}
	a.SystemID = srv.SystemID
	bases, _, err := a.Bases(ctx)
	if err != nil {
		return err
	}
	if n := len(bases); n > 0 && now.Sub(bases[n-1].StartedAt) < walDays(s.WAL.BaseEveryDays) {
		st.WALLastBase, st.WALBaseFailedAt = bases[n-1].StartedAt, time.Time{}
		return nil
	}
	fmt.Printf("Surface %s: taking a base backup for its WAL archive.\n", s.ID)
	info, err := a.Base(ctx, wal.BaseOptions{ConnURL: connURL, Server: srv})
	if err != nil {
		return err
	}
	st.WALLastBase, st.WALBaseFailedAt = info.StartedAt, time.Time{}
	fmt.Printf("Base backup %s (%s, %s), %s\n", info.BaseID, formatBytes(info.StoredBytes),
		info.EndedAt.Sub(info.StartedAt).Round(time.Second), walLockLine(a, info.LockedUntil))
	return nil
}
