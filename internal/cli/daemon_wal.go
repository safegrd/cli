package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/safegrd/cli/pkg/config"
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
		held := *s
		node := s.ID
		if st != nil && st.ServerNodeID != "" {
			node = st.ServerNodeID
		}
		fetchHeldSurfaceSecret(ctx, c, node, &held)
		u, err := resolveSurfaceDatabaseURLAsGiven(ctx, c, &held)
		if err != nil || u == "" {
			return walArchiverSaid[s.ID] == ""
		}
		dbURL, _ = cleanPostgresURL(u)
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
	if !baseDue && !bundleDue && now.Sub(walSizeChecked[s.ID]) < walSizeEvery {
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
	return ok
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
