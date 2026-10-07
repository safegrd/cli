package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safegrd/cli/pkg/config"
)

// backupNamedSurface backs up one surface from the config now, whatever its
// schedule says, through the same path the daemon takes for it: the surface's
// own engine, storage, retention and held credential, its lock, and its record
// in the daemon's state, so a scheduled run that follows counts from this one.
// It is what an agent or a script asks for before changing one database on a
// host that protects several.
//
// A running daemon keeps its own copy of the state while it ticks, and may
// write over what this run saved. The worst that does is a scheduled backup
// sooner than it needed to be; the surface lock still keeps the two from
// backing up the same surface at once.
func backupNamedSurface(ctx context.Context, c *config.CLIConfig, surfaceID string, newEpoch, rescan bool) error {
	var surface *config.SurfaceConfig
	var ids []string
	for i := range c.Surfaces {
		ids = append(ids, c.Surfaces[i].ID)
		if c.Surfaces[i].ID == surfaceID {
			s := c.Surfaces[i]
			surface = &s
		}
	}
	if surface == nil {
		if len(ids) == 0 {
			return fmt.Errorf("--surface %s: this config defines no surfaces. Add one under surfaces:, or back up with --database-url or --files", surfaceID)
		}
		return fmt.Errorf("--surface %s: no surface with that id in this config. It has: %s", surfaceID, strings.Join(ids, ", "))
	}

	stateDir := resolveStateDir("", c)
	lockDir := filepath.Join(stateDir, "locks")
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return fmt.Errorf("failed to create the locks directory: %w", err)
	}
	statePath := filepath.Join(stateDir, "daemon_state.json")
	daemonState := loadDaemonState(statePath)
	sState, ok := daemonState.Surfaces[surface.ID]
	if !ok {
		sState = &SurfaceState{SurfaceID: surface.ID, SurfaceType: surface.Type}
		daemonState.Surfaces[surface.ID] = sState
	}

	surface.Schedule = effectiveSchedule(c, *surface)
	nodeID := surfaceNodeID(ctx, c, surface, sState, map[string]bool{})
	if nodeID == "" {
		warnIfStateUnsaved(saveDaemonState(statePath, daemonState), statePath)
		return fmt.Errorf("surface %s: %s", surface.ID, sState.Retired)
	}
	configured := *surface
	applyConsoleSettings(surface, &configured, sState)
	files := strings.EqualFold(surface.Type, "files")
	database := surface.Type == "" || strings.EqualFold(surface.Type, "postgres") || strings.EqualFold(surface.Type, "sqlite")
	if f, _ := fileFormat(surface.Format); (newEpoch || rescan) && (!(files || database) || f != formatRepo) {
		return fmt.Errorf("--new-epoch and --rescan apply to a surface with format: repo; %s is not one", surface.ID)
	}
	if rescan && !files {
		return fmt.Errorf("--rescan applies to a files surface: a database run reads every table")
	}
	sState.newEpoch, sState.rescan = newEpoch, rescan

	fmt.Printf("Surface %s (%s): backing up now.\n", surface.ID, surface.Type)
	fetchHeldSurfaceSecret(ctx, c, nodeID, surface)
	attempted := sState.LastAttempt
	if _, err := backupSurfaceNow(ctx, c, surface, sState, nodeID, lockDir, statePath, daemonState); err != nil {
		return err
	}
	// backupSurfaceNow skips a surface whose lock is held and returns nil,
	// which suits a daemon tick. Here the caller is about to change the
	// database on the strength of this backup, so a skip is a failure.
	if sState.LastAttempt.Equal(attempted) {
		return fmt.Errorf("surface %s was not backed up: another backup of it is running. Run this again when it finishes", surface.ID)
	}
	if sState.LastSnapshotID != "" {
		fmt.Printf("   Snapshot ID:     %s\n", sState.LastSnapshotID)
	}
	if sState.LastError != "" {
		// The backup is taken; what follows is about its report or its hook.
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: %s %s\n", surface.ID, sState.BackupReason.Words(), sState.LastError)
	}
	return nil
}

// surfaceForDatabaseURL is the configured surface that backs up the database
// url names, or nil. A surface whose URL comes from a credential block is not
// matched: it is named with --surface.
func surfaceForDatabaseURL(c *config.CLIConfig, url string) *config.SurfaceConfig {
	want, err := resolveConfigSecret("database-url", strings.TrimSpace(url))
	if err != nil || want == "" {
		return nil
	}
	for i := range c.Surfaces {
		s := c.Surfaces[i]
		if s.DatabaseURL == "" {
			continue
		}
		got, err := resolveConfigSecret("database_url", s.DatabaseURL)
		if err == nil && got == want {
			return &s
		}
	}
	return nil
}

// adhocDatabaseSurfaceID names the repository a database backup without
// --surface writes to. The config's own database_url is the surface the
// config loads it as (named after this host), which is what the daemon and
// guard back up: naming it after the URL instead gave one database two
// histories, each opening its own epoch and uploading everything. Any other
// database is named after its URL, so the same database always lands in
// the same repository.
func adhocDatabaseSurfaceID(c *config.CLIConfig) string {
	want := repoDatabaseSurfaceID(c.DatabaseURL)
	if len(c.Surfaces) == 1 && implicitSurface(c, &c.Surfaces[0]) {
		// Compared by host, port and database, as the repository is: the
		// URL in hand has been resolved and stripped of unsupported options.
		if got, err := resolveConfigSecret("database_url", c.Surfaces[0].DatabaseURL); err == nil && got != "" && repoDatabaseSurfaceID(got) == want {
			return c.Surfaces[0].ID
		}
	}
	return want
}

// implicitSurface reports whether s is the surface a config with a
// top-level database_url and no surfaces: list loads as.
func implicitSurface(c *config.CLIConfig, s *config.SurfaceConfig) bool {
	return s.ID == c.NodeID || (c.NodeID == "" && s.ID == "default-postgres")
}
