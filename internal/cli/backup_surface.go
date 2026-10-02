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
func backupNamedSurface(ctx context.Context, c *config.CLIConfig, surfaceID string) error {
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

	fmt.Printf("⏰ Surface %s (%s): backing up now.\n", surface.ID, surface.Type)
	fetchHeldSurfaceSecret(ctx, c, nodeID, surface)
	attempted := sState.LastAttempt
	if err := backupSurfaceNow(ctx, c, surface, sState, nodeID, lockDir, statePath, daemonState); err != nil {
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
		fmt.Fprintf(os.Stderr, "⚠️  Surface %s: %s\n", surface.ID, sState.LastError)
	}
	return nil
}
