package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

// SurfaceState tracks execution and schedule status per surface.
type SurfaceState struct {
	SurfaceID           string    `json:"surface_id"`
	SurfaceType         string    `json:"surface_type"`
	LastAttempt         time.Time `json:"last_attempt,omitempty"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
	LastSnapshotID      string    `json:"last_snapshot_id,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	NextDue             time.Time `json:"next_due,omitempty"`
	LastError           string    `json:"last_error,omitempty"`

	// The remote server's side. ServerNodeID is the child node
	// this surface reports as. LastBackupRequestID is the last console
	// "back up now" honoured, so a request is run once however many
	// heartbeats repeat it.
	ServerNodeID        string    `json:"server_node_id,omitempty"`
	LastBackupRequestID string    `json:"last_backup_request_id,omitempty"`
	DrillStatus         string    `json:"drill_status,omitempty"`
	LastDrillAttempt    time.Time `json:"last_drill_attempt,omitempty"`
	DrillFailures       int       `json:"drill_failures,omitempty"`
	LastDrillSnapshotID string    `json:"last_drill_snapshot_id,omitempty"`
	// DrillInFlight is saved before a drill starts and cleared when it ends.
	// Found set at the next start, the drill took the process down with it
	// (an out-of-memory kill, say) and counts as a failure — otherwise a
	// supervisor restart would start the same drill straight away, forever,
	// and the surfaces after it would never reach their backups.
	DrillInFlight bool `json:"drill_in_flight,omitempty"`
	// LastDailySlot, LastWeeklySlot and LastMonthlySlot are the UTC day
	// ("2026-09-24"), ISO week ("2026-W39") and month ("2026-09") whose
	// longer-lived backup has been taken (gfs.go).
	LastDailySlot   string `json:"last_daily_slot,omitempty"`
	LastWeeklySlot  string `json:"last_weekly_slot,omitempty"`
	LastMonthlySlot string `json:"last_monthly_slot,omitempty"`
}

// AgentState persists state across daemon ticks.
type AgentState struct {
	AgentID   string                   `json:"agent_id"`
	UpdatedAt time.Time                `json:"updated_at"`
	Surfaces  map[string]*SurfaceState `json:"surfaces"`
}

// LockInfo records in-flight execution to prevent concurrent runs.
type LockInfo struct {
	PID        int       `json:"pid"`
	StartTime  time.Time `json:"start_time"`
	SnapshotID string    `json:"snapshot_id"`
	SurfaceID  string    `json:"surface_id"`
}

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage the SafeGrd unattended always-on backup daemon",
		Long: `The SafeGrd Agent runs as a resident background service, monitoring
all configured surfaces (PostgreSQL, Files, IMAP Email) and performing
zero-knowledge WORM backups on their scheduled intervals without manual intervention.`,
	}

	cmd.AddCommand(newAgentRunCmd())
	cmd.AddCommand(newAgentStatusCmd())
	cmd.AddCommand(newAgentInstallCmd())
	cmd.AddCommand(newAgentUninstallCmd())
	cmd.AddCommand(newAgentRestartCmd())

	return cmd
}

func newAgentRunCmd() *cobra.Command {
	var (
		once        bool
		intervalStr string
		stateDir    string
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the resident backup daemon (or run once with --once)",
		Long: `Executes the unattended agent loop. Supervised by systemd or launchd,
evaluates due surfaces based on local state, acquires per-surface single-flight locks,
and performs streaming backups to immutable WORM storage.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-sigChan
				fmt.Println("\n🛑 Shutdown signal received. Finishing active tasks...")
				cancel()
			}()

			resolvedStateDir := resolveStateDir(stateDir, cfg)
			if err := os.MkdirAll(resolvedStateDir, 0700); err != nil {
				return fmt.Errorf("failed to create state directory: %w", err)
			}
			lockDir := filepath.Join(resolvedStateDir, "locks")
			if err := os.MkdirAll(lockDir, 0700); err != nil {
				return fmt.Errorf("failed to create locks directory: %w", err)
			}

			// Singleton agent process lock
			agentLockPath := filepath.Join(lockDir, "agent.lock")
			releaseAgentLock, err := acquireLock(agentLockPath, "agent", "")
			if err != nil {
				return fmt.Errorf("agent is already running: %w", err)
			}
			defer releaseAgentLock()

			fmt.Println("🛡️  SafeGrd Always-On Agent Started")
			fmt.Printf("   Configured Surfaces: %d\n", len(cfg.Surfaces))
			fmt.Printf("   State Directory:     %s\n", resolvedStateDir)
			// Said once, at start: an agent with no token reports nothing, and
			// an enrolled host that lost its token must not look the same as
			// one reporting fine.
			if !hostIsEnrolled(cfg) {
				fmt.Printf("   Remote Server:       not reporting (no server_token; standalone)\n")
			}
			if msg := unusedAlertBlock(cfg); msg != "" {
				fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg)
			}
			for _, msg := range ignoredConfigKeys(cfg) {
				fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg)
			}
			warnAboutSchedules(cfg)

			if len(cfg.Surfaces) == 0 {
				fmt.Println("ℹ️  No surfaces defined in config. Agent is idling.")
				if once {
					return nil
				}
			}

			// Surfaces registered with the remote server during this process:
			// once per start, so a config change reaches the
			// console on the next restart without re-registering every tick.
			registered := map[string]bool{}

			if once {
				// No tick: a cron-driven run must not look like a resident
				// agent, or it would be reported silent between runs and a
				// console "back up now" would wait for a daemon that does
				// not exist.
				return reconcileSurfaces(ctx, cfg, resolvedStateDir, 0, registered)
			}

			// Parse daemon poll interval
			interval := 5 * time.Minute
			if intervalStr != "" {
				if d, err := time.ParseDuration(intervalStr); err == nil && d > 0 {
					interval = d
				}
			} else if cfg.Agent.Interval != "" {
				if d, err := time.ParseDuration(cfg.Agent.Interval); err == nil && d > 0 {
					interval = d
				}
			}

			fmt.Printf("   Poll Interval:       %s (±10%% jitter)\n\n", interval)

			// Initial pass immediately
			if err := reconcileSurfaces(ctx, cfg, resolvedStateDir, interval, registered); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Error in initial reconciliation: %v\n", err)
			}

			for {
				// Apply ±10% jitter to avoid thundering herd against remote server / storage
				jitterFactor := 0.9 + rand.Float64()*0.2
				sleepDur := time.Duration(float64(interval) * jitterFactor)

				select {
				case <-ctx.Done():
					fmt.Println("Agent stopped gracefully.")
					return nil
				case <-time.After(sleepDur):
					if err := reconcileSurfaces(ctx, cfg, resolvedStateDir, interval, registered); err != nil {
						fmt.Fprintf(os.Stderr, "⚠️  Reconciliation error: %v\n", err)
					}
				}
			}
		},
	}

	cmd.Flags().BoolVar(&once, "once", false, "Execute a single reconciliation pass and exit (cron/k8s mode)")
	cmd.Flags().StringVar(&intervalStr, "interval", "", "Daemon poll interval (default: 5m)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "Path to state and locks directory")

	return cmd
}

func resolveStateDir(explicit string, c *config.CLIConfig) string {
	if explicit != "" {
		return explicit
	}
	if c.Agent.StateDir != "" {
		return c.Agent.StateDir
	}
	home, err := os.UserHomeDir()
	if err == nil {
		return filepath.Join(home, ".safegrd")
	}
	return "/var/lib/safegrd"
}

func loadAgentState(statePath string) *AgentState {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return &AgentState{
			AgentID:   uuid.New().String()[:8],
			UpdatedAt: time.Now().UTC(),
			Surfaces:  make(map[string]*SurfaceState),
		}
	}
	var state AgentState
	if err := json.Unmarshal(data, &state); err != nil {
		return &AgentState{
			AgentID:   uuid.New().String()[:8],
			UpdatedAt: time.Now().UTC(),
			Surfaces:  make(map[string]*SurfaceState),
		}
	}
	if state.Surfaces == nil {
		state.Surfaces = make(map[string]*SurfaceState)
	}
	return &state
}

func saveAgentState(statePath string, state *AgentState) error {
	state.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmpFile := fmt.Sprintf("%s.tmp.%d", statePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpFile, statePath)
}

func isPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 checks process existence without killing it on Unix
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

func acquireLock(lockPath, surfaceID, snapshotID string) (func(), error) {
	if data, err := os.ReadFile(lockPath); err == nil {
		var lock LockInfo
		if jsonErr := json.Unmarshal(data, &lock); jsonErr == nil {
			// Check for stale lock (PID is dead or lock > 2h old)
			if !isPIDAlive(lock.PID) || time.Since(lock.StartTime) > 2*time.Hour {
				fmt.Fprintf(os.Stderr, "⚠️  Reclaiming stale lock for surface %s (previous PID %d dead or timed out)\n", surfaceID, lock.PID)
				_ = os.Remove(lockPath)
			} else {
				return nil, fmt.Errorf("surface %s backup is already in-progress by PID %d (started %s)", surfaceID, lock.PID, lock.StartTime.Format(time.RFC3339))
			}
		}
	}

	info := LockInfo{
		PID:        os.Getpid(),
		StartTime:  time.Now().UTC(),
		SnapshotID: snapshotID,
		SurfaceID:  surfaceID,
	}
	data, _ := json.Marshal(info)
	if err := os.WriteFile(lockPath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write lockfile %s: %w", lockPath, err)
	}

	return func() {
		_ = os.Remove(lockPath)
	}, nil
}

// effectiveSchedule is the schedule a surface actually runs on: its own, or the
// config's defaults.schedule when it names none. The defaults block was
// documented as inherited and was not — a surface with no schedule of its own
// ran daily whatever the defaults said.
func effectiveSchedule(c *config.CLIConfig, s config.SurfaceConfig) string {
	if strings.TrimSpace(s.Schedule) == "" && c != nil {
		return c.Defaults.Schedule
	}
	return s.Schedule
}

// warnAboutSchedules says out loud, once per agent start, every surface whose
// schedule the agent will not run as written. The agent still protects the
// surface — at the floor, or daily — because refusing over a typo would leave
// it unprotected; but a substitution nobody is told about is how a host ends
// up on a cadence its operator never chose.
func warnAboutSchedules(c *config.CLIConfig) {
	for _, s := range c.Surfaces {
		sched := effectiveSchedule(c, s)
		if interval, err := model.ScheduleInterval(sched); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Surface %s: %v.\n   Backing it up every %s instead. Fix the schedule and run 'safegrd config validate'.\n",
				s.ID, err, model.ShortDuration(interval))
		}
	}
}

// warnIfStateUnsaved says out loud that the agent could not record what it did.
//
// Both saves were `_ =`. The state file is what tells the next tick a surface
// was backed up, so a save that fails silently makes every surface look
// never-backed-up on every tick: a backup every five minutes, each one an
// object Object Lock will not let anyone delete. That is the retention blowout
// the schedule floor closes, arriving by another door.
func warnIfStateUnsaved(err error, path string) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "❌ Could not save agent state to %s: %v\n"+
		"   The next tick will not know this run happened and will back up again.\n", path, err)
}

func isSurfaceDue(s *config.SurfaceConfig, state *SurfaceState, now time.Time) (bool, time.Time) {
	// The problem, if any, is reported once at agent start by
	// warnAboutSchedules rather than on every tick.
	interval, _ := model.ScheduleInterval(s.Schedule)

	// Exponential backoff if consecutive failures exist: 5m, 10m, 20m, 40m, max 1h
	if state.ConsecutiveFailures > 0 && !state.LastAttempt.IsZero() {
		backoffMult := 1 << min(state.ConsecutiveFailures-1, 4) // up to 16 * 5m = 80m clamped to 1h
		backoff := time.Duration(backoffMult) * 5 * time.Minute
		if backoff > time.Hour {
			backoff = time.Hour
		}
		retryAt := state.LastAttempt.Add(backoff)
		if now.Before(retryAt) {
			return false, retryAt
		}
	}

	// Never backed up -> due immediately
	if state.LastSuccess.IsZero() {
		return true, now
	}

	nextDue := state.LastSuccess.Add(interval)
	return now.After(nextDue) || now.Equal(nextDue), nextDue
}

func reconcileSurfaces(ctx context.Context, c *config.CLIConfig, stateDir string, tick time.Duration, registered map[string]bool) error {
	statePath := filepath.Join(stateDir, "agent_state.json")
	lockDir := filepath.Join(stateDir, "locks")
	agentState := loadAgentState(statePath)
	now := time.Now().UTC()

	var hasErrors bool
	var drills []pendingDrill

	// A drill still marked in flight took the last process down with it.
	for _, st := range agentState.Surfaces {
		if st.DrillInFlight {
			st.DrillInFlight = false
			st.DrillFailures++
			st.DrillStatus = model.DrillStatusFailed
			fmt.Fprintf(os.Stderr, "❌ Surface %s: the last Fire Drill did not finish — the agent stopped during it. "+
				"Counted as a failure; the next is at least %s away.\n", st.SurfaceID, drillBackoff(st.DrillFailures))
		}
	}

	for _, surface := range c.Surfaces {
		if surface.ID == "" {
			continue
		}

		sState, exists := agentState.Surfaces[surface.ID]
		if !exists {
			sState = &SurfaceState{
				SurfaceID:   surface.ID,
				SurfaceType: surface.Type,
			}
			agentState.Surfaces[surface.ID] = sState
		}

		surface.Schedule = effectiveSchedule(c, surface)
		nodeID := surfaceNodeID(ctx, c, &surface, sState, registered)
		hb := sendHeartbeat(ctx, c, nodeID, sState, tick)

		due, nextDue := isSurfaceDue(&surface, sState, now)
		sState.NextDue = nextDue

		// A console "back up now" is run once, by its id. TriggerBackup is
		// deliberately not read: it is true whenever the remote server has
		// not heard of a recent success, and obeying it would back up on
		// every tick whenever a report failed.
		requested := hb != nil && hb.BackupRequestID != "" && hb.BackupRequestID != sState.LastBackupRequestID
		if requested {
			sState.LastBackupRequestID = hb.BackupRequestID
		}

		if due || requested {
			if requested && !due {
				fmt.Printf("⏰ Surface %s (%s): backup requested from the console.\n", surface.ID, surface.Type)
			} else {
				fmt.Printf("⏰ Surface %s (%s) is due for backup.\n", surface.ID, surface.Type)
			}
			if err := backupSurfaceNow(ctx, c, &surface, sState, nodeID, lockDir, statePath, agentState); err != nil {
				hasErrors = true
			}
		}

		// Fire Drills are decided by the remote server from the plan, never
		// by the host. Not due clears a stale "no key". Drills
		// run after every surface's backup, so a long drill of one surface
		// never delays another's backup.
		if hb != nil {
			if hb.TriggerFireDrill && hb.DrillSnapshotID != "" {
				s := surface
				drills = append(drills, pendingDrill{surface: &s, state: sState, nodeID: nodeID, snapshotID: hb.DrillSnapshotID})
			} else if sState.DrillStatus == model.DrillStatusNoKey {
				sState.DrillStatus = ""
			}
		}
		warnIfStateUnsaved(saveAgentState(statePath, agentState), statePath)
	}

	for _, d := range drills {
		if ctx.Err() != nil {
			break
		}
		runUnattendedDrill(ctx, c, d.surface, d.state, d.nodeID, d.snapshotID, func() {
			warnIfStateUnsaved(saveAgentState(statePath, agentState), statePath)
		})
	}

	warnIfStateUnsaved(saveAgentState(statePath, agentState), statePath)

	if hasErrors {
		return fmt.Errorf("one or more surface backups failed during reconciliation")
	}
	return nil
}

// backupSurfaceNow runs one surface's backup under its lock and records the
// outcome in the agent's state. It returns the backup's error, if any.
func backupSurfaceNow(ctx context.Context, c *config.CLIConfig, surface *config.SurfaceConfig, sState *SurfaceState,
	nodeID, lockDir, statePath string, agentState *AgentState) error {
	now := time.Now().UTC()

	// Acquire single-flight surface lock
	surfaceLockPath := filepath.Join(lockDir, fmt.Sprintf("%s.lock", surface.ID))
	releaseLock, err := acquireLock(surfaceLockPath, surface.ID, "")
	if err != nil {
		fmt.Printf("   Skipping %s: %v\n", surface.ID, err)
		return nil
	}

	sState.LastAttempt = now
	var (
		meta      *model.SnapshotMetadata
		plan      retentionPlan
		backupErr error
		postErr   error
	)
	// pre_backup must succeed for the backup to run: a hook that was meant to
	// quiesce the application and did not would make a backup of a moving
	// target, which is the thing the hook exists to prevent.
	if surface.PreBackup != "" {
		if err := runHook(ctx, surface, "pre_backup", surface.PreBackup); err != nil {
			backupErr = fmt.Errorf("not backed up: %w", err)
		}
	}
	if backupErr == nil {
		meta, plan, backupErr = runSurfaceBackup(ctx, c, surface, nodeID, sState)
	}
	// post_backup runs after every attempt, so whatever pre_backup paused is
	// resumed even when the backup fails. Its failure does not undo a backup
	// that was taken, but it is said out loud.
	if surface.PostBackup != "" {
		status, snapID := "success", ""
		if backupErr != nil {
			status = "failed"
		}
		if meta != nil {
			snapID = meta.SnapshotID
		}
		postErr = runHook(ctx, surface, "post_backup", surface.PostBackup,
			"SAFEGRD_BACKUP_STATUS="+status, "SAFEGRD_SNAPSHOT_ID="+snapID)
		if postErr != nil {
			fmt.Fprintf(os.Stderr, "❌ Surface %s: %v\n", surface.ID, postErr)
		}
	}
	releaseLock()

	if backupErr != nil {
		sState.ConsecutiveFailures++
		sState.LastError = backupErr.Error()
		fmt.Fprintf(os.Stderr, "❌ Surface %s backup failed: %v\n", surface.ID, backupErr)
	} else {
		sState.ConsecutiveFailures = 0
		sState.LastError = ""
		// The backup is taken; a post_backup that failed is still reported,
		// since it may have left the application paused.
		if postErr != nil {
			sState.LastError = "post_backup: " + postErr.Error()
		}
		sState.LastSuccess = time.Now().UTC()
		if meta != nil {
			sState.LastSnapshotID = meta.SnapshotID
		}
		plan.record(sState)
		fmt.Printf("✅ Surface %s backup completed successfully.\n", surface.ID)
	}
	// Recomputed from the attempt just made. It kept the value from before
	// the backup — "due now" — so `agent status` reported a surface as due
	// the moment it had succeeded, which is the one field a monitor reads.
	_, sState.NextDue = isSurfaceDue(surface, sState, time.Now().UTC())

	warnIfStateUnsaved(saveAgentState(statePath, agentState), statePath)
	return backupErr
}

// runSurfaceBackup backs one surface up and reports it as nodeID — the child
// node the remote server assigned, or the surface's own id without one. The
// snapshot is written under the same id, so the node a restore finds on the
// remote server's record is the prefix it looks under.
func runSurfaceBackup(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string, st *SurfaceState) (*model.SnapshotMetadata, retentionPlan, error) {
	var plan retentionPlan
	storageCfg := c.Storage
	if s.Storage != nil {
		storageCfg = *s.Storage
	}
	if nodeID != "" && storageCfg.NodeID == "" {
		storageCfg.NodeID = nodeID
	}
	if s.RetentionDays > 0 {
		storageCfg.RetentionDays = s.RetentionDays
	} else if storageCfg.RetentionDays == 0 && c.Defaults.RetentionDays > 0 {
		storageCfg.RetentionDays = c.Defaults.RetentionDays
	}
	// Hosted storage: a write lease, refused when the organization is full.
	lease, err := resolveHostedStorage(ctx, c, &storageCfg, true)
	if err != nil {
		return nil, plan, err
	}

	storageProvider, err := storage.NewProvider(ctx, storageCfg)
	if err != nil {
		return nil, plan, fmt.Errorf("storage provider init failed: %w", err)
	}

	pubKey := c.Encryption.PublicKey
	if s.Encryption != nil && s.Encryption.PublicKey != "" {
		pubKey = s.Encryption.PublicKey
	}
	if pubKey == "" {
		return nil, plan, fmt.Errorf("encryption public key missing for surface %s", s.ID)
	}

	snapshotID := fmt.Sprintf("snap-%s-%s", time.Now().UTC().Format("20060102-150405"), uuid.New().String()[:6])
	tiers := gfsTiers(c, s)
	if tiers == (gfs{}) {
		// On hosted storage the plan's tiers apply where the config sets none,
		// so a typical estate fits its quota.
		tiers = lease.gfs()
	}
	plan = planRetention(time.Now(), storageCfg.RetentionDays, tiers, st)
	retentionUntil := plan.Until
	// Under worm_mode NONE nothing is locked, so no tier is claimed either.
	if plan.Tier != "base" && storageCfg.WORMMode != config.WORMModeNone {
		fmt.Printf("   Surface %s: this is the %s backup, locked until %s\n", s.ID, plan.Tier, retentionUntil.UTC().Format("2006-01-02"))
	}

	switch strings.ToLower(s.Type) {
	case "files":
		roots := s.Roots
		if len(roots) == 0 {
			return nil, plan, fmt.Errorf("surface %s has no root paths specified", s.ID)
		}
		started := time.Now()
		collector := dump.NewFileCollector(dump.FileCollectorConfig{
			RootDir:  roots[0],
			Excludes: s.Excludes,
		})
		rawStream, meta, err := collector.ScanAndStream(ctx)
		// What the walk left out is said out loud, even when the backup succeeds.
		warnSkipped(collector.Skipped())
		if err != nil {
			return nil, plan, fmt.Errorf("file collection failed: %w", err)
		}

		cipherReader, cipherWriter := io.Pipe()
		metricsChan := make(chan *crypto.StreamMetrics, 1)
		errChan := make(chan error, 1)

		go func() {
			m, encErr := crypto.EncryptStream(rawStream, cipherWriter, pubKey)
			if encErr != nil {
				_ = cipherWriter.CloseWithError(encErr)
				errChan <- encErr
				return
			}
			_ = cipherWriter.Close()
			metricsChan <- m
		}()

		storageURI, err := storageProvider.UploadSnapshot(ctx, snapshotID, cipherReader, -1, retentionUntil)
		if err != nil {
			return nil, plan, fmt.Errorf("storage upload failed: %w", err)
		}
		metrics := <-metricsChan

		meta.SnapshotID = snapshotID
		meta.NodeID = nodeID
		meta.StorageURI = storageURI
		now := time.Now().UTC()
		meta.CompletedAt = &now
		meta.DurationMs = now.Sub(started).Milliseconds()
		meta.Status = model.SnapshotStatusCompleted
		recordRetention(meta, storageCfg, retentionUntil)
		meta.RawSizeBytes = metrics.RawBytes
		meta.EncryptedSizeBytes = metrics.EncryptedBytes
		meta.Sha256Checksum = metrics.RawSha256
		meta.EncryptedSha256 = metrics.EncryptedSha256
		meta.CalculateTotals()

		warnIfManifestFailed(storageProvider.UploadMetadata(ctx, snapshotID, meta), snapshotID)
		if hostIsEnrolled(c) {
			sendMetadataToServer(ctx, c.ServerURL, c.ServerToken, meta, false)
		}
		return meta, plan, nil

	case "email":
		host := s.Host
		if host == "" {
			host = "imap.gmail.com"
		}
		port := s.Port
		if port == 0 {
			port = 993
		}
		user := s.Username
		pass, err := surfaceEmailPassword(ctx, s)
		if err != nil {
			return nil, plan, err
		}
		if user == "" || pass == "" {
			return nil, plan, fmt.Errorf("email credentials unresolved for surface %s", s.ID)
		}

		// The same private-CA trust `backup --email-ca-file` has: without it a
		// self-hosted mailbox could be backed up by hand and never by the agent.
		tlsCfg, err := emailTLSConfig(host, os.Getenv("SAFEGRD_EMAIL_CA_FILE"))
		if err != nil {
			return nil, plan, fmt.Errorf("surface %s: %w", s.ID, err)
		}

		started := time.Now()
		collector := dump.NewEmailCollector(dump.EmailCollectorConfig{
			Host:           host,
			Port:           port,
			Username:       user,
			Password:       pass,
			IncludeFolders: s.Folders,
			ExcludeFolders: []string{"[Gmail]/Spam", "[Gmail]/Trash"},
			TLSConfig:      tlsCfg,
		})
		rawStream, meta, err := collector.ScanAndStream(ctx, nil)
		if err != nil {
			return nil, plan, fmt.Errorf("email collection failed: %w", err)
		}

		cipherReader, cipherWriter := io.Pipe()
		metricsChan := make(chan *crypto.StreamMetrics, 1)
		errChan := make(chan error, 1)

		go func() {
			m, encErr := crypto.EncryptStream(rawStream, cipherWriter, pubKey)
			if encErr != nil {
				_ = cipherWriter.CloseWithError(encErr)
				errChan <- encErr
				return
			}
			_ = cipherWriter.Close()
			metricsChan <- m
		}()

		storageURI, err := storageProvider.UploadSnapshot(ctx, snapshotID, cipherReader, -1, retentionUntil)
		if err != nil {
			return nil, plan, fmt.Errorf("storage upload failed: %w", err)
		}
		metrics := <-metricsChan

		meta.SnapshotID = snapshotID
		meta.NodeID = nodeID
		meta.StorageURI = storageURI
		now := time.Now().UTC()
		meta.CompletedAt = &now
		meta.DurationMs = now.Sub(started).Milliseconds()
		meta.Status = model.SnapshotStatusCompleted
		recordRetention(meta, storageCfg, retentionUntil)
		meta.RawSizeBytes = metrics.RawBytes
		meta.EncryptedSizeBytes = metrics.EncryptedBytes
		meta.Sha256Checksum = metrics.RawSha256
		meta.EncryptedSha256 = metrics.EncryptedSha256
		meta.CalculateTotals()

		warnIfManifestFailed(storageProvider.UploadMetadata(ctx, snapshotID, meta), snapshotID)
		if hostIsEnrolled(c) {
			sendMetadataToServer(ctx, c.ServerURL, c.ServerToken, meta, false)
		}
		return meta, plan, nil

	default: // "postgres"
		dbURL, err := resolveSurfaceDatabaseURL(ctx, c, s)
		if err != nil {
			return nil, plan, err
		}
		if dbURL == "" {
			return nil, plan, fmt.Errorf("database URL unresolved for surface %s", s.ID)
		}

		dumper := dump.NewDumper(dump.EngineTypeNative, dbURL)
		dumpReader, dumpWriter := io.Pipe()
		cipherReader, cipherWriter := io.Pipe()

		metaChan := make(chan *model.SnapshotMetadata, 1)
		dumpErrChan := make(chan error, 1)
		go func() {
			m, dumpErr := dumper.Dump(ctx, "", dumpWriter)
			if dumpErr != nil {
				_ = dumpWriter.CloseWithError(dumpErr)
				dumpErrChan <- dumpErr
				return
			}
			_ = dumpWriter.Close()
			metaChan <- m
		}()

		metricsChan := make(chan *crypto.StreamMetrics, 1)
		encErrChan := make(chan error, 1)
		go func() {
			m, encErr := crypto.EncryptStream(dumpReader, cipherWriter, pubKey)
			if encErr != nil {
				_ = cipherWriter.CloseWithError(encErr)
				encErrChan <- encErr
				return
			}
			_ = cipherWriter.Close()
			metricsChan <- m
		}()

		storageURI, err := storageProvider.UploadSnapshot(ctx, snapshotID, cipherReader, -1, retentionUntil)
		if err != nil {
			return nil, plan, fmt.Errorf("storage upload failed: %w", err)
		}

		var dumpMeta *model.SnapshotMetadata
		select {
		case dumpErr := <-dumpErrChan:
			return nil, plan, fmt.Errorf("database dump failed: %w", dumpErr)
		case dumpMeta = <-metaChan:
		}

		var metrics *crypto.StreamMetrics
		select {
		case encErr := <-encErrChan:
			return nil, plan, fmt.Errorf("encryption failed: %w", encErr)
		case metrics = <-metricsChan:
		}

		dumpMeta.SnapshotID = snapshotID
		dumpMeta.NodeID = nodeID
		dumpMeta.StorageURI = storageURI
		now := time.Now().UTC()
		if dumpMeta.CreatedAt.IsZero() {
			dumpMeta.CreatedAt = now
		}
		dumpMeta.CompletedAt = &now
		dumpMeta.Status = model.SnapshotStatusCompleted
		recordRetention(dumpMeta, storageCfg, retentionUntil)
		dumpMeta.RawSizeBytes = metrics.RawBytes
		dumpMeta.EncryptedSizeBytes = metrics.EncryptedBytes
		dumpMeta.Sha256Checksum = metrics.RawSha256
		dumpMeta.EncryptedSha256 = metrics.EncryptedSha256
		dumpMeta.CalculateTotals()

		warnIfManifestFailed(storageProvider.UploadMetadata(ctx, snapshotID, dumpMeta), snapshotID)
		if hostIsEnrolled(c) {
			sendMetadataToServer(ctx, c.ServerURL, c.ServerToken, dumpMeta, false)
		}
		return dumpMeta, plan, nil
	}
}

func newAgentStatusCmd() *cobra.Command {
	var (
		jsonOut  bool
		stateDir string
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "View live status of all configured surfaces and the agent daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedStateDir := resolveStateDir(stateDir, cfg)
			statePath := filepath.Join(resolvedStateDir, "agent_state.json")
			agentState := loadAgentState(statePath)

			// last_success and next_due are what the table prints — "Never",
			// "Due now", a local-looking stamp — and they stay that way,
			// because that is what an operator reading the table expects.
			//
			// The *_at pair beside them is RFC3339 or absent, and it exists
			// because this is the agent's only machine-readable surface. A
			// monitor cannot answer "when did this host last back up" from the
			// word "Never": a host that has stopped being protected and a host
			// that never started look identical. That is the same failure the
			// reporting paths had — a thing that is wrong and does not say so —
			// one layer out, in the surface built for the thing that would say
			// it.
			type SurfaceStatusView struct {
				ID            string `json:"id"`
				Type          string `json:"type"`
				Schedule      string `json:"schedule"`
				LastSuccess   string `json:"last_success"`
				LastSuccessAt string `json:"last_success_at,omitempty"`
				NextDue       string `json:"next_due"`
				NextDueAt     string `json:"next_due_at,omitempty"`
				Failures      int    `json:"consecutive_failures"`
				Status        string `json:"status"`
				LastSnapshot  string `json:"last_snapshot_id,omitempty"`
				LastError     string `json:"last_error,omitempty"`
				// ScheduleProblem is set when the agent is not running the
				// schedule as written — clamped to the floor, or unreadable
				// and run daily — so a monitor reading only JSON is told.
				ScheduleProblem string `json:"schedule_problem,omitempty"`
			}

			views := make([]SurfaceStatusView, 0, len(cfg.Surfaces))
			for _, s := range cfg.Surfaces {
				st, ok := agentState.Surfaces[s.ID]
				lastSucc := "Never"
				lastSuccAt := ""
				nextDueStr := "Due now"
				nextDueAt := ""
				failures := 0
				lastSnap := ""
				lastErr := ""
				status := "OK"

				if ok && st != nil {
					if !st.LastSuccess.IsZero() {
						lastSucc = st.LastSuccess.Format("2006-01-02 15:04:05")
						lastSuccAt = st.LastSuccess.UTC().Format(time.RFC3339)
					}
					if !st.NextDue.IsZero() {
						nextDueAt = st.NextDue.UTC().Format(time.RFC3339)
						if time.Now().UTC().After(st.NextDue) {
							nextDueStr = "Due now"
						} else {
							nextDueStr = st.NextDue.Format("2006-01-02 15:04:05")
						}
					}
					failures = st.ConsecutiveFailures
					lastSnap = st.LastSnapshotID
					lastErr = st.LastError
					if failures > 0 {
						status = fmt.Sprintf("FAILED (%d)", failures)
					}
				}

				sched := effectiveSchedule(cfg, s)
				schedProblem := ""
				if _, err := model.ScheduleInterval(sched); err != nil {
					schedProblem = err.Error()
				}

				views = append(views, SurfaceStatusView{
					ScheduleProblem: schedProblem,
					ID:              s.ID,
					Type:            s.Type,
					Schedule:        sched,
					LastSuccess:     lastSucc,
					LastSuccessAt:   lastSuccAt,
					NextDue:         nextDueStr,
					NextDueAt:       nextDueAt,
					Failures:        failures,
					Status:          status,
					LastSnapshot:    lastSnap,
					LastError:       lastErr,
				})
			}

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"agent_id":  agentState.AgentID,
					"surfaces":  views,
					"state_dir": resolvedStateDir,
				})
			}

			fmt.Println("🛡️  SafeGrd Always-On Agent Status")
			fmt.Printf("   Agent ID:    %s\n", agentState.AgentID)
			fmt.Printf("   State Dir:   %s\n\n", resolvedStateDir)

			if len(views) == 0 {
				fmt.Println("No surfaces configured in config.yaml.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "SURFACE ID\tTYPE\tSCHEDULE\tLAST SUCCESS\tNEXT DUE\tSTATUS")
			for _, v := range views {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					v.ID, v.Type, v.Schedule, v.LastSuccess, v.NextDue, v.Status)
			}
			w.Flush()
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output status as JSON")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "Path to state directory")

	return cmd
}

func newAgentInstallCmd() *cobra.Command {
	var (
		printOnly bool
		userScope bool
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Generate or install SafeGrd system service (systemd / launchd)",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := agentServiceSpec(userScope)
			if err != nil {
				return err
			}

			var body, targetPath string
			if runtime.GOOS == "darwin" {
				body, targetPath = launchdPlist(svc), launchdPath(userScope)
			} else {
				body, targetPath = systemdUnit(svc, userScope), systemdPath(userScope)
			}
			if printOnly {
				fmt.Print(body)
				return nil
			}
			if targetPath == "" {
				return fmt.Errorf("could not work out where to install the service: no home directory")
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create %s: %w", filepath.Dir(targetPath), err)
			}
			// The service's filesystem is read-only except for these, so the
			// agent cannot create them itself. Made now, owned by whoever owns
			// the config, so the same person's own safegrd commands can write
			// there too.
			for _, w := range svc.writable {
				if _, err := os.Stat(w); err == nil {
					continue
				}
				if err := os.MkdirAll(w, 0700); err != nil {
					return fmt.Errorf("failed to create %s, which the agent writes to: %w", w, err)
				}
				if err := chownLike(w, svc.configPath); err != nil {
					fmt.Fprintf(os.Stderr, "[!] Created %s but could not give it to the config's owner: %v\n", w, err)
				}
			}
			if err := os.WriteFile(targetPath, []byte(body), 0644); err != nil {
				return fmt.Errorf("failed to write the service file %s (try sudo, or --user): %w", targetPath, err)
			}

			fmt.Printf("✅ Installed %s\n", targetPath)
			fmt.Printf("   Config:     %s\n   State:      %s\n", svc.configPath, svc.stateDir)
			switch {
			case runtime.GOOS == "darwin":
				fmt.Printf("   To activate:\n   launchctl load %s\n", targetPath)
			case userScope:
				fmt.Println("   To activate:\n   systemctl --user daemon-reload && systemctl --user enable --now safegrd")
				fmt.Println("   To keep it running after you log out:\n   loginctl enable-linger $USER")
			default:
				fmt.Println("   To activate:\n   sudo systemctl daemon-reload && sudo systemctl enable --now safegrd")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&printOnly, "print", false, "Print service definition to stdout without installing")
	cmd.Flags().BoolVar(&userScope, "user", false, "Install as user agent instead of system service")

	return cmd
}

// agentService is what a service definition needs to run the agent exactly
// as `safegrd agent run` runs here: the same binary, config and state.
type agentService struct {
	exe, configPath, stateDir, home string
	writable                        []string
}

// agentServiceSpec resolves the paths a service definition names, all
// absolute. The unit used to run "safegrd agent run" with no --config, so a
// system service looked for /root/.safegrd/config.yaml instead of the config
// of the person who enrolled, and with ProtectSystem=strict and no
// ReadWritePaths it could not write its own state.
func agentServiceSpec(userScope bool) (agentService, error) {
	exe, err := os.Executable()
	if err != nil {
		return agentService{}, fmt.Errorf("cannot find the safegrd binary to run: %w", err)
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	configPath := cfgFile
	if configPath == "" {
		if configPath, err = config.DefaultConfigFile(); err != nil {
			return agentService{}, fmt.Errorf("cannot find the config to run with: %w", err)
		}
	}
	if configPath, err = filepath.Abs(configPath); err != nil {
		return agentService{}, err
	}
	if _, err := os.Stat(configPath); err != nil {
		return agentService{}, fmt.Errorf("the service would run with %s, which cannot be read (%v); run 'safegrd enroll' or pass --config", configPath, err)
	}
	stateDir, err := filepath.Abs(resolveStateDir("", cfg))
	if err != nil {
		return agentService{}, err
	}
	home, _ := os.UserHomeDir()
	svc := agentService{exe: exe, configPath: configPath, stateDir: stateDir, home: home, writable: []string{stateDir}}
	// A local sink is written to by the agent, so it must be writable under
	// the unit's read-only filesystem too.
	addLocal := func(sc config.StorageConfig) {
		if sc.Type == config.StorageTypeLocal && sc.LocalPath != "" {
			if abs, err := filepath.Abs(sc.LocalPath); err == nil {
				svc.writable = append(svc.writable, abs)
			}
		}
	}
	addLocal(cfg.Storage)
	for _, s := range cfg.Surfaces {
		if s.Storage != nil {
			addLocal(*s.Storage)
		}
	}
	return svc, nil
}

func (s agentService) args() []string {
	return []string{s.exe, "--config", s.configPath, "agent", "run", "--state-dir", s.stateDir}
}

func systemdPath(userScope bool) string {
	if !userScope {
		return "/etc/systemd/system/safegrd.service"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config/systemd/user/safegrd.service")
}

func launchdPath(userScope bool) string {
	if !userScope {
		return "/Library/LaunchDaemons/dev.safegrd.agent.plist"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library/LaunchAgents/dev.safegrd.agent.plist")
}

// systemdUnit is a unit for this host. A system unit keeps the hardening and
// names every path the agent writes; a user unit cannot use ProtectSystem, and
// is wanted by default.target — multi-user.target does not exist in a user
// manager, so a user unit enabled against it never started.
func systemdUnit(s agentService, userScope bool) string {
	quoted := make([]string, 0, 7)
	for _, a := range s.args() {
		quoted = append(quoted, systemdQuote(a))
	}
	var b strings.Builder
	b.WriteString("[Unit]\nDescription=SafeGrd backup agent\n")
	if !userScope {
		b.WriteString("Wants=network-online.target\nAfter=network-online.target\n")
	}
	b.WriteString("\n[Service]\nType=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s\n", strings.Join(quoted, " "))
	b.WriteString("Restart=on-failure\nRestartSec=10\nNoNewPrivileges=true\n")
	if s.home != "" {
		fmt.Fprintf(&b, "Environment=%s\n", systemdQuote("HOME="+s.home))
	}
	if !userScope {
		// The filesystem is read-only to the agent except for what it
		// writes: its state and locks, and a local sink if it has one.
		b.WriteString("ProtectSystem=strict\nPrivateTmp=true\n")
		// "-": a path that does not exist is skipped rather than failing the
		// unit. Without it systemd refused to start the service at all
		// (226/NAMESPACE) when a local sink had not been written to yet —
		// found by running the unit under real systemd.
		for _, w := range s.writable {
			fmt.Fprintf(&b, "ReadWritePaths=-%s\n", systemdQuote(w))
		}
	}
	b.WriteString("\n[Install]\n")
	if userScope {
		b.WriteString("WantedBy=default.target\n")
	} else {
		b.WriteString("WantedBy=multi-user.target\n")
	}
	return b.String()
}

func systemdQuote(v string) string {
	if !strings.ContainsAny(v, " \t\"'\\") {
		return v
	}
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(v) + "\""
}

// launchdPlist logs beside the state rather than to /tmp, where the log was
// readable by every user on the machine.
func launchdPlist(s agentService) string {
	var args strings.Builder
	for _, a := range s.args() {
		fmt.Fprintf(&args, "        <string>%s</string>\n", html.EscapeString(a))
	}
	logPath := html.EscapeString(filepath.Join(s.stateDir, "agent.log"))
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.safegrd.agent</string>
    <key>ProgramArguments</key>
    <array>
%s    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
</dict>
</plist>
`, args.String(), logPath, logPath)
}

func newAgentUninstallCmd() *cobra.Command {
	var userScope bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall and disable the SafeGrd system service",
		RunE: func(cmd *cobra.Command, args []string) error {
			targetPath, stop := systemdPath(userScope), "sudo systemctl disable --now safegrd"
			if userScope {
				stop = "systemctl --user disable --now safegrd"
			}
			if runtime.GOOS == "darwin" {
				targetPath, stop = launchdPath(userScope), "launchctl unload "+launchdPath(userScope)
			}
			// It printed "Removed" whether or not anything was, including
			// when the delete was refused for want of sudo.
			switch err := os.Remove(targetPath); {
			case os.IsNotExist(err):
				fmt.Printf("Nothing to remove: %s does not exist.\n", targetPath)
				return nil
			case err != nil:
				return fmt.Errorf("could not remove %s (try sudo, or --user for a user service): %w", targetPath, err)
			}
			fmt.Printf("✅ Removed %s\n", targetPath)
			fmt.Printf("   A service that was running keeps running until it is stopped:\n   %s\n", stop)
			return nil
		},
	}
	cmd.Flags().BoolVar(&userScope, "user", false, "Target user-scoped service")
	return cmd
}

func newAgentRestartCmd() *cobra.Command {
	var userScope bool
	cmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart the installed agent service",
		RunE: func(cmd *cobra.Command, args []string) error {
			// It printed "Signaling agent service restart..." and restarted
			// nothing; it now runs the service manager and says what happened.
			var name string
			var argv []string
			switch {
			case runtime.GOOS == "darwin" && userScope:
				name, argv = "launchctl", []string{"kickstart", "-k", fmt.Sprintf("gui/%d/dev.safegrd.agent", os.Getuid())}
			case runtime.GOOS == "darwin":
				name, argv = "launchctl", []string{"kickstart", "-k", "system/dev.safegrd.agent"}
			case userScope:
				name, argv = "systemctl", []string{"--user", "restart", "safegrd"}
			default:
				name, argv = "systemctl", []string{"restart", "safegrd"}
			}
			out, err := exec.Command(name, argv...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s failed (a system service needs sudo; a user one needs --user): %v\n%s",
					name, strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
			}
			fmt.Printf("✅ Restarted: %s %s\n", name, strings.Join(argv, " "))
			return nil
		},
	}
	cmd.Flags().BoolVar(&userScope, "user", false, "Target user-scoped service")
	return cmd
}

// hostIsEnrolled decides whether the agent reports at all: a host with a
// server token. A standalone agent under systemd logged "NOT RECORDED" for
// every backup it took.
func hostIsEnrolled(c *config.CLIConfig) bool {
	return c.ServerURL != "" && c.ServerToken != ""
}
