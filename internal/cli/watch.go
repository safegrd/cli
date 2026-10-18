package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/runner"
	"github.com/safegrd/cli/pkg/watch"
)

// A watched surface (pkg/watch) checks the PostgreSQL backups another tool
// writes, where that tool puts them, instead of backing up a database. A
// check that finds a new backup reports it as a snapshot dated by the
// backup, so the surface goes Overdue when the other tool stops writing and
// Threat Shield compares each backup with the last. A check that finds
// nothing new reports nothing: "checked, unchanged" would keep it from going
// Overdue, which is the alert this surface exists for.

// errNothingNew is a check that found the backup it read last time.
var errNothingNew = errors.New("no new backup since the last check")

// watchedBackup is the backup a surface's last check read.
type watchedBackup struct {
	Object watch.Object            `json:"object"`
	Meta   *model.SnapshotMetadata `json:"meta"`
}

// watchLocation is a surface's watch: block, its keys resolved.
func watchLocation(s *config.SurfaceConfig) (watch.Location, error) {
	w := s.Watch
	loc := watch.Location{URL: strings.TrimSpace(w.URL), Endpoint: w.Endpoint, Region: w.Region, Match: w.Match}
	if loc.URL == "" {
		return loc, fmt.Errorf("surface %s: watch: needs a url (s3://bucket/prefix, or a directory)", s.ID)
	}
	var err error
	if loc.AccessKeyID, err = resolveConfigSecret("watch.access_key", w.AccessKey); err != nil {
		return loc, err
	}
	if loc.SecretAccessKey, err = resolveConfigSecret("watch.secret_key", w.SecretKey); err != nil {
		return loc, err
	}
	return loc, nil
}

// watchScratch is the directory a watched surface downloads into.
func watchScratch(stateDir string) (string, error) {
	dir := filepath.Join(stateDir, "watch")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// runWatchCheck is a watched surface's run: the newest backup at its
// location, read once if it is new.
func runWatchCheck(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string, st *SurfaceState, stateDir string) (*model.SnapshotMetadata, error) {
	if !strings.EqualFold(s.Type, "postgres") {
		return nil, stageErr(model.BackupReasonConfig, fmt.Errorf("surface %s: watch: reads PostgreSQL backups; set type: postgres", s.ID))
	}
	loc, err := watchLocation(s)
	if err != nil {
		return nil, stageErr(model.BackupReasonConfig, err)
	}
	obj, err := loc.Newest(ctx)
	if err != nil {
		return nil, stageErr(model.BackupReasonSource, err)
	}
	if st.Watched != nil && st.Watched.Object.Same(obj) {
		return nil, errNothingNew
	}
	scratch, err := watchScratch(stateDir)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	file, sum, err := loc.Download(ctx, obj, scratch)
	if err != nil {
		return nil, stageErr(model.BackupReasonSource, err)
	}
	defer os.Remove(file)
	contents, err := watch.Inspect(ctx, file)
	if err != nil {
		return nil, stageErr(model.BackupReasonSource, fmt.Errorf("the backup at %s cannot be read: %w", obj.URI, err))
	}
	now := time.Now().UTC()
	meta := &model.SnapshotMetadata{
		SnapshotID:  fmt.Sprintf("snap-%s-%s", now.Format("20060102-150405"), uuid.New().String()[:6]),
		NodeID:      nodeID,
		SurfaceType: model.SurfaceTypePostgres,
		// The file's name stands in for the database's, which a dump names
		// only in a comment.
		DatabaseName:       path.Base(obj.Key),
		CreatedAt:          obj.Modified,
		CompletedAt:        &now,
		Status:             model.SnapshotStatusCompleted,
		RawSizeBytes:       obj.Size,
		EncryptedSizeBytes: obj.Size,
		Sha256Checksum:     sum,
		StorageURI:         obj.URI,
		WORMMode:           string(config.WORMModeNone),
		TableStats:         contents.Tables,
		Extensions:         contents.Extensions,
		CronJobs:           contents.CronJobs,
		DurationMs:         backupMilliseconds(started),
		External: &model.ExternalBackup{URI: obj.URI, Tool: watch.Tool(obj), Format: contents.Format,
			Modified: obj.Modified},
	}
	if contents.ServerVersion != "" {
		meta.PostgresVersion = "PostgreSQL " + contents.ServerVersion
	}
	meta.CalculateTotals()
	fmt.Printf("[%s] Read %s (made by %s, %s, written %s): %d %s, %s rows.\n", s.ID, obj.URI, meta.External.MadeBy(),
		formatBytes(obj.Size), obj.Modified.Format("2006-01-02 15:04 UTC"), len(contents.Tables),
		pluralWord(int64(len(contents.Tables)), "table", "tables"), formatNumber(contents.Rows))
	if !contents.Loadable() {
		fmt.Printf("[%s] This dump creates databases or roles, so its drills read it in memory and do not load it.\n", s.ID)
	}
	if hostIsEnrolled(c) {
		st.notRecorded = reportSnapshot(ctx, c, st, meta)
	}
	st.Watched = &watchedBackup{Object: obj, Meta: meta}
	return meta, nil
}

// runWatchDrill drills the backup a watched surface's last check read. It
// needs no key: the other tool's backup is not sealed to one.
func runWatchDrill(ctx context.Context, c *config.CLIConfig, d pendingDrill, save func()) {
	s, st := d.surface, d.state
	now := time.Now().UTC()
	if d.requestID != "" {
		st.LastDrillRequestID = d.requestID
	} else if !st.LastDrillAttempt.IsZero() && !now.Before(st.LastDrillAttempt) && now.Before(st.LastDrillAttempt.Add(drillMinSpacing)) {
		return
	}
	if st.Watched == nil || st.Watched.Meta == nil {
		// Nothing checked yet on this host: the next check reads one.
		return
	}
	st.LastDrillAttempt = now
	st.DrillInFlight = true
	save()
	defer func() {
		st.DrillInFlight = false
		save()
	}()
	loc, err := watchLocation(s)
	if err != nil {
		st.DrillFailures++
		st.setDrill(model.DrillStatusFailed, model.DrillReasonOther, err.Error())
		fmt.Fprintf(os.Stderr, "Error: Surface %s: Fire Drill could not run: %v\n", s.ID, err)
		return
	}
	meta := st.Watched.Meta
	verifier := runner.NewVerifier(nil, c.ServerURL)
	verifier.SetServerToken(c.ServerToken)
	scratch, _ := watchScratch(d.stateDir)
	drill := runner.ExternalDrill{Meta: meta, Location: loc, Object: st.Watched.Object, Scratch: scratch}
	sandbox, sandboxErr := surfaceSandboxURL(ctx, c, s)
	var local *runner.LocalPostgres
	var report *model.VerificationReport
	how := "in-memory read"
	switch {
	case sandboxErr != nil:
		err = sandboxErr
	case sandbox != "":
		how = "load into the sandbox database"
		fmt.Printf("Surface %s: Fire Drill due: loading %s into its sandbox database.\n", s.ID, meta.External.URI)
		report, err = verifier.RunExternalDrill(ctx, drill, sandbox)
		if resetErr := runner.ResetSandbox(ctx, sandbox); resetErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Surface %s: could not empty the sandbox after the drill: %v\n", s.ID, resetErr)
		}
	case d.sandboxIncluded:
		var why error
		if local, _, why = startLocalSandbox(ctx, nil, meta.SnapshotID, meta, d.stateDir); why != nil || local == nil {
			if why != nil {
				fmt.Fprintf(os.Stderr, "Warning: Surface %s: drilling in memory, not in a local sandbox: %v\n", s.ID, why)
			}
			report, err = verifier.RunExternalDrill(ctx, drill, "")
			break
		}
		defer local.Stop()
		how = "load into a throwaway PostgreSQL " + local.Server.Version + " on this host"
		fmt.Printf("Surface %s: Fire Drill due: loading %s into a throwaway PostgreSQL %s on this host.\n", s.ID, meta.External.URI, local.Server.Version)
		report, err = verifier.RunExternalDrill(ctx, drill, local.URL)
	default:
		fmt.Printf("Surface %s: Fire Drill due: reading %s in memory.\n", s.ID, meta.External.URI)
		report, err = verifier.RunExternalDrill(ctx, drill, "")
	}
	switch {
	case err != nil:
		st.DrillFailures++
		st.setDrill(model.DrillStatusFailed, model.DrillReasonRestoreFailed, err.Error())
		fmt.Fprintf(os.Stderr, "Error: Surface %s: Fire Drill could not run: %v\n", s.ID, err)
	case report.Status != model.VerificationStatusPassed:
		st.DrillFailures++
		st.setDrill(model.DrillStatusFailed, failedDrillReason(report), report.ErrorMessage)
		fmt.Fprintf(os.Stderr, "Error: Surface %s: Fire Drill FAILED for %s: %s\n", s.ID, meta.External.URI, report.ErrorMessage)
	default:
		st.DrillFailures = 0
		st.setDrill(model.DrillStatusPassed, "", "")
		st.LastDrillSnapshotID = meta.SnapshotID
		fmt.Printf("Surface %s: Fire Drill passed (%s of %s, made by %s; certificate %s).\n", s.ID, how, meta.External.URI,
			meta.External.MadeBy(), report.CertificateHash)
	}
}

// verifyWatchedSurface drills, from the command line, the backup a watched
// surface's last check read, and prints it the way verify prints every
// drill.
func verifyWatchedSurface(ctx context.Context, surfaceID, sandboxURL string) error {
	var s *config.SurfaceConfig
	for i := range cfg.Surfaces {
		if cfg.Surfaces[i].ID == surfaceID {
			s = &cfg.Surfaces[i]
		}
	}
	if s == nil || s.Watch == nil {
		return fmt.Errorf("--surface %s: no surface with watch: of that id in this config", surfaceID)
	}
	stateDir := resolveStateDir("", cfg)
	st := loadDaemonState(filepath.Join(stateDir, "daemon_state.json")).Surfaces[surfaceID]
	if st == nil || st.Watched == nil || st.Watched.Meta == nil {
		return fmt.Errorf("surface %s has no checked backup on this host yet; run 'safegrd backup --surface %s' first", surfaceID, surfaceID)
	}
	loc, err := watchLocation(s)
	if err != nil {
		return err
	}
	scratch, err := watchScratch(stateDir)
	if err != nil {
		return err
	}
	meta := st.Watched.Meta
	verifier := runner.NewVerifier(nil, cfg.ServerURL)
	if cfg.ServerToken != "" {
		verifier.SetServerToken(cfg.ServerToken)
	}
	where := "in memory"
	if sandboxURL != "" {
		where = "into " + dump.RedactURL(sandboxURL)
	}
	fmt.Printf("Verifying %s (made by %s, written %s): reading it again and loading it %s.\n", meta.External.URI,
		meta.External.MadeBy(), meta.External.Modified.Format("2006-01-02 15:04 UTC"), where)
	report, err := verifier.RunExternalDrill(ctx, runner.ExternalDrill{Meta: meta, Location: loc, Object: st.Watched.Object, Scratch: scratch}, sandboxURL)
	if err != nil {
		return err
	}
	for _, a := range report.Assertions {
		status := "PASS"
		if !a.Passed {
			status = "FAIL"
		}
		if a.Message != "" {
			fmt.Printf("   [%s] %s: %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Message, a.Expected, a.Actual)
		} else {
			fmt.Printf("   [%s] %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Expected, a.Actual)
		}
	}
	if report.Status != model.VerificationStatusPassed {
		return drillFailure(verifier, fmt.Errorf("fire drill of %s failed: %s", meta.External.URI, report.ErrorMessage))
	}
	fmt.Printf("\nFire Drill Passed\n   Made by:         %s\n   Read from:       %s\n   Tables:          %d\n   Rows:            %d\n   Certificate:     %s\n",
		meta.External.MadeBy(), meta.External.URI, report.TablesRestored, report.RowsRestored, report.CertificateHash)
	fmt.Println("   Not proven:      that the dump holds the whole database; SafeGrd never read the database it came from.")
	return nil
}
