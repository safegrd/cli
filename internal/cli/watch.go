package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// A watched surface (pkg/watch) checks the backups another tool writes
// (PostgreSQL, MySQL or MongoDB), where that tool puts them, instead of
// backing up a database. A
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
	// URL is the location the backup was read from, as resolved.
	URL string `json:"url,omitempty"`
}

// watchedEngine is the engine a watched surface's type names, or an error
// for a type this cannot watch.
func watchedEngine(s *config.SurfaceConfig) (model.SurfaceType, error) {
	switch kind := model.SurfaceType(strings.ToLower(s.Type)); kind {
	case model.SurfaceTypePostgres, model.SurfaceTypeMySQL, model.SurfaceTypeMongoDB:
		return kind, nil
	default:
		return "", fmt.Errorf("surface %s: watch: reads PostgreSQL, MySQL and MongoDB backups; set type: postgres, mysql or mongodb", s.ID)
	}
}

// watchLocation is a surface's watch: block, its keys resolved.
func watchLocation(s *config.SurfaceConfig) (watch.Location, error) {
	w := s.Watch
	engine, err := watchedEngine(s)
	if err != nil {
		return watch.Location{}, err
	}
	loc := watch.Location{URL: strings.TrimSpace(w.URL), Engine: engine, Endpoint: w.Endpoint, Region: w.Region, Match: w.Match}
	if loc.URL == "" {
		return loc, fmt.Errorf("surface %s: watch: needs a url (s3://bucket/prefix, or a directory)", s.ID)
	}
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
	return checkWatchedObject(ctx, c, s, loc, obj, nodeID, st, stateDir)
}

// checkWatchedObject reads one backup at a location, counts it, reports it
// as a snapshot when this host is enrolled, and records it as the surface's
// last check.
func checkWatchedObject(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, loc watch.Location, obj watch.Object, nodeID string, st *SurfaceState, stateDir string) (*model.SnapshotMetadata, error) {
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
	if contents.Engine != loc.Engine {
		return nil, stageErr(model.BackupReasonConfig, fmt.Errorf("the newest backup at %s is a %s dump, and surface %s is type: %s; set the type the backups are of, or match: to its files",
			obj.URI, contents.Engine, s.ID, s.Type))
	}
	// The file's name stands in for the database's where the dump does not
	// name it: a pg_dump names it only in a comment.
	database := contents.Database
	if database == "" {
		database = path.Base(obj.Key)
	}
	now := time.Now().UTC()
	meta := &model.SnapshotMetadata{
		SnapshotID:         fmt.Sprintf("snap-%s-%s", now.Format("20060102-150405"), uuid.New().String()[:6]),
		NodeID:             nodeID,
		SurfaceType:        loc.Engine,
		DatabaseName:       database,
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
	switch {
	case contents.ServerVersion == "":
	case loc.Engine == model.SurfaceTypePostgres:
		meta.PostgresVersion = "PostgreSQL " + contents.ServerVersion
	default:
		meta.ServerVersion = contents.ServerVersion
	}
	meta.CalculateTotals()
	containers, items := contents.CountWords()
	fmt.Printf("[%s] Read %s (made by %s, %s, written %s): %d %s, %s %s.\n", s.ID, obj.URI, meta.External.MadeBy(),
		formatBytes(obj.Size), obj.Modified.Format("2006-01-02 15:04 UTC"), len(contents.Tables),
		pluralWord(int64(len(contents.Tables)), strings.TrimSuffix(containers, "s"), containers), formatNumber(contents.Rows), items)
	if !contents.Loadable() {
		fmt.Printf("[%s] This dump creates databases or roles, or holds more than one database, so its drills read it in memory and do not load it.\n", s.ID)
	}
	if hostIsEnrolled(c) {
		st.notRecorded = reportSnapshot(ctx, c, st, meta)
	}
	st.Watched = &watchedBackup{Object: obj, Meta: meta, URL: loc.URL}
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
	case d.sandboxIncluded && meta.SurfaceType == model.SurfaceTypePostgres:
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
	return printExternalDrill(verifier, meta, report)
}

// A watched surface the remote server runs (no host): SafeGrd holds a
// read-only key for the location, and the machine it starts for a check or a
// drill fetches that key with its job token, as a host fetches a held
// database credential. The machine keeps no state between jobs, so a check
// decides "nothing new" against the remote server's record of the surface's
// newest backup, before it downloads anything.

// heldLocation is a Location from the bucket the remote server holds.
func heldLocation(o *dump.ObjectStoreSource, match string) watch.Location {
	return watch.Location{URL: o.Root(), Endpoint: o.Endpoint, Region: o.Region, Match: match,
		AccessKeyID: o.AccessKeyID, SecretAccessKey: o.SecretAccessKey, SessionToken: o.SessionToken}
}

// newestRecordedExternal is the remote server's newest record of a backup
// another tool made for this node, or nil.
func newestRecordedExternal(ctx context.Context, c *config.CLIConfig) (*model.SnapshotMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.ServerURL, "/")+"/api/v1/snapshots?node_id="+url.QueryEscape(c.NodeID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the remote server answered HTTP %d to the snapshot list", resp.StatusCode)
	}
	var list []model.SnapshotMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("the snapshot list could not be read: %w", err)
	}
	var newest *model.SnapshotMetadata
	for i := range list {
		s := &list[i]
		if s.External == nil || s.Status == model.SnapshotStatusFailed {
			continue
		}
		if newest == nil || s.CreatedAt.After(newest.CreatedAt) {
			newest = s
		}
	}
	return newest, nil
}

// recordedObject is the object a recorded backup was read from, as a
// listing would name it.
func recordedObject(rec *model.SnapshotMetadata) watch.Object {
	obj := watch.Object{URI: rec.External.URI, Size: rec.RawSizeBytes, Modified: rec.External.Modified}
	switch {
	case strings.HasPrefix(obj.URI, "s3://"):
		if _, after, ok := strings.Cut(strings.TrimPrefix(obj.URI, "s3://"), "/"); ok {
			obj.Key = after
		}
	case strings.HasPrefix(obj.URI, "file://"):
		obj.Key = strings.TrimPrefix(obj.URI, "file://")
	}
	return obj
}

// runHeldWatchCheck is `safegrd backup` on a machine the remote server
// started for a watched surface: the newest backup at the location SafeGrd
// holds the key of, read and counted once if the remote server has no
// record of it yet. It prints the check and exits 0 either way; nothing new
// is a check that recorded nothing, so the surface goes Overdue when the
// other tool stops.
func runHeldWatchCheck(ctx context.Context, c *config.CLIConfig, held credentialSource) error {
	kind := model.SurfaceType(strings.ToLower(held.Watch.SurfaceType))
	switch kind {
	case model.SurfaceTypePostgres, model.SurfaceTypeMySQL, model.SurfaceTypeMongoDB:
	default:
		return fmt.Errorf("the remote server holds a watched location for a %q surface, which this build cannot check", held.Watch.SurfaceType)
	}
	loc := heldLocation(held.ObjectStore, held.Watch.Match)
	loc.Engine = kind
	obj, err := loc.Newest(ctx)
	if err != nil {
		return err
	}
	known, err := newestRecordedExternal(ctx, c)
	if err != nil {
		return fmt.Errorf("could not read what the remote server has of this surface: %w", err)
	}
	if known != nil && recordedObject(known).Same(obj) {
		fmt.Printf("No new backup at %s since %s: the newest there is the one recorded as %s.\n", loc.URL,
			obj.Modified.Format("2006-01-02 15:04 UTC"), known.SnapshotID)
		return nil
	}
	s := &config.SurfaceConfig{ID: c.NodeID, Type: string(kind), Watch: &config.WatchConfig{URL: loc.URL, Match: loc.Match}}
	st := &SurfaceState{}
	meta, err := checkWatchedObject(ctx, c, s, loc, obj, c.NodeID, st, resolveStateDir("", c))
	if err != nil {
		return err
	}
	if st.notRecorded != "" {
		return fmt.Errorf("the check of %s was not recorded: %s", obj.URI, st.notRecorded)
	}
	fmt.Printf("Recorded %s as %s.\n", obj.URI, meta.SnapshotID)
	return nil
}

// verifyExternalSnapshot drills a recorded backup another tool made, by its
// snapshot id: on a host, from the watch: surface in this config that
// records for the snapshot's node; on a machine the remote server started,
// from the location whose key the remote server holds. It prints the drill
// the way verify prints every drill.
func verifyExternalSnapshot(ctx context.Context, c *config.CLIConfig, rec *model.SnapshotMetadata, sandboxURL string) error {
	var loc watch.Location
	found := false
	stateDir := resolveStateDir("", c)
	if c.NodeID == rec.NodeID || c.NodeID == "" {
		state := loadDaemonState(filepath.Join(stateDir, "daemon_state.json"))
		for i := range c.Surfaces {
			s := &c.Surfaces[i]
			st := state.Surfaces[s.ID]
			if s.Watch == nil || !(s.ID == rec.NodeID || (st != nil && st.ServerNodeID == rec.NodeID)) {
				continue
			}
			l, err := watchLocation(s)
			if err != nil {
				return err
			}
			loc, found = l, true
			break
		}
	}
	if !found {
		held := resolveRuntimeCredentials(ctx, c, &config.StorageConfig{Type: config.StorageTypeHosted}, false)
		if held.ObjectStore == nil || held.Watch == nil {
			return fmt.Errorf("snapshot %s is a backup another tool made, and this config has no watch: surface for its node %s", rec.SnapshotID, rec.NodeID)
		}
		loc = heldLocation(held.ObjectStore, held.Watch.Match)
		loc.Engine = rec.SurfaceType
	}
	scratch, err := watchScratch(stateDir)
	if err != nil {
		return err
	}
	verifier := runner.NewVerifier(nil, c.ServerURL)
	if c.ServerToken != "" {
		verifier.SetServerToken(c.ServerToken)
	}
	where := "in memory"
	if sandboxURL != "" {
		where = "into " + dump.RedactURL(sandboxURL)
	}
	fmt.Printf("Verifying %s (made by %s, written %s): reading it again and loading it %s.\n", rec.External.URI,
		rec.External.MadeBy(), rec.External.Modified.Format("2006-01-02 15:04 UTC"), where)
	report, err := verifier.RunExternalDrill(ctx, runner.ExternalDrill{Meta: rec, Location: loc, Object: recordedObject(rec), Scratch: scratch}, sandboxURL)
	if err != nil {
		return err
	}
	return printExternalDrill(verifier, rec, report)
}

// printExternalDrill prints a drill of a backup another tool made, and
// returns the drill's failure as the command's error.
func printExternalDrill(verifier *runner.Verifier, meta *model.SnapshotMetadata, report *model.VerificationReport) error {
	for _, a := range report.Assertions {
		status := assertionWord(a)
		if a.Message != "" {
			fmt.Printf("   [%s] %s: %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Message, a.Expected, a.Actual)
		} else {
			fmt.Printf("   [%s] %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Expected, a.Actual)
		}
	}
	if report.Status != model.VerificationStatusPassed {
		return drillFailure(verifier, fmt.Errorf("fire drill of %s failed: %s", meta.External.URI, report.ErrorMessage))
	}
	containers, items := watch.CountWords(meta.SurfaceType)
	fmt.Printf("\nFire Drill Passed\n   Made by:         %s\n   Read from:       %s\n   %-16s %d\n   %-16s %d\n   Certificate:     %s\n",
		meta.External.MadeBy(), meta.External.URI, strings.ToUpper(containers[:1])+containers[1:]+":", report.TablesRestored, strings.ToUpper(items[:1])+items[1:]+":", report.RowsRestored, report.CertificateHash)
	fmt.Println("   Not proven:      that the dump holds the whole database; SafeGrd never read the database it came from.")
	return nil
}
