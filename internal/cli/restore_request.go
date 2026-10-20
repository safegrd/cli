package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
)

// restoreFlags are the restore command's flags, and what a restore asked for
// in the console sets in their place.
type restoreFlags struct {
	snapshotID, targetURL, targetDir, toSQL, engineStr, keyPath, privKey, fromPath string
	paths                                                                         []string
	version                                                                       int
	surfaceSel                                                                    string
	tables, schemas, dataOnly                                                     []string
	noOwner, keepCron                                                             bool
	// withoutErasures restores a snapshot whose erasure record cannot be
	// read, and says erased rows may be back.
	withoutErasures, salvage bool

	// A bucket to restore a files snapshot into, as backup reads one.
	sourceEndpoint, sourceRegion, sourceAccessKey, sourceSecretKey string
	sourceFlagsSet                                                 bool

	// requestID is a restore asked for in the console (--request).
	requestID string

	// Set by a requested restore, never by a flag: the target and the key are
	// already resolved, so they are not read as env:/file: references or
	// warned about as values on a command line; bucket is the bucket target
	// with its keys; surface is the configured surface whose storage the
	// snapshot is in.
	targetResolved bool
	key            string
	bucket         *dump.ObjectStoreSource
	surface        *config.SurfaceConfig
}

// restoreStorage is the storage a restore reads: the surface's own when the
// restore is one of a configured surface with storage of its own, the host's
// routed as backup routes it otherwise.
func restoreStorage(ctx context.Context, f *restoreFlags) (config.StorageConfig, error) {
	if f.surface != nil && f.surface.Storage != nil {
		st := *f.surface.Storage
		return st, checkSurfaceStorage(ctx, cfg, &st)
	}
	return resolveStorageRouting(ctx, cfg, "", "", "", "", false)
}

// restoreTally is what a restore wrote, as it prints it: tables and rows,
// directories and files, folders and messages.
type restoreTally struct {
	containers int
	items      int64
}

type restoreTallyKey struct{}

func withRestoreTally(ctx context.Context) (context.Context, *restoreTally) {
	t := &restoreTally{}
	return context.WithValue(ctx, restoreTallyKey{}, t), t
}

// noteRestored records the counts a restore printed, for its report.
func noteRestored(ctx context.Context, containers int, items int64) {
	if t, ok := ctx.Value(restoreTallyKey{}).(*restoreTally); ok {
		t.containers, t.items = containers, items
	}
}

// runRestoreRequest is `safegrd restore --request <id>`: a restore asked for
// in the console, run by hand on a host that holds the key. When the request
// asks for a backup first, the surface is backed up from this host's config.
func runRestoreRequest(ctx context.Context, f *restoreFlags) error {
	if f.snapshotID != "" || f.targetURL != "" || f.targetDir != "" || f.toSQL != "" || f.fromPath != "" || len(f.paths) > 0 ||
		len(f.tables) > 0 || len(f.schemas) > 0 || len(f.dataOnly) > 0 || f.version > 0 || f.sourceFlagsSet || f.salvage {
		return fmt.Errorf("--request takes the snapshot, the target and what to restore from the console's request; leave out the other flags except --key-path and --private-key")
	}
	if !canReport(cfg) {
		return fmt.Errorf("--request needs this host to be enrolled with the remote server: run 'safegrd enroll' first")
	}
	key := ""
	if f.privKey != "" {
		k, err := ResolveSecretRef("private-key", f.privKey)
		if err != nil {
			return err
		}
		key = k
	}
	run := requestedRestore{
		requestID: f.requestID,
		key:       key,
		keyPath:   f.keyPath,
		safety: func(ctx context.Context, plan *model.RestorePlan) (string, error) {
			return backupSurfaceOfNode(ctx, cfg, plan.NodeID)
		},
	}
	return run.run(ctx, cfg)
}

// requestedRestore runs one restore asked for in the console.
type requestedRestore struct {
	requestID string
	// key is the private key when the caller has it already; keyPath is a
	// key file to read. Both empty: the config's, then one SafeGrd holds.
	key, keyPath string
	// surface is the configured surface the restore is of, when known.
	surface *config.SurfaceConfig
	// safety takes the backup the request asks for first, and returns its
	// snapshot id.
	safety func(ctx context.Context, plan *model.RestorePlan) (string, error)
}

// run fetches the plan, takes the backup it asks for first, restores, and
// reports the outcome. The target's credential is held in memory for this
// call only. A restore that fails returns its error; one that worked and
// could not be reported returns a server failure, said on stderr too.
func (q requestedRestore) run(ctx context.Context, c *config.CLIConfig) error {
	var plan model.RestorePlan
	if status, err := getJSON(ctx, c, "/api/v1/restores/"+url.PathEscape(q.requestID)+"/plan", &plan); err != nil {
		noteServerStatus(status)
		if status == http.StatusGone {
			return fmt.Errorf("restore %s: %v", q.requestID, strings.TrimPrefix(err.Error(), "HTTP 410: "))
		}
		if status == 0 || status >= 500 {
			return serverFailure(fmt.Errorf("restore %s: could not read the request from the remote server: %w", q.requestID, err))
		}
		return fmt.Errorf("restore %s: %w", q.requestID, err)
	}
	defer func() {
		plan.Target.URL, plan.Target.SecretAccessKey = "", ""
	}()

	started := time.Now().UTC()
	report := model.RestoreReport{RestoreID: plan.RestoreID, StartedAt: started, SafetySnapshotID: plan.SafetySnapshotID}
	fmt.Printf("Restore %s, asked for in the console: %s of snapshot %s into %s\n",
		plan.RestoreID, plan.Scope.Describe(), plan.SnapshotID, restoreTargetLabel(plan.Target))

	restoreErr := func() error {
		if plan.SafetyBackup && plan.SafetySnapshotID == "" {
			q.progress(ctx, c, model.RestoreProgress{State: model.RestoreBackingUp, Message: "Backing up the surface before the restore"})
			if q.safety == nil {
				return fmt.Errorf("the request asks for a backup of the surface first, and this host cannot take one")
			}
			id, err := q.safety(ctx, &plan)
			if err != nil {
				return fmt.Errorf("the backup taken before the restore failed, so nothing was restored: %w", err)
			}
			if id == "" {
				return fmt.Errorf("the backup taken before the restore recorded no snapshot, so nothing was restored")
			}
			report.SafetySnapshotID = id
			fmt.Printf("   Backed up first: %s\n", id)
		}
		q.progress(ctx, c, model.RestoreProgress{State: model.RestoreRunning, SafetySnapshotID: report.SafetySnapshotID, Message: "Restoring"})
		f, err := restoreFlagsOf(&plan)
		if err != nil {
			return err
		}
		f.key, f.keyPath, f.surface = q.key, q.keyPath, q.surface
		tctx, tally := withRestoreTally(ctx)
		err = executeRestore(tctx, f)
		report.Containers, report.Items = tally.containers, tally.items
		return err
	}()

	report.CompletedAt = time.Now().UTC()
	report.DurationMs = report.CompletedAt.Sub(started).Milliseconds()
	report.State = model.RestoreCompleted
	if restoreErr != nil {
		report.State = model.RestoreFailed
		report.Error = firstLines(restoreErr.Error(), 2000)
	}
	status, sendErr := postJSON(ctx, c, "/api/v1/restores/"+url.PathEscape(plan.RestoreID)+"/report", report, nil)
	if sendErr != nil {
		noteServerStatus(status)
		fmt.Fprintf(os.Stderr, "Error: restore %s %s, and the remote server was not told: %v\n"+
			"   The console shows it as running until it gives up on it.\n", plan.RestoreID, report.State, sendErr)
		if restoreErr != nil {
			return restoreErr
		}
		return serverFailure(fmt.Errorf("restore %s completed and could not be reported: %w", plan.RestoreID, sendErr))
	}
	if restoreErr != nil {
		return restoreErr
	}
	fmt.Printf("Restore %s reported to the remote server.\n", plan.RestoreID)
	return nil
}

// progress tells the remote server where the restore is. A failure is said
// and the restore goes on: the report at the end is what counts.
func (q requestedRestore) progress(ctx context.Context, c *config.CLIConfig, p model.RestoreProgress) {
	if status, err := postJSON(ctx, c, "/api/v1/restores/"+url.PathEscape(q.requestID)+"/progress", p, nil); err != nil {
		noteServerStatus(status)
		fmt.Fprintf(os.Stderr, "Warning: restore %s: could not tell the remote server it is %s: %v\n", q.requestID, p.State, err)
	}
}

// restoreFlagsOf is the restore command's flags for a plan.
func restoreFlagsOf(plan *model.RestorePlan) (*restoreFlags, error) {
	if err := plan.Scope.Validate(); err != nil {
		return nil, fmt.Errorf("the request's scope: %w", err)
	}
	f := &restoreFlags{snapshotID: plan.SnapshotID, engineStr: "native", targetResolved: true,
		schemas: plan.Scope.Schemas, dataOnly: plan.Scope.DataOnlySchemas, tables: plan.Scope.Tables, paths: plan.Scope.Paths,
		noOwner: plan.Options.NoOwner, keepCron: plan.Options.KeepCronActive, withoutErasures: plan.Options.WithoutErasures}
	t := plan.Target
	switch t.Kind {
	case model.RestoreTargetDatabase:
		if t.URL == "" {
			return nil, fmt.Errorf("the request names no database URL")
		}
		f.targetURL = t.URL
	case model.RestoreTargetDirectory:
		if !filepath.IsAbs(t.Path) {
			return nil, fmt.Errorf("the request's directory %q is not an absolute path", t.Path)
		}
		f.targetDir = t.Path
	case model.RestoreTargetBucket:
		if t.Bucket == "" || t.AccessKeyID == "" || t.SecretAccessKey == "" {
			return nil, fmt.Errorf("the request's bucket needs a name and both keys")
		}
		f.targetURL = "s3://" + t.Bucket
		if p := strings.Trim(t.Prefix, "/"); p != "" {
			f.targetURL += "/" + p
		}
		f.bucket = &dump.ObjectStoreSource{Endpoint: t.Endpoint, Region: t.Region, Bucket: t.Bucket, Prefix: strings.Trim(t.Prefix, "/"),
			AccessKeyID: t.AccessKeyID, SecretAccessKey: t.SecretAccessKey}
	default:
		return nil, fmt.Errorf("the request's target kind %q is not one this version restores into", t.Kind)
	}
	return f, nil
}

// restoreTargetLabel names a target without its secret.
func restoreTargetLabel(t model.RestoreTarget) string {
	switch t.Kind {
	case model.RestoreTargetDatabase:
		return dump.RedactURL(t.URL)
	case model.RestoreTargetBucket:
		return "s3://" + strings.TrimSuffix(t.Bucket+"/"+strings.Trim(t.Prefix, "/"), "/")
	default:
		return t.Path
	}
}

// backupSurfaceOfNode backs up the configured surface that reports as
// nodeID, as `backup --surface` does, and returns its snapshot.
func backupSurfaceOfNode(ctx context.Context, c *config.CLIConfig, nodeID string) (string, error) {
	statePath := filepath.Join(resolveStateDir("", c), "daemon_state.json")
	st := loadDaemonState(statePath)
	for _, s := range c.Surfaces {
		if ss := st.Surfaces[s.ID]; ss != nil && ss.ServerNodeID == nodeID {
			if err := backupNamedSurface(ctx, c, s.ID, false, false, false); err != nil {
				return "", err
			}
			after := loadDaemonState(statePath)
			if ss := after.Surfaces[s.ID]; ss != nil {
				return ss.LastSnapshotID, nil
			}
			return "", nil
		}
	}
	return "", fmt.Errorf("this host's config has no surface that backs up as %s. Run this on the surface's own host, "+
		"or ask for the restore again in the console with the backup first turned off", nodeID)
}

// getJSON is postJSON's GET.
func getJSON(ctx context.Context, c *config.CLIConfig, path string, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.ServerURL, "/")+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	req.Header.Set("User-Agent", UserAgent())
	req.Header.Set(hostMachineHeader, hostMachine())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Error)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("the remote server's answer does not parse: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// firstLines is s cut to n bytes, from its start.
func firstLines(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// pendingRestore is a restore the heartbeat named for one surface.
type pendingRestore struct {
	surface   *config.SurfaceConfig
	state     *SurfaceState
	nodeID    string
	requestID string
}

// runConsoleRestore runs a restore asked for in the console on this host,
// once. The id is recorded before anything runs: the target is handed over
// once, so a restore cut off half way is asked for again, not retried.
func runConsoleRestore(ctx context.Context, c *config.CLIConfig, rq pendingRestore, lockDir, statePath string, daemonState *DaemonState) {
	rq.state.LastRestoreRequestID = rq.requestID
	warnIfStateUnsaved(saveDaemonState(statePath, daemonState), statePath)
	fmt.Printf("Surface %s (%s): restore %s requested from the console.\n", rq.surface.ID, rq.surface.Type, rq.requestID)
	run := requestedRestore{
		requestID: rq.requestID,
		key:       daemonPrivateKey(ctx, c),
		surface:   rq.surface,
		safety: func(ctx context.Context, _ *model.RestorePlan) (string, error) {
			s := *rq.surface
			fetchHeldSurfaceSecret(ctx, c, rq.nodeID, &s)
			attempted := rq.state.LastAttempt
			meta, err := backupSurfaceNow(ctx, c, &s, rq.state, rq.nodeID, lockDir, statePath, daemonState)
			switch {
			case err != nil:
				return "", err
			case meta != nil:
				return meta.SnapshotID, nil
			case rq.state.LastAttempt.Equal(attempted):
				return "", fmt.Errorf("another backup of surface %s holds its lock", s.ID)
			}
			// skip_if_unchanged: nothing changed since the newest backup,
			// which is then the copy to go back to.
			return rq.state.LastSnapshotID, nil
		},
	}
	if err := run.run(ctx, c); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Surface %s: restore %s: %v\n", rq.surface.ID, rq.requestID, err)
	}
}
