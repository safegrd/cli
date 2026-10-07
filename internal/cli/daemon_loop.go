package cli

// The reporting half of the daemon:
// each surface registered as its own node under the host's, a heartbeat per
// surface per tick, the one-shot "back up now", and unattended Fire Drills
// where the private key already is.
//
// Nothing here may stop a backup. The remote server being unreachable, slow
// or refusing is said on stderr and the tick carries on.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/diskspace"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/runner"
	"github.com/safegrd/cli/pkg/storage"
)

var upgradeNoticeOnce sync.Once

func notifyUpgrade(latest string) {
	upgradeNoticeOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "SafeGrd CLI v%s is available (installed: %s). See https://safegrd.dev/changelog\n", latest, Version)
	})
}

// canReport says whether this config can talk to a remote server at all.
func canReport(c *config.CLIConfig) bool {
	return c.ServerURL != "" && c.ServerToken != ""
}

func postJSON(ctx context.Context, c *config.CLIConfig, path string, body, out any) (int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.ServerURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	req.Header.Set("User-Agent", UserAgent())
	// This host's clock, so the remote server can say when it is wrong.
	req.Header.Set("X-Safegrd-Host-Time", time.Now().UTC().Format(time.RFC3339Nano))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// surfaceNodeID is the node a surface reports as. With a remote server and an
// enrolled node it is the child the remote server assigned; registered once
// per daemon process, so a changed schedule or name in the config reaches the
// console on the next start. Without one it is the surface's own id, which is
// what every backup reported as before surfaces were children.
func surfaceNodeID(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, st *SurfaceState, registered map[string]bool) string {
	if !canReport(c) || c.NodeID == "" {
		return s.ID
	}
	if registered[s.ID] && st.ServerNodeID != "" {
		return st.ServerNodeID
	}
	retention := s.RetentionDays
	if retention == 0 {
		retention = c.Defaults.RetentionDays
	}
	pub := c.Encryption.PublicKey
	if s.Encryption != nil && s.Encryption.PublicKey != "" {
		pub = s.Encryption.PublicKey
	}
	var resp model.SurfaceRegisterResponse
	status, err := postJSON(ctx, c, "/api/v1/nodes/"+url.PathEscape(c.NodeID)+"/surfaces", model.SurfaceRegisterRequest{
		SurfaceID:     s.ID,
		Name:          s.Name,
		SurfaceType:   model.SurfaceType(strings.ToLower(s.Type)),
		SurfaceRef:    surfaceRef(s),
		Schedule:      s.Schedule,
		RetentionDays: retention,
		PublicKey:     pub,
		// Where its credential comes from, so the remote server holds one
		// only for a surface that fetches it (one origin per credential).
		CredentialSource: credentialSourceOf(s),
	}, &resp)
	if status == http.StatusGone {
		// Retired in the console. The surface is not backed up; "" tells
		// the caller to skip it, and the caller says why.
		st.Retired = strings.TrimPrefix(err.Error(), "HTTP 410: ")
		st.ServerNodeID = ""
		return ""
	}
	st.Retired = ""
	if err != nil || resp.NodeID == "" {
		// The backup still runs. Its report will be refused, and the backup
		// path says so; this says why.
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: could not register it with the remote server (%v).\n"+
			"   It is still backed up; the console will not show it until this succeeds.\n", s.ID, err)
		if st.ServerNodeID != "" {
			return st.ServerNodeID
		}
		return s.ID
	}
	registered[s.ID] = true
	st.ServerNodeID = resp.NodeID
	return resp.NodeID
}

func surfaceRef(s *config.SurfaceConfig) string {
	switch strings.ToLower(s.Type) {
	case "files":
		return strings.Join(s.Roots, ",")
	case "email":
		return s.Username
	}
	return ""
}

// sendHeartbeat reports one surface and returns what the remote server asks
// of it, or nil when it could not be asked.
func sendHeartbeat(ctx context.Context, c *config.CLIConfig, nodeID string, st *SurfaceState, tick time.Duration, s *config.SurfaceConfig) *model.HeartbeatResponse {
	if !canReport(c) {
		return nil
	}
	var resp model.HeartbeatResponse
	failing := st.ConsecutiveFailures > 0
	// Without a probe this tick, the two flags are what the last backup
	// said; with one, they are what the probe found just now.
	pgUp, storeUp := !(failing && st.BackupReason == model.BackupReasonSource), !(failing && storageReason(st.BackupReason))
	if st.probe.probed {
		pgUp, storeUp = st.probe.dbUp, st.probe.storageUp
	}
	status, err := postJSON(ctx, c, "/api/v1/nodes/heartbeat", model.HeartbeatRequest{
		NodeID:              nodeID,
		CLI_Version:         Version,
		OS:                  runtime.GOOS,
		Arch:                runtime.GOARCH,
		PostgresUp:          pgUp,
		StorageUp:           storeUp,
		Probed:              st.probe.probed,
		ProbeError:          st.probe.words(),
		LastSnapshot:        st.LastSnapshotID,
		TickSeconds:         int(tick / time.Second),
		ConsecutiveFailures: st.ConsecutiveFailures,
		LastError:           st.LastError,
		BackupReason:        st.BackupReason,
		DrillStatus:         st.DrillStatus,
		DrillReason:         st.DrillReason,
		DrillDetail:         st.DrillDetail,
		Schedule:            s.Schedule,
		RetentionDays:       s.RetentionDays,
	}, &resp)
	if status == http.StatusNotFound && st.ServerNodeID != "" && st.ServerNodeID == nodeID && nodeID != c.NodeID {
		// The surface's node is gone: retired in the console while this
		// daemon ran. Registering it again, next tick, hears why.
		st.ServerNodeID = ""
		return nil
	}
	if err != nil {
		// "Backups carry on" was false on hosted storage, which needs the
		// remote server for every upload; and a rejected token never said
		// which token or how to replace it.
		hint := "Backups to your own bucket carry on; hosted storage waits for the remote server. The console shows this host as silent if it persists."
		if strings.Contains(err.Error(), "HTTP 401") {
			hint = "This host's token was replaced or revoked in the console. Put the current one in with: safegrd enroll --token <node token from the console>"
		}
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: heartbeat failed (%v). %s\n", st.SurfaceID, err, hint)
		return nil
	}
	if resp.UpgradeAvailable {
		notifyUpgrade(resp.LatestCLIVersion)
	}
	return &resp
}

// storageReason reports whether a backup that failed for r could not write
// to its storage.
func storageReason(r model.BackupReason) bool {
	return r == model.BackupReasonStorage || r == model.BackupReasonNoDisk || r == model.BackupReasonQuota
}

// pendingDrill is a drill the remote server asked for this tick, run after
// every surface's backup.
type pendingDrill struct {
	surface    *config.SurfaceConfig
	state      *SurfaceState
	nodeID     string
	snapshotID string
	requestID  string // a "drill now" not yet run, or empty
	// stateDir holds a local sandbox's cluster, when the drill starts one.
	stateDir string
	// sandboxIncluded: the plan records sandbox drills, so a Postgres surface
	// with no drill.sandbox_url drills into a throwaway local cluster.
	sandboxIncluded bool
}

// drillMinSpacing is the least time between two unattended drill attempts of
// one surface, whatever the last one's outcome. A drill that passed but whose
// report never landed leaves the remote server asking again on every
// heartbeat; without this, each ask downloads the whole snapshot again. No
// plan drills more often than daily, so this never delays one that is due.
const drillMinSpacing = 6 * time.Hour

// drillBackoff is how long after a failed unattended drill the next is
// allowed: an hour, doubling, capped at a day. Each attempt downloads the
// whole snapshot, and the remote server keeps asking until a report lands.
func drillBackoff(failures int) time.Duration {
	d := time.Hour << min(failures, 5)
	if d > 24*time.Hour {
		d = 24 * time.Hour
	}
	return d
}

// daemonPrivateKey is the identity this host already holds, if any. The daemon
// never fetches or copies one to make a drill possible: every surface of an
// organization is sealed to one key, so a key on every host would let one
// compromised host read every other host's backups. Managed
// custody is the exception the customer chose.
func daemonPrivateKey(ctx context.Context, c *config.CLIConfig) string {
	if c.Encryption.PrivateKey != "" {
		return c.Encryption.PrivateKey
	}
	if v := strings.TrimSpace(os.Getenv("SAFEGRD_PRIVATE_KEY")); v != "" {
		return v
	}
	if c.Encryption.KeyPath != "" {
		if k, err := crypto.LoadPrivateKey(c.Encryption.KeyPath); err == nil {
			return k
		}
	}
	return resolveManagedIdentity(ctx, c, false)
}

// runUnattendedDrill proves d's snapshot restores and reports it. A database
// surface with drill.sandbox_url is restored into that scratch database for
// real and counted there. A Postgres surface without one, on a plan that
// records sandbox drills, is restored into a throwaway cluster this host
// starts, when it can; everything else is replayed in memory, and the report
// says which.
//
// d.requestID is a "drill now" not yet run: it goes ahead inside the usual
// spacing, once, because a person or a daemon asked for it.
func runUnattendedDrill(ctx context.Context, c *config.CLIConfig, d pendingDrill, save func()) {
	s, st, nodeID, snapshotID, requestID := d.surface, d.state, d.nodeID, d.snapshotID, d.requestID
	now := time.Now().UTC()
	if requestID != "" {
		st.LastDrillRequestID = requestID
		fmt.Printf("Surface %s: Fire Drill requested.\n", s.ID)
	} else if !st.LastDrillAttempt.IsZero() && !now.Before(st.LastDrillAttempt) {
		// (A last attempt in the future means the clock went backwards;
		// the spacing is not waited out from a time that has not happened.)
		wait := drillMinSpacing
		if st.DrillFailures > 0 && drillBackoff(st.DrillFailures) > wait {
			wait = drillBackoff(st.DrillFailures)
		}
		if now.Before(st.LastDrillAttempt.Add(wait)) {
			return
		}
	}
	key := daemonPrivateKey(ctx, c)
	if key == "" {
		if st.DrillStatus != model.DrillStatusNoKey {
			fmt.Fprintf(os.Stderr, "Warning: Surface %s: a Fire Drill is due and this host does not hold the private key.\n"+
				"   The daemon never copies it here. Run 'safegrd verify --snapshot %s' where the key is,\n"+
				"   or set key_path / SAFEGRD_PRIVATE_KEY on this host. The console shows this surface as unproven.\n", s.ID, snapshotID)
		}
		st.setDrill(model.DrillStatusNoKey, model.DrillReasonNoKey, "")
		// Looked again after the same spacing, not every tick: looking asks
		// the remote server for a managed identity each time.
		st.LastDrillAttempt = now
		return
	}
	st.LastDrillAttempt = now
	st.DrillInFlight = true
	save() // before the drill, so a drill that kills the process is not retried at once
	defer func() {
		st.DrillInFlight = false
		save()
	}()
	sandbox, sandboxErr := surfaceSandboxURL(ctx, c, s)
	keep := s.Drill != nil && s.Drill.KeepFailedSandbox
	if sandboxErr == nil && sandbox != "" && !st.SandboxKeptUntil.IsZero() {
		if now.Before(st.SandboxKeptUntil) {
			fmt.Fprintf(os.Stderr, "Warning: Surface %s: Fire Drill not run: its sandbox is kept after a failed drill until %s. "+
				"The first drill after that empties it.\n", s.ID, st.SandboxKeptUntil.Format(time.RFC3339))
			return
		}
		if err := runner.ResetKeptSandbox(ctx, sandbox, st.SandboxKeptRoles); err != nil {
			st.DrillFailures++
			st.setDrill(model.DrillStatusFailed, model.DrillReasonSandboxRefused, err.Error())
			fmt.Fprintf(os.Stderr, "Error: Surface %s: could not empty the sandbox kept after a failed drill: %v\n", s.ID, err)
			return
		}
		fmt.Printf("Surface %s: emptied the sandbox kept after the last failed drill.\n", s.ID)
		st.SandboxKeptUntil, st.SandboxKeptRoles = time.Time{}, nil
	}

	// The same storage the surface backs up to (runSurfaceBackup), or the
	// drill restores from somewhere its backups never went.
	storageCfg := c.Storage
	var err error
	if s.Storage != nil {
		storageCfg = *s.Storage
		err = checkSurfaceStorage(ctx, c, &storageCfg)
	} else {
		err = routeProjectSink(ctx, c, &storageCfg, false, false)
	}
	storageCfg.NodeID = nodeID
	// Hosted storage: a read lease, which is never refused for quota.
	if err == nil {
		_, err = resolveHostedStorage(ctx, c, &storageCfg, false)
	}
	var provider storage.StorageProvider
	if err == nil {
		applyHeldSinkKey(ctx, c, &storageCfg)
		provider, err = openStorage(ctx, c, storageCfg)
	}
	if err != nil {
		st.DrillFailures++
		st.setDrill(model.DrillStatusFailed, model.DrillReasonStorage, err.Error())
		fmt.Fprintf(os.Stderr, "Error: Surface %s: Fire Drill could not open storage: %v\n", s.ID, err)
		return
	}
	verifier := runner.NewVerifier(provider, c.ServerURL)
	verifier.SetServerToken(c.ServerToken)
	verifier.KeepFailedSandbox = keep
	var report *model.VerificationReport
	how := "in-memory restore"
	// A surface whose last snapshot is still an archive from before it was
	// incremental takes the archive's drill.
	var rs *repoSnapshot
	// A PostgreSQL or SQLite surface is a run of its repository unless it
	// says format: tar.
	notTar := !strings.EqualFold(strings.TrimSpace(s.Format), formatTar)
	if notTar && (strings.EqualFold(s.Type, "files") || surfaceIsPostgres(s) || strings.EqualFold(s.Type, "sqlite") || strings.TrimSpace(s.Type) == "") {
		rs = repoDrillTarget(ctx, c, storageCfg, snapshotID)
	}
	dbRun := rs != nil && runner.IsRepoDatabase(rs.Meta)
	var local *runner.LocalPostgres
	// shallow is why this drill is shallower than the plan's, said on the
	// heartbeat as well as here: the report alone reads as a passing drill.
	var shallow model.DrillReason
	var shallowWhy string
	if sandboxErr == nil && sandbox == "" && d.sandboxIncluded && surfaceIsPostgres(s) {
		var why error
		var known *model.SnapshotMetadata
		if dbRun {
			known = rs.Meta
		}
		if local, shallow, why = startLocalSandbox(ctx, provider, snapshotID, known, d.stateDir); why != nil {
			shallowWhy = why.Error()
			fmt.Fprintf(os.Stderr, "Warning: Surface %s: drilling in memory, not in a local sandbox: %v\n", s.ID, why)
		} else if local != nil {
			defer func() {
				if report == nil || !report.SandboxKept {
					local.Stop()
				}
			}()
		}
	}
	switch {
	case sandboxErr != nil:
		err = sandboxErr
	case local != nil:
		how = "restore into a throwaway PostgreSQL " + local.Server.Version + " on this host"
		fmt.Printf("Surface %s: Fire Drill due: restoring snapshot %s into a throwaway PostgreSQL %s on this host.\n",
			s.ID, snapshotID, local.Server.Version)
		// The cluster is deleted after the drill, so it is not emptied.
		if dbRun {
			report, err = verifier.RunRepoDatabaseDrill(ctx, runner.RepoDrill{Backend: rs.Backend, Epoch: rs.Epoch, Meta: rs.Meta}, key, local.URL)
		} else {
			report, err = verifier.RunFireDrill(ctx, snapshotID, key, local.URL)
		}
	case sandbox != "":
		how = "restore into the sandbox database"
		fmt.Printf("Surface %s: Fire Drill due: restoring snapshot %s into its sandbox database.\n", s.ID, snapshotID)
		if dbRun {
			report, err = verifier.RunRepoSandboxDrill(ctx, runner.RepoDrill{Backend: rs.Backend, Epoch: rs.Epoch, Meta: rs.Meta}, key, sandbox)
		} else {
			report, err = verifier.RunSandboxDrill(ctx, snapshotID, key, sandbox)
		}
	case rs != nil:
		// A repository snapshot is proven by restoring every file and
		// recomputing its content root from what landed on disk.
		// A database run is decrypted and checked table by table in
		// memory, not loaded anywhere: the record says in memory, and so
		// does this line (it said "full restore" right after a warning
		// that the drill would run in memory).
		how = "full restore"
		if dbRun {
			how = "in-memory restore"
			// A SQLite run is written out to a scratch file and opened,
			// which is the whole of a SQLite restore; the server counts it
			// as one, and this line said "in-memory" over it.
			if rs.Meta.SurfaceType == model.SurfaceTypeSQLite {
				how = "restore to a scratch file"
			}
		}
		fmt.Printf("Surface %s: Fire Drill due: restoring snapshot %s and recomputing its content root.\n", s.ID, snapshotID)
		report, err = verifier.RunRepoDrill(ctx, runner.RepoDrill{Backend: rs.Backend, Epoch: rs.Epoch, Meta: rs.Meta,
			Scratch: drillScratchIn(d.stateDir)}, key)
	default:
		fmt.Printf("Surface %s: Fire Drill due: restoring snapshot %s in memory.\n", s.ID, snapshotID)
		report, _, err = verifier.RunDryRestore(ctx, snapshotID, key)
	}
	if report != nil && report.SandboxKept {
		sayKeptSandbox(s, st, local, sandbox, verifier.CreatedRoles())
	}
	var blocked *runner.DrillBlockedError
	switch {
	case errors.As(err, &blocked):
		// Not a failure: nothing was learned about the backup. It is tried
		// again after the usual spacing.
		reason := model.DrillReasonOther
		if errors.Is(err, diskspace.ErrNotEnoughDisk) {
			reason = model.DrillReasonNoDisk
		}
		st.setDrill(model.DrillStatusBlocked, reason, blocked.Error())
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: Fire Drill not run: %v\n", s.ID, blocked)
	case sandboxErr != nil:
		st.DrillFailures++
		st.setDrill(model.DrillStatusFailed, model.DrillReasonSandboxRefused, err.Error())
		fmt.Fprintf(os.Stderr, "Error: Surface %s: Fire Drill could not run: %v\n", s.ID, err)
	case err != nil:
		st.DrillFailures++
		st.setDrill(model.DrillStatusFailed, model.DrillReasonRestoreFailed, err.Error())
		fmt.Fprintf(os.Stderr, "Error: Surface %s: Fire Drill could not run: %v\n", s.ID, err)
	case report.Status != model.VerificationStatusPassed:
		st.DrillFailures++
		st.setDrill(model.DrillStatusFailed, failedDrillReason(report), report.ErrorMessage)
		fmt.Fprintf(os.Stderr, "Error: Surface %s: Fire Drill FAILED for %s: %s\n", s.ID, snapshotID, report.ErrorMessage)
	default:
		st.DrillFailures = 0
		if shallow != "" {
			st.setDrill(model.DrillStatusShallow, shallow, shallowWhy)
		} else {
			st.setDrill(model.DrillStatusPassed, "", "")
		}
		st.LastDrillSnapshotID = snapshotID
		fmt.Printf("Surface %s: Fire Drill passed (%s of %s, certificate %s).\n", s.ID, how, snapshotID, report.CertificateHash)
	}
}

// keptSandboxFor is how long a failed drill's sandbox is kept.
const keptSandboxFor = 24 * time.Hour

// sayKeptSandbox records and says where a failed drill's sandbox was kept.
// A local cluster keeps running until the sweep removes it; a sandbox_url
// database is emptied by the first drill after the day is up.
func sayKeptSandbox(s *config.SurfaceConfig, st *SurfaceState, local *runner.LocalPostgres, sandbox string, roles []string) {
	until := time.Now().UTC().Add(keptSandboxFor)
	switch {
	case local != nil:
		if err := local.Keep(until); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Surface %s: could not keep the failed drill's sandbox: %v\n", s.ID, err)
			return
		}
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: sandbox kept at %q (data in %s) until %s, then removed.\n"+
			"   Look at it with: psql %q\n", s.ID, local.URL, local.DataDir(), until.Format(time.RFC3339), local.URL)
	case sandbox != "":
		st.SandboxKeptUntil, st.SandboxKeptRoles = until, roles
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: sandbox kept at %s until %s; the first drill after that empties it.\n",
			s.ID, dump.RedactURL(sandbox), until.Format(time.RFC3339))
	}
}

// recordedNodeID is the node the remote server recorded snapshotID under, or
// "" when it cannot say. A surface's snapshots live under its own node, not
// the host's, so restore and verify ask before looking in the bucket.
func recordedNodeID(ctx context.Context, c *config.CLIConfig, snapshotID string) string {
	if rec := recordedSnapshot(ctx, c, snapshotID); rec != nil {
		return rec.NodeID
	}
	return ""
}

// recordedSnapshot is the remote server's record of a snapshot, or nil when
// this host cannot ask or the server has none.
func recordedSnapshot(ctx context.Context, c *config.CLIConfig, snapshotID string) *model.SnapshotMetadata {
	if !canReport(c) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.ServerURL, "/")+"/api/v1/snapshots/"+url.PathEscape(snapshotID), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var rec model.SnapshotMetadata
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rec) != nil || rec.SnapshotID != snapshotID {
		return nil
	}
	return &rec
}

// surfaceIsPostgres reports whether s backs up a PostgreSQL database.
func surfaceIsPostgres(s *config.SurfaceConfig) bool {
	return model.SurfaceType(strings.ToLower(s.Type)) == model.SurfaceTypePostgres
}

// startLocalSandbox starts a throwaway cluster for the snapshot's drill, or
// says why it cannot, as a reason and in words: no PostgreSQL server here,
// one older than the snapshot's, no room on the disk, or an extension the
// snapshot uses that the server lacks.
// A drill that cannot have one replays the snapshot in memory instead: a
// restore that failed for one of these reasons would report the backup as
// broken when the host was the problem.
func startLocalSandbox(ctx context.Context, provider storage.StorageProvider, snapshotID string, known *model.SnapshotMetadata, stateDir string) (*runner.LocalPostgres, model.DrillReason, error) {
	// A run's sidecar is in its repository, read already; an archive's is
	// beside the archive.
	meta := known
	if meta == nil {
		var err error
		if meta, err = provider.DownloadMetadata(ctx, snapshotID); err != nil {
			return nil, model.DrillReasonManifestUnreadable, fmt.Errorf("cannot read the snapshot's manifest: %w", err)
		}
	}
	if meta.SurfaceType != "" && meta.SurfaceType != model.SurfaceTypePostgres {
		return nil, "", nil
	}
	srv, err := runner.FindPgServer(ctx, runner.SourceMajor(meta))
	switch {
	case errors.Is(err, runner.ErrNoPgServer):
		return nil, model.DrillReasonNoPostgresServer, err
	case errors.Is(err, runner.ErrPgServerBroken):
		return nil, model.DrillReasonPostgresServerBroken, err
	case errors.Is(err, runner.ErrPgServerTooOld):
		return nil, model.DrillReasonPostgresServerOld, err
	case err != nil:
		return nil, model.DrillReasonSandboxStartFailed, err
	}
	lp, err := runner.StartLocalPostgres(ctx, srv, stateDir, runner.SandboxBytesNeeded(meta))
	if errors.Is(err, diskspace.ErrNotEnoughDisk) {
		return nil, model.DrillReasonSandboxNoDisk, err
	} else if err != nil {
		return nil, model.DrillReasonSandboxStartFailed, err
	}
	missing, err := lp.MissingExtensions(ctx, meta.Extensions)
	if err != nil {
		lp.Stop()
		return nil, model.DrillReasonSandboxStartFailed, err
	}
	if len(missing) > 0 {
		lp.Stop()
		return nil, model.DrillReasonMissingExtensions, fmt.Errorf("the snapshot uses %s, which this host's PostgreSQL %s does not have; install them for %s, "+
			"or point drill.sandbox_url at a database that has them", strings.Join(missing, ", "), srv.Version, srv.BinDir)
	}
	return lp, "", nil
}

// failedDrillReason tells a drill whose data did not match the manifest from
// one that did not restore at all.
func failedDrillReason(report *model.VerificationReport) model.DrillReason {
	for _, a := range report.Assertions {
		if !a.Passed {
			return model.DrillReasonAssertionsFailed
		}
	}
	return model.DrillReasonRestoreFailed
}

// surfaceSandboxURL is the scratch database a Postgres surface drills into, or
// "" for an in-memory drill. A sandbox that is the surface's own database is
// refused here, before anything connects to it: a drill restores into its
// sandbox, and that one would be a restore over production.
func surfaceSandboxURL(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (string, error) {
	if s.Drill == nil || !model.SurfaceType(strings.ToLower(s.Type)).IsDatabase() {
		return "", nil
	}
	url := s.Drill.SandboxURL
	if url == "" && s.Drill.SandboxURLEnv != "" {
		url = os.Getenv(s.Drill.SandboxURLEnv)
	}
	resolved, err := resolveConfigSecret("drill.sandbox_url", url)
	if err != nil || resolved == "" {
		return "", err
	}
	source, err := resolveSurfaceDatabaseURL(ctx, c, s)
	if err != nil {
		return "", fmt.Errorf("refusing to drill: cannot tell whether the sandbox is surface %s's own database: %w", s.ID, err)
	}
	if runner.SameDatabase(resolved, source) {
		return "", fmt.Errorf("refusing to drill: surface %s's drill.sandbox_url is the database it backs up. "+
			"A drill restores into its sandbox; point it at a separate, empty database", s.ID)
	}
	return resolved, nil
}

// repoDrillTarget finds snapshotID in the surface's repository, or nil when
// it is not a repository snapshot (or the repository cannot be read, which
// the archive drill then reports).
func repoDrillTarget(ctx context.Context, c *config.CLIConfig, storageCfg config.StorageConfig, snapshotID string) *repoSnapshot {
	rb, err := repoBackend(ctx, c, storageCfg)
	if err != nil {
		return nil
	}
	rs, err := findRepoSnapshot(ctx, rb, snapshotID)
	if err != nil {
		return nil
	}
	return rs
}
