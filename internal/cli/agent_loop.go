package cli

// The reporting half of the agent:
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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/runner"
	"github.com/safegrd/cli/pkg/storage"
)

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
// per agent process, so a changed schedule or name in the config reaches the
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
	_, err := postJSON(ctx, c, "/api/v1/nodes/"+url.PathEscape(c.NodeID)+"/surfaces", model.SurfaceRegisterRequest{
		SurfaceID:     s.ID,
		Name:          s.Name,
		SurfaceType:   model.SurfaceType(strings.ToLower(s.Type)),
		SurfaceRef:    surfaceRef(s),
		Schedule:      s.Schedule,
		RetentionDays: retention,
		PublicKey:     pub,
	}, &resp)
	if err != nil || resp.NodeID == "" {
		// The backup still runs. Its report will be refused, and the backup
		// path says so; this says why.
		fmt.Fprintf(os.Stderr, "⚠️  Surface %s: could not register it with the remote server (%v).\n"+
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
func sendHeartbeat(ctx context.Context, c *config.CLIConfig, nodeID string, st *SurfaceState, tick time.Duration) *model.HeartbeatResponse {
	if !canReport(c) {
		return nil
	}
	var resp model.HeartbeatResponse
	_, err := postJSON(ctx, c, "/api/v1/nodes/heartbeat", model.HeartbeatRequest{
		NodeID:              nodeID,
		CLI_Version:         Version,
		PostgresUp:          st.ConsecutiveFailures == 0,
		StorageUp:           st.ConsecutiveFailures == 0,
		LastSnapshot:        st.LastSnapshotID,
		TickSeconds:         int(tick / time.Second),
		ConsecutiveFailures: st.ConsecutiveFailures,
		LastError:           st.LastError,
		DrillStatus:         st.DrillStatus,
	}, &resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Surface %s: heartbeat failed (%v). Backups carry on; the console will show this host as silent if it persists.\n", st.SurfaceID, err)
		return nil
	}
	return &resp
}

// pendingDrill is a drill the remote server asked for this tick, run after
// every surface's backup.
type pendingDrill struct {
	surface    *config.SurfaceConfig
	state      *SurfaceState
	nodeID     string
	snapshotID string
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

// agentPrivateKey is the identity this host already holds, if any. The agent
// never fetches or copies one to make a drill possible: every surface of an
// organization is sealed to one key, so a key on every host would let one
// compromised host read every other host's backups. Managed
// custody is the exception the customer chose.
func agentPrivateKey(ctx context.Context, c *config.CLIConfig) string {
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

// runUnattendedDrill proves snapshotID restores and reports it. A Postgres
// surface with drill.sandbox_url is restored into that scratch database for
// real and counted there; everything else is replayed in memory, and
// the report says which.
func runUnattendedDrill(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, st *SurfaceState, nodeID, snapshotID string, save func()) {
	now := time.Now().UTC()
	if !st.LastDrillAttempt.IsZero() {
		wait := drillMinSpacing
		if st.DrillFailures > 0 && drillBackoff(st.DrillFailures) > wait {
			wait = drillBackoff(st.DrillFailures)
		}
		if now.Before(st.LastDrillAttempt.Add(wait)) {
			return
		}
	}
	key := agentPrivateKey(ctx, c)
	if key == "" {
		if st.DrillStatus != model.DrillStatusNoKey {
			fmt.Fprintf(os.Stderr, "⚠️  Surface %s: a Fire Drill is due and this host does not hold the private key.\n"+
				"   The agent never copies it here. Run 'safegrd verify --snapshot %s' where the key is,\n"+
				"   or set key_path / SAFEGRD_PRIVATE_KEY on this host. The console shows this surface as unproven.\n", s.ID, snapshotID)
		}
		st.DrillStatus = model.DrillStatusNoKey
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

	storageCfg := c.Storage
	if s.Storage != nil {
		storageCfg = *s.Storage
	}
	storageCfg.NodeID = nodeID
	// Hosted storage: a read lease, which is never refused for quota.
	_, err := resolveHostedStorage(ctx, c, &storageCfg, false)
	var provider storage.StorageProvider
	if err == nil {
		provider, err = storage.NewProvider(ctx, storageCfg)
	}
	if err != nil {
		st.DrillFailures++
		st.DrillStatus = model.DrillStatusFailed
		fmt.Fprintf(os.Stderr, "❌ Surface %s: Fire Drill could not open storage: %v\n", s.ID, err)
		return
	}
	verifier := runner.NewVerifier(provider, c.ServerURL)
	verifier.SetServerToken(c.ServerToken)
	var report *model.VerificationReport
	how := "in-memory restore"
	switch {
	case sandboxErr != nil:
		err = sandboxErr
	case sandbox != "":
		how = "restore into the sandbox database"
		fmt.Printf("🔥 Surface %s: Fire Drill due — restoring snapshot %s into its sandbox database.\n", s.ID, snapshotID)
		report, err = verifier.RunSandboxDrill(ctx, snapshotID, key, sandbox)
	default:
		fmt.Printf("🔥 Surface %s: Fire Drill due — restoring snapshot %s in memory.\n", s.ID, snapshotID)
		report, _, err = verifier.RunDryRestore(ctx, snapshotID, key)
	}
	switch {
	case err != nil:
		st.DrillFailures++
		st.DrillStatus = model.DrillStatusFailed
		fmt.Fprintf(os.Stderr, "❌ Surface %s: Fire Drill could not run: %v\n", s.ID, err)
	case report.Status != model.VerificationStatusPassed:
		st.DrillFailures++
		st.DrillStatus = model.DrillStatusFailed
		fmt.Fprintf(os.Stderr, "❌ Surface %s: Fire Drill FAILED for %s: %s\n", s.ID, snapshotID, report.ErrorMessage)
	default:
		st.DrillFailures = 0
		st.DrillStatus = ""
		st.LastDrillSnapshotID = snapshotID
		fmt.Printf("✅ Surface %s: Fire Drill passed (%s of %s, certificate %s).\n", s.ID, how, snapshotID, report.CertificateHash)
	}
}

// recordedNodeID is the node the remote server recorded snapshotID under, or
// "" when it cannot say. A surface's snapshots live under its own node, not
// the host's, so restore and verify ask before looking in the bucket.
func recordedNodeID(ctx context.Context, c *config.CLIConfig, snapshotID string) string {
	if !canReport(c) {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.ServerURL, "/")+"/api/v1/snapshots/"+url.PathEscape(snapshotID), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var rec model.SnapshotMetadata
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rec) != nil || rec.SnapshotID != snapshotID {
		return ""
	}
	return rec.NodeID
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
	resolved, err := ResolveSecretRef("drill.sandbox_url", url)
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
