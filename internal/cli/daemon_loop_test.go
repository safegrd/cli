package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// fakeRemoteServer answers the daemon's calls and counts backups and drills.
type fakeRemoteServer struct {
	mu        sync.Mutex
	trigger   bool   // HeartbeatResponse.TriggerBackup
	requestID string // HeartbeatResponse.BackupRequestID
	snapshots int

	paused       bool   // HeartbeatResponse.Paused
	down         bool   // heartbeats answered 503, as when the server cannot be reached
	drill        bool   // ask for a drill of the last snapshot on every heartbeat
	lastSnapshot string // the last snapshot the daemon reported
	drillReports int    // POST /api/v1/verifications, each answered 500
	// records and reports are the snapshot records and drill reports the
	// daemon sent, as the real server would read them.
	records []model.SnapshotMetadata
	reports []model.VerificationReport
	// events is every heartbeat and snapshot in the order they arrived:
	// "beat", "beat:running" for one that says a backup is starting, and
	// "snapshot".
	events []string
}

func (f *fakeRemoteServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// As the real server: no node token, no answer.
	if r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/api/v1/nodes/host-1/surfaces":
		_ = json.NewEncoder(w).Encode(model.SurfaceRegisterResponse{NodeID: "host-1--docs"})
	case "/api/v1/nodes/heartbeat":
		if f.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		var beat model.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&beat)
		if beat.BackupRunning {
			f.events = append(f.events, "beat:running")
		} else {
			f.events = append(f.events, "beat")
		}
		resp := model.HeartbeatResponse{Acknowledge: true, TriggerBackup: f.trigger, BackupRequestID: f.requestID, Paused: f.paused}
		if f.drill && f.lastSnapshot != "" {
			resp.TriggerFireDrill, resp.DrillSnapshotID, resp.FireDrillsIncluded = true, f.lastSnapshot, true
		}
		_ = json.NewEncoder(w).Encode(resp)
	case "/api/v1/verifications":
		var rep model.VerificationReport
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, `{"error":"not a report"}`, http.StatusBadRequest)
			return
		}
		f.reports = append(f.reports, rep)
		f.drillReports++
		http.Error(w, "the report never lands", http.StatusInternalServerError)
	case "/api/v1/snapshots":
		var meta model.SnapshotMetadata
		// The real server refuses a record it cannot read, or one that
		// names no snapshot or another node than the surface's.
		if err := json.NewDecoder(r.Body).Decode(&meta); err != nil || meta.SnapshotID == "" || meta.NodeID != "host-1--docs" {
			http.Error(w, `{"error":"bad snapshot record"}`, http.StatusBadRequest)
			return
		}
		f.records = append(f.records, meta)
		f.lastSnapshot = meta.SnapshotID
		f.snapshots++
		f.events = append(f.events, "snapshot")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("{}"))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeRemoteServer) set(trigger bool, requestID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trigger, f.requestID = trigger, requestID
}

// lastRecord is the last snapshot record the daemon sent.
func (f *fakeRemoteServer) lastRecord(t *testing.T) model.SnapshotMetadata {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.records) == 0 {
		t.Fatal("the daemon sent no snapshot record")
	}
	return f.records[len(f.records)-1]
}

func (f *fakeRemoteServer) backups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshots
}

// TriggerBackup is true whenever the remote server has not heard of a recent
// success, including when this host's report of one was lost. A daemon that
// obeyed it would back up on every tick, and under Object Lock every one of
// those is an object nobody can delete. Only a
// one-shot request id starts an unscheduled backup, and each id runs once.
func TestTheDaemonIgnoresTriggerBackupAndRunsARequestOnce(t *testing.T) {
	forgetWhatTheDaemonSaid(t)
	fake := &fakeRemoteServer{}
	ts := httptest.NewServer(fake)
	defer ts.Close()

	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &config.CLIConfig{
		ServerURL:   ts.URL,
		ServerToken: "tok",
		NodeID:      "host-1",
		Storage:     config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: filepath.Join(dir, "worm"), RetentionDays: 1},
		Encryption:  config.EncryptionConfig{PublicKey: id.Recipient().String()},
		Surfaces:    []config.SurfaceConfig{{ID: "docs", Type: "files", Format: "tar", Schedule: "@daily", Roots: []string{tree}}},
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The daemon keeps what it registered across ticks.
	registered := map[string]bool{}
	tick := func() {
		t.Helper()
		if err := reconcileSurfaces(context.Background(), c, stateDir, time.Minute, registered); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}

	tick() // never backed up: due
	if got := fake.backups(); got != 1 {
		t.Fatalf("first tick backed up %d times, want 1", got)
	}
	// The remote server hears that the backup is starting before the
	// snapshot arrives, so the console can show it running meanwhile.
	fake.mu.Lock()
	events := strings.Join(fake.events, " ")
	fake.mu.Unlock()
	if events != "beat beat:running snapshot" {
		t.Fatalf("the first tick's calls were %q, want the heartbeat, one saying the backup is starting, then the snapshot", events)
	}
	// The sidecar records no lock: worm_mode defaults to COMPLIANCE, and a
	// directory on the host has no Object Lock to apply it.
	prov, err := openStorage(context.Background(), c, c.Storage)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := prov.ListSnapshots(context.Background())
	if err != nil || len(ids) != 1 {
		t.Fatalf("snapshots in the directory: %v, %v", ids, err)
	}
	if s, ok := prov.(interface{ SetNodeID(string) }); ok {
		s.SetNodeID("host-1--docs") // the surface's own node, as the fake registers it
	}
	meta, err := prov.DownloadMetadata(context.Background(), ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if meta.WORMMode != string(config.WORMModeNone) || meta.WORMRetentionUntil.IsZero() {
		t.Fatalf("a snapshot in a directory recorded worm_mode %q until %s, want NONE with its keep date", meta.WORMMode, meta.WORMRetentionUntil)
	}
	// The record the remote server got says the same as the sidecar.
	if rec := fake.lastRecord(t); rec.SnapshotID != ids[0] || rec.WORMMode != string(config.WORMModeNone) || rec.Status != model.SnapshotStatusCompleted {
		t.Fatalf("the snapshot record sent was %s, worm_mode %q, status %q; want %s, NONE, completed", rec.SnapshotID, rec.WORMMode, rec.Status, ids[0])
	}

	fake.set(true, "") // the remote server thinks it is overdue
	tick()
	tick()
	if got := fake.backups(); got != 1 {
		t.Fatalf("the daemon obeyed TriggerBackup: %d backups after two ticks of it, want 1", got)
	}

	fake.set(true, "req-1")
	tick()
	tick()
	tick()
	if got := fake.backups(); got != 2 {
		t.Fatalf("a backup request ran %d times over three ticks, want once", got-1)
	}

	fake.set(false, "req-2")
	tick()
	if got := fake.backups(); got != 3 {
		t.Fatalf("a second, different request did not run: %d backups", got)
	}
}

// A surface paused in the console takes no scheduled backup, also while the
// remote server cannot be reached, and a backup requested from the console
// still runs. Resumed, the backup that was due runs on the next tick.
func TestThePausedSurfaceTakesNoScheduledBackup(t *testing.T) {
	forgetWhatTheDaemonSaid(t)
	fake := &fakeRemoteServer{paused: true}
	ts := httptest.NewServer(fake)
	defer ts.Close()

	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &config.CLIConfig{
		ServerURL:   ts.URL,
		ServerToken: "tok",
		NodeID:      "host-1",
		Storage:     config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: filepath.Join(dir, "worm"), RetentionDays: 1},
		Encryption:  config.EncryptionConfig{PublicKey: id.Recipient().String()},
		Surfaces:    []config.SurfaceConfig{{ID: "docs", Type: "files", Format: "tar", Schedule: "@hourly", Roots: []string{tree}}},
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The daemon keeps what it registered across ticks.
	registered := map[string]bool{}
	tick := func() {
		t.Helper()
		if err := reconcileSurfaces(context.Background(), c, stateDir, time.Minute, registered); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}

	tick() // never backed up, so due, but paused
	if got := fake.backups(); got != 0 {
		t.Fatalf("a paused surface backed up %d times on schedule", got)
	}
	fake.mu.Lock()
	fake.down = true
	fake.mu.Unlock()
	tick()
	if got := fake.backups(); got != 0 {
		t.Fatalf("a paused surface backed up %d times while the server was unreachable", got)
	}
	fake.mu.Lock()
	fake.down = false
	fake.mu.Unlock()

	fake.set(false, "req-1")
	tick()
	if got := fake.backups(); got != 1 {
		t.Fatalf("a backup requested while paused ran %d times, want once", got)
	}

	// Resumed, and the request's backup made an hour ago: due again.
	statePath := filepath.Join(stateDir, "daemon_state.json")
	state := loadDaemonState(statePath)
	st := state.Surfaces["docs"]
	st.LastSuccess, st.LastAttempt = st.LastSuccess.Add(-2*time.Hour), st.LastAttempt.Add(-2*time.Hour)
	if err := saveDaemonState(statePath, state); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.paused = false
	fake.mu.Unlock()
	tick()
	if got := fake.backups(); got != 2 {
		t.Fatalf("after resuming, the due backup did not run: %d backups", got)
	}

	// The control for the unreachable half above: a surface that is not
	// paused and is due backs up while heartbeats fail, so the zero backups
	// there came from the pause it remembered.
	state = loadDaemonState(statePath)
	st = state.Surfaces["docs"]
	st.LastSuccess, st.LastAttempt = st.LastSuccess.Add(-2*time.Hour), st.LastAttempt.Add(-2*time.Hour)
	if err := saveDaemonState(statePath, state); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.down = true
	fake.mu.Unlock()
	tick()
	if got := fake.backups(); got != 3 {
		t.Fatalf("an unpaused, due surface did not back up while the remote server was unreachable: %d backups", got)
	}
}

// A drill that passes but whose report never lands leaves the remote server
// asking for it on every heartbeat. Each attempt downloads the whole snapshot,
// so the daemon must not drill again every tick however often it is asked.
func TestALostDrillReportDoesNotBecomeADrillEveryTick(t *testing.T) {
	forgetWhatTheDaemonSaid(t)
	fake := &fakeRemoteServer{drill: true}
	ts := httptest.NewServer(fake)
	defer ts.Close()

	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "daemon.key")
	if err := os.WriteFile(keyPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &config.CLIConfig{
		ServerURL:   ts.URL,
		ServerToken: "tok",
		NodeID:      "host-1",
		Storage:     config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: filepath.Join(dir, "worm"), RetentionDays: 1},
		Encryption:  config.EncryptionConfig{PublicKey: id.Recipient().String(), KeyPath: keyPath},
		Surfaces:    []config.SurfaceConfig{{ID: "docs", Type: "files", Format: "tar", Schedule: "@daily", Roots: []string{tree}}},
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	var errs []error
	stderr := captureStderr(t, func() {
		for i := 0; i < 5; i++ {
			errs = append(errs, reconcileSurfaces(context.Background(), c, stateDir, time.Minute, registered))
		}
	})
	for i, err := range errs {
		if err != nil {
			t.Errorf("tick %d: %v", i+1, err)
		}
	}
	fake.mu.Lock()
	reports := append([]model.VerificationReport(nil), fake.reports...)
	fake.mu.Unlock()
	if len(reports) != 1 {
		t.Fatalf("the daemon drilled %d times in five ticks while every report was lost, want 1", len(reports))
	}
	if reports[0].Status != model.VerificationStatusPassed || reports[0].SnapshotID != fake.lastSnapshot {
		t.Fatalf("the drill reported %q for %s; want a pass of %s", reports[0].Status, reports[0].SnapshotID, fake.lastSnapshot)
	}
	// The host says the report was lost: the console will not show the drill.
	if !strings.Contains(stderr, "NOT RECORDED") || !strings.Contains(stderr, "HTTP 500") {
		t.Errorf("a drill report the remote server refused was not said on stderr:\n%s", stderr)
	}

	// A drill that took the process down is found at the next start and
	// counted as a failure, rather than started again at once.
	st := loadDaemonState(filepath.Join(stateDir, "daemon_state.json"))
	st.Surfaces["docs"].DrillInFlight = true
	if err := saveDaemonState(filepath.Join(stateDir, "daemon_state.json"), st); err != nil {
		t.Fatal(err)
	}
	_ = captureStderr(t, func() {
		if err := reconcileSurfaces(context.Background(), c, stateDir, time.Minute, registered); err != nil {
			t.Errorf("the tick after an interrupted drill: %v", err)
		}
	})
	st = loadDaemonState(filepath.Join(stateDir, "daemon_state.json"))
	if got := st.Surfaces["docs"]; got.DrillInFlight || got.DrillFailures != 1 || got.DrillStatus != model.DrillStatusFailed {
		t.Errorf("an interrupted drill: in_flight=%t failures=%d status=%q, want it counted as one failure",
			got.DrillInFlight, got.DrillFailures, got.DrillStatus)
	}
}
