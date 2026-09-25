package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// fakeRemoteServer answers the agent's calls and counts backups and drills.
type fakeRemoteServer struct {
	mu        sync.Mutex
	trigger   bool   // HeartbeatResponse.TriggerBackup
	requestID string // HeartbeatResponse.BackupRequestID
	snapshots int

	drill        bool   // ask for a drill of the last snapshot on every heartbeat
	lastSnapshot string // the last snapshot the agent reported
	drillReports int    // POST /api/v1/verifications, each answered 500
}

func (f *fakeRemoteServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/api/v1/nodes/host-1/surfaces":
		_ = json.NewEncoder(w).Encode(model.SurfaceRegisterResponse{NodeID: "host-1--docs"})
	case "/api/v1/nodes/heartbeat":
		resp := model.HeartbeatResponse{Acknowledge: true, TriggerBackup: f.trigger, BackupRequestID: f.requestID}
		if f.drill && f.lastSnapshot != "" {
			resp.TriggerFireDrill, resp.DrillSnapshotID, resp.FireDrillsIncluded = true, f.lastSnapshot, true
		}
		_ = json.NewEncoder(w).Encode(resp)
	case "/api/v1/verifications":
		f.drillReports++
		http.Error(w, "the report never lands", http.StatusInternalServerError)
	case "/api/v1/snapshots":
		var meta model.SnapshotMetadata
		_ = json.NewDecoder(r.Body).Decode(&meta)
		f.lastSnapshot = meta.SnapshotID
		f.snapshots++
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

func (f *fakeRemoteServer) backups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshots
}

// TriggerBackup is true whenever the remote server has not heard of a recent
// success, including when this host's report of one was lost. An agent that
// obeyed it would back up on every tick, and under Object Lock every one of
// those is an object nobody can delete. Only a
// one-shot request id starts an unscheduled backup, and each id runs once.
func TestTheAgentIgnoresTriggerBackupAndRunsARequestOnce(t *testing.T) {
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
		Surfaces:    []config.SurfaceConfig{{ID: "docs", Type: "files", Schedule: "@daily", Roots: []string{tree}}},
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	tick := func() {
		t.Helper()
		if err := reconcileSurfaces(context.Background(), c, stateDir, time.Minute, map[string]bool{}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}

	tick() // never backed up: due
	if got := fake.backups(); got != 1 {
		t.Fatalf("first tick backed up %d times, want 1", got)
	}

	fake.set(true, "") // the remote server thinks it is overdue
	tick()
	tick()
	if got := fake.backups(); got != 1 {
		t.Fatalf("the agent obeyed TriggerBackup: %d backups after two ticks of it, want 1", got)
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

// A drill that passes but whose report never lands leaves the remote server
// asking for it on every heartbeat. Each attempt downloads the whole snapshot,
// so the agent must not drill again every tick however often it is asked.
func TestALostDrillReportDoesNotBecomeADrillEveryTick(t *testing.T) {
	fake := &fakeRemoteServer{drill: true}
	ts := httptest.NewServer(fake)
	defer ts.Close()

	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "agent.key")
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
		Surfaces:    []config.SurfaceConfig{{ID: "docs", Type: "files", Schedule: "@daily", Roots: []string{tree}}},
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_ = reconcileSurfaces(context.Background(), c, stateDir, time.Minute, map[string]bool{})
	}
	fake.mu.Lock()
	reports := fake.drillReports
	fake.mu.Unlock()
	if reports != 1 {
		t.Fatalf("the agent drilled %d times in five ticks while every report was lost, want 1", reports)
	}

	// A drill that took the process down is found at the next start and
	// counted as a failure, rather than started again at once.
	st := loadAgentState(filepath.Join(stateDir, "agent_state.json"))
	st.Surfaces["docs"].DrillInFlight = true
	if err := saveAgentState(filepath.Join(stateDir, "agent_state.json"), st); err != nil {
		t.Fatal(err)
	}
	_ = reconcileSurfaces(context.Background(), c, stateDir, time.Minute, map[string]bool{})
	st = loadAgentState(filepath.Join(stateDir, "agent_state.json"))
	if got := st.Surfaces["docs"]; got.DrillInFlight || got.DrillFailures != 1 || got.DrillStatus != model.DrillStatusFailed {
		t.Errorf("an interrupted drill: in_flight=%t failures=%d status=%q, want it counted as one failure",
			got.DrillInFlight, got.DrillFailures, got.DrillStatus)
	}
}
