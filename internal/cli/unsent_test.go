package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// A host offline for months keeps at most maxUnsentPerSurface records, the
// newest, so its state file does not grow without bound.
func TestUnsentRecordsAreCapped(t *testing.T) {
	st := &SurfaceState{SurfaceID: "db"}
	for i := 0; i < maxUnsentPerSurface+3; i++ {
		keepUnsent(st, &model.SnapshotMetadata{SnapshotID: fmt.Sprintf("snap-%d", i)}, "down")
	}
	if len(st.Unsent) != maxUnsentPerSurface {
		t.Fatalf("kept %d records, want %d", len(st.Unsent), maxUnsentPerSurface)
	}
	if st.Unsent[0].Meta.SnapshotID != "snap-3" {
		t.Errorf("the oldest kept is %s; the three oldest should have gone", st.Unsent[0].Meta.SnapshotID)
	}
}

// Sending again stops at a failure that may pass later (5xx), so order holds,
// and drops one the remote server refuses outright, which would be refused
// for ever.
func TestResendKeepsOrderAndDropsRefusals(t *testing.T) {
	answers := map[string]int{"snap-refused": http.StatusForbidden, "snap-ok": http.StatusCreated, "snap-busy": http.StatusServiceUnavailable}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m model.SnapshotMetadata
		_ = json.NewDecoder(r.Body).Decode(&m)
		w.WriteHeader(answers[m.SnapshotID])
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := &config.CLIConfig{ServerURL: srv.URL, ServerToken: "sg_tok_x"}
	st := &SurfaceState{SurfaceID: "db", LastError: "not recorded: x; sent again when the remote server answers"}
	for _, id := range []string{"snap-refused", "snap-ok", "snap-busy", "snap-ok"} {
		st.Unsent = append(st.Unsent, UnsentRecord{Meta: model.SnapshotMetadata{SnapshotID: id, NodeID: "n"}})
	}
	if sent := resendUnsent(context.Background(), c, st); sent != 1 {
		t.Errorf("sent %d, want 1 (the refused one dropped, the busy one stops the run)", sent)
	}
	if len(st.Unsent) != 2 || st.Unsent[0].Meta.SnapshotID != "snap-busy" {
		t.Fatalf("left %+v, want snap-busy then snap-ok", st.Unsent)
	}
	if st.LastError == "" {
		t.Error("the not-recorded error was cleared while records still wait")
	}
}
