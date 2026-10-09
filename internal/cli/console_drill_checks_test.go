package cli

import (
	"testing"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// The console's drill checks reach the surface's drill beside the config's
// own: a name the config already uses keeps the config's check, a command
// from the remote server is never taken, and the config's struct is not
// changed underneath it.
func TestConsoleDrillChecksJoinTheConfigsOwn(t *testing.T) {
	configured := config.SurfaceConfig{ID: "db", Drill: &config.DrillConfig{
		SandboxURL: "postgres://sandbox",
		Checks:     []model.DrillCheck{{Name: "users", SQL: "SELECT 1", Expect: "1"}},
	}}
	st := &SurfaceState{SurfaceID: "db"}
	hb := &model.HeartbeatResponse{DrillChecks: []model.DrillCheck{
		{Name: "users", SQL: "SELECT 2", Expect: "2"},
		{Name: "orders", SQL: "SELECT count(*) FROM orders", Expect: "> 0"},
		{Name: "shell", Command: "rm -rf /"},
	}}
	if !noteConsoleSettings(st, &configured, hb) {
		t.Fatal("new console checks were not noted as a change")
	}
	if noteConsoleSettings(st, &configured, hb) {
		t.Fatal("the same checks again were noted as a change")
	}
	s := configured
	applyConsoleSettings(&s, &configured, st)
	if s.Drill.SandboxURL != "postgres://sandbox" {
		t.Errorf("the config's sandbox was lost: %+v", s.Drill)
	}
	var names []string
	for _, c := range s.Drill.Checks {
		names = append(names, c.Name)
	}
	if len(names) != 2 || names[0] != "users" || names[1] != "orders" || s.Drill.Checks[0].SQL != "SELECT 1" {
		t.Errorf("the drill's checks are %+v, want the config's users and the console's orders", s.Drill.Checks)
	}
	if len(configured.Drill.Checks) != 1 {
		t.Errorf("the config's own checks were changed: %+v", configured.Drill.Checks)
	}

	// A surface with no drill block in its config takes the console's.
	bare := config.SurfaceConfig{ID: "db2"}
	st2 := &SurfaceState{SurfaceID: "db2", ConsoleDrillChecks: hb.DrillChecks[1:2]}
	s2 := bare
	applyConsoleSettings(&s2, &bare, st2)
	if s2.Drill == nil || len(s2.Drill.Checks) != 1 || bare.Drill != nil {
		t.Errorf("a surface with no drill block: %+v, config %+v", s2.Drill, bare.Drill)
	}
}
