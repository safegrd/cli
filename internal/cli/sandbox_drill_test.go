package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// A drill restores into its sandbox, so a sandbox that is the surface's own
// database would be a restore over production. It is refused before anything
// connects, however the two URLs are spelled.
func TestADrillSandboxCannotBeTheSurfaceItself(t *testing.T) {
	c := &config.CLIConfig{}
	for _, sandbox := range []string{
		"postgres://app:secret@db.internal:5432/app?sslmode=disable",
		"postgres://someone-else:pw@DB.internal:5432/app",
		"postgresql://db.internal/app",
	} {
		s := &config.SurfaceConfig{ID: "app", Type: "postgres",
			DatabaseURL: "postgres://app:secret@db.internal:5432/app?sslmode=disable",
			Drill:       &config.DrillConfig{SandboxURL: sandbox}}
		if _, err := surfaceSandboxURL(context.Background(), c, s); err == nil || !strings.Contains(err.Error(), "is the database it backs up") {
			t.Errorf("sandbox %q for the same database was accepted: %v", sandbox, err)
		}
	}
	s := &config.SurfaceConfig{ID: "app", Type: "postgres",
		DatabaseURL: "postgres://app@db.internal:5432/app",
		Drill:       &config.DrillConfig{SandboxURL: "postgres://app@db.internal:5432/app_drill"}}
	if got, err := surfaceSandboxURL(context.Background(), c, s); err != nil || got == "" {
		t.Errorf("a separate sandbox was refused: %q %v", got, err)
	}
	files := &config.SurfaceConfig{ID: "docs", Type: "files", Drill: &config.DrillConfig{SandboxURL: "postgres://x/y"}}
	if got, _ := surfaceSandboxURL(context.Background(), c, files); got != "" {
		t.Errorf("a files surface was given a database sandbox: %q", got)
	}
}
