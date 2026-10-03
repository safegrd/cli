package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
)

func epoch(t *testing.T, surface string) format.Epoch {
	e, err := policy.NewEpoch(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), surface, format.ReasonFirst, format.TierBase,
		policy.Retention{Days: 7}, "age1x")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestAMissingCorruptOrForeignCacheIsLostNeverAPanic(t *testing.T) {
	dir := t.TempDir()
	if c, lost, err := Current(filepath.Join(dir, "absent"), "s"); c != nil || lost || err != nil {
		t.Fatalf("missing: %v %v %v", c, lost, err)
	}
	c, err := Create(dir, epoch(t, "s"))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	got, lost, err := Current(dir, "s")
	if err != nil || lost || got == nil || got.Epoch().SurfaceID != "s" {
		t.Fatalf("readable: %v %v %v", got, lost, err)
	}
	got.Close()

	// Another surface's cache in this directory is not ours.
	if got, lost, _ := Current(dir, "other"); got != nil || !lost {
		t.Fatalf("foreign: %v %v", got, lost)
	}
	// It was moved aside, so the next look sees nothing to use, once.
	matches, _ := filepath.Glob(filepath.Join(dir, "*.unusable-*"))
	if len(matches) != 1 {
		t.Fatalf("moved aside: %v", matches)
	}

	// Garbage where a cache should be.
	bad := filepath.Join(dir, "e202610-00000000.db")
	if err := os.WriteFile(bad, []byte("not a database at all, just bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, lost, err := Current(dir, "s"); got != nil || !lost || err != nil {
		t.Fatalf("corrupt: %v %v %v", got, lost, err)
	}
}
