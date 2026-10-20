package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, y string) *CLIConfig {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCLIConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// copies: is a list of storage blocks with names; a surface names a subset,
// or none with an empty list, and every key of a block is a setting.
func TestCopiesAreReadAndChosenPerSurface(t *testing.T) {
	c := loadYAML(t, `storage:
  type: s3
  bucket: main
copies:
  - name: offsite
    type: s3
    bucket: other
    worm_mode: COMPLIANCE
    retention_days: 90
  - name: archive
    type: s3
    bucket: cold
    worm_mode: NONE
surfaces:
  - id: all
    type: postgres
  - id: some
    type: postgres
    copies: [archive]
  - id: none
    type: postgres
    copies: []
`)
	if len(c.UnknownKeys) != 0 {
		t.Fatalf("keys of a copy read as unknown: %v", c.UnknownKeys)
	}
	if err := c.ValidateCopies(); err != nil {
		t.Fatal(err)
	}
	if c.Copies[0].Bucket != "other" || c.Copies[0].RetentionDays != 90 || c.Copies[1].WORMMode != WORMModeNone {
		t.Fatalf("the copies were not read: %+v", c.Copies)
	}
	names := func(s *SurfaceConfig) string {
		var out []string
		for _, cp := range c.CopiesOf(s) {
			out = append(out, cp.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(&c.Surfaces[0]); got != "offsite,archive" {
		t.Errorf("a surface naming no copies writes to %q, want all", got)
	}
	if got := names(&c.Surfaces[1]); got != "archive" {
		t.Errorf("a surface naming archive writes to %q", got)
	}
	if got := names(&c.Surfaces[2]); got != "" {
		t.Errorf("a surface with copies: [] writes to %q, want none", got)
	}
}

func TestCopiesThatCannotBeWrittenAreRefused(t *testing.T) {
	base := CLIConfig{Storage: StorageConfig{Type: StorageTypeS3, Bucket: "main", Prefix: "p"}}
	ok := CopyConfig{Name: "offsite", StorageConfig: StorageConfig{Type: StorageTypeS3, Bucket: "other", WORMMode: "COMPLIANCE"}}
	for _, c := range []struct {
		why    string
		copies []CopyConfig
		want   string
	}{
		{"three", []CopyConfig{ok, func() CopyConfig { x := ok; x.Name, x.Bucket = "b", "b"; return x }(), func() CopyConfig { x := ok; x.Name, x.Bucket = "c", "c"; return x }()}, "at most 2"},
		{"a bad name", []CopyConfig{func() CopyConfig { x := ok; x.Name = "Off Site"; return x }()}, "lowercase"},
		{"a name twice", []CopyConfig{ok, func() CopyConfig { x := ok; x.Bucket = "b"; return x }()}, "used twice"},
		{"not s3", []CopyConfig{func() CopyConfig { x := ok; x.Type = StorageTypeLocal; return x }()}, "must be s3"},
		{"no lock stated", []CopyConfig{func() CopyConfig { x := ok; x.WORMMode = ""; return x }()}, "worm_mode"},
		{"the primary", []CopyConfig{func() CopyConfig { x := ok; x.Bucket, x.Prefix = "main", "p"; return x }()}, "same bucket"},
	} {
		cfg := base
		cfg.Copies = c.copies
		err := cfg.ValidateCopies()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.why, err, c.want)
		}
	}
	cfg := base
	cfg.Copies = []CopyConfig{ok}
	missing := []string{"nowhere"}
	cfg.Surfaces = []SurfaceConfig{{ID: "s", Copies: &missing}}
	if err := cfg.ValidateCopies(); err == nil || !strings.Contains(err.Error(), "nowhere") {
		t.Errorf("a surface naming a copy that does not exist: %v", err)
	}
}
