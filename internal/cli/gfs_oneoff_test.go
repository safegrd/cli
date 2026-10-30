package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// A one-off backup's slots are kept per source and sink, survive a reload,
// and are never shared between two trees or two buckets: a weekly copy of
// one tree in one bucket says nothing about the other.
func TestAOneOffBackupKeepsItsSlotsPerSourceAndSink(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 2, 2, 0, 0, 0, time.UTC) // Monday
	tree, other := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	s3 := config.StorageConfig{Type: config.StorageTypeS3, Bucket: "backups", Prefix: "one"}
	s3Other := config.StorageConfig{Type: config.StorageTypeS3, Bucket: "backups", Prefix: "two"}
	local := config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: filepath.Join(dir, "worm")}

	src := oneOffSource(&config.CLIConfig{}, "", tree, false, "", "")
	if src != oneOffSource(&config.CLIConfig{}, "", tree, false, "", "") || src == oneOffSource(&config.CLIConfig{}, "", other, false, "", "") {
		t.Fatalf("a tree's source id is not stable, or two trees share one: %s", src)
	}
	keys := map[string]bool{}
	for _, k := range []string{oneOffSlotKey(src, s3), oneOffSlotKey(src, s3Other), oneOffSlotKey(src, local)} {
		keys[k] = true
	}
	if len(keys) != 3 {
		t.Fatalf("three sinks gave %d keys", len(keys))
	}
	mail := oneOffSource(&config.CLIConfig{}, "", "", true, "imap.example.com", "ops@example.com")
	if mail != oneOffSource(&config.CLIConfig{}, "", "", true, "IMAP.example.com", "ops@example.com") || mail[:6] != "email-" {
		t.Fatalf("a mailbox's source id: %s", mail)
	}
	db := oneOffSource(&config.CLIConfig{}, "postgres://app:secret@db.example.com:5432/orders", "", false, "", "")
	if db != oneOffSource(&config.CLIConfig{}, "postgres://app:other@db.example.com:5432/orders?schema=public", "", false, "", "") {
		t.Fatalf("a database's source id depends on its password or options: %s", db)
	}

	key := oneOffSlotKey(src, s3)
	slots := loadOneOffSlots(dir)
	p := planRetention(at, 3, gfs{Weeks: 4}, slots.slotsFor(key))
	if p.Tier != "weekly" || !p.takesASlot() {
		t.Fatalf("the week's first one-off backup is %s", p.Tier)
	}
	p.record(slots.slotsFor(key))
	if err := slots.save(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, oneOffSlotsFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("slots file: %v %v", fi, err)
	}
	again := loadOneOffSlots(dir)
	// With weeks alone the second run of the week is base: the slot read
	// back from the file.
	if p := planRetention(at.Add(time.Hour), 3, gfs{Weeks: 4}, again.slotsFor(key)); p.Tier != "base" || p.takesASlot() {
		t.Fatalf("the week's second one-off backup read back as %s (%+v)", p.Tier, p)
	}
	if p := planRetention(at.Add(time.Hour), 3, gfs{Weeks: 4}, again.slotsFor(oneOffSlotKey(src, local))); p.Tier != "weekly" {
		t.Fatalf("the same tree into a directory shares the bucket's slot: %s", p.Tier)
	}
	// A tier the run kept beside the plan leaves the slots open.
	open := keptAtEpochTier(p, "base", false)
	if open.takesASlot() || open.Tier != "weekly" {
		t.Fatalf("an epoch's base tier did not release the week's slot: %+v", open)
	}
}

// The tiers of a one-off come from the --keep-* flags, else the config's
// defaults, else hosted storage's plan. An explicit --retention-days alone
// turns them off: the flag names the days this backup is locked, and a
// lock under compliance mode cannot be shortened afterwards.
func TestAOneOffBackupsTiersComeFromFlagsThenDefaults(t *testing.T) {
	cfg := &config.CLIConfig{}
	cfg.Defaults.KeepDaily, cfg.Defaults.KeepWeekly, cfg.Defaults.KeepMonthly = 7, 4, 12
	if got := oneOffTiers(cfg, gfs{}, false, nil); got != (gfs{Days: 7, Weeks: 4, Months: 12}) {
		t.Errorf("defaults: %+v", got)
	}
	if got := oneOffTiers(cfg, gfs{}, true, nil); got != (gfs{}) {
		t.Errorf("--retention-days alone still promoted: %+v", got)
	}
	if got := oneOffTiers(cfg, gfs{Weeks: 8}, true, nil); got != (gfs{Days: 7, Weeks: 8, Months: 12}) {
		t.Errorf("--keep-weekly beside --retention-days: %+v", got)
	}
	none := &config.CLIConfig{}
	if got := oneOffTiers(none, gfs{}, false, &hostedInfo{KeepDaily: 14, KeepWeekly: 4}); got != (gfs{Days: 14, Weeks: 4}) {
		t.Errorf("hosted storage's plan with no config tiers: %+v", got)
	}
	if got := oneOffTiers(none, gfs{}, false, nil); got != (gfs{}) {
		t.Errorf("no tiers anywhere: %+v", got)
	}
}
