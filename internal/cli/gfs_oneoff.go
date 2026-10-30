package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// A one-off backup (--database-url, --files, --email) has no surface and so
// no SurfaceState to say whether this week's or this month's copy is taken.
// The slots it takes are kept per source and sink in one_off_slots.json
// beside the daemon's state. Only one-off runs write that file: a one-off
// beside a running daemon must not rewrite daemon_state.json from a stale
// load, and the daemon's own slots stay the daemon's. A lost or stale file
// promotes the next backup again, which over-keeps.

const oneOffSlotsFile = "one_off_slots.json"

// oneOffSlots is the slots file: the day, week and month each source's
// one-off backups have taken in each sink.
type oneOffSlots struct {
	path    string
	Sources map[string]*gfsSlots `json:"sources"`
}

func loadOneOffSlots(stateDir string) *oneOffSlots {
	o := &oneOffSlots{path: filepath.Join(stateDir, oneOffSlotsFile), Sources: map[string]*gfsSlots{}}
	data, err := os.ReadFile(o.path)
	if err != nil {
		return o
	}
	var saved oneOffSlots
	if err := json.Unmarshal(data, &saved); err == nil && saved.Sources != nil {
		o.Sources = saved.Sources
	}
	return o
}

// slotsFor is the slots of one source in one sink, created empty when the
// file has none.
func (o *oneOffSlots) slotsFor(key string) *gfsSlots {
	s, ok := o.Sources[key]
	if !ok {
		s = &gfsSlots{}
		o.Sources[key] = s
	}
	return s
}

func (o *oneOffSlots) save() error {
	if err := os.MkdirAll(filepath.Dir(o.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", o.path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, o.path)
}

// oneOffSlotKey names one source in one sink. The same tree or database
// backed up into two buckets takes a slot in each: a weekly copy in one
// bucket says nothing about the other.
func oneOffSlotKey(source string, sc config.StorageConfig) string {
	sink := string(sc.Type)
	switch sc.Type {
	case config.StorageTypeLocal:
		sink += ":" + sc.LocalPath
	case config.StorageTypeHosted:
	default:
		sink += ":" + sc.Bucket + "/" + sc.Prefix
	}
	return source + "@" + sink
}

// oneOffSource names what a one-off backup reads, in the id its repository
// carries, so a tree later promoted to a surface with format: repo and a
// database the config names both keep their slots.
func oneOffSource(cfg *config.CLIConfig, dbURL, filesPath string, email bool, emailHost, emailUser string) string {
	switch {
	case filesPath != "":
		return repoSurfaceID([]string{filesPath})
	case email || emailHost != "":
		host := emailHost
		if host == "" {
			host = "imap.gmail.com"
		}
		user := emailUser
		if user == "" {
			user = os.Getenv("SAFEGRD_EMAIL_USER")
		}
		sum := sha256.Sum256([]byte(strings.ToLower(host) + "|" + user))
		return "email-" + hex.EncodeToString(sum[:])[:12]
	}
	raw := dbURL
	if raw == "" {
		raw = cfg.DatabaseURL
	}
	// The backup resolves the reference and reports a bad one; here a bad
	// reference only names the slot after the reference itself.
	if resolved, err := ResolveSecretRef("database-url", raw); err == nil && resolved != "" {
		raw = resolved
	}
	raw, _ = cleanPostgresURL(raw)
	c := *cfg
	c.DatabaseURL = raw
	return adhocDatabaseSurfaceID(&c)
}

// oneOffTiers is what a one-off backup locks its daily, weekly and monthly
// copies for: the --keep-* flags, else the config's defaults, else, on hosted
// storage, the plan's. An explicit --retention-days with no --keep-* flag
// locks for exactly that many days: a flag that says "days this backup is
// locked" must not lock a throwaway run for a year under compliance mode,
// which nothing can undo.
func oneOffTiers(cfg *config.CLIConfig, flags gfs, retentionDaysSet bool, hosted *hostedInfo) gfs {
	if flags != (gfs{}) {
		g := flags
		if g.Days == 0 {
			g.Days = cfg.Defaults.KeepDaily
		}
		if g.Weeks == 0 {
			g.Weeks = cfg.Defaults.KeepWeekly
		}
		if g.Months == 0 {
			g.Months = cfg.Defaults.KeepMonthly
		}
		return g
	}
	if retentionDaysSet {
		return gfs{}
	}
	g := gfs{Days: cfg.Defaults.KeepDaily, Weeks: cfg.Defaults.KeepWeekly, Months: cfg.Defaults.KeepMonthly}
	if g == (gfs{}) {
		g = hosted.gfs()
	}
	return g
}

// lockedUntilWords says what the sink does with the planned date: an Object
// Lock holds it, a directory or an SFTP server only keeps it, and under
// worm_mode NONE nothing is locked.
func lockedUntilWords(sc config.StorageConfig, until time.Time) string {
	day := until.UTC().Format("2006-01-02")
	if sc.Type == config.StorageTypeLocal || sc.Type == config.StorageTypeSFTP {
		return "kept until " + day + ", not locked"
	}
	if mode, err := sc.ResolveWORMMode(); err == nil && mode == config.WORMModeNone {
		return "kept until " + day + ", not locked (worm_mode is NONE)"
	}
	return "locked until " + day
}

// keptAtEpochTier is the plan after a repository run that kept its epoch's
// opening tier instead of the one offered: the slots the run did not take
// stay open for the next backup, which would otherwise skip this month's
// copy. The daemon does the same for a surface.
func keptAtEpochTier(plan retentionPlan, got string, say bool) retentionPlan {
	if got == "" || got == plan.Tier {
		return plan
	}
	if say {
		fmt.Printf("   Kept at the epoch's %s tier. The %s slot stays open for the next backup.\n", got, plan.Tier)
	}
	plan.DayKey, plan.WeekKey, plan.MonthKey = "", "", ""
	return plan
}
