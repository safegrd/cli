package cli

import (
	"fmt"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// Grandfather-father-son retention. Under Object Lock a
// snapshot's retention is fixed when it is written and can never be
// shortened, so the tier is decided here, at upload, and not by a pruning job
// afterwards: the first backup of each UTC day is locked for keep_daily days,
// the first of each ISO week for keep_weekly weeks, the first of each month
// for keep_monthly months, and every other backup for retention_days. That is
// what makes an hourly schedule affordable: the hourly copies need only a
// short lock, and a day's first backup carries the longer history.
//
// "First" comes from the agent's state. If the state is lost, the next backup
// is promoted again: that keeps a backup longer than planned, never shorter,
// which is the only safe way to be wrong about a lock nobody can lift.

// retentionPlan is what one backup is locked for, and why.
type retentionPlan struct {
	Until    time.Time
	Tier     string // "base", "daily", "weekly" or "monthly"
	DayKey   string // set when this backup takes the day's slot
	WeekKey  string // set when this backup takes the week's slot
	MonthKey string // set when this backup takes the month's slot
}

// gfs is how long the first backup of each day, week and month is kept; zero
// turns a tier off.
type gfs struct{ Days, Weeks, Months int }

func dayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }

func isoWeekKey(t time.Time) string {
	y, w := t.UTC().ISOWeek()
	return fmt.Sprintf("%d-W%02d", y, w)
}

func monthKey(t time.Time) string { return t.UTC().Format("2006-01") }

// planRetention decides the tier for a backup taken at now.
func planRetention(now time.Time, days int, g gfs, st *SurfaceState) retentionPlan {
	p := retentionPlan{Until: now.Add(time.Duration(days) * 24 * time.Hour), Tier: "base"}
	if g.Days > 0 && (st == nil || st.LastDailySlot != dayKey(now)) {
		if until := now.AddDate(0, 0, g.Days); until.After(p.Until) {
			p.Until, p.Tier = until, "daily"
		}
		p.DayKey = dayKey(now)
	}
	weeks, months := g.Weeks, g.Months
	if weeks > 0 && (st == nil || st.LastWeeklySlot != isoWeekKey(now)) {
		if until := now.AddDate(0, 0, 7*weeks); until.After(p.Until) {
			p.Until, p.Tier = until, "weekly"
		}
		p.WeekKey = isoWeekKey(now)
	}
	if months > 0 && (st == nil || st.LastMonthlySlot != monthKey(now)) {
		if until := now.AddDate(0, months, 0); until.After(p.Until) {
			p.Until, p.Tier = until, "monthly"
		}
		p.MonthKey = monthKey(now)
	}
	return p
}

// record marks the slots this backup took, once it has succeeded.
func (p retentionPlan) record(st *SurfaceState) {
	if st == nil {
		return
	}
	if p.DayKey != "" {
		st.LastDailySlot = p.DayKey
	}
	if p.WeekKey != "" {
		st.LastWeeklySlot = p.WeekKey
	}
	if p.MonthKey != "" {
		st.LastMonthlySlot = p.MonthKey
	}
}

// gfsTiers resolves a surface's daily, weekly and monthly tiers from the
// surface, then the defaults.
func gfsTiers(c *config.CLIConfig, s *config.SurfaceConfig) gfs {
	g := gfs{Days: s.KeepDaily, Weeks: s.KeepWeekly, Months: s.KeepMonthly}
	if g.Days == 0 {
		g.Days = c.Defaults.KeepDaily
	}
	if g.Weeks == 0 {
		g.Weeks = c.Defaults.KeepWeekly
	}
	if g.Months == 0 {
		g.Months = c.Defaults.KeepMonthly
	}
	return g
}
