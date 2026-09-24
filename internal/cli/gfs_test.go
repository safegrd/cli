package cli

import (
	"testing"
	"time"
)

// A day of backups under daily 7 / weekly 4 / monthly 12: the first of the
// month is kept a year, the first of each later week four weeks, the rest a
// week. A lost state promotes again, which over-keeps and never under-keeps.
func TestGFSRetentionTiers(t *testing.T) {
	st := &SurfaceState{}
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	steps := []struct {
		when, tier string
		keepDays   int
	}{
		{"2026-09-01T02:00:00Z", "monthly", 365}, // Tuesday, first of the month and week
		{"2026-09-01T08:00:00Z", "base", 7},
		{"2026-09-06T02:00:00Z", "base", 7},    // Sunday, same ISO week
		{"2026-09-07T02:00:00Z", "weekly", 28}, // Monday, a new week
		{"2026-09-07T09:00:00Z", "base", 7},
		{"2026-10-01T02:00:00Z", "monthly", 365},
	}
	for _, step := range steps {
		now := at(step.when)
		p := planRetention(now, 7, gfs{Weeks: 4, Months: 12}, st)
		if p.Tier != step.tier {
			t.Errorf("%s: tier %s, want %s", step.when, p.Tier, step.tier)
		}
		if got := int(p.Until.Sub(now).Hours() / 24); got < step.keepDays-1 || got > step.keepDays+1 {
			t.Errorf("%s: kept %d days, want about %d", step.when, got, step.keepDays)
		}
		p.record(st)
	}
	// A failed backup takes no slot: the next one is still promoted.
	fresh := &SurfaceState{}
	_ = planRetention(at("2026-11-02T02:00:00Z"), 7, gfs{Weeks: 4, Months: 12}, fresh) // failed, not recorded
	if p := planRetention(at("2026-11-02T05:00:00Z"), 7, gfs{Weeks: 4, Months: 12}, fresh); p.Tier != "monthly" {
		t.Errorf("a failed backup used up the month's slot: %s", p.Tier)
	}
	// No tiers configured: every backup is base.
	if p := planRetention(at("2026-12-01T00:00:00Z"), 14, gfs{}, &SurfaceState{}); p.Tier != "base" || p.WeekKey != "" || p.MonthKey != "" {
		t.Errorf("tiers applied with none configured: %+v", p)
	}
	// A base period longer than the weekly tier: the longer wins.
	if p := planRetention(at("2026-12-07T00:00:00Z"), 60, gfs{Weeks: 4}, &SurfaceState{}); p.Tier != "base" || p.WeekKey == "" {
		t.Errorf("a 60-day daily tier was shortened by a 4-week weekly one: %+v", p)
	}
}

// Hourly backups under a 2-day base lock with 14 days of dailies: each day's
// first backup is kept two weeks, every other hour two days. That is the
// shape hosted storage defaults to, and what keeps hourly schedules cheap.
func TestGFSDailyTierOnAnHourlySchedule(t *testing.T) {
	st := &SurfaceState{}
	start := time.Date(2026, 9, 10, 0, 30, 0, 0, time.UTC)
	daily, base := 0, 0
	for h := 0; h < 72; h++ {
		now := start.Add(time.Duration(h) * time.Hour)
		p := planRetention(now, 2, gfs{Days: 14}, st)
		switch p.Tier {
		case "daily":
			daily++
			if got := p.Until.Sub(now); got != 14*24*time.Hour {
				t.Errorf("%s: daily kept %s, want 14 days", now, got)
			}
		case "base":
			base++
			if got := p.Until.Sub(now); got != 48*time.Hour {
				t.Errorf("%s: base kept %s, want 2 days", now, got)
			}
		default:
			t.Errorf("%s: unexpected tier %s", now, p.Tier)
		}
		p.record(st)
	}
	if daily != 3 || base != 69 {
		t.Errorf("72 hourly backups over 3 days gave %d daily and %d base, want 3 and 69", daily, base)
	}
}
