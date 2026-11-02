package model

import (
	"strings"
	"testing"
	"time"
)

func TestCronSchedules(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse("2006-01-02 15:04 Mon", s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, c := range []struct {
		schedule, after, want string
	}{
		{"at 02:00", "2026-10-17 01:00 Sat", "2026-10-17 02:00 Sat"},
		{"at 02:00", "2026-10-17 02:00 Sat", "2026-10-18 02:00 Sun"},
		{"30 */6 * * *", "2026-10-17 07:00 Sat", "2026-10-17 12:30 Sat"},
		{"0 3 * * 1-5", "2026-10-17 04:00 Sat", "2026-10-19 03:00 Mon"},
		{"0 0 1 * *", "2026-10-17 04:00 Sat", "2026-11-01 00:00 Sun"},
		{"0 4 * * 0", "2026-10-17 04:00 Sat", "2026-10-18 04:00 Sun"},
		{"0 4 * * 7", "2026-10-17 04:00 Sat", "2026-10-18 04:00 Sun"},
	} {
		cr, err := ParseCron(c.schedule)
		if err != nil {
			t.Fatalf("%q: %v", c.schedule, err)
		}
		if got := cr.Next(at(c.after)); !got.Equal(at(c.want)) {
			t.Errorf("%q after %s = %s, want %s", c.schedule, c.after, got.Format("2006-01-02 15:04 Mon"), c.want)
		}
	}

	for schedule, want := range map[string]time.Duration{
		"at 02:00":    24 * time.Hour,
		"0 3 * * 1-5": 72 * time.Hour, // Friday to Monday
		"0 */6 * * *": 6 * time.Hour,
		"0 0 1 * *":   31 * 24 * time.Hour,
	} {
		if d, err := ParseSchedule(schedule); err != nil || d != want {
			t.Errorf("ParseSchedule(%q) = %s, %v; want %s", schedule, d, err, want)
		}
	}
	for bad, words := range map[string]string{
		"*/30 * * * *": "30m apart at its closest, more often than the minimum of 1h",
		"* * * * *":    "1m apart at its closest",
		"0 25 * * *":   `hour: "25" is outside 0-23`,
		"at 25:00":     "write a time of day as at HH:MM",
		"0 0 31 2 *":   "never runs",
		"a b c d e":    `minute: "a" is not a number`,
	} {
		if _, err := ParseSchedule(bad); err == nil || !strings.Contains(err.Error(), words) {
			t.Errorf("ParseSchedule(%q) = %v; want an error saying %q", bad, err, words)
		}
	}
}
