package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MinScheduleInterval is the shortest interval a surface may be backed up on.
// Under compliance-mode Object Lock, backups cannot be deleted until retention expires.
// One hour is the shortest supported schedule interval (@hourly).
const MinScheduleInterval = time.Hour

// DefaultScheduleInterval is what an empty schedule means.
const DefaultScheduleInterval = 24 * time.Hour

// ParseSchedule returns the interval a schedule names, or an error saying why
// it names none.
//
// Accepted: "" (daily), "@hourly"/"hourly", "@daily"/"daily",
// "@weekly"/"weekly", a Go duration ("6h", "90m"), or whole days ("2d").
// Anything shorter than MinScheduleInterval is refused.
func ParseSchedule(schedule string) (time.Duration, error) {
	s := strings.ToLower(strings.TrimSpace(schedule))
	var d time.Duration
	switch s {
	case "":
		return DefaultScheduleInterval, nil
	case "@hourly", "hourly":
		d = time.Hour
	case "@daily", "daily":
		d = 24 * time.Hour
	case "@weekly", "weekly":
		d = 7 * 24 * time.Hour
	default:
		if days, ok := strings.CutSuffix(s, "d"); ok {
			n, err := strconv.Atoi(days)
			if err != nil || n <= 0 {
				return 0, fmt.Errorf("schedule %q is not a number of days", schedule)
			}
			d = time.Duration(n) * 24 * time.Hour
			break
		}
		parsed, err := time.ParseDuration(s)
		if err != nil || parsed <= 0 {
			return 0, fmt.Errorf("schedule %q is not recognised: use @hourly, @daily, @weekly, "+
				"a duration such as 6h, or a number of days such as 2d", schedule)
		}
		d = parsed
	}
	if d < MinScheduleInterval {
		return 0, fmt.Errorf("schedule %q is more frequent than the minimum of %s: every backup is "+
			"an object that Object Lock will not let anyone delete until it expires", schedule, ShortDuration(MinScheduleInterval))
	}
	return d, nil
}

// ScheduleInterval is ParseSchedule for code that executes scheduled tasks
// (such as agent intervals and heartbeat checks).
//
// It falls back to safe defaults rather than failing outright. A schedule that
// is too frequent runs at the floor, and an unparseable schedule runs daily.
// Any parsing error is returned alongside the duration so callers can log warnings.
func ScheduleInterval(schedule string) (time.Duration, error) {
	d, err := ParseSchedule(schedule)
	if err == nil {
		return d, nil
	}
	s := strings.ToLower(strings.TrimSpace(schedule))
	if parsed, perr := time.ParseDuration(s); perr == nil && parsed > 0 && parsed < MinScheduleInterval {
		return MinScheduleInterval, err
	}
	return DefaultScheduleInterval, err
}

// ShortDuration renders an interval the way a schedule is written: "1h", not
// "1h0m0s".
func ShortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
