package model

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cron is a schedule of fixed times: five fields (minute, hour, day of month,
// month, day of week) with *, lists, ranges and steps, or "at HH:MM" for one
// time a day. A day of the month and a day of the week that are both set
// match when either does, as in cron.
type Cron struct {
	Text                  string
	min, hour, dom, month []bool
	dow                   []bool
	domAny, dowAny        bool
}

// IsCron reports whether a schedule is written as fixed times rather than
// an interval.
func IsCron(schedule string) bool {
	s := strings.TrimSpace(strings.ToLower(schedule))
	return strings.HasPrefix(s, "at ") || len(strings.Fields(s)) == 5
}

// ParseCron reads a cron schedule.
func ParseCron(schedule string) (*Cron, error) {
	s := strings.TrimSpace(strings.ToLower(schedule))
	if at, ok := strings.CutPrefix(s, "at "); ok {
		t, err := time.Parse("15:04", strings.TrimSpace(at))
		if err != nil {
			return nil, fmt.Errorf("schedule %q: write a time of day as at HH:MM", schedule)
		}
		s = fmt.Sprintf("%d %d * * *", t.Minute(), t.Hour())
	}
	f := strings.Fields(s)
	if len(f) != 5 {
		return nil, fmt.Errorf("schedule %q: a cron schedule has five fields: minute, hour, day of month, month, day of week", schedule)
	}
	c := &Cron{Text: strings.TrimSpace(schedule)}
	var err error
	if c.min, err = cronField(f[0], 0, 59); err != nil {
		return nil, fmt.Errorf("schedule %q, minute: %w", schedule, err)
	}
	if c.hour, err = cronField(f[1], 0, 23); err != nil {
		return nil, fmt.Errorf("schedule %q, hour: %w", schedule, err)
	}
	if c.dom, err = cronField(f[2], 1, 31); err != nil {
		return nil, fmt.Errorf("schedule %q, day of month: %w", schedule, err)
	}
	if c.month, err = cronField(f[3], 1, 12); err != nil {
		return nil, fmt.Errorf("schedule %q, month: %w", schedule, err)
	}
	if c.dow, err = cronField(f[4], 0, 7); err != nil {
		return nil, fmt.Errorf("schedule %q, day of week: %w", schedule, err)
	}
	if c.dow[7] {
		c.dow[0] = true // 7 is Sunday too
	}
	c.domAny, c.dowAny = f[2] == "*", f[4] == "*"
	if c.Next(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)).IsZero() {
		return nil, fmt.Errorf("schedule %q never runs", schedule)
	}
	return c, nil
}

func cronField(field string, lo, hi int) ([]bool, error) {
	set := make([]bool, hi+1)
	for _, part := range strings.Split(field, ",") {
		rng, stepText, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepText)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("%q is not a step", stepText)
			}
			step = n
		}
		from, to := lo, hi
		switch {
		case rng == "*":
		case strings.Contains(rng, "-"):
			a, b, _ := strings.Cut(rng, "-")
			var err1, err2 error
			from, err1 = strconv.Atoi(a)
			to, err2 = strconv.Atoi(b)
			if err1 != nil || err2 != nil || from > to {
				return nil, fmt.Errorf("%q is not a range", rng)
			}
		default:
			n, err := strconv.Atoi(rng)
			if err != nil {
				return nil, fmt.Errorf("%q is not a number", rng)
			}
			from, to = n, n
			if hasStep {
				to = hi
			}
		}
		if from < lo || to > hi {
			return nil, fmt.Errorf("%q is outside %d-%d", rng, lo, hi)
		}
		for v := from; v <= to; v += step {
			set[v] = true
		}
	}
	return set, nil
}

func (c *Cron) dayMatches(t time.Time) bool {
	dom, dow := c.dom[t.Day()], c.dow[int(t.Weekday())]
	switch {
	case c.domAny && c.dowAny:
		return true
	case c.domAny:
		return dow
	case c.dowAny:
		return dom
	}
	return dom || dow
}

// Next is the first time after t that the schedule runs, in t's location,
// or zero when there is none in the next five years.
func (c *Cron) Next(t time.Time) time.Time {
	t = t.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		if !c.month[int(t.Month())] {
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location()).AddDate(0, 1, 0)
			continue
		}
		if !c.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()).AddDate(0, 0, 1)
			continue
		}
		if !c.hour[t.Hour()] {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location()).Add(time.Hour)
			continue
		}
		if !c.min[t.Minute()] {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

// cronGaps caches Gaps by schedule: the server asks on every heartbeat and
// sweep, and a year of an hourly schedule is 8,784 runs.
var cronGaps sync.Map

type gapPair struct{ shortest, longest time.Duration }

// Gaps is the shortest and the longest time between two runs over a year,
// from a fixed start, so the answer does not depend on today's date. A
// schedule that runs more often than MinScheduleInterval is found from its
// first runs, without the year.
func (c *Cron) Gaps() (shortest, longest time.Duration) {
	if g, ok := cronGaps.Load(c.Text); ok {
		return g.(gapPair).shortest, g.(gapPair).longest
	}
	shortest, longest = c.gaps()
	cronGaps.Store(c.Text, gapPair{shortest, longest})
	return shortest, longest
}

func (c *Cron) gaps() (shortest, longest time.Duration) {
	at := c.Next(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	end := at.AddDate(1, 0, 0)
	for at.Before(end) {
		next := c.Next(at)
		if next.IsZero() {
			break
		}
		gap := next.Sub(at)
		if shortest == 0 || gap < shortest {
			shortest = gap
			if shortest < MinScheduleInterval {
				return shortest, longest
			}
		}
		if gap > longest {
			longest = gap
		}
		at = next
	}
	return shortest, longest
}
