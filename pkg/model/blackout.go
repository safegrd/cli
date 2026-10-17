package model

import (
	"fmt"
	"strings"
	"time"
)

// BlackoutWindow is a time of day, in UTC, inside which a daemon starts no
// scheduled backup: "22:00-02:00" crosses midnight. A backup running when a
// window opens finishes; a backup asked for from the console is not held.
type BlackoutWindow struct {
	Text       string
	Start, End time.Duration // since midnight UTC
}

// ParseBlackout reads a surface's blackout windows. Each is "HH:MM-HH:MM";
// start and end may not be equal.
func ParseBlackout(windows []string) ([]BlackoutWindow, error) {
	var out []BlackoutWindow
	for _, w := range windows {
		text := strings.TrimSpace(w)
		from, to, ok := strings.Cut(text, "-")
		if !ok {
			return nil, fmt.Errorf("blackout window %q: write it as HH:MM-HH:MM, in UTC", w)
		}
		start, err := clockTime(from)
		if err != nil {
			return nil, fmt.Errorf("blackout window %q: %w", w, err)
		}
		end, err := clockTime(to)
		if err != nil {
			return nil, fmt.Errorf("blackout window %q: %w", w, err)
		}
		if start == end {
			return nil, fmt.Errorf("blackout window %q starts and ends at the same time", w)
		}
		out = append(out, BlackoutWindow{Text: text, Start: start, End: end})
	}
	return out, nil
}

func clockTime(s string) (time.Duration, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not a time of day (HH:MM)", strings.TrimSpace(s))
	}
	return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute, nil
}

// Length is how long the window lasts.
func (w BlackoutWindow) Length() time.Duration {
	if w.End > w.Start {
		return w.End - w.Start
	}
	return 24*time.Hour - w.Start + w.End
}

// Inside reports whether t falls in the window, and when it ends if so.
func (w BlackoutWindow) Inside(t time.Time) (bool, time.Time) {
	t = t.UTC()
	midnight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	of := t.Sub(midnight)
	switch {
	case w.End > w.Start && of >= w.Start && of < w.End:
		return true, midnight.Add(w.End)
	case w.End < w.Start && of >= w.Start:
		return true, midnight.Add(24*time.Hour + w.End)
	case w.End < w.Start && of < w.End:
		return true, midnight.Add(w.End)
	}
	return false, time.Time{}
}

// BlackoutAt is the window t falls in, and when the last window holding it
// ends: windows that overlap or touch are waited out together.
func BlackoutAt(windows []BlackoutWindow, t time.Time) (BlackoutWindow, time.Time, bool) {
	var first BlackoutWindow
	end, found := t, false
	for moved := true; moved; {
		moved = false
		for _, w := range windows {
			if in, until := w.Inside(end); in && until.After(end) {
				if !found {
					first = w
				}
				end, found, moved = until, true, true
			}
		}
	}
	return first, end, found
}

// BlackoutTotal is the sum of the windows' lengths: how much later than its
// schedule a surface may back up, which Overdue allows for (decided
// 2026-10-17: the sum, not the longest).
func BlackoutTotal(windows []BlackoutWindow) time.Duration {
	var d time.Duration
	for _, w := range windows {
		d += w.Length()
	}
	return d
}
