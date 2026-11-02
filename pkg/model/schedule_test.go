package model

import (
	"strings"
	"testing"
	"time"
)

func TestParseScheduleAcceptsBothOldVocabularies(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"":        24 * time.Hour,
		"@hourly": time.Hour,
		"hourly":  time.Hour,
		"@DAILY":  24 * time.Hour,
		"daily":   24 * time.Hour,
		"@weekly": 7 * 24 * time.Hour,
		"weekly":  7 * 24 * time.Hour,
		"7d":      7 * 24 * time.Hour,
		"2d":      48 * time.Hour,
		"6h":      6 * time.Hour,
		"90m":     90 * time.Minute,
		" 12h ":   12 * time.Hour,
	} {
		got, err := ParseSchedule(in)
		if err != nil || got != want {
			t.Errorf("ParseSchedule(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
}

func TestParseScheduleRefusesTheFloorAndTheUnreadable(t *testing.T) {
	for in, words := range map[string]string{
		"1m": "more frequent than the minimum of 1h", "30s": "more frequent than the minimum", "59m": "more frequent than the minimum",
		"@hourlyy": "is not recognised: use @hourly", "0 3 * *": "is not recognised", "-2h": "is not recognised",
		"0d": "is not a number of days", "xd": "is not a number of days",
		"106751992d": "106751992d", "1000000000d": "1000000000d",
	} {
		if d, err := ParseSchedule(in); err == nil || !strings.Contains(err.Error(), words) {
			t.Errorf("ParseSchedule(%q) = %v, %v; want an error saying %q", in, d, err, words)
		}
	}
	_, err := ParseSchedule("5m")
	if err == nil || !strings.Contains(err.Error(), "minimum") {
		t.Errorf("a too-frequent schedule must name the floor, got %v", err)
	}
}

func TestScheduleIntervalNeverFailsAndNeverGoesBelowTheFloor(t *testing.T) {
	for in, want := range map[string]struct {
		interval time.Duration
		words    string
	}{
		"1m":       {MinScheduleInterval, "more frequent than the minimum"},
		"30s":      {MinScheduleInterval, "more frequent than the minimum"},
		"@hourlyy": {DefaultScheduleInterval, "is not recognised"},
		"0 3 * *":  {DefaultScheduleInterval, "is not recognised"},
	} {
		got, err := ScheduleInterval(in)
		if got != want.interval || err == nil || !strings.Contains(err.Error(), want.words) {
			t.Errorf("ScheduleInterval(%q) = %v, %v; want %v with the problem reported (%q)", in, got, err, want.interval, want.words)
		}
	}
	if got, err := ScheduleInterval("@hourly"); got != time.Hour || err != nil {
		t.Errorf("ScheduleInterval(@hourly) = %v, %v", got, err)
	}
}

func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Hour: "1h", 24 * time.Hour: "24h", 90 * time.Minute: "1h30m",
		10 * time.Second: "10s", 5 * time.Minute: "5m",
	} {
		if got := ShortDuration(d); got != want {
			t.Errorf("ShortDuration(%v) = %q, want %q", d, got, want)
		}
	}
}
