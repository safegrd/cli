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
	for _, in := range []string{"1m", "30s", "59m", "@hourlyy", "0 3 * * *", "0d", "-2h", "xd"} {
		if d, err := ParseSchedule(in); err == nil {
			t.Errorf("ParseSchedule(%q) = %v with no error", in, d)
		}
	}
	_, err := ParseSchedule("5m")
	if err == nil || !strings.Contains(err.Error(), "minimum") {
		t.Errorf("a too-frequent schedule must name the floor, got %v", err)
	}
}

func TestScheduleIntervalNeverFailsAndNeverGoesBelowTheFloor(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"1m":        MinScheduleInterval,
		"30s":       MinScheduleInterval,
		"@hourlyy":  DefaultScheduleInterval,
		"0 3 * * *": DefaultScheduleInterval,
	} {
		got, err := ScheduleInterval(in)
		if got != want || err == nil {
			t.Errorf("ScheduleInterval(%q) = %v, %v; want %v with the problem reported", in, got, err, want)
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
