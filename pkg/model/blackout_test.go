package model

import (
	"testing"
	"time"
)

func TestBlackoutWindows(t *testing.T) {
	ws, err := ParseBlackout([]string{"22:00-02:00", "12:00-12:30"})
	if err != nil {
		t.Fatal(err)
	}
	at := func(hm string) time.Time {
		tm, _ := time.Parse("2006-01-02 15:04", "2026-10-17 "+hm)
		return tm
	}
	for hm, want := range map[string]bool{"21:59": false, "22:00": true, "23:30": true, "01:59": true, "02:00": false, "12:10": true, "12:30": false} {
		if _, _, in := BlackoutAt(ws, at(hm)); in != want {
			t.Errorf("%s inside a window = %v, want %v", hm, in, want)
		}
	}
	if _, end, _ := BlackoutAt(ws, at("23:30")); !end.Equal(at("02:00").Add(24 * time.Hour)) {
		t.Errorf("23:30 waits until %s, want 02:00 the next day", end)
	}
	if got := BlackoutTotal(ws); got != 4*time.Hour+30*time.Minute {
		t.Errorf("total %s, want 4h30m", got)
	}
	// Touching windows are waited out together.
	touching, _ := ParseBlackout([]string{"01:00-02:00", "02:00-03:00"})
	if _, end, _ := BlackoutAt(touching, at("01:30")); !end.Equal(at("03:00")) {
		t.Errorf("touching windows end at %s, want 03:00", end)
	}
	for _, bad := range []string{"22:00", "25:00-01:00", "10:00-10:00", "ten-eleven"} {
		if _, err := ParseBlackout([]string{bad}); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
