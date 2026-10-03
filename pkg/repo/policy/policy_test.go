package policy

import (
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/repo/format"
)

func date(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// The worked example: retention 7 days, daily 7, weekly 4, monthly 12, an
// epoch opening 2026-10-01 02:00.
func TestTheWorkedExample(t *testing.T) {
	r := Retention{Days: 7, KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 12}
	if r.TMidDays() != 28 {
		t.Fatalf("T_mid %d", r.TMidDays())
	}
	end, opening, later := Locks(date("2026-10-01T02:00:00Z"), format.TierMonthly, r)
	if !end.Equal(date("2026-11-01T00:00:00Z")) {
		t.Errorf("planned end %s", end)
	}
	if !later.Equal(date("2026-11-29T00:00:00Z")) {
		t.Errorf("later lock %s", later)
	}
	if !opening.Equal(date("2027-10-04T02:00:00Z")) {
		t.Errorf("opening lock %s", opening)
	}
	// The weekly snapshot of 10-12 is kept until 11-09, inside the later lock.
	e, err := NewEpoch(date("2026-10-01T02:00:00Z"), "s", format.ReasonMonth, format.TierMonthly, r, "age1x")
	if err != nil {
		t.Fatal(err)
	}
	weekly := TierUntil(date("2026-10-12T02:00:00Z"), format.TierWeekly, r)
	if until, capped := RetainUntil(weekly, format.ClassLater, e); capped || !until.Equal(date("2026-11-09T02:00:00Z")) {
		t.Errorf("weekly snapshot kept until %s (capped %v)", until, capped)
	}
}

func TestPlannedEndInEveryMonth(t *testing.T) {
	cases := map[string]string{
		"2026-01-31T23:59:59Z":      "2026-02-01T00:00:00Z",
		"2026-02-01T00:00:00Z":      "2026-03-01T00:00:00Z",
		"2028-02-29T12:00:00Z":      "2028-03-01T00:00:00Z",
		"2026-12-31T23:59:59Z":      "2027-01-01T00:00:00Z",
		"2026-06-15T08:00:00Z":      "2026-07-01T00:00:00Z",
		"2026-10-31T23:30:00-02:00": "2026-12-01T00:00:00Z", // 11-01 01:30 UTC
	}
	for in, want := range cases {
		if got := PlannedEnd(date(in)); !got.Equal(date(want)) {
			t.Errorf("PlannedEnd(%s) = %s, want %s", in, got, want)
		}
	}
	for m := 1; m <= 12; m++ {
		at := time.Date(2027, time.Month(m), 10, 0, 0, 0, 0, time.UTC)
		end := PlannedEnd(at)
		if end.Day() != 1 || end.Hour() != 0 || !end.After(at) || end.Sub(at) > 22*24*time.Hour {
			t.Errorf("month %d: planned end %s", m, end)
		}
	}
}

func TestMonthlyTierAcrossLeapAndYearEnd(t *testing.T) {
	r := Retention{Days: 1, KeepMonthly: 1}
	_, opening, later := Locks(date("2028-01-31T10:00:00Z"), format.TierMonthly, r)
	// Go's AddDate normalises 2028-02-31 to 03-02; the lock covers it.
	if !opening.Equal(date("2028-03-05T10:00:00Z")) {
		t.Errorf("opening %s", opening)
	}
	if !later.Equal(date("2028-02-02T00:00:00Z")) {
		t.Errorf("later %s", later)
	}
	_, opening, _ = Locks(date("2026-12-31T23:00:00Z"), format.TierMonthly, Retention{Days: 1, KeepMonthly: 12})
	if !opening.Equal(date("2028-01-03T23:00:00Z")) {
		t.Errorf("opening %s", opening)
	}
}

func TestNoMonthlyTier(t *testing.T) {
	r := Retention{Days: 7}
	_, opening, later := Locks(date("2026-10-01T02:00:00Z"), format.TierBase, r)
	if !later.Equal(date("2026-11-08T00:00:00Z")) || !opening.Equal(later.Add(Slack)) {
		t.Fatalf("opening %s later %s", opening, later)
	}
}

func TestDecide(t *testing.T) {
	r := Retention{Days: 7, KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 12}
	e, _ := NewEpoch(date("2026-10-01T02:00:00Z"), "s", format.ReasonFirst, format.TierMonthly, r, "age1x")
	cur := func(done bool) *Current { return &Current{Epoch: e, OpeningDone: done} }
	mid := date("2026-10-15T02:00:00Z")
	next := date("2026-11-01T02:00:00Z")
	longer := r
	longer.KeepWeekly = 8
	shorter := r
	shorter.KeepWeekly = 1
	old := *cur(true)
	old.Epoch.Version = 0
	for name, c := range map[string]struct {
		now       time.Time
		cur       *Current
		r         Retention
		lost, req bool
		want      Decision
	}{
		"first":                   {mid, nil, r, false, false, Decision{true, format.ReasonFirst}},
		"cache lost":              {mid, nil, r, true, false, Decision{true, format.ReasonCacheLost}},
		"continue":                {mid, cur(true), r, false, false, Decision{}},
		"resume opening":          {mid, cur(false), r, false, false, Decision{}},
		"month":                   {next, cur(true), r, false, false, Decision{true, format.ReasonMonth}},
		"opening spans the month": {next, cur(false), r, false, false, Decision{}},
		"requested":               {mid, cur(true), r, false, true, Decision{true, format.ReasonRequested}},
		"retention increased":     {mid, cur(true), longer, false, false, Decision{true, format.ReasonRetentionIncreased}},
		"retention decreased":     {mid, cur(true), shorter, false, false, Decision{}},
		"monthly only grew":       {mid, cur(true), Retention{Days: 7, KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 24}, false, false, Decision{}},
		"format":                  {mid, &old, r, false, false, Decision{true, format.ReasonFormat}},
	} {
		if got := Decide(c.now, c.cur, c.r, c.lost, c.req, "age1x"); got != c.want {
			t.Errorf("%s: %+v, want %+v", name, got, c.want)
		}
	}
	// Packs are wrapped to one recipient per epoch: a new public key opens
	// a new epoch at once, whatever else is unchanged.
	if got := Decide(mid, cur(true), r, false, false, "age1other"); got != (Decision{true, format.ReasonRecipient}) {
		t.Errorf("recipient changed: %+v", got)
	}
}

// A resumed opening run keeps the opening tier, and the class lock caps it;
// the cap bites only when the resume is days later than the open.
func TestRetainUntilIsCappedByTheClassLock(t *testing.T) {
	r := Retention{Days: 7, KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 12}
	e, _ := NewEpoch(date("2026-10-01T02:00:00Z"), "s", format.ReasonFirst, format.TierMonthly, r, "age1x")
	onTime := TierUntil(date("2026-10-02T02:00:00Z"), format.TierMonthly, r)
	if _, capped := RetainUntil(onTime, format.ClassOpening, e); capped {
		t.Error("a resume a day later was capped")
	}
	late := TierUntil(date("2026-10-06T02:00:00Z"), format.TierMonthly, r)
	until, capped := RetainUntil(late, format.ClassOpening, e)
	if !capped || !until.Equal(e.OpeningRetainUntil) {
		t.Errorf("a resume five days later: %s capped %v", until, capped)
	}
}

func TestNewEpochIDShape(t *testing.T) {
	id := NewEpochID(date("2026-10-01T02:00:00Z"))
	if !format.ValidEpochID(id) || id[:7] != "e202610" {
		t.Fatalf("epoch id %q", id)
	}
	if _, err := NewEpoch(date("2026-10-01T02:00:00Z"), "s", format.ReasonFirst, "yearly", Retention{}, "age1x"); err == nil {
		t.Fatal("an unknown tier accepted")
	}
}
