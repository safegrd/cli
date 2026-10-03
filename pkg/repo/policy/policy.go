// Package policy decides when an epoch opens and what every object in it is
// locked until. It is pure: the clock is a parameter.
//
// Snapshots inside an epoch share objects, so an object's lock must cover every
// snapshot that can reference it, and locks are set once and never extended.
// Let T_mid be the longest any snapshot other than the epoch's first can be
// kept: max(retention days, daily tier days, weekly tier weeks × 7). Then:
//
//   - objects written by the opening run are locked until
//     max(planned_end + T_mid, opened_at + the opening tier) + 3 days;
//   - objects written by any later run are locked until planned_end + T_mid;
//   - planned_end is the first instant of the next UTC month, fixed when the
//     epoch opens.
//
// A later snapshot is taken before planned_end and kept at most T_mid, so every
// object it can reference outlives it. The opening snapshot references only
// what its own run wrote. No snapshot references an object written after it.
package policy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/safegrd/cli/pkg/repo/format"
)

// Slack is added to the opening class's lock, so capping a resumed opening
// snapshot by it shortens nothing in practice.
const Slack = 3 * 24 * time.Hour

// Retention is a surface's retention: every backup is kept Days, and the
// first of each UTC day, ISO week and month for the daily, weekly and monthly
// tiers. Zero turns a tier off.
type Retention struct {
	Days        int `json:"days"`
	KeepDaily   int `json:"keep_daily"`
	KeepWeekly  int `json:"keep_weekly"`
	KeepMonthly int `json:"keep_monthly"`
}

// TMidDays is the longest, in days, any snapshot but an epoch's first can be
// kept.
func (r Retention) TMidDays() int {
	t := r.Days
	if r.KeepDaily > t {
		t = r.KeepDaily
	}
	if 7*r.KeepWeekly > t {
		t = 7 * r.KeepWeekly
	}
	if t < 0 {
		return 0
	}
	return t
}

// PlannedEnd is the first instant of the UTC month after t.
func PlannedEnd(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
}

// TierUntil is how long a backup taken at start is kept at tier.
func TierUntil(start time.Time, tier string, r Retention) time.Time {
	until := start.Add(days(r.Days))
	switch tier {
	case format.TierDaily:
		if u := start.AddDate(0, 0, r.KeepDaily); u.After(until) {
			until = u
		}
	case format.TierWeekly:
		if u := start.AddDate(0, 0, 7*r.KeepWeekly); u.After(until) {
			until = u
		}
	case format.TierMonthly:
		if u := start.AddDate(0, r.KeepMonthly, 0); u.After(until) {
			until = u
		}
	}
	return until
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// ValidTier reports whether tier is one an opening snapshot can be declared at.
func ValidTier(tier string) bool {
	switch tier {
	case format.TierBase, format.TierDaily, format.TierWeekly, format.TierMonthly:
		return true
	}
	return false
}

// Locks returns the epoch's two lock dates for an epoch opened at opened with
// the opening snapshot declared at tier.
func Locks(opened time.Time, tier string, r Retention) (plannedEnd, opening, later time.Time) {
	plannedEnd = PlannedEnd(opened)
	later = plannedEnd.Add(days(r.TMidDays()))
	opening = later
	if t := TierUntil(opened.UTC(), tier, r); t.After(opening) {
		opening = t
	}
	return plannedEnd, opening.Add(Slack), later
}

// NewEpochID returns e<YYYYMM>-<8 lowercase hex> for an epoch opened at t.
func NewEpochID(t time.Time) string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("policy: the system random source failed: " + err.Error())
	}
	return fmt.Sprintf("e%s-%s", t.UTC().Format("200601"), hex.EncodeToString(b[:]))
}

// NewEpoch builds the descriptor of an epoch opening now. The dates are frozen
// here: a later change of retention never moves them.
func NewEpoch(now time.Time, surfaceID, reason, tier string, r Retention, recipient string) (format.Epoch, error) {
	if !ValidTier(tier) {
		return format.Epoch{}, fmt.Errorf("opening tier %q is not base, daily, weekly or monthly", tier)
	}
	now = now.UTC()
	end, opening, later := Locks(now, tier, r)
	e := format.Epoch{
		Format:             format.FormatName,
		Version:            format.Version,
		EpochID:            NewEpochID(now),
		SurfaceID:          surfaceID,
		OpenedAt:           now,
		PlannedEnd:         end,
		Reason:             reason,
		TMidDays:           r.TMidDays(),
		OpeningTier:        tier,
		OpeningRetainUntil: opening,
		LaterRetainUntil:   later,
		Recipient:          recipient,
		Chunker:            format.DefaultChunker,
		PackTargetBytes:    format.DefaultPackTarget,
	}
	return e, e.Validate()
}

// Current is what the writer knows about the epoch it last wrote into.
type Current struct {
	Epoch       format.Epoch
	OpeningDone bool
}

// Decision is whether a run continues the current epoch or opens a new one.
type Decision struct {
	Open   bool
	Reason string
}

// Decide says whether a run at now continues cur or opens a new epoch, and
// why. cur is nil when the writer knows no epoch; lost says it once did and its
// cache is gone or unreadable, which is never repaired by reading the
// repository back. recipient is the public key this run seals to: an epoch
// holds packs wrapped to one recipient, so another key opens a new one.
func Decide(now time.Time, cur *Current, r Retention, lost, requested bool, recipient string) Decision {
	switch {
	case cur == nil && lost:
		return Decision{true, format.ReasonCacheLost}
	case cur == nil:
		return Decision{true, format.ReasonFirst}
	case requested:
		return Decision{true, format.ReasonRequested}
	case cur.Epoch.Version != format.Version:
		return Decision{true, format.ReasonFormat}
	case cur.Epoch.Recipient != recipient:
		return Decision{true, format.ReasonRecipient}
	case r.TMidDays() > cur.Epoch.TMidDays:
		// The customer asked for longer protection; it must not wait for the
		// month to turn. A decrease waits: the frozen locks are longer anyway.
		return Decision{true, format.ReasonRetentionIncreased}
	case !now.Before(cur.Epoch.PlannedEnd) && cur.OpeningDone:
		return Decision{true, format.ReasonMonth}
	}
	// Includes an opening run still uploading when the month ends: it
	// finishes in the epoch it opened.
	return Decision{}
}

// RetainUntil caps a snapshot's planned retain-until by the lock of its class.
// capped reports that the cap shortened it, which the writer says out loud.
func RetainUntil(planned time.Time, class string, e format.Epoch) (until time.Time, capped bool) {
	lock := e.RetainUntil(class)
	if planned.After(lock) {
		return lock, true
	}
	return planned, false
}
