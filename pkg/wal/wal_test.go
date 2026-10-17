package wal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

const seg16 = 16 << 20

func testArchive(t *testing.T) (*Archive, *time.Time) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewDirStore(t.TempDir(), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	a := &Archive{Store: st, SurfaceID: "db", SystemID: "7697520923061272610", Recipient: id.Recipient().String(),
		Identity: id.String(), Window: 7 * 24 * time.Hour, BaseEvery: 7 * 24 * time.Hour, Now: func() time.Time { return now }}
	return a, &now
}

func walFile(seed byte) []byte {
	b := bytes.Repeat([]byte{seed}, 1<<16)
	b[0] = 'W'
	return b
}

func TestAPushedFileFetchesBackFromTheSegmentsAndFromABundle(t *testing.T) {
	ctx := context.Background()
	a, now := testArchive(t)
	names := []string{"000000010000000000000001", "000000010000000000000002", "00000002.history"}
	for i, n := range names {
		*now = now.Add(time.Minute)
		if err := a.Push(ctx, n, bytes.NewReader(walFile(byte(i)))); err != nil {
			t.Fatalf("push %s: %v", n, err)
		}
	}
	fetch := func(n string) []byte {
		t.Helper()
		var out bytes.Buffer
		if err := a.Fetch(ctx, n, &out); err != nil {
			t.Fatalf("fetch %s: %v", n, err)
		}
		return out.Bytes()
	}
	if got := fetch(names[1]); !bytes.Equal(got, walFile(1)) {
		t.Fatalf("fetched %d bytes that are not the pushed file", len(got))
	}

	res, err := a.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 3 || res.Deleted != 3 || res.Kept != 0 {
		t.Fatalf("bundle: %+v, want 3 files bundled and 3 deleted", res)
	}
	if !res.LockedUntil.IsZero() {
		t.Fatalf("a directory locks nothing, and the bundle says locked until %s", res.LockedUntil)
	}
	if left, err := a.Pushed(ctx); err != nil || len(left) != 0 {
		t.Fatalf("unlocked files after the bundle: %v %v", left, err)
	}
	for i, n := range names {
		if got := fetch(n); !bytes.Equal(got, walFile(byte(i))) {
			t.Fatalf("%s from the bundle is not the pushed file", n)
		}
	}
	err = a.Fetch(ctx, "000000010000000000000003", &bytes.Buffer{})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetching a file never pushed: %v, want ErrNotFound", err)
	}
}

func TestARepeatedPushIsAcceptedAndADifferentOneRefused(t *testing.T) {
	ctx := context.Background()
	a, now := testArchive(t)
	n := "000000010000000000000001"
	if err := a.Push(ctx, n, bytes.NewReader(walFile(1))); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if err := a.Push(ctx, n, bytes.NewReader(walFile(1))); err != nil {
		t.Fatalf("the same file again: %v", err)
	}
	if p, _ := a.Pushed(ctx); len(p) != 1 {
		t.Fatalf("a repeated push wrote again: %d objects", len(p))
	}
	err := a.Push(ctx, n, bytes.NewReader(walFile(2)))
	if err == nil || !strings.Contains(err.Error(), "already archived with different contents") {
		t.Fatalf("a different file under the same name: %v", err)
	}
	if err := a.Push(ctx, "../../etc/passwd", bytes.NewReader(nil)); err == nil {
		t.Fatal("a name PostgreSQL never archives was accepted")
	}
}

func TestAFileAlreadyBundledIsDeletedNotBundledAgain(t *testing.T) {
	ctx := context.Background()
	a, now := testArchive(t)
	n := "000000010000000000000001"
	if err := a.Push(ctx, n, bytes.NewReader(walFile(1))); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Bundle(ctx); err != nil {
		t.Fatal(err)
	}
	// PostgreSQL pushes it again after a crash.
	*now = now.Add(time.Hour)
	if err := a.Push(ctx, n, bytes.NewReader(walFile(1))); err != nil {
		t.Fatal(err)
	}
	res, err := a.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 0 || res.Deleted != 1 {
		t.Fatalf("second bundle: %+v, want nothing bundled and one deleted", res)
	}
	if b, _ := a.Bundles(ctx); len(b) != 1 {
		t.Fatalf("%d bundles, want 1", len(b))
	}
}

func TestStatusNamesAGapAndTheBaseItBreaks(t *testing.T) {
	ctx := context.Background()
	a, now := testArchive(t)
	base := BaseInfo{Version: 1, BaseID: "b-20261017T120000Z-0000abcd", SurfaceID: "db", SystemID: a.SystemID,
		StartedAt: *now, EndedAt: now.Add(time.Minute), ServerVersionNum: 160004, SegmentSize: seg16, Timeline: 1,
		StartWAL: "000000010000000000000002", EndWAL: "000000010000000000000002"}
	writeBase(t, a, base)
	for _, n := range []string{"000000010000000000000002", "000000010000000000000003", "000000010000000000000005"} {
		*now = now.Add(time.Minute)
		if err := a.Push(ctx, n, bytes.NewReader([]byte(n))); err != nil {
			t.Fatal(err)
		}
	}
	st, err := a.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Gaps) != 1 || st.Gaps[0].First != "000000010000000000000004" || st.Gaps[0].Last != "000000010000000000000004" {
		t.Fatalf("gaps: %+v, want segment 4 missing", st.Gaps)
	}
	if len(st.Gaps[0].Breaks) != 1 || st.Gaps[0].Breaks[0] != base.BaseID {
		t.Fatalf("the gap breaks %v, want %s", st.Gaps[0].Breaks, base.BaseID)
	}
	// The window ends at segment 3, the last before the gap.
	want := time.Date(2026, 10, 17, 12, 2, 0, 0, time.UTC)
	if !st.HasWindow || !st.WindowFrom.Equal(base.EndedAt) || !st.WindowTo.Equal(want) {
		t.Fatalf("window %v %s to %s, want %s to %s", st.HasWindow, st.WindowFrom, st.WindowTo, base.EndedAt, want)
	}
}

func writeBase(t *testing.T, a *Archive, b BaseInfo) {
	t.Helper()
	body := []byte(`{"version":1,"base_id":"` + b.BaseID + `","surface_id":"db","system_id":"` + b.SystemID +
		`","started_at":"` + b.StartedAt.Format(time.RFC3339) + `","ended_at":"` + b.EndedAt.Format(time.RFC3339) +
		`","server_version_num":160004,"wal_segment_size":16777216,"timeline":1,"start_wal":"` + b.StartWAL + `","end_wal":"` + b.EndWAL + `"}`)
	if _, err := a.Store.Put(context.Background(), a.baseKey(b.BaseID, "base.json"), bytes.NewReader(body), time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestTheWALABaseNeedsEndsBeforeABoundary(t *testing.T) {
	r := []walRange{{Timeline: 1, Start: 0x4000028, End: 0x6000000}}
	got := neededWAL(r, seg16)
	want := []string{"000000010000000000000004", "000000010000000000000005"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("needed %v, want %v", got, want)
	}
	if n := SegmentName(1, 0x1_0000_0000, seg16); n != "000000010000000100000000" {
		t.Fatalf("segment of 1/0 is %s", n)
	}
}

func TestASegmentKeyReadsBack(t *testing.T) {
	at := time.Unix(1792238400, 0).UTC()
	k := segmentKey("r/wal/db/1", "000000010000000A0000003F.partial", at, strings.Repeat("ab", 32))
	p, ok := parseSegmentKey(k)
	if !ok || p.Name != "000000010000000A0000003F.partial" || !p.PushedAt.Equal(at) || p.Sha16 != strings.Repeat("ab", 8) {
		t.Fatalf("%s read back as %+v %v", k, p, ok)
	}
}

func TestPgControlIsReadLittleEndian(t *testing.T) {
	head := []byte{0x22, 0x40, 0x34, 0x0e, 0x7f, 0x16, 0xd3, 0x6a, 0x14, 0x05, 0x00, 0x00}
	id, err := systemIDFromControl(head, "pg_control")
	if err != nil || id != "7697520923061272610" {
		t.Fatalf("system id %q %v", id, err)
	}
	if _, err := systemIDFromControl(make([]byte, 12), "pg_control"); err == nil {
		t.Fatal("an all-zero pg_control was read as a system id")
	}
}

func TestTheArchiverIsFailingOnlyWhileItsLastAttemptFailed(t *testing.T) {
	t0 := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		a    Archiver
		want bool
	}{
		{Archiver{}, false},
		{Archiver{ArchivedAt: t0}, false},
		{Archiver{FailedAt: t0}, true},
		{Archiver{ArchivedAt: t0, FailedAt: t0.Add(time.Second)}, true},
		{Archiver{ArchivedAt: t0.Add(time.Second), FailedAt: t0}, false},
	}
	for i, c := range cases {
		if got := c.a.Failing(); got != c.want {
			t.Fatalf("case %d: Failing() = %v", i, got)
		}
	}
}

// A restore fetches each WAL file in its own process. Once a bundle's index
// is cached, a fetch reads it from disk and not from the store.
func TestAFetchReadsABundleIndexFromTheCache(t *testing.T) {
	ctx := context.Background()
	a, _ := testArchive(t)
	a.IndexCache = t.TempDir()
	n := "000000010000000000000001"
	if err := a.Push(ctx, n, bytes.NewReader(walFile(1))); err != nil {
		t.Fatal(err)
	}
	res, err := a.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Fetch(ctx, n, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	// The store's copy of the index goes bad; the cached one is read.
	p := a.Store.(*DirStore).Describe() + "/" + strings.TrimPrefix(a.indexKey(res.BundleID), a.Store.Root()+"/")
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := a.Fetch(ctx, n, &out); err != nil {
		t.Fatalf("fetch with the index cached: %v", err)
	}
	if !bytes.Equal(out.Bytes(), walFile(1)) {
		t.Fatal("the fetched file is not the pushed one")
	}
	a.IndexCache = ""
	if err := a.Fetch(ctx, n, &bytes.Buffer{}); err == nil {
		t.Fatal("without the cache the bad index was not read: the test proves nothing")
	}
}

// After a promotion the replay reads timeline 2 from the segment holding the
// switch. The window follows it; the old timeline's last segment, left
// partial, is not a gap.
func TestTheWindowFollowsATimelineSwitch(t *testing.T) {
	ctx := context.Background()
	a, now := testArchive(t)
	base := BaseInfo{Version: 1, BaseID: "b-20261017T120000Z-0000abcd", SurfaceID: "db", SystemID: a.SystemID,
		StartedAt: *now, EndedAt: now.Add(time.Minute), ServerVersionNum: 160004, SegmentSize: seg16, Timeline: 1,
		StartWAL: "000000010000000000000002", EndWAL: "000000010000000000000002"}
	writeBase(t, a, base)
	for _, n := range []string{"000000010000000000000002", "000000010000000000000003", "000000010000000000000004.partial",
		"00000002.history", "000000020000000000000004", "000000020000000000000005"} {
		*now = now.Add(time.Minute)
		if err := a.Push(ctx, n, bytes.NewReader([]byte(n))); err != nil {
			t.Fatal(err)
		}
	}
	st, err := a.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Gaps) != 0 {
		t.Fatalf("gaps across a timeline switch: %+v", st.Gaps)
	}
	if want := time.Date(2026, 10, 17, 12, 6, 0, 0, time.UTC); !st.HasWindow || !st.WindowTo.Equal(want) {
		t.Fatalf("window ends %s (%v), want %s on timeline 2", st.WindowTo, st.HasWindow, want)
	}
	// Timeline 2's first segment goes missing: that is the gap.
	pushed, _ := a.Pushed(ctx)
	for _, p := range pushed {
		if p.Name == "000000020000000000000005" {
			if err := a.Store.Delete(ctx, p.Key); err != nil {
				t.Fatal(err)
			}
		}
	}
	*now = now.Add(time.Minute)
	if err := a.Push(ctx, "000000020000000000000006", bytes.NewReader([]byte("6"))); err != nil {
		t.Fatal(err)
	}
	st, err = a.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Gaps) != 1 || st.Gaps[0].First != "000000020000000000000005" {
		t.Fatalf("gaps %+v, want timeline 2 segment 5", st.Gaps)
	}
}
