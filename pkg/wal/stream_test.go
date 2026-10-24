package wal

import (
	"strings"
	"testing"
	"time"
)

func TestStreamSegmentNamesRoundTrip(t *testing.T) {
	for _, s := range []StreamSeg{
		{File: 2, Start: 0x23da, End: 0x2740},
		{File: 2, Start: 0x2740, End: 0x2eef, Rotates: true},
		{File: 3, Start: 4, End: 4, Idle: 0x6adc7203},
	} {
		n := mysqlSegName(s)
		got, ok := parseMySQLSegment(n)
		s.Name = n
		if !ok || got != s {
			t.Errorf("%s reads back as %+v, %v", n, got, ok)
		}
		if ValidName(n) != nil {
			t.Errorf("%s is not a valid archive name", n)
		}
	}
	n := mongoSegName(MongoTS(100, 1), MongoTS(105, 3))
	got, ok := parseMongoSegment(n)
	if !ok || got.Start != MongoTS(100, 1) || got.End != MongoTS(105, 3) || ValidName(n) != nil {
		t.Errorf("%s reads back as %+v, %v", n, got, ok)
	}
}

// A run follows a file's segments, crosses to the next file only after a
// rotate, takes empty segments in its stride, and names the first segment
// out of place.
func TestStreamRunFindsTheGap(t *testing.T) {
	seg := func(file uint32, a, b uint64, rot bool, idle uint32) streamEntry {
		s := StreamSeg{File: file, Start: a, End: b, Rotates: rot, Idle: idle}
		s.Name = mysqlSegName(s)
		return streamEntry{StreamSeg: s, PushedAt: time.Unix(int64(a), 0)}
	}
	es := []streamEntry{
		seg(2, 100, 200, false, 0),
		seg(2, 200, 200, false, 7),
		seg(2, 200, 300, true, 0),
		seg(3, 4, 90, false, 0),
		seg(3, 120, 150, false, 0), // 90 to 120 is missing
	}
	run, gap := streamRun(es, 2, 150)
	if len(run) != 4 || gap != es[4].Name {
		t.Fatalf("run of %d, gap %q", len(run), gap)
	}
	if _, gap := streamRun(es, 2, 50); gap == "" {
		t.Fatal("a base before the first segment starts a run")
	}
	run, gap = streamRun(es[:4], 3, 4)
	if len(run) != 1 || gap != "" {
		t.Fatalf("from the start of file 3: run of %d, gap %q", len(run), gap)
	}
	// Without the rotate, file 3 does not follow file 2.
	es[2] = seg(2, 200, 300, false, 0)
	if _, gap := streamRun(es[:4], 2, 100); gap != es[3].Name {
		t.Fatalf("a run crossed to the next file without a rotate: gap %q", gap)
	}
}

// Whole transactions only: a segment is cut after an XID, never inside
// BEGIN, and a GTID event belongs to the transaction after it.
func TestTxGrouperCutsAtTransactions(t *testing.T) {
	ev := func(typ byte) binlogEvent { return binlogEvent{Type: typ, Raw: make([]byte, 19)} }
	g := txGrouper{}
	q := func(stmt string) binlogEvent {
		e := ev(evQuery)
		e.Raw = append(make([]byte, 19), make([]byte, 13)...)
		e.Raw = append(e.Raw, 0)
		e.Raw = append(e.Raw, stmt...)
		return e
	}
	g.fd = formatDesc{PostHeader: make([]byte, 40)}
	g.fd.PostHeader[evQuery-1] = 13
	steps := []struct {
		e    binlogEvent
		done bool
	}{
		{ev(evGTID), false},
		{q("BEGIN"), false},
		{ev(evTableMap), false},
		{ev(evWriteRowsV2), false},
		{ev(evXID), true},
		{ev(evGTID), false},
		{q("CREATE TABLE t (id int)"), true},
	}
	for i, s := range steps {
		if got := g.add(s.e) != nil; got != s.done {
			t.Fatalf("step %d: completed %v, want %v", i, got, s.done)
		}
	}
}

// A compressed transaction stops the follower, in words, instead of being
// archived and then dropped by a restore that cannot see inside it.
func TestTheFollowerRefusesACompressedTransaction(t *testing.T) {
	raw := make([]byte, 40)
	raw[4] = evTxPayload
	raw[9] = 40
	raw[13] = 200
	s := &mysqlStreamState{f: &MySQLFollower{}, haveFD: true, fileName: "binlog.000002"}
	err := s.take(t.Context(), raw)
	if err == nil || !strings.Contains(err.Error(), "binlog_transaction_compression") {
		t.Fatalf("a compressed transaction was taken: %v", err)
	}
}
