package wal

import (
	"bytes"
	"context"
	"testing"
)

func TestASpoolHoldsWALUntilItIsDrainedAndDropsTheOldestPastItsBound(t *testing.T) {
	ctx := context.Background()
	a, _ := testArchive(t)
	sp := Spool{Dir: t.TempDir()}
	names := []string{"000000010000000000000003", "000000010000000000000004", "000000010000000000000005"}
	for i, n := range names {
		if err := sp.Add(a.SystemID, n, walFile(byte(i+1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := sp.Add(a.SystemID, names[0], walFile(1)); err != nil {
		t.Fatalf("the same file spooled twice: %v", err)
	}
	if err := sp.Add(a.SystemID, names[0], walFile(9)); err == nil {
		t.Fatal("a file spooled again with other contents was taken")
	}
	// Two files' worth: the oldest goes.
	dropped, err := sp.DropOldest(2*(1<<16), 1<<16)
	if err != nil || len(dropped) != 2 || dropped[0].Name != names[0] || dropped[1].Name != names[1] {
		t.Fatalf("dropped %+v, %v", dropped, err)
	}
	if err := sp.RecordDropped(dropped...); err != nil {
		t.Fatal(err)
	}
	if rec, _ := sp.Dropped(); len(rec) != 2 {
		t.Fatalf("the record holds %d", len(rec))
	}
	n, err := Drain(ctx, a, sp, 4)
	if err != nil || n != 1 {
		t.Fatalf("drained %d: %v", n, err)
	}
	if left, _ := sp.List(); len(left) != 0 {
		t.Fatalf("%d left in the spool", len(left))
	}
	var got bytes.Buffer
	if err := a.Fetch(ctx, names[2], &got); err != nil || !bytes.Equal(got.Bytes(), walFile(3)) {
		t.Fatalf("the drained file does not fetch back: %v", err)
	}
	if next := NextSegments("0000000100000000000000FF", 16<<20, 2); len(next) != 2 || next[0] != "000000010000000100000000" {
		t.Fatalf("next segments: %v", next)
	}
}
