package diskspace

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCheckFreeSpaceKeepsAShareOfTheDiskFree(t *testing.T) {
	standIn(t, 100<<20, 1000<<20)
	// 50 MiB of 1000 is kept: 50 more may be written, 51 may not.
	if err := CheckFreeSpace("/data", 50<<20, "a test", ""); err != nil {
		t.Errorf("50 MiB with 100 free: %v", err)
	}
	err := CheckFreeSpace("/data", 51<<20, "a test", "free some space")
	if !errors.Is(err, ErrNotEnoughDisk) || !strings.Contains(err.Error(),
		"not enough disk under /data for a test: it needs about 51.0 MiB and 100.0 MiB is free (keeping 50.0 MiB spare for the rest of the host); free some space") {
		t.Errorf("51 MiB with 100 free: %v", err)
	}
	// A large disk keeps a gibibyte, not 5%: 2.6 GiB free of 72 GiB refused
	// a 137 KiB drill on a CI runner.
	spaceOf = func(string) (int64, int64, error) { return 2600 << 20, 72 << 30, nil }
	if err := CheckFreeSpace("/data", 137<<10, "a test", ""); err != nil {
		t.Errorf("137 KiB with 2.6 GiB of 72 free: %v", err)
	}
	if err := CheckFreeSpace("/data", 1600<<20, "a test", ""); !errors.Is(err, ErrNotEnoughDisk) || !strings.Contains(err.Error(), "keeping 1.0 GiB spare") {
		t.Errorf("1.6 GiB with 2.6 GiB free should keep 1 GiB: %v", err)
	}
	spaceOf = func(string) (int64, int64, error) { return 0, 0, errors.New("unreadable") }
	if err := CheckFreeSpace("/data", 1<<60, "a test", ""); err != nil {
		t.Errorf("a filesystem that cannot be read refused a write; the write should speak for itself: %v", err)
	}
}

// A write of unknown size stops before the disk drops below the share kept
// free, not after it is full.
func TestGuardStopsAWriteBeforeTheDiskFills(t *testing.T) {
	var written int64
	standIn(t, 0, 0)
	spaceOf = func(string) (int64, int64, error) { return 300<<20 - written, 1000 << 20, nil }
	var dst bytes.Buffer
	g := NewGuard(&dst, "/data", "a backup", "")
	chunk := make([]byte, 32<<20)
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		var n int
		n, err = g.Write(chunk)
		written += int64(n)
		dst.Reset()
	}
	if !errors.Is(err, ErrNotEnoughDisk) {
		t.Fatalf("the guard never stopped the write: %v", err)
	}
	// 300 MiB free and 50 kept: it may not write past 250 MiB, and stops
	// within one check interval of it.
	if written > 250<<20 || written < 250<<20-guardEvery-int64(len(chunk)) {
		t.Errorf("stopped after %d MiB; want just under 250", written>>20)
	}
}

// standIn replaces the free space and the filesystem lookup for one test:
// every path is its own filesystem with avail of total bytes free.
func standIn(t *testing.T, avail, total int64) {
	t.Helper()
	spaceOf = func(string) (int64, int64, error) { return avail, total, nil }
	ids := map[string]uint64{}
	filesystemOf = func(dir string) uint64 {
		if _, ok := ids[dir]; !ok {
			ids[dir] = uint64(len(ids) + 1)
		}
		return ids[dir]
	}
	t.Cleanup(func() {
		spaceOf, filesystemOf = DiskSpace, filesystemID
		if left := len(inFlight); left != 0 {
			t.Errorf("%d filesystems still hold reservations after the test: %v", left, inFlight)
		}
	})
}

// Writes running at once each read the same free space: a reservation
// counts what the others are about to put on disk, so the second of two
// writes that fit one at a time, and not together, is refused.
func TestReservationsCountWritesRunningAtOnce(t *testing.T) {
	standIn(t, 150<<20, 1000<<20)
	release, err := Reserve("/sink", 60<<20, "a backup", "free space")
	if err != nil {
		t.Fatalf("the first write of 60 MiB into 150 MiB free: %v", err)
	}
	_, err = Reserve("/sink", 60<<20, "a backup", "free space")
	if !errors.Is(err, ErrNotEnoughDisk) || !strings.Contains(err.Error(), "90.0 MiB is free") {
		t.Fatalf("the second write was not refused for the first one's bytes: %v", err)
	}
	err = CheckFreeSpace("/sink", 60<<20, "a backup", "free space")
	if !errors.Is(err, ErrNotEnoughDisk) || !strings.Contains(err.Error(), "90.0 MiB is free") {
		t.Fatalf("a plain check did not count the write in flight: %v", err)
	}
	release()
	release() // twice is once
	again, err := Reserve("/sink", 60<<20, "a backup", "free space")
	if err != nil {
		t.Fatalf("after the first write released its bytes: %v", err)
	}
	again()
}

// A write to one disk does not count against the free space of another.
func TestAReservationCountsOnlyOnItsOwnFilesystem(t *testing.T) {
	standIn(t, 150<<20, 1000<<20)
	release, err := Reserve("/sink", 60<<20, "a backup", "free space")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	other, err := Reserve("/other-disk", 60<<20, "a backup", "free space")
	if err != nil {
		t.Fatalf("a write to another disk was refused for this one's reservation: %v", err)
	}
	other()
}
