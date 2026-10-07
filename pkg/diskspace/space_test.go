package diskspace

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCheckFreeSpaceKeepsAShareOfTheDiskFree(t *testing.T) {
	spaceOf = func(string) (int64, int64, error) { return 100 << 20, 1000 << 20, nil }
	t.Cleanup(func() { spaceOf = DiskSpace })
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
	if err := CheckFreeSpace("/data", 1600<<20, "a test", ""); !errors.Is(err, ErrNotEnoughDisk) {
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
	spaceOf = func(string) (int64, int64, error) { return 300<<20 - written, 1000 << 20, nil }
	t.Cleanup(func() { spaceOf = DiskSpace })
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
