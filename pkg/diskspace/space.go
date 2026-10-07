package diskspace

import (
	"errors"
	"fmt"
	"io"
)

// KeepFreeShare is the share of a filesystem a backup or a drill leaves free
// after writing to it, up to KeepFreeMax. The host's own database, logs and
// applications live on the same disk, and filling it would take them down
// with the backup.
const KeepFreeShare = 0.05

// KeepFreeMax caps what is kept free. 5% of a 72 GB disk is 3.6 GiB, and a
// host with 2.6 GiB free refused to drill a 137 KiB snapshot; 5% of 2 TB
// held back 100 GB. A gibibyte is room for the host to go on writing.
const KeepFreeMax = 1 << 30

// keepFree is what is kept free on a filesystem of total bytes.
func keepFree(total int64) int64 {
	return min(int64(float64(total)*KeepFreeShare), KeepFreeMax)
}

// ErrNotEnoughDisk is a NotEnoughDiskError's sentinel, for errors.Is.
var ErrNotEnoughDisk = errors.New("not enough disk")

// NotEnoughDiskError is a refusal to write need bytes under Dir.
type NotEnoughDiskError struct {
	Dir         string
	What        string // "a Fire Drill of this snapshot"
	Need, Avail int64
	Keep        int64
	Remedy      string // what the operator can do, one clause
}

func (e *NotEnoughDiskError) Error() string {
	msg := fmt.Sprintf("not enough disk under %s for %s: it needs about %s and %s is free (keeping %s spare for the rest of the host)",
		e.Dir, e.What, HumanBytes(e.Need), HumanBytes(e.Avail), HumanBytes(e.Keep))
	if e.Remedy != "" {
		msg += "; " + e.Remedy
	}
	return msg
}

func (e *NotEnoughDiskError) Is(target error) bool { return target == ErrNotEnoughDisk }

// CheckFreeSpace refuses to write need bytes under dir when that would leave
// less than keepFree of the filesystem free. A filesystem whose free
// space cannot be read is not refused: the write itself will say so.
func CheckFreeSpace(dir string, need int64, what, remedy string) error {
	avail, total, err := spaceOf(dir)
	if err != nil {
		return nil
	}
	keep := keepFree(total)
	if avail < need+keep {
		return &NotEnoughDiskError{Dir: dir, What: what, Need: need, Avail: avail, Keep: keep, Remedy: remedy}
	}
	return nil
}

// HumanBytes prints n in binary units: "1.5 GiB".
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// spaceOf is DiskSpace, replaced in tests to stand in for a filling disk.
var spaceOf = DiskSpace

// guardEvery is how much a Guard writes between looks at the free space.
const guardEvery = 64 << 20

// Guard writes to w and stops, with a NotEnoughDiskError, before the
// filesystem under dir drops below keepFree free. It is for a write
// whose size is not known in advance.
type Guard struct {
	w           io.Writer
	dir, what   string
	remedy      string
	sinceCheck  int64
	checkedOnce bool
}

// NewGuard wraps w, which writes to the filesystem under dir.
func NewGuard(w io.Writer, dir, what, remedy string) *Guard {
	return &Guard{w: w, dir: dir, what: what, remedy: remedy}
}

func (g *Guard) Write(p []byte) (int, error) {
	if !g.checkedOnce || g.sinceCheck >= guardEvery {
		// Room for everything written before the next look, so the write
		// never reaches into the share kept free.
		if err := CheckFreeSpace(g.dir, guardEvery+int64(len(p)), g.what, g.remedy); err != nil {
			return 0, err
		}
		g.checkedOnce, g.sinceCheck = true, 0
	}
	n, err := g.w.Write(p)
	g.sinceCheck += int64(n)
	return n, err
}
