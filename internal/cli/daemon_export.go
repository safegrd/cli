package cli

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// The daemon's scheduled export (daemon.export_to): `safegrd export`, run
// after the backups of a pass when its schedule says so, so a copy of every
// snapshot sits in a bucket or directory the customer owns without a crontab
// line. The heartbeat carries when the last copy was made and whether the
// last run failed, and the console shows it on the host.

// exportRetryAfter is how long after a failed export the daemon tries again,
// short of the schedule: a bucket unreachable for an hour does not cost a day.
const exportRetryAfter = time.Hour

// exportTargetOf is the export the daemon runs and how often, from the
// config block, or an error saying what is wrong with it.
func exportTargetOf(d *config.ExportToConfig) (exportTarget, time.Duration, error) {
	var t exportTarget
	if (d.Bucket == "") == (d.Dir == "") {
		return t, 0, fmt.Errorf("daemon.export_to: set one of bucket and dir")
	}
	every, err := model.ParseSchedule(d.Schedule)
	if err != nil {
		return t, 0, fmt.Errorf("daemon.export_to.schedule: %w", err)
	}
	key, err := resolveConfigSecret("daemon.export_to.access_key_id", d.AccessKeyID)
	if err != nil {
		return t, 0, err
	}
	secret, err := resolveConfigSecret("daemon.export_to.secret_access_key", d.SecretAccessKey)
	if err != nil {
		return t, 0, err
	}
	if (key == "") != (secret == "") {
		return t, 0, fmt.Errorf("daemon.export_to: set both access_key_id and secret_access_key, or neither to use the AWS environment")
	}
	t = exportTarget{
		Dir: d.Dir, Bucket: d.Bucket, Endpoint: d.Endpoint, Region: d.Region, Prefix: d.Prefix, WORM: string(d.WORMMode),
		AccessKeyID: key, SecretAccessKey: secret, ForcePathStyle: d.ForcePathStyle,
	}
	return t, every, nil
}

// exportWhere names the destination for the log and the console.
func exportWhere(d *config.ExportToConfig) string {
	if d.Dir != "" {
		return d.Dir
	}
	return d.Bucket
}

// exportDue reports whether the scheduled export runs this pass: when the
// schedule has elapsed since the last copy, or exportRetryAfter since a run
// that failed. A daemon that has never exported runs it on its first pass.
func exportDue(st *DaemonState, every time.Duration, now time.Time) bool {
	if st.LastExportTry.After(st.LastExport) {
		return now.Sub(st.LastExportTry) >= exportRetryAfter
	}
	return st.LastExport.IsZero() || now.Sub(st.LastExport) >= every
}

// exportConfigSaid is the last complaint about daemon.export_to, so a block
// that does not parse is said once, not on every pass.
var exportConfigSaid string

// runScheduledExport runs daemon.export_to when it is due and records the
// outcome in the daemon's state. A failure is said on stderr and tried again
// after exportRetryAfter; it never stops the daemon or fails the pass.
func runScheduledExport(ctx context.Context, c *config.CLIConfig, st *DaemonState, now time.Time) {
	d := c.Daemon.ExportTo
	if d == nil || ctx.Err() != nil {
		return
	}
	t, every, err := exportTargetOf(d)
	if err != nil {
		if exportConfigSaid != err.Error() {
			exportConfigSaid = err.Error()
			fmt.Fprintf(os.Stderr, "Warning: %v. No export runs until it is fixed.\n", err)
		}
		return
	}
	if !exportDue(st, every, now) {
		return
	}
	where := exportWhere(d)
	st.LastExportTry = now
	fmt.Printf("Export to %s (daemon.export_to): copying snapshots not yet there.\n", where)
	if err := runExport(ctx, c, t); err != nil {
		st.LastExportError = err.Error()
		fmt.Fprintf(os.Stderr, "Warning: Export to %s failed: %v. Tries again in %s.\n", where, err, model.ShortDuration(exportRetryAfter))
	} else {
		st.LastExport, st.LastExportError = now, ""
		fmt.Printf("Export to %s: done. Next in %s.\n", where, model.ShortDuration(every))
	}
	hostExport.set(exportReport(c, st))
}

// exportReport is what the heartbeat says about the scheduled export: nil
// without daemon.export_to, or before its first run.
func exportReport(c *config.CLIConfig, st *DaemonState) *model.ExportStatus {
	d := c.Daemon.ExportTo
	if d == nil || (st.LastExport.IsZero() && st.LastExportTry.IsZero()) {
		return nil
	}
	r := &model.ExportStatus{To: exportWhere(d)}
	if !st.LastExport.IsZero() {
		at := st.LastExport.UTC()
		r.At = &at
	}
	if st.LastExportTry.After(st.LastExport) {
		at := st.LastExportTry.UTC()
		r.FailedAt, r.Error = &at, st.LastExportError
	}
	return r
}

// hostExport is the export status the heartbeat carries, set by each pass
// from the daemon's state: the heartbeat has the surface's state, not the
// daemon's.
var hostExport exportStatusHolder

type exportStatusHolder struct {
	mu sync.Mutex
	s  *model.ExportStatus
}

func (h *exportStatusHolder) set(s *model.ExportStatus) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.s = s
}

// report is a copy for one heartbeat, or nil.
func (h *exportStatusHolder) report() *model.ExportStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.s == nil {
		return nil
	}
	c := *h.s
	return &c
}
