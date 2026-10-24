package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/wal"
)

// walStreamChecks checks, for each MySQL or MongoDB surface with a wal:
// block, what following its binary log or oplog needs: the log, the grants,
// and how long the server keeps it.
func walStreamChecks(c *config.CLIConfig) []CheckResult {
	var out []CheckResult
	for i := range c.Surfaces {
		s := &c.Surfaces[i]
		if s.WAL == nil || !walIsStream(s) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		u, err := walStreamURL(ctx, c, s)
		if err != nil {
			out = append(out, CheckResult{Name: "Point in time for " + s.ID, Status: "FAIL", Message: err.Error()})
			cancel()
			continue
		}
		if walStreamEngine(s) == wal.StreamMongo {
			out = append(out, mongoStreamCheck(ctx, s.ID, u))
		} else {
			out = append(out, mysqlStreamCheck(ctx, s.ID, u)...)
		}
		cancel()
	}
	return out
}

func mysqlStreamCheck(ctx context.Context, id, u string) []CheckResult {
	check := CheckResult{Name: "Binary log for " + id}
	r, err := wal.CheckMySQLStream(ctx, u)
	if err != nil {
		check.Status, check.Message = "FAIL", err.Error()
		return []CheckResult{check}
	}
	var warn []string
	if r.RowImage != "" && !strings.EqualFold(r.RowImage, "FULL") {
		warn = append(warn, "binlog_row_image is "+r.RowImage+"; set it to FULL, so each row change in the log carries the whole row")
	}
	if r.Retention > 0 && r.Retention < 24*time.Hour {
		warn = append(warn, fmt.Sprintf("the server keeps its binary log for %s; a daemon away longer than that leaves a gap. Keep it a day or more", r.Retention.Round(time.Minute)))
	}
	if !r.LockGrant {
		warn = append(warn, "this account may not hold FLUSH TABLES WITH READ LOCK, which a base backup and a restore point need. Grant FLUSH_TABLES ON *.* (RELOAD before MySQL 8.0.23)")
	}
	check.Status = "PASS"
	check.Message = fmt.Sprintf("on, ROW, now at %s %d; this account can read it", r.Server.File, r.Server.Pos)
	if len(warn) > 0 {
		check.Status, check.Message = "WARN", strings.Join(warn, "; ")
	}
	tool := CheckResult{Name: "mysqlbinlog for " + id}
	if t, err := dump.MySQLBinlogToolFor(ctx, r.Server.MariaDB); err != nil {
		tool.Status, tool.Message = "WARN", "a restore replays the binary log with the server's own mysqlbinlog, and this host has none: "+err.Error()
	} else {
		tool.Status, tool.Message = "PASS", t.String()+" replays it in a restore"
	}
	return []CheckResult{check, tool}
}

func mongoStreamCheck(ctx context.Context, id, u string) CheckResult {
	check := CheckResult{Name: "Oplog for " + id}
	srv, err := wal.InspectMongo(ctx, u)
	if err != nil {
		check.Status, check.Message = "FAIL", err.Error()
		return check
	}
	span := wal.MongoTSTime(srv.Newest).Sub(wal.MongoTSTime(srv.Oldest))
	check.Status = "PASS"
	check.Message = fmt.Sprintf("replica set %s; the oplog holds %s and this user can read it", srv.SetName, span.Round(time.Minute))
	if span < 24*time.Hour {
		check.Status = "WARN"
		check.Message = fmt.Sprintf("replica set %s; the oplog holds only %s, so a daemon away longer than that leaves a gap. Raise its size (replSetResizeOplog) or its minimum retention", srv.SetName, span.Round(time.Minute))
	}
	return check
}
