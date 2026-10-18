package runner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/watch"
)

// ExternalDrill is a drill of a backup another tool made: the check's record
// of it, and where to read it from again.
type ExternalDrill struct {
	// Meta is the snapshot the check reported: the object, its SHA-256 and
	// the rows of each table.
	Meta     *model.SnapshotMetadata
	Location watch.Location
	Object   watch.Object
	// Scratch is the directory the backup is downloaded into.
	Scratch string
}

// RunExternalDrill reads a backup another tool made again, from where that
// tool put it, and holds it to what the check recorded: the same bytes, and
// the same rows in every table. With sandboxURL it loads the backup into
// that empty database in one transaction and counts what came back; without,
// it counts the backup's own rows again, in memory. pg_cron's job rows are
// never loaded, so nothing the backup scheduled runs in the sandbox.
func (v *Verifier) RunExternalDrill(ctx context.Context, d ExternalDrill, sandboxURL string) (*model.VerificationReport, error) {
	started := time.Now()
	meta := d.Meta
	v.sandboxDrill = sandboxURL != ""
	report := &model.VerificationReport{
		VerificationID: "verif-dry-" + uuid.New().String()[:8],
		SnapshotID:     meta.SnapshotID,
		NodeID:         meta.NodeID,
		SurfaceType:    model.SurfaceTypePostgres,
		DatabaseName:   meta.DatabaseName,
		StartedAt:      started,
		SandboxEngine:  "in-memory-dry-restore",
		Status:         model.VerificationStatusRunning,
		External:       meta.External,
		ExternalSha256: meta.Sha256Checksum,
	}
	if sandboxURL != "" {
		report.VerificationID = "verif-" + uuid.New().String()[:8]
		report.SandboxEngine = sandboxEngineName(model.SurfaceTypePostgres, meta)
		if err := CheckSandboxEmpty(ctx, sandboxURL); err != nil {
			return nil, err
		}
	}
	scratch := d.Scratch
	if scratch == "" {
		scratch = os.TempDir()
	}
	file, sum, err := d.Location.Download(ctx, d.Object, scratch)
	if err != nil {
		v.storageFailed = true
		v.failEarly(ctx, report, started, err.Error())
		return report, nil
	}
	defer os.Remove(file)
	same := model.AssertionResult{Name: "BackupUnchanged", Expected: meta.Sha256Checksum, Actual: sum, Passed: sum == meta.Sha256Checksum}
	report.Assertions = append(report.Assertions, same)
	if !same.Passed {
		v.failEarly(ctx, report, started, fmt.Sprintf("%s is not the backup SafeGrd read on %s: its bytes changed",
			d.Object.URI, meta.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")))
		return report, nil
	}
	contents, err := watch.Inspect(ctx, file)
	if err != nil {
		v.failEarly(ctx, report, started, "the backup could not be read: "+err.Error())
		return report, nil
	}
	got := map[string]int64{}
	for _, t := range contents.Tables {
		got[t.Schema+"."+t.TableName] = t.RowCount
	}
	if sandboxURL != "" && contents.Loadable() {
		if err := watch.Load(ctx, file, contents, sandboxURL); err != nil {
			report.Assertions = append(report.Assertions, model.AssertionResult{Name: "RestoreIntegrity",
				Expected: "the backup loads into the sandbox", Actual: err.Error()})
			v.failEarly(ctx, report, started, "restore execution failed: "+err.Error())
			return report, nil
		}
		restored, err := inspectSandbox(ctx, sandboxURL, meta)
		if err != nil {
			v.failEarly(ctx, report, started, "sandbox inspection failed: "+err.Error())
			return report, nil
		}
		got = map[string]int64{}
		for _, t := range restored.TableStats {
			got[t.Schema+"."+t.TableName] = t.RowCount
		}
		report.ExtensionsBooted = restored.Extensions
	} else if sandboxURL != "" {
		report.Assertions = append(report.Assertions, model.AssertionResult{Name: "LoadedIntoSandbox", Passed: true,
			Expected: "the backup loads into the sandbox", Actual: "read in memory only",
			Message: "A dump that creates databases or roles (pg_dumpall, pg_dump --create) is not loaded into a sandbox"})
	}
	allPassed := true
	var rows int64
	for _, t := range meta.TableStats {
		key := t.Schema + "." + t.TableName
		n, ok := got[key]
		a := model.AssertionResult{Name: "Row Count: " + key, Expected: fmt.Sprintf("%d rows", t.RowCount), Actual: fmt.Sprintf("%d rows", n), Passed: ok && n == t.RowCount}
		if !ok {
			a.Actual, a.Message = "missing", "The table is not in what was read back"
		} else if !a.Passed {
			a.Message = "The table's rows are not the rows the check counted"
		}
		allPassed = allPassed && a.Passed
		rows += n
		report.Assertions = append(report.Assertions, a)
	}
	totals := model.AssertionResult{Name: "RowCountMatch", Expected: fmt.Sprintf("%d rows", meta.TotalRows), Actual: fmt.Sprintf("%d rows", rows), Passed: rows == meta.TotalRows}
	report.Assertions = append(report.Assertions, totals)
	allPassed = allPassed && totals.Passed
	if contents.CronJobs > 0 {
		report.Assertions = append(report.Assertions, model.AssertionResult{Name: "CronJobsLeftOut", Passed: true,
			Expected: "pg_cron jobs not scheduled in the drill", Actual: fmt.Sprintf("%d jobs in the backup, left out", contents.CronJobs)})
	}
	report.TablesRestored, report.RowsRestored = len(meta.TableStats), rows
	report.TotalContainers, report.TotalItems = len(meta.TableStats), rows
	report.CompletedAt = time.Now()
	report.DurationMs = drillMilliseconds(report.CompletedAt.Sub(started))
	if allPassed {
		report.Status = model.VerificationStatusPassed
	} else {
		report.Status = model.VerificationStatusFailed
		report.ErrorMessage = "The rows read back are not the rows the check counted"
	}
	report.CertificateHash = computeCertificateHash(report)
	v.submitReport(ctx, report)
	return report, nil
}
