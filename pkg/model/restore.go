package model

import (
	"fmt"
	"strings"
	"time"
)

// A restore asked for from the console: a person names a snapshot, a target
// and what to restore, and the surface's host (or a machine the remote
// server starts for it) runs `safegrd restore` once. These are the shapes the
// host and the remote server exchange.

// RestoreState is where a requested restore is.
type RestoreState string

const (
	// RestoreRequested waits for the host's next check-in, or for a machine.
	RestoreRequested RestoreState = "requested"
	// RestoreBackingUp is taking the backup of the surface that comes first.
	RestoreBackingUp RestoreState = "backing_up"
	// RestoreRunning is restoring.
	RestoreRunning   RestoreState = "running"
	RestoreCompleted RestoreState = "completed"
	RestoreFailed    RestoreState = "failed"
	// RestoreCancelled was cancelled before it started.
	RestoreCancelled RestoreState = "cancelled"
	// RestoreExpired was not picked up within a day, and its target's
	// credential was deleted unused.
	RestoreExpired RestoreState = "expired"
)

// Open reports whether the restore has not ended.
func (s RestoreState) Open() bool {
	return s == RestoreRequested || s == RestoreBackingUp || s == RestoreRunning
}

// Restore target kinds.
const (
	RestoreTargetDatabase  = "database"
	RestoreTargetDirectory = "directory"
	RestoreTargetBucket    = "bucket"
)

// RestoreTarget is where a restore writes. URL and SecretAccessKey are
// secrets: the remote server keeps them sealed and hands them over once.
type RestoreTarget struct {
	Kind string `json:"kind"`
	// URL is a database URL (postgres://, mysql://, mongodb://, sqlite:///).
	URL string `json:"url,omitempty"`
	// Path is a directory on the host.
	Path string `json:"path,omitempty"`
	// A bucket, for a files snapshot.
	Bucket          string `json:"bucket,omitempty"`
	Prefix          string `json:"prefix,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
}

// RestoreScope is what of the snapshot is restored: exactly one of these.
type RestoreScope struct {
	Whole           bool     `json:"whole,omitempty"`
	Schemas         []string `json:"schemas,omitempty"`
	DataOnlySchemas []string `json:"data_only_schemas,omitempty"`
	Tables          []string `json:"tables,omitempty"`
	Paths           []string `json:"paths,omitempty"`
}

// Partial reports whether the scope restores part of a database into one
// that has other things in it, which is when a backup of the surface comes
// first.
func (s RestoreScope) Partial() bool {
	return len(s.Schemas) > 0 || len(s.DataOnlySchemas) > 0 || len(s.Tables) > 0
}

// Validate refuses a scope that names nothing or more than one kind of part.
func (s RestoreScope) Validate() error {
	n := 0
	if s.Whole {
		n++
	}
	if len(s.Schemas) > 0 || len(s.DataOnlySchemas) > 0 {
		n++
	}
	if len(s.Tables) > 0 {
		n++
	}
	if len(s.Paths) > 0 {
		n++
	}
	if n != 1 {
		return fmt.Errorf("choose one of: the whole backup, schemas, tables or paths")
	}
	for _, list := range [][]string{s.Schemas, s.DataOnlySchemas, s.Tables, s.Paths} {
		for _, v := range list {
			if strings.TrimSpace(v) == "" || strings.ContainsAny(v, "\x00\r\n") {
				return fmt.Errorf("a schema, table or path is empty or has a line break in it")
			}
		}
	}
	return nil
}

// Describe is the scope in words: "the whole backup", "schema public".
func (s RestoreScope) Describe() string {
	switch {
	case s.Whole:
		return "the whole backup"
	case len(s.Tables) > 0:
		return plural(len(s.Tables), "table", "tables") + " " + strings.Join(s.Tables, ", ")
	case len(s.Paths) > 0:
		return plural(len(s.Paths), "path", "paths") + " " + strings.Join(s.Paths, ", ")
	}
	var parts []string
	if len(s.Schemas) > 0 {
		parts = append(parts, plural(len(s.Schemas), "schema", "schemas")+" "+strings.Join(s.Schemas, ", "))
	}
	if len(s.DataOnlySchemas) > 0 {
		parts = append(parts, "the rows of "+strings.Join(s.DataOnlySchemas, ", "))
	}
	return strings.Join(parts, " and ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// RestoreOptions are the restore command's PostgreSQL choices.
type RestoreOptions struct {
	NoOwner         bool `json:"no_owner,omitempty"`
	KeepCronActive  bool `json:"keep_cron_active,omitempty"`
	WithoutErasures bool `json:"without_erasures,omitempty"`
}

// RestorePlan is what GET /api/v1/restores/{id}/plan answers the host that
// runs the restore. The target's secret is in it once: a second call is
// refused.
type RestorePlan struct {
	RestoreID   string         `json:"restore_id"`
	NodeID      string         `json:"node_id"`
	SnapshotID  string         `json:"snapshot_id"`
	SurfaceName string         `json:"surface_name,omitempty"`
	SurfaceType SurfaceType    `json:"surface_type,omitempty"`
	Target      RestoreTarget  `json:"target"`
	Scope       RestoreScope   `json:"scope"`
	Options     RestoreOptions `json:"options"`
	// SafetyBackup asks the host to back the surface up before it restores,
	// and to stop if that backup fails. SafetySnapshotID, when set, is a
	// backup taken in the last few minutes that serves instead.
	SafetyBackup     bool   `json:"safety_backup,omitempty"`
	SafetySnapshotID string `json:"safety_snapshot_id,omitempty"`
}

// RestoreProgress is what the host says while it works:
// POST /api/v1/restores/{id}/progress.
type RestoreProgress struct {
	State            RestoreState `json:"state"`
	SafetySnapshotID string       `json:"safety_snapshot_id,omitempty"`
	Message          string       `json:"message,omitempty"`
}

// RestoreReport is the outcome: POST /api/v1/restores/{id}/report. The remote
// server signs the record it keeps of a completed restore.
type RestoreReport struct {
	RestoreID   string       `json:"restore_id"`
	State       RestoreState `json:"state"` // completed or failed
	StartedAt   time.Time    `json:"started_at"`
	CompletedAt time.Time    `json:"completed_at"`
	DurationMs  int64        `json:"duration_ms"`
	// Containers are the tables, collections, directories or folders
	// restored; Items the rows, documents, files or messages.
	Containers       int    `json:"containers"`
	Items            int64  `json:"items"`
	Error            string `json:"error,omitempty"`
	SafetySnapshotID string `json:"safety_snapshot_id,omitempty"`
}
