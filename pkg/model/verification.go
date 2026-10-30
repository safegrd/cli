package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// VerificationStatus represents the outcome of an automated sandbox restore drill.
type VerificationStatus string

const (
	VerificationStatusPending VerificationStatus = "pending"
	VerificationStatusRunning VerificationStatus = "running"
	VerificationStatusPassed  VerificationStatus = "passed"
	VerificationStatusFailed  VerificationStatus = "failed"
)

// AssertionResult captures a single integrity assertion in the Fire Drill.
type AssertionResult struct {
	Name     string `json:"name" yaml:"name"` // e.g. "TableCountMatch", "ExtensionCheck", "RowCountMatch"
	Passed   bool   `json:"passed" yaml:"passed"`
	Expected string `json:"expected" yaml:"expected"`
	Actual   string `json:"actual" yaml:"actual"`
	Message  string `json:"message,omitempty" yaml:"message,omitempty"`
	// Kind is AssertionKindCheck for a check the customer wrote
	// (drill.checks), AssertionKindData for the database's own check of
	// the restored data, and empty for SafeGrd's other assertions.
	Kind string `json:"kind,omitempty" yaml:"kind,omitempty"`
	// NotRun is a check the sandbox could not run: recorded, and neither
	// passed nor failed. Passed is false and does not fail the drill.
	NotRun bool `json:"not_run,omitempty" yaml:"not_run,omitempty"`
}

// AssertionKindData marks the database's own check of the data restored
// into the sandbox: amcheck, CHECK TABLE, validate, integrity_check.
const AssertionKindData = "data"

// Holds reports whether the assertion lets the drill pass: it passed, or
// it could not run.
func (a AssertionResult) Holds() bool { return a.Passed || a.NotRun }

// Result is the assertion's outcome in one word: "passed", "failed" or
// "not_run". A reader of the JSON gets it beside passed and not_run, so a
// check that could not run is never read as a failure.
func (a AssertionResult) Result() string {
	switch {
	case a.NotRun:
		return "not_run"
	case a.Passed:
		return "passed"
	}
	return "failed"
}

// MarshalJSON writes the assertion with its result. Reading it back ignores
// result, which is derived.
func (a AssertionResult) MarshalJSON() ([]byte, error) {
	type plain AssertionResult
	return json.Marshal(struct {
		plain
		Result string `json:"result"`
	}{plain(a), a.Result()})
}

// AssertionKindCheck marks an assertion that is one of the customer's own
// drill checks: a query and its expected value, or a command, run against the
// sandbox after the restore.
const AssertionKindCheck = "check"

// VerificationReport contains complete results of an ephemeral sandbox restore test.
type VerificationReport struct {
	VerificationID   string             `json:"verification_id" yaml:"verification_id"`
	SnapshotID       string             `json:"snapshot_id" yaml:"snapshot_id"`
	NodeID           string             `json:"node_id" yaml:"node_id"`
	SurfaceType      SurfaceType        `json:"surface_type,omitempty" yaml:"surface_type,omitempty"`
	DatabaseName     string             `json:"database_name,omitempty" yaml:"database_name,omitempty"`
	StartedAt        time.Time          `json:"started_at" yaml:"started_at"`
	CompletedAt      time.Time          `json:"completed_at" yaml:"completed_at"`
	DurationMs       int64              `json:"duration_ms" yaml:"duration_ms"`
	Status           VerificationStatus `json:"status" yaml:"status"`
	SandboxEngine    string             `json:"sandbox_engine" yaml:"sandbox_engine"` // e.g. "docker-postgres-16"
	TotalItems       int64              `json:"total_items,omitempty" yaml:"total_items,omitempty"`
	TotalContainers  int                `json:"total_containers,omitempty" yaml:"total_containers,omitempty"`
	TablesRestored   int                `json:"tables_restored" yaml:"tables_restored"`
	RowsRestored     int64              `json:"rows_restored" yaml:"rows_restored"`
	ExtensionsBooted []string           `json:"extensions_booted" yaml:"extensions_booted"`
	Assertions       []AssertionResult  `json:"assertions" yaml:"assertions"`
	CertificateHash  string             `json:"certificate_hash" yaml:"certificate_hash"`
	ErrorMessage     string             `json:"error_message,omitempty" yaml:"error_message,omitempty"`
	// RanOn is RanOnSafeGrd when a machine the remote server started ran
	// this drill, the id of another host of the organization when that host
	// drilled this node's snapshot, and empty when the node's own host ran
	// it. The server sets it from the credential that reported the drill.
	// It is not part of the signed bytes.
	RanOn string `json:"ran_on,omitempty" yaml:"ran_on,omitempty"`
	// Tamper-Evident Attestation Record
	PrevHash     string `json:"prev_hash,omitempty" yaml:"prev_hash,omitempty"`
	Signature    string `json:"signature,omitempty" yaml:"signature,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty" yaml:"signing_key_id,omitempty"`
	// SandboxKept says a failed drill left its sandbox in place for a person
	// to look at, as the surface's drill.keep_failed_sandbox asks, and that
	// the host removes it a day later.
	SandboxKept bool `json:"sandbox_kept,omitempty" yaml:"sandbox_kept,omitempty"`
	// ObjectsRead is every storage object the drill read of a repository
	// snapshot. The server checks it against the objects the run's commit
	// named, so a copy kept for months is one whose every object is locked.
	// Not stored and not part of the certificate.
	ObjectsRead []string `json:"objects_read,omitempty" yaml:"-"`
	// External is set on a drill of a backup another tool made. Its URI and
	// the backup's SHA-256 are inside the certificate hash, so the signed
	// record fixes which object was drilled.
	External       *ExternalBackup `json:"external,omitempty" yaml:"external,omitempty"`
	ExternalSha256 string          `json:"external_sha256,omitempty" yaml:"external_sha256,omitempty"`
	// SourceBucket names the copy a drill read, when it read one of the
	// surface's other buckets rather than its own storage. It is inside the
	// certificate hash, so the signed record fixes which bucket was proven.
	SourceBucket string `json:"source_bucket,omitempty" yaml:"source_bucket,omitempty"`
	// TableChanges lists every table whose row count differs between the
	// drilled snapshot and the backup before it (TableChangesFrom), largest
	// move first, with the tables added and gone. TablesUnchanged counts the
	// rest, and TableChangesOmitted the changed tables past the list's cap.
	// The remote server fills them from its own records when the drill is
	// reported, and they are signed through TableChangesDigest: a record
	// with TableChangesFrom set has the digest in its CanonicalBytes.
	TableChanges        []TableChange `json:"table_changes,omitempty" yaml:"table_changes,omitempty"`
	TableChangesFrom    string        `json:"table_changes_from,omitempty" yaml:"table_changes_from,omitempty"`
	TablesUnchanged     int           `json:"tables_unchanged,omitempty" yaml:"tables_unchanged,omitempty"`
	TableChangesOmitted int           `json:"table_changes_omitted,omitempty" yaml:"table_changes_omitted,omitempty"`
}

// TableChange is one table whose row count differs between a drilled
// snapshot and the backup before it. A table in only one of the two is
// Added or Gone; a partition rotated out for a newer one of the same name
// stem shows as one gone and one added.
type TableChange struct {
	Schema     string `json:"schema" yaml:"schema"`
	TableName  string `json:"table_name" yaml:"table_name"`
	RowsBefore int64  `json:"rows_before" yaml:"rows_before"`
	RowsAfter  int64  `json:"rows_after" yaml:"rows_after"`
	Added      bool   `json:"added,omitempty" yaml:"added,omitempty"`
	Gone       bool   `json:"gone,omitempty" yaml:"gone,omitempty"`
}

// TableChangesDigest is the SHA-256, hex, of the record's table changes in
// a fixed text form: a header line with the snapshot compared against and
// the unchanged and omitted counts, then one line per change in the list's
// order. The verifier page computes the same bytes in JavaScript.
func (v *VerificationReport) TableChangesDigest() string {
	var b strings.Builder
	fmt.Fprintf(&b, "tables|%s|%d|%d\n", v.TableChangesFrom, v.TablesUnchanged, v.TableChangesOmitted)
	for _, c := range v.TableChanges {
		flag := ""
		switch {
		case c.Added:
			flag = "added"
		case c.Gone:
			flag = "gone"
		}
		fmt.Fprintf(&b, "%s.%s|%d|%d|%s\n", c.Schema, c.TableName, c.RowsBefore, c.RowsAfter, flag)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// CanonicalBytes returns the deterministic serialization for cryptographic
// signing and chaining. A record with table changes carries their digest
// as an eleventh field; one without keeps the ten.
func (v *VerificationReport) CanonicalBytes() []byte {
	s := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%d|%d|%s|%s",
		v.VerificationID,
		v.SnapshotID,
		v.NodeID,
		v.SurfaceType,
		v.Status,
		v.TablesRestored,
		v.RowsRestored,
		v.DurationMs,
		v.CertificateHash,
		v.PrevHash,
	)
	if v.TableChangesFrom != "" {
		s += "|" + v.TableChangesDigest()
	}
	return []byte(s)
}

// AssertionRepositoryRead is the check a repository drill fails when storage
// did not answer a read: a 503, a dropped connection. It says nothing about
// the stored objects, so it never marks an epoch damaged.
const AssertionRepositoryRead = "RepositoryRead"

// storedDamageMarks are what a drill's failure says when stored objects are
// damaged or missing, as opposed to the drill's host failing to restore them.
var storedDamageMarks = []string{"does not authenticate", "is missing", "shorter than its index", "is in no index",
	"not found", "No such object", "does not parse"}

// StoredObjectsDamaged returns the failed check of a repository drill that
// names damaged or missing objects in storage. A backup that went on writing
// into the same set of objects would reference them again.
func (v *VerificationReport) StoredObjectsDamaged() (string, bool) {
	if v == nil || v.Status == VerificationStatusPassed {
		return "", false
	}
	for _, a := range v.Assertions {
		// A check the customer wrote reports what its own query or command
		// printed ("table not found", "psql: command not found"), and the
		// database's check of the sandbox reports on the sandbox: neither
		// says anything about the stored objects.
		if a.Passed || a.Kind == AssertionKindCheck || a.Kind == AssertionKindData || a.Name == AssertionRepositoryRead {
			continue
		}
		text := a.Actual + " " + a.Message
		if a.Name == "RepositoryIntegrity" {
			return strings.TrimSpace(a.Actual), true
		}
		for _, m := range storedDamageMarks {
			if strings.Contains(text, m) {
				return strings.TrimSpace(a.Actual), true
			}
		}
	}
	return "", false
}
