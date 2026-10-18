package model

import (
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
	// (drill.checks), and empty for SafeGrd's own assertions.
	Kind string `json:"kind,omitempty" yaml:"kind,omitempty"`
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
}

// CanonicalBytes returns the deterministic serialization for cryptographic signing and chaining.
func (v *VerificationReport) CanonicalBytes() []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s|%d|%d|%d|%s|%s",
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
	))
}

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
		// printed ("table not found", "psql: command not found"), which says
		// nothing about the stored objects.
		if a.Passed || a.Kind == AssertionKindCheck {
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
