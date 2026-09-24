package model

import (
	"fmt"
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
}

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
	// Tamper-Evident Attestation Record
	PrevHash     string `json:"prev_hash,omitempty" yaml:"prev_hash,omitempty"`
	Signature    string `json:"signature,omitempty" yaml:"signature,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty" yaml:"signing_key_id,omitempty"`
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
