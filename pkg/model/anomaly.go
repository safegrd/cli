package model

import (
	"time"
)

// AnomalySeverity represents priority level for Threat Shield alerts.
type AnomalySeverity string

const (
	AnomalySeverityWarning  AnomalySeverity = "warning"
	AnomalySeverityCritical AnomalySeverity = "critical"
)

// AnomalyType categorizes the detected threat.
type AnomalyType string

const (
	AnomalyTypeRowVolumeDrop AnomalyType = "row_volume_drop"    // > 20% loss
	AnomalyTypeTableDrop     AnomalyType = "table_drop"         // tables missing
	AnomalyTypeExtensionLost AnomalyType = "extension_mismatch" // critical extension missing
	AnomalyTypeEmptySnapshot AnomalyType = "empty_snapshot"     // zero rows/tables
)

// AnomalyReport records detected anomalies and the resulting retention lock.
type AnomalyReport struct {
	ID                 string          `json:"id" yaml:"id"`
	NodeID             string          `json:"node_id" yaml:"node_id"`
	SnapshotID         string          `json:"snapshot_id" yaml:"snapshot_id"`
	BaselineSnapshotID string          `json:"baseline_snapshot_id" yaml:"baseline_snapshot_id"`
	DetectedAt         time.Time       `json:"detected_at" yaml:"detected_at"`
	Severity           AnomalySeverity `json:"severity" yaml:"severity"`
	Type               AnomalyType     `json:"type" yaml:"type"`
	Description        string          `json:"description" yaml:"description"`
	PreviousRowCount   int64           `json:"previous_row_count" yaml:"previous_row_count"`
	CurrentRowCount    int64           `json:"current_row_count" yaml:"current_row_count"`
	PercentChange      float64         `json:"percent_change" yaml:"percent_change"`
	DroppedTables      []string        `json:"dropped_tables,omitempty" yaml:"dropped_tables,omitempty"`
	RetentionFrozen    bool            `json:"retention_frozen" yaml:"retention_frozen"`
	FrozenSnapshotID   string          `json:"frozen_snapshot_id" yaml:"frozen_snapshot_id"`
}
