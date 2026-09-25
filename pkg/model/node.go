package model

import (
	"time"
)

// NodeStatus tracks agent node connectivity status.
type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusDegraded NodeStatus = "degraded"
	NodeStatusOffline  NodeStatus = "offline"
)

// Node represents an enrolled CLI agent or backup runner.
type Node struct {
	ID                string     `json:"id" yaml:"id"`
	OrgID             string     `json:"org_id" yaml:"org_id"`
	ProjectID         string     `json:"project_id" yaml:"project_id"`
	Name              string     `json:"name" yaml:"name"`
	DatabaseName      string     `json:"database_name" yaml:"database_name"`
	SurfaceRef        string     `json:"surface_ref,omitempty" yaml:"surface_ref,omitempty"` // database name, root-path list, or mailbox address
	Token             string     `json:"-" yaml:"token,omitempty"`
	TokenHash         string     `json:"-" yaml:"token_hash,omitempty"`
	Status            NodeStatus `json:"status" yaml:"status"`
	Schedule          string     `json:"schedule" yaml:"schedule"` // e.g., "@daily", "@hourly", "@weekly", or Go duration "6h", "12h"
	WORMRetentionDays int        `json:"worm_retention_days" yaml:"worm_retention_days"`
	LastHeartbeat     time.Time  `json:"last_heartbeat" yaml:"last_heartbeat"`
	LastBackupAt      *time.Time `json:"last_backup_at,omitempty" yaml:"last_backup_at,omitempty"`
	LastVerifiedAt    *time.Time `json:"last_verified_at,omitempty" yaml:"last_verified_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at" yaml:"created_at"`
	StorageBucket     string     `json:"storage_bucket" yaml:"storage_bucket"`

	// Which Age recipient this node encrypts to, and whether SafeGrd holds the
	// matching identity. Per node, not per organization: a host that brought
	// its own key and a host that did not can sit in the same org, and the
	// honest view is to report that rather than to forbid it.
	PublicKey                 string         `json:"public_key,omitempty" yaml:"public_key,omitempty"`
	KeyFingerprint            string         `json:"key_fingerprint,omitempty" yaml:"key_fingerprint,omitempty"`
	KeyEscrowed               bool           `json:"key_escrowed" yaml:"key_escrowed,omitempty"`
	SurfaceType               SurfaceType    `json:"surface_type,omitempty" yaml:"surface_type,omitempty"`
	LastBackupStatus          SnapshotStatus `json:"last_backup_status,omitempty" yaml:"last_backup_status,omitempty"`
	LastBackupDurationMs      int64          `json:"last_backup_duration_ms,omitempty" yaml:"last_backup_duration_ms,omitempty"`
	LastBackupSizeBytes       int64          `json:"last_backup_size_bytes,omitempty" yaml:"last_backup_size_bytes,omitempty"`
	LastBackupRawSizeBytes    int64          `json:"last_backup_raw_size_bytes,omitempty" yaml:"last_backup_raw_size_bytes,omitempty"`
	LastBackupTableCount      int            `json:"last_backup_table_count,omitempty" yaml:"last_backup_table_count,omitempty"`
	LastBackupRowCount        int64          `json:"last_backup_row_count,omitempty" yaml:"last_backup_row_count,omitempty"`
	LastBackupTotalItems      int64          `json:"last_backup_total_items,omitempty" yaml:"last_backup_total_items,omitempty"`
	LastBackupTotalContainers int            `json:"last_backup_total_containers,omitempty" yaml:"last_backup_total_containers,omitempty"`
	LastBackupSnapshotID      string         `json:"last_backup_snapshot_id,omitempty" yaml:"last_backup_snapshot_id,omitempty"`

	// ParentNodeID is set on a surface an agent registered under its host's
	// node. The host's token acts for its children and no other node, so one
	// token per host covers every surface on it.
	ParentNodeID string `json:"parent_node_id,omitempty" yaml:"parent_node_id,omitempty"`

	// BackupRequestedAt is a one-shot "back up now" from the console or API,
	// cleared when the next snapshot for this node arrives. Never inferred
	// from due-ness: see HeartbeatResponse.BackupRequestID.
	BackupRequestedAt *time.Time `json:"backup_requested_at,omitempty" yaml:"backup_requested_at,omitempty"`
	// DrillRequestedAt is a one-shot "drill now", from the console, the API or
	// an agent over MCP. The heartbeat answers it with TriggerFireDrill,
	// and the next drill report clears it.
	DrillRequestedAt *time.Time `json:"drill_requested_at,omitempty" yaml:"drill_requested_at,omitempty"`

	// What the agent said on its last heartbeat. Absent for a node that has
	// never sent a heartbeat (for example, one run manually or from cron).
	AgentVersion         string `json:"agent_version,omitempty" yaml:"agent_version,omitempty"`
	AgentIntervalSeconds int    `json:"agent_interval_seconds,omitempty" yaml:"agent_interval_seconds,omitempty"`
	AgentFailures        int    `json:"agent_failures,omitempty" yaml:"agent_failures,omitempty"`
	AgentLastError       string `json:"agent_last_error,omitempty" yaml:"agent_last_error,omitempty"`
	DrillStatus          string `json:"drill_status,omitempty" yaml:"drill_status,omitempty"`

	// AlertState is the open alert episode, if any: AlertStateSilent or
	// AlertStateOverdue. One alert opens it and one closes it, so it is
	// persisted across restarts.
	AlertState      string     `json:"alert_state,omitempty" yaml:"alert_state,omitempty"`
	AlertStateSince *time.Time `json:"alert_state_since,omitempty" yaml:"alert_state_since,omitempty"`
}

// Alert episodes a node can be in. Empty means none.
const (
	// AlertStateSilent: an agent that has heartbeated has stopped.
	AlertStateSilent = "silent"
	// AlertStateOverdue: no backup for twice the schedule's interval.
	AlertStateOverdue = "overdue"
)

// Drill statuses an agent reports. Empty means nothing to report.
const (
	// DrillStatusNoKey: a drill is due and this host does not hold the
	// private key, which the agent never copies.
	DrillStatusNoKey = "no_key"
	// DrillStatusFailed: the last unattended drill did not pass.
	DrillStatusFailed = "failed"
)

// NodeRegisterRequest is sent by CLI `safegrd init` to register with the remote server.
type NodeRegisterRequest struct {
	NodeID        string      `json:"node_id"`
	OrgID         string      `json:"org_id,omitempty"`
	ProjectID     string      `json:"project_id,omitempty"`
	Name          string      `json:"name"`
	SurfaceType   SurfaceType `json:"surface_type,omitempty"`
	DatabaseName  string      `json:"database_name"`
	SurfaceRef    string      `json:"surface_ref,omitempty"`
	EmailHost     string      `json:"email_host,omitempty"`
	EmailPort     int         `json:"email_port,omitempty"`
	EmailUsername string      `json:"email_username,omitempty"`
	Password      string      `json:"password,omitempty"`
	EmailPassword string      `json:"email_password,omitempty"`
	StorageBucket string      `json:"storage_bucket"`

	// Key material. The recipient is public by construction and
	// is always sent: the remote server needs it to name which key a node uses,
	// and to spot a mismatch before a restore fails rather than after.
	PublicKey      string `json:"public_key,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`

	// ManagedIdentity is the Age PRIVATE key, and it is present only when the
	// CLI generated a key during this enrollment and the operator did not ask
	// to keep it local. Sending it is what "SafeGrd holds my key" means.
	//
	// A server that receives this and cannot seal it MUST refuse the whole
	// enrollment. Accepting and dropping it would leave the customer believing
	// their key is escrowed, and the day they delete their local copy the
	// backups become ciphertext nobody can read.
	ManagedIdentity string `json:"managed_identity,omitempty"`
	Schedule        string `json:"schedule"`
	RetentionDays   int    `json:"retention_days"`
}

// NodeRegisterResponse returns API credentials and registration confirmation.
type NodeRegisterResponse struct {
	NodeID       string `json:"node_id"`
	ProjectID    string `json:"project_id,omitempty"`
	Token        string `json:"token"`
	DashboardURL string `json:"dashboard_url"`
	Message      string `json:"message"`

	// KeyEscrowed is the server's confirmation that it sealed and stored the
	// identity it was sent. The CLI treats a false value here after sending one
	// as an error and prints the key for the operator to save.
	KeyEscrowed    bool   `json:"key_escrowed"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
}

// SurfaceRegisterRequest is sent by `agent run` for each surface in its
// config, under the host's enrolled node. Idempotent: the same
// surface id always names the same child node.
type SurfaceRegisterRequest struct {
	SurfaceID     string      `json:"surface_id"`
	Name          string      `json:"name,omitempty"`
	SurfaceType   SurfaceType `json:"surface_type,omitempty"`
	SurfaceRef    string      `json:"surface_ref,omitempty"`
	Schedule      string      `json:"schedule,omitempty"`
	RetentionDays int         `json:"retention_days,omitempty"`
	PublicKey     string      `json:"public_key,omitempty"`
}

// SurfaceRegisterResponse names the node the surface reports as. The host's
// own token authenticates for it; there is no per-surface token.
type SurfaceRegisterResponse struct {
	NodeID  string `json:"node_id"`
	Created bool   `json:"created"`
}

// HeartbeatRequest updates server on node health and pulls schedule tasks.
type HeartbeatRequest struct {
	NodeID       string `json:"node_id"`
	CLI_Version  string `json:"cli_version"`
	PostgresUp   bool   `json:"postgres_up"`
	StorageUp    bool   `json:"storage_up"`
	LastSnapshot string `json:"last_snapshot,omitempty"`

	// Sent by `agent run`, so the console can tell "the agent is dead" from
	// "the agent is alive and this surface is failing".
	// TickSeconds is how often the agent looks; silence is measured in it.
	TickSeconds         int    `json:"tick_seconds,omitempty"`
	ConsecutiveFailures int    `json:"consecutive_failures,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	DrillStatus         string `json:"drill_status,omitempty"`
}

// HeartbeatResponse instructs the node on next actions.
//
// Drill instructions are scheduled on the remote server
// and sent to the node. When no drill is scheduled,
// TriggerFireDrill is false and NextDrillDue is absent.
type HeartbeatResponse struct {
	Acknowledge   bool      `json:"acknowledge"`
	NextBackupDue time.Time `json:"next_backup_due"`
	TriggerBackup bool      `json:"trigger_backup"`
	ServerTime    time.Time `json:"server_time"`

	// TriggerFireDrill asks the node to run a verified restore now.
	TriggerFireDrill bool `json:"trigger_fire_drill"`
	// NextDrillDue is absent when no drill is scheduled.
	NextDrillDue *time.Time `json:"next_drill_due,omitempty"`
	// FireDrillsIncluded lets the CLI explain a refusal before it posts a report
	// the remote server will reject with 402.
	FireDrillsIncluded bool `json:"fire_drills_included"`

	// BackupRequestID names a one-shot "back up now". The agent runs each id
	// once and remembers it. TriggerBackup is NOT this and an agent must not
	// act on it: it is true whenever the server has not heard of a recent
	// success, so obeying it would back up on every tick whenever a report
	// failed (creating excess objects under Object Lock).
	BackupRequestID string `json:"backup_request_id,omitempty"`
	// DrillSnapshotID is the snapshot a triggered drill should restore: the
	// latest the remote server has recorded for this node.
	DrillSnapshotID string `json:"drill_snapshot_id,omitempty"`
	// DrillRequestID names a one-shot "drill now". The agent runs each id once,
	// even inside its usual spacing between drills: someone asked for it.
	DrillRequestID string `json:"drill_request_id,omitempty"`
}
