package model

import (
	"strconv"
	"strings"
	"time"
)

// NodeStatus tracks daemon node connectivity status.
type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusDegraded NodeStatus = "degraded"
	NodeStatusOffline  NodeStatus = "offline"
)

// RunsOnSafeGrd marks a surface the remote server backs up and drills itself.
const RunsOnSafeGrd = "safegrd"

// Node represents an enrolled CLI daemon or backup runner.
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

	// ParentNodeID is set on a surface a daemon registered under its host's
	// node. The host's token acts for its children and no other node, so one
	// token per host covers every surface on it.
	ParentNodeID string `json:"parent_node_id,omitempty" yaml:"parent_node_id,omitempty"`

	// RunsOn is set to RunsOnSafeGrd on a surface with no host: the remote
	// server takes its backups and drills on machines it starts, with the
	// credential it holds for the surface. Empty for a surface a host runs.
	RunsOn string `json:"runs_on,omitempty" yaml:"runs_on,omitempty"`

	// CredentialSource is where a surface's own credential comes from, as its
	// host's config says: "held" (the remote server holds it and the host
	// fetches it), "host" (the host's config or environment has it), or
	// empty (the surface needs none, or its daemon is too old to say). A
	// credential has one origin, and only that side may change it.
	CredentialSource string `json:"credential_source,omitempty" yaml:"credential_source,omitempty"`
	// CredentialHeld is whether the remote server holds a credential for
	// this node now. Filled in when nodes are listed; never stored.
	CredentialHeld bool `json:"credential_held,omitempty" yaml:"-"`

	// Set from the console, and never by a host registering its surfaces.
	// Schedule and WORMRetentionDays are what the host's daemon last said it
	// runs; ConsoleSchedule and ConsoleRetentionDays are what the console
	// asked for, sent to the daemon on every heartbeat until cleared. Empty or
	// zero means the host's own config decides. NamedInConsole keeps a name
	// given in the console from being replaced by the host's config.
	ConsoleSchedule      string `json:"console_schedule,omitempty" yaml:"console_schedule,omitempty"`
	ConsoleRetentionDays int    `json:"console_retention_days,omitempty" yaml:"console_retention_days,omitempty"`
	NamedInConsole       bool   `json:"named_in_console,omitempty" yaml:"named_in_console,omitempty"`

	// BackupRequestedAt is a one-shot "back up now" from the console or API,
	// cleared when the next snapshot for this node arrives. Never inferred
	// from due-ness: see HeartbeatResponse.BackupRequestID.
	BackupRequestedAt *time.Time `json:"backup_requested_at,omitempty" yaml:"backup_requested_at,omitempty"`
	// DrillRequestedAt is a one-shot "drill now", from the console, the API or
	// an agent over MCP. The heartbeat answers it with TriggerFireDrill,
	// and the next drill report clears it.
	DrillRequestedAt *time.Time `json:"drill_requested_at,omitempty" yaml:"drill_requested_at,omitempty"`

	// What the daemon said on its last heartbeat. Absent for a node that has
	// never sent a heartbeat (for example, one run manually or from cron).
	DaemonVersion         string `json:"daemon_version,omitempty" yaml:"daemon_version,omitempty"`
	DaemonIntervalSeconds int    `json:"daemon_interval_seconds,omitempty" yaml:"daemon_interval_seconds,omitempty"`
	DaemonFailures        int    `json:"daemon_failures,omitempty" yaml:"daemon_failures,omitempty"`
	DaemonLastError       string `json:"daemon_last_error,omitempty" yaml:"daemon_last_error,omitempty"`
	// BackupReason is why the last backup failed, or what went wrong after
	// one that was taken; DaemonLastError is the host's words for it.
	BackupReason BackupReason `json:"backup_reason,omitempty" yaml:"backup_reason,omitempty"`
	DrillStatus  DrillStatus  `json:"drill_status,omitempty" yaml:"drill_status,omitempty"`
	// DrillReason is why the last drill was not the drill the plan includes,
	// or why it did not pass. DrillDetail is the host's words for it, shown
	// and never parsed.
	DrillReason DrillReason `json:"drill_reason,omitempty" yaml:"drill_reason,omitempty"`
	DrillDetail string      `json:"drill_detail,omitempty" yaml:"drill_detail,omitempty"`
	// BackupWords and DrillWords are the two reasons in a sentence, filled
	// in when nodes are listed so the console words them as alerts do.
	BackupWords string `json:"backup_words,omitempty" yaml:"-"`
	DrillWords  string `json:"drill_words,omitempty" yaml:"-"`

	// Platform telemetry (OS / Arch) and update notification.
	OS               string `json:"os,omitempty" yaml:"os,omitempty"`
	Arch             string `json:"arch,omitempty" yaml:"arch,omitempty"`
	UpgradeAvailable bool   `json:"upgrade_available,omitempty" yaml:"upgrade_available,omitempty"`
	LatestCLIVersion string `json:"latest_cli_version,omitempty" yaml:"latest_cli_version,omitempty"`

	// AlertState is the open alert episode, if any: AlertStateSilent or
	// AlertStateOverdue. One alert opens it and one closes it, so it is
	// persisted across restarts.
	AlertState      string     `json:"alert_state,omitempty" yaml:"alert_state,omitempty"`
	AlertStateSince *time.Time `json:"alert_state_since,omitempty" yaml:"alert_state_since,omitempty"`
}

// Alert episodes a node can be in. Empty means none.
const (
	// AlertStateSilent: a daemon that has heartbeated has stopped.
	AlertStateSilent = "silent"
	// AlertStateOverdue: no backup for twice the schedule's interval.
	AlertStateOverdue = "overdue"
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

	// LocalStorage says where this host's own config sends its backups: "s3",
	// "hosted" or "local" when the operator configured one, "none" when the
	// only storage settings are the defaults enrollment itself just wrote.
	// With "none" the remote server refuses the enrollment unless the project
	// has a bucket, because a host with nowhere to send its backups would
	// look enrolled and back up nothing. Empty (a CLI that predates this
	// field) is never refused on this account.
	LocalStorage string `json:"local_storage,omitempty"`
	// AllowUnconfigured enrolls a host with nowhere to send its backups yet,
	// on purpose: storage is configured after enrollment.
	AllowUnconfigured bool `json:"allow_unconfigured,omitempty"`
	// Claim is the code a console session issued for this host. It names the
	// organization, project and surfaces the enrollment is for; the caller
	// still authenticates as a member of that organization.
	Claim         string `json:"claim,omitempty"`
	RetentionDays int    `json:"retention_days"`
	OS            string `json:"os,omitempty"`
	Arch          string `json:"arch,omitempty"`
	CLIVersion    string `json:"cli_version,omitempty"`
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

	// StorageKind is "hosted" when the host said it has no storage of its own
	// and its project backs up to hosted storage: the host writes that into
	// its config, as a claim would have told it to.
	StorageKind string `json:"storage_kind,omitempty"`
}

// SurfaceRegisterRequest is sent by `daemon run` for each surface in its
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
	// CredentialSource is "held", "host" or empty, as Node.CredentialSource.
	CredentialSource string `json:"credential_source,omitempty"`
}

// NodeSinkRegisterRequest is a host reporting the bucket its own config
// names, for PUT /api/v1/nodes/{id}/sink. KeyFingerprint is an HMAC of the
// secret access key under the salt the remote server gives the project's
// hosts, or empty when the host sets no key; the key itself is never sent.
type NodeSinkRegisterRequest struct {
	Bucket         string `json:"bucket"`
	Region         string `json:"region,omitempty"`
	Endpoint       string `json:"endpoint,omitempty"`
	Prefix         string `json:"prefix,omitempty"`
	AccessKeyID    string `json:"access_key_id,omitempty"`
	ForcePathStyle bool   `json:"force_path_style,omitempty"`
	WORMMode       string `json:"worm_mode,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
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
	OS           string `json:"os,omitempty"`
	Arch         string `json:"arch,omitempty"`
	PostgresUp   bool   `json:"postgres_up"`
	StorageUp    bool   `json:"storage_up"`
	LastSnapshot string `json:"last_snapshot,omitempty"`

	// Sent by `daemon run`, so the console can tell "the daemon is dead" from
	// "the daemon is alive and this surface is failing".
	// TickSeconds is how often the daemon looks; silence is measured in it.
	TickSeconds         int          `json:"tick_seconds,omitempty"`
	ConsecutiveFailures int          `json:"consecutive_failures,omitempty"`
	LastError           string       `json:"last_error,omitempty"`
	BackupReason        BackupReason `json:"backup_reason,omitempty"`
	DrillStatus         DrillStatus  `json:"drill_status,omitempty"`
	DrillReason         DrillReason  `json:"drill_reason,omitempty"`
	DrillDetail         string       `json:"drill_detail,omitempty"`
	// Schedule and RetentionDays are what the daemon runs this surface on,
	// after any setting from the console, so the remote server measures
	// "overdue" against the schedule actually in force.
	Schedule      string `json:"schedule,omitempty"`
	RetentionDays int    `json:"retention_days,omitempty"`
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
	// SandboxDrillsIncluded says the plan records a drill that restored into
	// a real database. With it, a Postgres surface that names no sandbox
	// drills into a throwaway local cluster when the host can start one.
	SandboxDrillsIncluded bool `json:"sandbox_drills_included,omitempty"`

	// BackupRequestID names a one-shot "back up now". The daemon runs each id
	// once and remembers it. TriggerBackup is NOT this and a daemon must not
	// act on it: it is true whenever the server has not heard of a recent
	// success, so obeying it would back up on every tick whenever a report
	// failed (creating excess objects under Object Lock).
	BackupRequestID string `json:"backup_request_id,omitempty"`
	// DrillSnapshotID is the snapshot a triggered drill should restore: the
	// latest the remote server has recorded for this node.
	DrillSnapshotID string `json:"drill_snapshot_id,omitempty"`
	// DrillRequestID names a one-shot "drill now". The daemon runs each id once,
	// even inside its usual spacing between drills: someone asked for it.
	DrillRequestID string `json:"drill_request_id,omitempty"`

	// Schedule and RetentionDays, when set, were chosen in the console and
	// replace the host's config for this surface. Absent means the config
	// decides.
	Schedule      string `json:"schedule,omitempty"`
	RetentionDays int    `json:"retention_days,omitempty"`

	// LatestCLIVersion and UpgradeAvailable inform the client when a newer
	// version of SafeGrd CLI is released.
	LatestCLIVersion string `json:"latest_cli_version,omitempty"`
	UpgradeAvailable bool   `json:"upgrade_available,omitempty"`
}

// IsVersionOutdated reports whether current is strictly older than latest according to semantic versioning.
// Returns false if either string is empty, or if current/latest is "dev" or "unknown".
func IsVersionOutdated(current, latest string) bool {
	if current == "" || latest == "" || current == "dev" || latest == "dev" || current == "unknown" || latest == "unknown" {
		return false
	}
	curParts := parseSemver(current)
	latParts := parseSemver(latest)
	if curParts == nil || latParts == nil {
		return false
	}
	for i := 0; i < 3; i++ {
		if curParts[i] < latParts[i] {
			return true
		}
		if curParts[i] > latParts[i] {
			return false
		}
	}
	return false
}

func parseSemver(v string) []int {
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
	if idx := strings.IndexAny(v, "-+"); idx != -1 {
		v = v[:idx]
	}
	parts := strings.Split(v, ".")
	nums := make([]int, 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return nil
		}
		nums[i] = n
	}
	return nums
}
