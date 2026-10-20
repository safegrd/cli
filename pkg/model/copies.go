package model

import "time"

// A copy is a snapshot written to a second or third bucket beside the
// surface's own, each under its own key, lock and retention. These are the
// shapes the host and the remote server exchange about copies.

// Copy states.
const (
	// CopyHeld: the bucket holds the snapshot, every byte of it.
	CopyHeld = "held"
	// CopyFailed: writing it failed; the host's catch-up tries again.
	CopyFailed = "failed"
)

// SnapshotCopy is one bucket's copy of one snapshot.
type SnapshotCopy struct {
	SnapshotID string `json:"snapshot_id"`
	// Bucket is the copy's name in the config or the project, not the
	// bucket's own name.
	Bucket      string     `json:"bucket"`
	StorageURI  string     `json:"storage_uri,omitempty"`
	WORMMode    string     `json:"worm_mode,omitempty"`
	RetainUntil *time.Time `json:"retain_until,omitempty"`
	State       string     `json:"state"`
	Error       string     `json:"error,omitempty"`
}

// CopiesReport is POST /api/v1/nodes/{id}/copies: what the host wrote, or
// failed to write, to the surface's other buckets.
type CopiesReport struct {
	Copies []SnapshotCopy `json:"copies"`
}

// CopyBehind is one bucket that lacks snapshots the surface's own bucket
// holds, as the heartbeat says it.
type CopyBehind struct {
	Name    string     `json:"name"`
	Missing int        `json:"missing"`
	Since   *time.Time `json:"since,omitempty"`
	Error   string     `json:"error,omitempty"`
}

// SinkCopy is a bucket the project writes every backup to beside its own,
// as GET /api/v1/nodes/{id}/sink answers it. The key, when the remote server
// holds it, comes with the node's credentials.
type SinkCopy struct {
	Name           string `json:"name"`
	Bucket         string `json:"bucket"`
	Region         string `json:"region,omitempty"`
	Endpoint       string `json:"endpoint,omitempty"`
	Prefix         string `json:"prefix,omitempty"`
	ForcePathStyle bool   `json:"force_path_style,omitempty"`
	WORMMode       string `json:"worm_mode,omitempty"`
	RetentionDays  int    `json:"retention_days,omitempty"`
	StorageClass   string `json:"storage_class,omitempty"`
	AccessKeyID    string `json:"access_key_id,omitempty"`
	KeyHeld        bool   `json:"key_held,omitempty"`
}

// CopyCredential is a project bucket's key the remote server holds, released
// to the node with its other credentials.
type CopyCredential struct {
	Name            string `json:"name"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}
