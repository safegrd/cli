package model

import (
	"time"
)

// SnapshotStatus represents the current lifecycle status of a snapshot.
type SnapshotStatus string

const (
	SnapshotStatusPending   SnapshotStatus = "pending"
	SnapshotStatusUploading SnapshotStatus = "uploading"
	SnapshotStatusCompleted SnapshotStatus = "completed"
	SnapshotStatusFailed    SnapshotStatus = "failed"
	SnapshotStatusVerified  SnapshotStatus = "verified"
	SnapshotStatusAnomalous SnapshotStatus = "anomalous"
)

// SurfaceType defines the protected data surface.
type SurfaceType string

const (
	SurfaceTypePostgres SurfaceType = "postgres"
	SurfaceTypeFiles    SurfaceType = "files"
	SurfaceTypeEmail    SurfaceType = "email"
	// SurfaceTypeMySQL is a MySQL or MariaDB database.
	SurfaceTypeMySQL SurfaceType = "mysql"
	// SurfaceTypeMongoDB is a MongoDB database: its
	// collections count as tables and its documents as rows.
	SurfaceTypeMongoDB SurfaceType = "mongodb"
	// SurfaceTypeSQLite is a SQLite database file.
	SurfaceTypeSQLite SurfaceType = "sqlite"
)

// IsDatabase reports whether a surface is a database, counted in tables and
// rows.
func (t SurfaceType) IsDatabase() bool {
	return t == "" || t == SurfaceTypePostgres || t == SurfaceTypeMySQL || t == SurfaceTypeMongoDB || t == SurfaceTypeSQLite
}

// ExtensionStat captures file counts and aggregate sizes per extension (e.g. .png, .pdf, .json).
type ExtensionStat struct {
	Extension string `json:"extension" yaml:"extension"`
	Count     int64  `json:"count" yaml:"count"`
	SizeBytes int64  `json:"size_bytes" yaml:"size_bytes"`
}

// FileStatsSummary captures aggregate metrics for a file-based snapshot.
// Individual file paths remain sealed inside the archive.
type FileStatsSummary struct {
	TotalFiles       int64           `json:"total_files" yaml:"total_files"`
	TotalDirectories int             `json:"total_directories" yaml:"total_directories"`
	TopExtensions    []ExtensionStat `json:"top_extensions,omitempty" yaml:"top_extensions,omitempty"`
}

// EmailFolderStat captures aggregate message counts and sizes per mailbox folder.
type EmailFolderStat struct {
	Folder       string `json:"folder" yaml:"folder"`
	MessageCount int64  `json:"message_count" yaml:"message_count"`
	SizeBytes    int64  `json:"size_bytes" yaml:"size_bytes"`
	UIDValidity  uint32 `json:"uid_validity,omitempty" yaml:"uid_validity,omitempty"` // IMAP mailbox UIDVALIDITY
	HighestUID   uint32 `json:"highest_uid,omitempty" yaml:"highest_uid,omitempty"`   // Highest retrieved message UID
}

// EmailStatsSummary captures aggregate metrics for an email-based snapshot.
// Subject lines and recipient lists remain sealed inside the archive.
type EmailStatsSummary struct {
	TotalEmails  int64             `json:"total_emails" yaml:"total_emails"`
	TotalFolders int               `json:"total_folders" yaml:"total_folders"`
	Folders      []EmailFolderStat `json:"folders,omitempty" yaml:"folders,omitempty"`
	OldestDate   *time.Time        `json:"oldest_date,omitempty" yaml:"oldest_date,omitempty"`
	NewestDate   *time.Time        `json:"newest_date,omitempty" yaml:"newest_date,omitempty"`
}

// TableStat captures schema and volume statistics for an individual table.
type TableStat struct {
	Schema    string `json:"schema" yaml:"schema"`
	TableName string `json:"table_name" yaml:"table_name"`
	RowCount  int64  `json:"row_count" yaml:"row_count"`
	SizeBytes int64  `json:"size_bytes" yaml:"size_bytes"`
}

// SnapshotMetadata represents client-side collected metadata sent to the remote server.
// Crucially: Plaintext database contents and credentials are NEVER in this metadata.
type SnapshotMetadata struct {
	SnapshotID         string         `json:"snapshot_id" yaml:"snapshot_id"`
	NodeID             string         `json:"node_id" yaml:"node_id"`
	SurfaceType        SurfaceType    `json:"surface_type" yaml:"surface_type"` // "postgres", "files", "email"
	DatabaseName       string         `json:"database_name,omitempty" yaml:"database_name,omitempty"`
	PostgresVersion    string         `json:"postgres_version,omitempty" yaml:"postgres_version,omitempty"`
	CreatedAt          time.Time      `json:"created_at" yaml:"created_at"`
	CompletedAt        *time.Time     `json:"completed_at,omitempty" yaml:"completed_at,omitempty"`
	Status             SnapshotStatus `json:"status" yaml:"status"`
	RawSizeBytes       int64          `json:"raw_size_bytes" yaml:"raw_size_bytes"`
	EncryptedSizeBytes int64          `json:"encrypted_size_bytes" yaml:"encrypted_size_bytes"`
	// Sha256Checksum is the digest of the PLAINTEXT stream: the dump as it
	// was read, before compression and encryption. It is used to verify restore
	// integrity to ensure restored bytes match what was originally read.
	Sha256Checksum string `json:"sha256_checksum" yaml:"sha256_checksum"`

	// EncryptedSha256 is the digest of the ciphertext as written to the storage sink.
	// It verifies at-rest object integrity without requiring decryption keys.
	// Empty on legacy snapshots taken before this field was added.
	EncryptedSha256    string    `json:"encrypted_sha256,omitempty" yaml:"encrypted_sha256,omitempty"`
	StorageURI         string    `json:"storage_uri" yaml:"storage_uri"`
	WORMRetentionUntil time.Time `json:"worm_retention_until" yaml:"worm_retention_until"`
	// WORMMode is the Object Lock mode the snapshot was written under:
	// COMPLIANCE, GOVERNANCE, or NONE. Empty on snapshots written before
	// this field existed.
	WORMMode        string      `json:"worm_mode,omitempty" yaml:"worm_mode,omitempty"`
	TotalItems      int64       `json:"total_items" yaml:"total_items"`           // rows, files, or emails
	TotalContainers int         `json:"total_containers" yaml:"total_containers"` // tables, directories, or folders
	TableStats      []TableStat `json:"table_stats,omitempty" yaml:"table_stats,omitempty"`
	TotalTables     int         `json:"total_tables,omitempty" yaml:"total_tables,omitempty"`
	TotalRows       int64       `json:"total_rows,omitempty" yaml:"total_rows,omitempty"`
	Extensions      []string    `json:"extensions,omitempty" yaml:"extensions,omitempty"`
	// SchemaSource says how a Postgres snapshot's schema was captured:
	// "pg_dump 18.6", or "native" when no usable pg_dump was on the host and
	// the schema was re-derived without foreign keys, views, triggers or enum
	// types. Empty on snapshots taken before it existed, which
	// were all native.
	SchemaSource string `json:"schema_source,omitempty" yaml:"schema_source,omitempty"`
	// ServerVersion is a MySQL or MariaDB snapshot's server, as it reported
	// itself ("8.4.3", "11.4.4-MariaDB"). PostgresVersion is Postgres's.
	ServerVersion      string             `json:"server_version,omitempty" yaml:"server_version,omitempty"`
	FileStats          *FileStatsSummary  `json:"file_stats,omitempty" yaml:"file_stats,omitempty"`
	EmailStats         *EmailStatsSummary `json:"email_stats,omitempty" yaml:"email_stats,omitempty"`
	DurationMs         int64              `json:"duration_ms" yaml:"duration_ms"`
	IsPoisonPillFrozen bool               `json:"is_poison_pill_frozen" yaml:"is_poison_pill_frozen"`
	ErrorMessage       string             `json:"error_message,omitempty" yaml:"error_message,omitempty"`
}

// CalculateTotals sums row counts, file totals, or email totals.
func (m *SnapshotMetadata) CalculateTotals() {
	if m.SurfaceType.IsDatabase() {
		if m.SurfaceType == "" {
			m.SurfaceType = SurfaceTypePostgres
		}
		m.TotalTables = len(m.TableStats)
		var rows int64
		for _, t := range m.TableStats {
			rows += t.RowCount
		}
		m.TotalRows = rows
		m.TotalItems = rows
		m.TotalContainers = m.TotalTables
	} else if m.SurfaceType == SurfaceTypeFiles && m.FileStats != nil {
		m.TotalItems = m.FileStats.TotalFiles
		m.TotalContainers = m.FileStats.TotalDirectories
	} else if m.SurfaceType == SurfaceTypeEmail && m.EmailStats != nil {
		m.TotalItems = m.EmailStats.TotalEmails
		m.TotalContainers = m.EmailStats.TotalFolders
	}
}
