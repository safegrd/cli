package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
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
	// SurfaceTypeWordPress is a WordPress site: its MySQL database and the
	// files under its root, in one archive.
	SurfaceTypeWordPress SurfaceType = "wordpress"
	// SurfaceTypeLaravel is a Laravel app: its database, its .env and the
	// files under storage/app, in one snapshot.
	SurfaceTypeLaravel SurfaceType = "laravel"
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
	// RowSecurity is set when row-level security applied to the role that
	// took the backup, so RowCount is the rows that role could see, which
	// may be fewer than the table holds.
	RowSecurity bool `json:"row_security,omitempty" yaml:"row_security,omitempty"`
	// FreshnessColumn is the first of updated_at, modified_at and created_at
	// the table has as a timestamp, and FreshnessMax its newest value at the
	// backup, in UTC (RFC 3339). Empty when the table has none, or when the
	// column has no index and the table is too large to read twice.
	FreshnessColumn string `json:"freshness_column,omitempty" yaml:"freshness_column,omitempty"`
	FreshnessMax    string `json:"freshness_max,omitempty" yaml:"freshness_max,omitempty"`
	// SampleHash is a SHA-256 of the table's first 100 rows by primary key,
	// as COPY text. Empty for a table with no primary key.
	SampleHash string `json:"sample_hash,omitempty" yaml:"sample_hash,omitempty"`
	// SchemaHash is an MD5 of the table's columns, types, defaults and
	// constraints as the catalog states them, so two runs can tell whether a
	// table's definition changed. OwnedSequences are the sequences its
	// columns own, and References the tables its foreign keys point at, each
	// as schema.name: what a one-table restore names and does not load.
	SchemaHash     string   `json:"schema_hash,omitempty" yaml:"schema_hash,omitempty"`
	OwnedSequences []string `json:"owned_sequences,omitempty" yaml:"owned_sequences,omitempty"`
	References     []string `json:"references,omitempty" yaml:"references,omitempty"`
	// Columns are the table's columns as the catalog states them, in
	// column order: schema, not contents. For a MongoDB collection they are
	// its top-level fields across every document in the backup, in order of
	// first appearance, with the BSON type ("mixed" when documents
	// disagree), NotNull for a field every document carries and _id as the
	// primary key. Nil when the backup did not record them (an empty
	// collection, the WordPress plugin, an older CLI), which the server
	// reads as "not recorded", never as a table with no columns.
	Columns []ColumnStat `json:"columns,omitempty" yaml:"columns,omitempty"`
	// NewBytes is, for a run of an incremental database backup, the bytes
	// of chunks this table added to the repository, before compression:
	// zero when its rows did not move. Absent on an archive.
	NewBytes *int64 `json:"new_bytes,omitempty" yaml:"new_bytes,omitempty"`
	// Carried is set when a run of an incremental database backup did not
	// read the table: the change log showed no write to it since the
	// previous run, whose rows and row count this run holds.
	Carried bool `json:"carried,omitempty" yaml:"carried,omitempty"`
}

// ColumnStat is one column of a table: its name and type as the engine
// states them, whether it refuses nulls and whether it is part of the
// primary key.
type ColumnStat struct {
	Name       string `json:"name" yaml:"name"`
	Type       string `json:"type" yaml:"type"`
	NotNull    bool   `json:"not_null,omitempty" yaml:"not_null,omitempty"`
	PrimaryKey bool   `json:"primary_key,omitempty" yaml:"primary_key,omitempty"`
}

// ColumnsHash is a SHA-256 over a table's columns, for an engine that has
// no catalog hash of its own (MySQL, SQLite): it moves when a column is
// added, removed, renamed or retyped, and for nothing else.
func ColumnsHash(cols []ColumnStat) string {
	if len(cols) == 0 {
		return ""
	}
	h := sha256.New()
	for _, c := range cols {
		fmt.Fprintf(h, "%s\x00%s\x00%t\x00%t\n", c.Name, c.Type, c.NotNull, c.PrimaryKey)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// WordPressStats is what a WordPress snapshot records about the site beside
// the database's table counts. Post content and file names stay sealed inside
// the archive; these are counts and settings.
type WordPressStats struct {
	SiteURL          string `json:"site_url,omitempty" yaml:"site_url,omitempty"`
	WordPressVersion string `json:"wordpress_version,omitempty" yaml:"wordpress_version,omitempty"`
	PHPVersion       string `json:"php_version,omitempty" yaml:"php_version,omitempty"`
	PluginVersion    string `json:"plugin_version,omitempty" yaml:"plugin_version,omitempty"`
	// TablePrefix is $table_prefix from wp-config.php. Only tables that
	// start with it are in the dump.
	TablePrefix string `json:"table_prefix" yaml:"table_prefix"`
	// UploadsPath is the uploads directory relative to the site root,
	// normally wp-content/uploads. Attachments are checked under it.
	UploadsPath string `json:"uploads_path" yaml:"uploads_path"`
	TotalFiles  int64  `json:"total_files" yaml:"total_files"`
	FileBytes   int64  `json:"file_bytes" yaml:"file_bytes"`
	Attachments int64  `json:"attachments" yaml:"attachments"`
	// Skipped lists what the backup left out on purpose (caches, other
	// backup plugins' archives) or could not read, as "path (why)".
	Skipped []string `json:"skipped,omitempty" yaml:"skipped,omitempty"`
}

// LaravelStats is what a Laravel snapshot records about the app beside the
// database's table counts. The .env and the files stay sealed in the
// snapshot; these are counts, names and versions.
type LaravelStats struct {
	// Connection is the app's DB_CONNECTION: mysql, mariadb, pgsql or
	// sqlite. The database is stored as that engine's surface stores it.
	Connection     string `json:"connection" yaml:"connection"`
	LaravelVersion string `json:"laravel_version,omitempty" yaml:"laravel_version,omitempty"`
	AppName        string `json:"app_name,omitempty" yaml:"app_name,omitempty"`
	AppEnv         string `json:"app_env,omitempty" yaml:"app_env,omitempty"`
	// MigrationsTable is the table the migrations ran are recorded in, and
	// MigrationsRan its rows as the backup read them.
	MigrationsTable string `json:"migrations_table" yaml:"migrations_table"`
	MigrationsRan   int64  `json:"migrations_ran" yaml:"migrations_ran"`
	// MigrationFiles counts database/migrations/*.php; Pending names the
	// ones the database had not run.
	MigrationFiles int64    `json:"migration_files" yaml:"migration_files"`
	Pending        []string `json:"pending,omitempty" yaml:"pending,omitempty"`
	// SchemaDump is set when database/schema holds a schema:dump file.
	SchemaDump bool  `json:"schema_dump,omitempty" yaml:"schema_dump,omitempty"`
	TotalFiles int64 `json:"total_files" yaml:"total_files"`
	FileBytes  int64 `json:"file_bytes" yaml:"file_bytes"`
	// FilesystemDisk is FILESYSTEM_DISK when it is not local: the uploads
	// are elsewhere and not in this snapshot.
	FilesystemDisk string `json:"filesystem_disk,omitempty" yaml:"filesystem_disk,omitempty"`
	// LeftOut names what the backup left out on purpose.
	LeftOut []string `json:"left_out,omitempty" yaml:"left_out,omitempty"`
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
	WORMMode string `json:"worm_mode,omitempty" yaml:"worm_mode,omitempty"`
	// Unlocked says the snapshot was written with no lock and is kept until
	// WORMRetentionUntil: a recent run of a project that locks only the
	// copies it keeps. Never set on a snapshot the bucket holds a lock on.
	Unlocked bool `json:"unlocked,omitempty" yaml:"unlocked,omitempty"`
	// KeptUntil is when a locked snapshot is deleted, when that is later
	// than its lock: the free floor locks a backup for its first day and
	// keeps it a week. Nil when the two are the same.
	KeptUntil *time.Time `json:"kept_until,omitempty" yaml:"kept_until,omitempty"`
	// OutsideProjectStorage is decided by the remote server, never by the
	// host: the report named a location other than the storage its project
	// uses, so the project's storage does not hold this backup, and a restore
	// has to fetch it from where the host put it.
	OutsideProjectStorage bool        `json:"outside_project_storage,omitempty" yaml:"outside_project_storage,omitempty"`
	TotalItems            int64       `json:"total_items" yaml:"total_items"`           // rows, files, or emails
	TotalContainers       int         `json:"total_containers" yaml:"total_containers"` // tables, directories, or folders
	TableStats            []TableStat `json:"table_stats,omitempty" yaml:"table_stats,omitempty"`
	TotalTables           int         `json:"total_tables,omitempty" yaml:"total_tables,omitempty"`
	TotalRows             int64       `json:"total_rows,omitempty" yaml:"total_rows,omitempty"`
	Extensions            []string    `json:"extensions,omitempty" yaml:"extensions,omitempty"`
	// SchemaSource says how a Postgres snapshot's schema was captured:
	// "pg_dump 18.6", or "native" when no usable pg_dump was on the host and
	// the schema was re-derived without foreign keys, views, triggers or enum
	// types. Empty on snapshots taken before it existed, which
	// were all native.
	SchemaSource string `json:"schema_source,omitempty" yaml:"schema_source,omitempty"`
	// Replica is set when a PostgreSQL backup was read from a standby, and
	// says how far behind the primary it had replayed when the backup's
	// snapshot was taken.
	Replica *ReplicaRead `json:"replica,omitempty" yaml:"replica,omitempty"`
	// LargeObjects is how many PostgreSQL large objects (pg_largeobject) the
	// database held; LargeObjectsLeftOut how many of them the backup's role
	// could not read, which the snapshot does not hold. LargeObjectsDigest
	// is one SHA-256 over every object it does hold, which a restore and a
	// drill check what they read against.
	LargeObjects        int64  `json:"large_objects,omitempty" yaml:"large_objects,omitempty"`
	LargeObjectsLeftOut int64  `json:"large_objects_left_out,omitempty" yaml:"large_objects_left_out,omitempty"`
	LargeObjectBytes    int64  `json:"large_object_bytes,omitempty" yaml:"large_object_bytes,omitempty"`
	LargeObjectsDigest  string `json:"large_objects_digest,omitempty" yaml:"large_objects_digest,omitempty"`
	// CronJobs is how many of pg_cron's jobs the archive carries. The jobs
	// themselves are in the archive only, sealed: a job's command can hold
	// a secret.
	CronJobs int `json:"cron_jobs,omitempty" yaml:"cron_jobs,omitempty"`
	// Erasures is where the surface's erasure record is kept and the tables
	// it covers, when the surface names any: a restore replays the erasures
	// this backup did not see before it commits.
	Erasures *ErasureRecord `json:"erasures,omitempty" yaml:"erasures,omitempty"`
	// External is set on a backup another tool made, which a watched
	// surface read where that tool put it. SafeGrd holds no archive of it:
	// StorageURI is the other tool's object, Sha256Checksum its bytes'.
	External *ExternalBackup `json:"external,omitempty" yaml:"external,omitempty"`
	// Copies are this snapshot's copies in the surface's other buckets, as
	// the host wrote them with the snapshot and as its catch-up writes them
	// later. Empty for a surface with one bucket.
	Copies []SnapshotCopy `json:"copies,omitempty" yaml:"copies,omitempty"`
	// Notes are key=value pairs on the snapshot, such as release=v2.3:
	// given with the backup or added later. The remote server keeps them,
	// not the locked archive or its sidecar, so they can change.
	Notes map[string]string `json:"notes,omitempty" yaml:"notes,omitempty"`
	// DatabaseSettings are the settings set on the PostgreSQL database
	// itself (ALTER DATABASE ... SET), as "name=value", which no pg_dump
	// section carries: a restore applies them to its target.
	DatabaseSettings []string `json:"database_settings,omitempty" yaml:"database_settings,omitempty"`
	// RoleSettings are the settings a role has in this database alone
	// (ALTER ROLE ... IN DATABASE ... SET), applied by a restore as
	// DatabaseSettings are.
	RoleSettings []RoleSetting `json:"role_settings,omitempty" yaml:"role_settings,omitempty"`
	// DatabaseGrants are the privileges granted on the database itself
	// (GRANT CONNECT ON DATABASE ...), set when they are not the default.
	// A restore revokes the default and grants these, so a database that
	// let only its own roles connect does not come back open to all.
	DatabaseGrants []DatabaseGrant `json:"database_grants,omitempty" yaml:"database_grants,omitempty"`
	// RolesNamed are the roles a Postgres snapshot's schema names (owners,
	// grantees, the roles policies apply to), sorted. RolesSource says how
	// roles.sql carried them: "pg_dumpall 16.4", with ", no passwords" when
	// the surface opted out or the backup role could not read them. Empty
	// RolesSource with roles named means the snapshot does not carry them,
	// and a restore into a cluster without them fails.
	RolesNamed  []string `json:"roles_named,omitempty" yaml:"roles_named,omitempty"`
	RolesSource string   `json:"roles_source,omitempty" yaml:"roles_source,omitempty"`
	// SourceSnapshot is the PostgreSQL snapshot the backup read under
	// (pg_current_snapshot, xmin:xmax:xip), and SourceLSN the WAL position
	// read inside it, at or just after the moment it was taken. They order
	// two backups of one database and say what each saw.
	SourceSnapshot string `json:"source_snapshot,omitempty" yaml:"source_snapshot,omitempty"`
	SourceLSN      string `json:"source_lsn,omitempty" yaml:"source_lsn,omitempty"`
	// ServerVersion is a MySQL or MariaDB snapshot's server, as it reported
	// itself ("8.4.3", "11.4.4-MariaDB"). PostgresVersion is Postgres's.
	ServerVersion string             `json:"server_version,omitempty" yaml:"server_version,omitempty"`
	FileStats     *FileStatsSummary  `json:"file_stats,omitempty" yaml:"file_stats,omitempty"`
	EmailStats    *EmailStatsSummary `json:"email_stats,omitempty" yaml:"email_stats,omitempty"`
	// WordPress describes a WordPress site's snapshot; nil for every other
	// surface.
	WordPress *WordPressStats `json:"wordpress,omitempty" yaml:"wordpress,omitempty"`
	// Laravel describes a Laravel app's snapshot; nil for every other
	// surface.
	Laravel            *LaravelStats `json:"laravel,omitempty" yaml:"laravel,omitempty"`
	DurationMs         int64         `json:"duration_ms" yaml:"duration_ms"`
	IsPoisonPillFrozen bool          `json:"is_poison_pill_frozen" yaml:"is_poison_pill_frozen"`
	ErrorMessage       string        `json:"error_message,omitempty" yaml:"error_message,omitempty"`
	// FailureReason is why a failed backup failed, as a code; ErrorMessage
	// is the same in the host's words.
	FailureReason BackupReason `json:"failure_reason,omitempty" yaml:"failure_reason,omitempty"`

	// Shield is what Threat Shield compared this snapshot with and what it
	// found, set by the remote server when the backup is recorded and never
	// by the host. Nil on a failed backup and on records from before it
	// existed.
	Shield *ShieldComparison `json:"shield,omitempty" yaml:"shield,omitempty"`

	// Format is how the snapshot is stored: empty for one archive object,
	// SnapshotFormatRepo for a snapshot in an incremental file repository.
	// For that format Sha256Checksum is the content root, EncryptedSha256 is
	// empty, RawSizeBytes and TotalItems are the whole tree's logical size and
	// file count, and EncryptedSizeBytes is what this run uploaded.
	Format string `json:"format,omitempty" yaml:"format,omitempty"`
	// EpochID is the repository epoch that holds the snapshot, and
	// ObjectClass whether the run that wrote it was the epoch's opening run
	// ("opening") or a later one ("later").
	EpochID     string `json:"epoch_id,omitempty" yaml:"epoch_id,omitempty"`
	ObjectClass string `json:"object_class,omitempty" yaml:"object_class,omitempty"`
}

// ShieldComparison is what Threat Shield held one snapshot to: the backup
// before it, each check with the numbers it looked at, and what changed
// between the two. It is recorded on every completed snapshot, so a clean
// one says what it was compared with and not only a flagged one.
type ShieldComparison struct {
	// BaselineSnapshotID is the snapshot this one was compared with: the
	// newest completed one of the same surface. Empty, with Skipped set,
	// when there was none.
	BaselineSnapshotID string     `json:"baseline_snapshot_id,omitempty" yaml:"baseline_snapshot_id,omitempty"`
	BaselineCreatedAt  *time.Time `json:"baseline_created_at,omitempty" yaml:"baseline_created_at,omitempty"`
	// Skipped says why no check ran: the surface's first backup, or a
	// backup taken across a CLI upgrade that changed what is counted.
	Skipped string `json:"skipped,omitempty" yaml:"skipped,omitempty"`
	// Checks are every check that ran, in the order they are decided, each
	// with whether it passed. A failed check is the anomaly the snapshot
	// was flagged with, or a warning.
	Checks []ShieldCheck `json:"checks,omitempty" yaml:"checks,omitempty"`
	// TablesAdded and TablesGone name the tables (schema.table) in one
	// snapshot and not the other. SchemaChanged names the tables whose
	// definition moved between the two, where both recorded a schema hash.
	TablesAdded   []string `json:"tables_added,omitempty" yaml:"tables_added,omitempty"`
	TablesGone    []string `json:"tables_gone,omitempty" yaml:"tables_gone,omitempty"`
	SchemaChanged []string `json:"schema_changed,omitempty" yaml:"schema_changed,omitempty"`
	// Columns lists each table whose columns changed by name, where both
	// snapshots recorded columns.
	Columns []ShieldColumnChange `json:"columns,omitempty" yaml:"columns,omitempty"`
	// RowMoves are the tables whose row count moved most, largest first,
	// at most five.
	RowMoves []ShieldRowMove `json:"row_moves,omitempty" yaml:"row_moves,omitempty"`
}

// ShieldCheck is one of Threat Shield's checks on one snapshot.
type ShieldCheck struct {
	// Type is the anomaly the check raises when it fails, as AnomalyType
	// names it (row_volume_drop, table_drop, column_drop, ...).
	Type   string `json:"type" yaml:"type"`
	Passed bool   `json:"passed" yaml:"passed"`
	// Words say what was compared, with the numbers: "70,210 rows, against
	// 70,000 before. Flags a drop of 20% or more."
	Words string `json:"words" yaml:"words"`
}

// ShieldColumnChange is one table whose columns changed between two
// snapshots, by name.
type ShieldColumnChange struct {
	Schema    string   `json:"schema" yaml:"schema"`
	TableName string   `json:"table_name" yaml:"table_name"`
	Dropped   []string `json:"dropped,omitempty" yaml:"dropped,omitempty"`
	Added     []string `json:"added,omitempty" yaml:"added,omitempty"`
}

// ShieldRowMove is one table's row count in the backup before and in this
// one.
type ShieldRowMove struct {
	Schema     string `json:"schema" yaml:"schema"`
	TableName  string `json:"table_name" yaml:"table_name"`
	RowsBefore int64  `json:"rows_before" yaml:"rows_before"`
	RowsNow    int64  `json:"rows_now" yaml:"rows_now"`
}

// SnapshotFormatRepo is the Format of a snapshot in an incremental file
// repository, version 1.
const SnapshotFormatRepo = "repo-v1"

// IsRepo reports whether the snapshot lives in an incremental file
// repository rather than one archive object.
func (m *SnapshotMetadata) IsRepo() bool { return m != nil && m.Format == SnapshotFormatRepo }

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
	} else if m.SurfaceType == SurfaceTypeWordPress || m.SurfaceType == SurfaceTypeLaravel {
		// Counted as the database it holds, so a drill's row and table
		// counts compare with the manifest's; the files are in WordPress or Laravel.
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

// ReplicaRead is what a backup read from a standby knew about its lag.
type ReplicaRead struct {
	// ReplayedAt is when the newest transaction the standby had replayed
	// committed on the primary; nil when it had replayed none since it
	// started.
	ReplayedAt *time.Time `json:"replayed_at,omitempty" yaml:"replayed_at,omitempty"`
	// LagSeconds is the backup's snapshot time less ReplayedAt. On a primary
	// with no writes it grows while nothing is behind.
	LagSeconds float64 `json:"lag_seconds" yaml:"lag_seconds"`
}

// RoleSetting is one setting a role has in one database, as "name=value".
type RoleSetting struct {
	Role    string `json:"role" yaml:"role"`
	Setting string `json:"setting" yaml:"setting"`
}

// DatabaseGrant is one privilege on a PostgreSQL database: CONNECT, CREATE
// or TEMPORARY, to a role or to PUBLIC.
type DatabaseGrant struct {
	Role      string `json:"role" yaml:"role"` // "PUBLIC" for every role
	Privilege string `json:"privilege" yaml:"privilege"`
	Grantable bool   `json:"grantable,omitempty" yaml:"grantable,omitempty"`
}

// ErasureRecord names a surface's erasure record: the directory its sealed
// objects are kept in, relative to the storage's root, and the tables whose
// deleted rows it records, as schema.table.
type ErasureRecord struct {
	Path   string   `json:"path" yaml:"path"`
	Tables []string `json:"tables" yaml:"tables"`
}

// ExternalBackup is what a check read about a backup another tool made.
type ExternalBackup struct {
	// URI is where the other tool put it: s3://bucket/key or file:///path.
	URI string `json:"uri" yaml:"uri"`
	// Tool names the tool when the file name says ("Coolify"), or is empty.
	Tool string `json:"tool,omitempty" yaml:"tool,omitempty"`
	// Format is custom (pg_dump --format=custom), plain or cluster
	// (pg_dumpall).
	Format string `json:"format" yaml:"format"`
	// Modified is when the other tool wrote it.
	Modified time.Time `json:"modified" yaml:"modified"`
}

// MadeBy names who made the backup, for a sentence: "Coolify" or "another
// tool".
func (e *ExternalBackup) MadeBy() string {
	if e == nil || e.Tool == "" {
		return "another tool"
	}
	return e.Tool
}

// MaxNotes is how many notes a snapshot holds.
const MaxNotes = 20

var noteKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,39}$`)

// ValidNote refuses a note key or value the console and alert emails could
// not show as written: a key of lowercase letters, digits, '_', '.' and
// '-', up to 40, and a value of up to 200 characters with no control
// characters.
func ValidNote(key, value string) error {
	if !noteKeyRe.MatchString(key) {
		return fmt.Errorf("note key %q: 1 to 40 lowercase letters, digits, '_', '.' or '-', starting with a letter or digit", key)
	}
	if len(value) > 200 {
		return fmt.Errorf("note %s: the value is %d characters; 200 at most", key, len(value))
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("note %s: the value holds a control character", key)
		}
	}
	return nil
}
