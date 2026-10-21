package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
)

// StorageType enumerates supported storage backends.
type StorageType string

const (
	StorageTypeS3    StorageType = "s3"
	StorageTypeLocal StorageType = "local"
	// StorageTypeHosted is SafeGrd's own locked bucket: the remote server
	// leases a credential for this organization's prefix at run time, so the
	// config holds no bucket and no secret.
	StorageTypeHosted StorageType = "hosted"
)

// WORMMode specifies Object Lock enforcement level.
type WORMMode string

const (
	WORMModeCompliance WORMMode = "COMPLIANCE"
	WORMModeGovernance WORMMode = "GOVERNANCE"

	// WORMModeNone writes objects with no Object Lock at all.
	//
	// It exists because several S3-compatible providers (such as DigitalOcean Spaces)
	// do not implement Object Lock.
	//
	// It is strictly opt-in and never a default or fallback.
	// still attested, but nothing stops an attacker who reaches the bucket from
	// deleting it, and `safegrd backup` says so on every run.
	WORMModeNone WORMMode = "NONE"
)

// StorageConfig holds settings for immutable snapshot storage.
type StorageConfig struct {
	Type          StorageType `yaml:"type" json:"type"`
	Bucket        string      `yaml:"bucket" json:"bucket"`
	Region        string      `yaml:"region" json:"region"`
	Endpoint      string      `yaml:"endpoint,omitempty" json:"endpoint,omitempty"` // For MinIO / R2
	Prefix        string      `yaml:"prefix" json:"prefix"`
	RetentionDays int         `yaml:"retention_days" json:"retention_days"`
	WORMMode      WORMMode    `yaml:"worm_mode" json:"worm_mode"`
	// StorageClass is the S3 storage class of each archive: STANDARD (the
	// default), STANDARD_IA or GLACIER_IR. A colder class costs less to hold
	// and charges a retrieval fee on every drill. The manifest beside the
	// archive stays STANDARD, since every list and drill reads it.
	StorageClass string `yaml:"storage_class,omitempty" json:"storage_class,omitempty"`
	// ExpireAfterLock lets the daemon delete snapshots from this bucket once
	// their Object Lock has ended (a day of grace, by the bucket's clock),
	// never the newest of a surface and never one the remote server keeps as
	// last known good. Off by default: it needs s3:DeleteObjectVersion, which
	// the recommended policy denies. `safegrd prune` does the same by hand.
	ExpireAfterLock bool `yaml:"expire_after_lock,omitempty" json:"expire_after_lock,omitempty"`
	// MinKeep is how many of each surface's newest snapshots that pruning
	// never deletes, whatever their locks say. Zero means 3.
	MinKeep         int    `yaml:"min_keep,omitempty" json:"min_keep,omitempty"`
	LocalPath       string `yaml:"local_path,omitempty" json:"local_path,omitempty"` // For local filesystem WORM
	AccessKeyID     string `yaml:"access_key_id,omitempty" json:"access_key_id,omitempty"`
	SecretAccessKey string `yaml:"secret_access_key,omitempty" json:"secret_access_key,omitempty"`
	// SessionToken accompanies a temporary credential (a hosted storage
	// lease). Never written to disk.
	SessionToken   string `yaml:"-" json:"-"`
	ForcePathStyle bool   `yaml:"force_path_style,omitempty" json:"force_path_style,omitempty"`
	NodeID         string `yaml:"node_id,omitempty" json:"node_id,omitempty"`
	IAMRoleARN     string `yaml:"iam_role_arn,omitempty" json:"iam_role_arn,omitempty"`
	// Layout "hosted", with type s3, reads hosted storage's bucket with the
	// bucket's own key and no remote server: Prefix is the organization's
	// folder, orgs/<org-id>/safegrd. It only reads; a backup is refused.
	Layout string `yaml:"layout,omitempty" json:"layout,omitempty"`
}

// StorageLayoutHosted is storage.layout's one value: the keys hosted storage
// files snapshots and repositories under.
const StorageLayoutHosted = "hosted"

// EncryptionConfig holds Age asymmetric keypair configuration.
type EncryptionConfig struct {
	PublicKey  string `yaml:"public_key" json:"public_key"` // Age recipient: age1...
	PrivateKey string `yaml:"-" json:"-"`                   // Age identity: AGE-SECRET-KEY-1... (held in-memory, resolved from key_path or SAFEGRD_PRIVATE_KEY)
	KeyPath    string `yaml:"key_path" json:"key_path"`     // Path to identity file
}

// DaemonConfig configures the resident unattended daemon.
type DaemonConfig struct {
	Interval string `yaml:"interval,omitempty" json:"interval,omitempty"`   // Poll interval, default "5m"
	StateDir string `yaml:"state_dir,omitempty" json:"state_dir,omitempty"` // Directory for state & locks
	// MetricsAddr is where the resident daemon serves Prometheus metrics,
	// at /metrics: "127.0.0.1:9847". Empty serves none.
	MetricsAddr string `yaml:"metrics_addr,omitempty" json:"metrics_addr,omitempty"`
	// PingURL is pinged after every pass over the surfaces, a Healthchecks.io
	// style check URL: the URL itself after a pass, URL/fail after one that
	// could not run. env:VAR or file:/path read it from elsewhere.
	PingURL string `yaml:"ping_url,omitempty" json:"ping_url,omitempty"`
	// Updates is "console" (the default): the daemon downloads each new
	// release, checks its signature, and installs it when someone approves it
	// in the console, which can also send the host back to the release it ran
	// before. "off" downloads and installs nothing.
	Updates string `yaml:"updates,omitempty" json:"updates,omitempty"`
	// UpdatesURL is where releases are downloaded from, in place of
	// https://github.com/safegrd/cli/releases/download: a mirror. Each
	// release is <url>/v<version>/<file>, and is checked the same way.
	UpdatesURL string `yaml:"updates_url,omitempty" json:"updates_url,omitempty"`
}

// DefaultsConfig defines fallback values inherited by surfaces.
type DefaultsConfig struct {
	Schedule string `yaml:"schedule,omitempty" json:"schedule,omitempty"` // "@daily", "@hourly", "6h", cron
	Timezone string `yaml:"timezone,omitempty" json:"timezone,omitempty"` // e.g. "UTC"
	// KeepDaily, KeepWeekly and KeepMonthly are the grandfather-father-son
	// tiers: the first backup of each UTC day is locked for KeepDaily days,
	// the first of each ISO week for KeepWeekly weeks, the first of each month
	// for KeepMonthly months, and every other backup for the surface's
	// retention_days, else the storage's. Zero turns a tier off.
	KeepDaily   int `yaml:"keep_daily,omitempty" json:"keep_daily,omitempty"`
	KeepWeekly  int `yaml:"keep_weekly,omitempty" json:"keep_weekly,omitempty"`
	KeepMonthly int `yaml:"keep_monthly,omitempty" json:"keep_monthly,omitempty"`
}

// Where a surface's credential comes from (CredentialConfig.From).
const (
	// CredentialFromSafeGrd: the remote server holds it, sealed, and the
	// daemon fetches it when the surface backs up. Nothing is set on the host.
	CredentialFromSafeGrd = "safegrd"
	// CredentialFromEnv: an environment variable on the host, named by Name.
	CredentialFromEnv = "env"
	// CredentialFromCommand: the output of a command run on the host (Run),
	// such as a secret manager's CLI.
	CredentialFromCommand = "command"
	// CredentialFromFile: a file on the host (Path), such as a mounted secret.
	CredentialFromFile = "file"
)

// CredentialConfig says where a surface's credential comes from.
type CredentialConfig struct {
	From string `yaml:"from" json:"from"`
	Name string `yaml:"name,omitempty" json:"name,omitempty"` // from: env
	Run  string `yaml:"run,omitempty" json:"run,omitempty"`   // from: command
	Path string `yaml:"path,omitempty" json:"path,omitempty"` // from: file
}

// CredentialFrom is where the surface's credential comes from, or "" when
// it names none.
func (s *SurfaceConfig) CredentialFrom() string {
	if s == nil || s.Credential == nil {
		return ""
	}
	return s.Credential.From
}

// FromSafeGrd says the remote server holds this surface's credential.
func (s *SurfaceConfig) FromSafeGrd() bool { return s.CredentialFrom() == CredentialFromSafeGrd }

// SurfaceConfig defines a protected surface on a host.
type SurfaceConfig struct {
	// implicit marks the surface SAFEGRD_DATABASE_URL made for this run,
	// which is not saved.
	implicit bool

	ID            string `yaml:"id" json:"id"`     // Stable identifier
	Type          string `yaml:"type" json:"type"` // "postgres", "mysql", "mongodb", "sqlite", "files", "email", "laravel"
	Name          string `yaml:"name,omitempty" json:"name,omitempty"`
	Schedule      string `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	RetentionDays int    `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	KeepDaily     int    `yaml:"keep_daily,omitempty" json:"keep_daily,omitempty"`
	KeepWeekly    int    `yaml:"keep_weekly,omitempty" json:"keep_weekly,omitempty"`
	KeepMonthly   int    `yaml:"keep_monthly,omitempty" json:"keep_monthly,omitempty"`
	// Blackout is the times of day, in UTC, inside which the daemon starts no
	// scheduled backup of this surface: ["22:00-02:00"]. A due backup waits
	// for the window to end; a backup asked for from the console does not.
	Blackout []string `yaml:"blackout,omitempty" json:"blackout,omitempty"`
	// Clock is the clock a schedule of fixed times ("at 02:00", a cron line)
	// and the blackout windows are read on: "utc" (the default) or "local",
	// this host's time zone.
	Clock string `yaml:"clock,omitempty" json:"clock,omitempty"`
	// SkipIfUnchanged writes no backup when an incremental run finds nothing
	// changed since the last one; the remote server is told the surface was
	// checked, so it is not Overdue. Own bucket and local storage only: on
	// hosted storage the server records a run before it writes.
	SkipIfUnchanged bool `yaml:"skip_if_unchanged,omitempty" json:"skip_if_unchanged,omitempty"`

	// PreBackup runs before each of the daemon's backups of this surface and
	// must succeed for the backup to happen; PostBackup runs after every
	// attempt, successful or not. Both are shell commands, run as the daemon.
	PreBackup  string `yaml:"pre_backup,omitempty" json:"pre_backup,omitempty"`
	PostBackup string `yaml:"post_backup,omitempty" json:"post_backup,omitempty"`
	// PreBackupOnError is what a failed pre_backup means: "skip" (the
	// default) takes no backup, "continue" takes it anyway and says the
	// hook failed, and "retry" runs the hook again, twice more with a
	// growing wait, before skipping.
	PreBackupOnError string `yaml:"pre_backup_on_error,omitempty" json:"pre_backup_on_error,omitempty"`
	// PostDrill runs after each of the daemon's Fire Drills of this surface,
	// told the outcome. Its failure is reported and changes nothing else.
	PostDrill string `yaml:"post_drill,omitempty" json:"post_drill,omitempty"`
	// PingURL is pinged around every backup of this surface (the daemon's,
	// backup --surface and guard), as Healthchecks.io and Cronitor take
	// them: URL/start before, URL after a backup, URL/fail after a failed
	// one, with one line of what happened as the body. env:VAR or
	// file:/path read it from elsewhere.
	PingURL string `yaml:"ping_url,omitempty" json:"ping_url,omitempty"`

	// Postgres fields
	DatabaseURL string `yaml:"database_url,omitempty" json:"database_url,omitempty"`

	// Files fields
	Roots    []string `yaml:"roots,omitempty" json:"roots,omitempty"`
	Excludes []string `yaml:"excludes,omitempty" json:"excludes,omitempty"`
	// Format is how a files, PostgreSQL or SQLite surface is stored: "tar",
	// one archive per backup, or "repo", an incremental repository where
	// each run uploads only what changed. Unset is repo for files and a
	// PostgreSQL or SQLite database, and tar for MySQL and MongoDB.
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	// ChangeLog lets a PostgreSQL repo surface skip reading tables nothing
	// wrote since its last run. It installs a trigger on each table and a
	// safegrd schema in the database, which `DROP SCHEMA safegrd CASCADE`
	// removes.
	ChangeLog bool `yaml:"change_log,omitempty" json:"change_log,omitempty"`
	// Watch makes a PostgreSQL surface check the backups another tool writes
	// (Coolify's, a cron pg_dump) where that tool puts them, instead of
	// backing up a database: the newest one is read and counted on the
	// surface's schedule, which is how often the other tool is expected to
	// write, and its drills load it into a sandbox.
	Watch *WatchConfig `yaml:"watch,omitempty" json:"watch,omitempty"`

	// Erasures names the tables, as schema.table, whose deleted rows are
	// erasures: a trigger records each one's primary key, the daemon moves
	// the record into sealed objects beside the backups, and a restore of an
	// older backup deletes those rows again before it commits. PostgreSQL,
	// with local storage or the customer's own bucket.
	Erasures []string `yaml:"erasures,omitempty" json:"erasures,omitempty"`
	// RolesWithoutPasswords leaves role passwords out of a PostgreSQL
	// surface's backups. By default the roles the schema names travel with
	// their password hashes, sealed like everything else, so a restored role
	// logs in as it did.
	RolesWithoutPasswords bool `yaml:"roles_without_passwords,omitempty" json:"roles_without_passwords,omitempty"`
	// RecoveryDocSealed seals the recovery document written beside each
	// snapshot with the surface's recipient. By default it is plain text,
	// so it can be read after SafeGrd is gone; it holds no secret.
	RecoveryDocSealed bool `yaml:"recovery_doc_sealed,omitempty" json:"recovery_doc_sealed,omitempty"`
	// Compression is how hard the surface's backups are compressed:
	// "zstd:1" (fastest) to "zstd:19" (smallest). Empty keeps the default.
	// The format is the same at every level, so a restore needs no setting.
	Compression string `yaml:"compression,omitempty" json:"compression,omitempty"`
	// Parallel is how many connections a restore and a sandbox drill of
	// the surface's incremental PostgreSQL runs load tables over at once,
	// capped by the server's free connections. Zero means 4; 1 loads them
	// in one transaction.
	Parallel int `yaml:"parallel,omitempty" json:"parallel,omitempty"`
	// OneFilesystem keeps a repo surface's walk on each root's filesystem.
	// Unset means yes when a root is "/", no otherwise.
	OneFilesystem *bool `yaml:"one_filesystem,omitempty" json:"one_filesystem,omitempty"`
	// ObjectStore makes a files surface read a bucket over the S3 API
	// (Supabase Storage, or any S3-compatible store) instead of paths on
	// this host. The root is then s3://bucket or s3://bucket/prefix, and the
	// format is tar. The keys reach every bucket the store has, so they are
	// given as env:VAR or file:/path like a database password.
	ObjectStore *ObjectStoreSourceConfig `yaml:"object_store,omitempty" json:"object_store,omitempty"`

	// MigrationsTable is the table a Laravel app records its migrations in,
	// when config/database.php names another than "migrations".
	MigrationsTable string `yaml:"migrations_table,omitempty" json:"migrations_table,omitempty"`

	// Email fields
	Host     string   `yaml:"host,omitempty" json:"host,omitempty"`
	Port     int      `yaml:"port,omitempty" json:"port,omitempty"`
	Username string   `yaml:"username,omitempty" json:"username,omitempty"`
	Folders  []string `yaml:"folders,omitempty" json:"folders,omitempty"`
	// CAFile is a PEM bundle the server's certificate is checked against: a
	// mailbox's on top of the system roots, a database's in place of them
	// (sslrootcert, ssl-ca or tlsCAFile in its URL, with verification on),
	// for a database its provider signs with a CA of its own (Aiven, RDS).
	CAFile string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`

	// Credential is where this surface's credential comes from: a
	// database's whole connection URL, or a mailbox's password. One block,
	// so there is one place to look and one origin.
	Credential *CredentialConfig `yaml:"credential,omitempty" json:"credential,omitempty"`
	// HeldSecret is that credential once fetched. Memory only: the tags keep
	// it out of the file, so withdrawing it on the server withdraws it here.
	HeldSecret string `yaml:"-" json:"-"`

	// Storage & Encryption overrides
	Storage *StorageConfig `yaml:"storage,omitempty" json:"storage,omitempty"`
	// Copies names which of the config's copies this surface writes to.
	// Absent means all of them; an empty list means none.
	Copies     *[]string         `yaml:"copies,omitempty" json:"copies,omitempty"`
	Encryption *EncryptionConfig `yaml:"encryption,omitempty" json:"encryption,omitempty"`

	// Drill configures how the daemon proves this surface restores.
	Drill *DrillConfig `yaml:"drill,omitempty" json:"drill,omitempty"`

	// WAL archives a PostgreSQL surface's write-ahead log, so it restores
	// to any moment inside the window and not only to its last backup.
	WAL *WALConfig `yaml:"wal,omitempty" json:"wal,omitempty"`
}

// WALConfig is a PostgreSQL surface's WAL archive. PostgreSQL pushes each WAL
// file with archive_command = 'safegrd wal push --surface <id> %p'; the
// daemon takes the base backups and bundles the WAL into locked objects.
type WALConfig struct {
	// WindowDays is how far back a restore can reach. Zero means 7.
	WindowDays int `yaml:"window_days,omitempty" json:"window_days,omitempty"`
	// BaseEveryDays is how often the daemon takes a base backup. A restore
	// replays every WAL file since its base, so a busy database wants them
	// more often. Zero means 7.
	BaseEveryDays int `yaml:"base_every_days,omitempty" json:"base_every_days,omitempty"`
	// BundleMB bundles the unlocked WAL as soon as it passes this size, as
	// well as once a day. Zero means 1024.
	BundleMB int `yaml:"bundle_mb,omitempty" json:"bundle_mb,omitempty"`
	// DrillEveryDays is how often the daemon restores the archive into a
	// throwaway cluster to prove it: to a restore point, and to the end.
	// Zero means 7.
	DrillEveryDays int `yaml:"drill_every_days,omitempty" json:"drill_every_days,omitempty"`
	// IntervalSeconds is how often the daemon copies a SQLite database's
	// newly committed WAL frames. Zero means 1.
	IntervalSeconds int `yaml:"interval_seconds,omitempty" json:"interval_seconds,omitempty"`
	// CheckpointMB is the size a SQLite database's WAL reaches before the
	// daemon checkpoints it. Zero means 4.
	CheckpointMB int `yaml:"checkpoint_mb,omitempty" json:"checkpoint_mb,omitempty"`
	// Spool has wal push return once a WAL file is copied into the spool
	// and synced to disk; the daemon uploads the spool Parallel files at a
	// time. Off: wal push uploads each file before it returns.
	Spool bool `yaml:"spool,omitempty" json:"spool,omitempty"`
	// SpoolDir is where the spool is. Empty means wal-spool under the state
	// directory. The user PostgreSQL runs as writes it, and the daemon's
	// user reads and empties it.
	SpoolDir string `yaml:"spool_dir,omitempty" json:"spool_dir,omitempty"`
	// Parallel is how many spooled WAL files the daemon uploads at once,
	// and how many a restore fetches ahead of PostgreSQL. Zero means 4.
	Parallel int `yaml:"parallel,omitempty" json:"parallel,omitempty"`
	// QueueMax bounds the WAL waiting to leave the host, as "8GB". Past it
	// wal push reports the oldest WAL archived without storing it, and says
	// so, because a full pg_wal stops the database. Empty: no bound.
	QueueMax string `yaml:"queue_max,omitempty" json:"queue_max,omitempty"`
}

// ObjectStoreSourceConfig is where a files surface's bucket is and how to
// sign requests to it. Endpoint is the store's S3 URL (for Supabase Storage,
// https://PROJECT.storage.supabase.co/storage/v1/s3); empty means AWS S3.
// Region is what the store shows for the bucket.
// WatchConfig is where another tool puts its backups: a prefix in a bucket
// (s3://bucket/prefix, with the endpoint and keys for one not on AWS) or a
// directory on this host. Match, when set, is a glob a backup's file name
// must match, for a location that holds other files too.
type WatchConfig struct {
	URL       string `yaml:"url" json:"url"`
	Endpoint  string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Region    string `yaml:"region,omitempty" json:"region,omitempty"`
	AccessKey string `yaml:"access_key,omitempty" json:"access_key,omitempty"`
	SecretKey string `yaml:"secret_key,omitempty" json:"secret_key,omitempty"`
	Match     string `yaml:"match,omitempty" json:"match,omitempty"`
}

type ObjectStoreSourceConfig struct {
	Endpoint        string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Region          string `yaml:"region,omitempty" json:"region,omitempty"`
	AccessKeyID     string `yaml:"access_key_id,omitempty" json:"access_key_id,omitempty"`
	SecretAccessKey string `yaml:"secret_access_key,omitempty" json:"secret_access_key,omitempty"`
}

// DrillConfig gives a Postgres surface a scratch database for its Fire Drills.
// With one, an unattended drill restores the snapshot into it for real and
// counts what came back; without one it replays the snapshot in memory. The
// database must hold nothing: a drill refuses a sandbox with tables in it, and
// empties it again afterwards.
type DrillConfig struct {
	SandboxURL string `yaml:"sandbox_url,omitempty" json:"sandbox_url,omitempty"`
	// KeepFailedSandbox leaves the sandbox of a drill that failed as the
	// drill left it, for a day, and says where it is: the database at
	// sandbox_url, or the throwaway local cluster when there is none.
	KeepFailedSandbox bool `yaml:"keep_failed_sandbox,omitempty" json:"keep_failed_sandbox,omitempty"`
	// Checks are the customer's own queries and commands, run against the
	// sandbox after the restore. A drill that restores in memory has no
	// database to run them in, and says so.
	Checks []model.DrillCheck `yaml:"checks,omitempty" json:"checks,omitempty"`
	// Source is which bucket a drill reads: "primary" (the default) or
	// "rotate", the next of the surface's buckets each drill, so every copy
	// is restored in turn.
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
}

// Drill sources.
const (
	DrillSourcePrimary = "primary"
	DrillSourceRotate  = "rotate"
)

// RemoteServerConfig is the file's server: block, the remote server this
// host reports to.
type RemoteServerConfig struct {
	URL   string `yaml:"url,omitempty" json:"url,omitempty"`
	Token string `yaml:"token,omitempty" json:"token,omitempty"`
}

// NodeIdentity is the file's node: block, who this host is to the remote
// server.
type NodeIdentity struct {
	ID      string `yaml:"id,omitempty" json:"id,omitempty"`
	Name    string `yaml:"name,omitempty" json:"name,omitempty"`
	Project string `yaml:"project,omitempty" json:"project,omitempty"`
}

// CLIConfig is the complete configuration for the `safegrd` CLI.
//
// The file groups the host's identity and its remote server in node: and
// server: blocks. The code reads them as the flat fields below, which
// LoadCLIConfig fills from the blocks (and the environment) and
// SaveCLIConfig writes back into them; the flat fields are never keys.
type CLIConfig struct {
	Server RemoteServerConfig `yaml:"server,omitempty" json:"-"`
	Node   NodeIdentity       `yaml:"node,omitempty" json:"-"`

	NodeID      string `yaml:"-" json:"node_id"`
	NodeName    string `yaml:"-" json:"node_name"`
	ProjectID   string `yaml:"-" json:"project_id,omitempty"`
	ServerURL   string `yaml:"-" json:"server_url"`
	ServerToken string `yaml:"-" json:"server_token,omitempty"`
	// DatabaseURL is a database to back up named outside the file: by
	// --database-url or SAFEGRD_DATABASE_URL. A database in the file is a
	// surface.
	DatabaseURL string `yaml:"-" json:"database_url"`

	Storage StorageConfig `yaml:"storage" json:"storage"`
	// Copies are up to two more S3 buckets every backup is written to,
	// each under its own key, lock and retention. A surface may name a
	// subset (SurfaceConfig.Copies).
	Copies     []CopyConfig     `yaml:"copies,omitempty" json:"copies,omitempty"`
	Encryption EncryptionConfig `yaml:"encryption" json:"encryption"`

	// Daemon & Multi-Surface Unattended Protection
	Daemon   DaemonConfig    `yaml:"daemon,omitempty" json:"daemon,omitempty"`
	Defaults DefaultsConfig  `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Surfaces []SurfaceConfig `yaml:"surfaces,omitempty" json:"surfaces,omitempty"`

	// UnknownKeys are the keys in the file that are not settings, as
	// "line 12: storage.retention_day". YAML ignores them, so a typo used to
	// fall back to a default without a word; the commands say them instead.
	UnknownKeys []string `yaml:"-" json:"-"`
}

var unknownFieldRe = regexp.MustCompile(`line (\d+): field (\S+) not found in type config\.(\w+)`)

// sectionOfType names the block a type decodes. YAML reports only the type,
// so a key inside a surface's own storage block is named "storage." too; the
// line number says which.
var sectionOfType = map[string]string{
	"CLIConfig": "", "RemoteServerConfig": "server.", "NodeIdentity": "node.", "StorageConfig": "storage.", "EncryptionConfig": "encryption.",
	"DaemonConfig": "daemon.", "DefaultsConfig": "defaults.", "SurfaceConfig": "surfaces[].", "DrillConfig": "surfaces[].drill.", "WALConfig": "surfaces[].wal.", "CopyConfig": "copies[].",
}

// unknownKeys decodes the file again, strictly, and names every key the
// lenient decode skipped.
func unknownKeys(data []byte) []string {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var probe CLIConfig
	err := dec.Decode(&probe)
	te, ok := err.(*yaml.TypeError)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range te.Errors {
		m := unknownFieldRe.FindStringSubmatch(e)
		if m == nil || m[2] == "private_key" { // private_key is migrated out below
			continue
		}
		out = append(out, "line "+m[1]+": "+sectionOfType[m[3]]+m[2])
	}
	return out
}

// replacedCredentialKeys refuses a config that names a surface's credential
// the way it used to be named. Ignored like any other unknown key, such a
// surface would have no credential, and a database surface would then back up
// whatever the host's own database_url points at.
func replacedCredentialKeys(unknown []string) error {
	replaced := map[string]string{
		"credential_held":    "credential: {from: safegrd}",
		"database_url_env":   "credential: {from: env, name: VARIABLE}",
		"password_env":       "credential: {from: env, name: VARIABLE}",
		"credential_command": "credential: {from: command, run: \"...\"}",
	}
	for _, k := range unknown {
		for old, now := range replaced {
			if strings.HasSuffix(k, "surfaces[]."+old) {
				return fmt.Errorf("%s: %s is no longer read; a surface says where its credential comes from with %s. "+
					"See safegrd.dev/docs/config", k, old, now)
			}
		}
	}
	// Keys removed because another one says the same thing. Dropped
	// quietly, a drill would fall back to memory and a backup would be
	// locked for another number of days.
	retired := map[string]string{
		"node_id":                          "node: {id: ...}",
		"node_name":                        "node: {name: ...}",
		"project_id":                       "node: {project: ...}",
		"server_url":                       "server: {url: ...}",
		"server_token":                     "server: {token: ...}",
		"database_url":                     "a surface (surfaces: [{id: db, type: postgres, database_url: ...}]), or SAFEGRD_DATABASE_URL for one run",
		"surfaces[].drill.sandbox_url_env": "drill.sandbox_url: env:VARIABLE",
		"defaults.retention_days":          "storage.retention_days, or a surface's retention_days",
	}
	for _, k := range unknown {
		for old, now := range retired {
			if strings.HasSuffix(k, ": "+old) {
				return fmt.Errorf("%s is no longer read; use %s. See safegrd.dev/docs/config", k, now)
			}
		}
	}
	return nil
}

// DefaultConfigDir returns ~/.safegrd.
func DefaultConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".safegrd"), nil
}

// DefaultConfigFile returns ~/.safegrd/config.yaml.
func DefaultConfigFile() (string, error) {
	dir, err := DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// readPrivateKeyFile reads the Age identity at path.
//
// It is held to the same rule as config.yaml: readable by its owner only. The
// key decrypts every backup this host has taken, so a copy left at 0644 is a
// copy every local user can read. init writes it 0600; one made or copied by
// hand may not be, and nothing said so.
//
// A key file that does not exist is not an error: a host that only backs up
// needs the public key alone, and keeping the private key off it is good
// practice. Restore and verify say so when they need it. Nor is a path this
// process cannot reach: a config written on a laptop and copied to a CI
// runner names the laptop's path, and on GitHub's runners /root is not
// readable, so the backup failed over a key it never needed. That
// one is said on stderr, since the key may be meant to be there.
func readPrivateKeyFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if errors.Is(err, fs.ErrPermission) {
		fmt.Fprintf(os.Stderr, "Warning: cannot reach the private key file %s (permission denied); continuing without it. A backup needs only the public key.\n", path)
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("could not read the private key file %s: %w", path, err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("insecure private key file permissions (%04o): %s must be readable only by its owner. Run: chmod 600 %s", fi.Mode().Perm(), path, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("could not read the private key file %s: %w", path, err)
	}
	return crypto.IdentityInFile(data), nil
}

// DefaultServerURL points to the production SafeGrd remote server.
const DefaultServerURL = "https://safegrd.dev"

// NewDefaultCLIConfig creates a sensible default configuration.
func NewDefaultCLIConfig() *CLIConfig {
	return &CLIConfig{
		ServerURL: DefaultServerURL,
		Storage: StorageConfig{
			Type:          StorageTypeLocal,
			LocalPath:     "./safegrd-storage",
			Prefix:        "safegrd/snapshots",
			RetentionDays: 14,
			WORMMode:      WORMModeCompliance,
		},
	}
}

// LoadCLIConfig loads configuration from a path with environment variable overrides.
func LoadCLIConfig(path string) (*CLIConfig, error) {
	cfg := NewDefaultCLIConfig()

	if path == "" {
		defPath, err := DefaultConfigFile()
		if err == nil {
			path = defPath
		}
	}

	if fi, err := os.Stat(path); err == nil {
		// Enforce secure permissions on POSIX:
		// Refuse to load if group- or world-readable (0077 mask).
		if runtime.GOOS != "windows" && (fi.Mode().Perm()&0077 != 0) {
			return nil, fmt.Errorf("insecure config file permissions (%04o): %s must be readable only by its owner (0600)", fi.Mode().Perm(), path)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
		}
		cfg.UnknownKeys = unknownKeys(data)
		if cfg.Server.URL != "" {
			cfg.ServerURL = cfg.Server.URL
		}
		cfg.ServerToken = cfg.Server.Token
		cfg.NodeID, cfg.NodeName, cfg.ProjectID = cfg.Node.ID, cfg.Node.Name, cfg.Node.Project
		// A relative key_path is relative to this file, not to wherever the
		// command runs (SaveCLIConfig writes it that way).
		// ~/ is the home directory, as the example config writes it.
		if kp := cfg.Encryption.KeyPath; strings.HasPrefix(kp, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				cfg.Encryption.KeyPath = filepath.Join(home, kp[2:])
			}
		}
		if kp := cfg.Encryption.KeyPath; kp != "" && !filepath.IsAbs(kp) {
			cfg.Encryption.KeyPath = filepath.Join(filepath.Dir(absOrSelf(path)), kp)
		}
		if err := replacedCredentialKeys(cfg.UnknownKeys); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}

		// Security migration:
		// Check for legacy inline private_key in config.yaml.
		// Move it to key_path with 0600 permissions, strip from config.yaml, and warn operator.
		var rawMap map[string]interface{}
		if err := yaml.Unmarshal(data, &rawMap); err == nil {
			if enc, ok := rawMap["encryption"].(map[string]interface{}); ok {
				if inlineKey, hasKey := enc["private_key"].(string); hasKey && strings.TrimSpace(inlineKey) != "" {
					inlineKey = strings.TrimSpace(inlineKey)
					keyPath := cfg.Encryption.KeyPath
					if keyPath == "" {
						keyPath = filepath.Join(filepath.Dir(path), "keys", "daemon.key")
						cfg.Encryption.KeyPath = keyPath
					}
					// The config is rewritten without the key only once keyPath is
					// on disk holding this same key. Stripping it after a failed
					// or mismatched write left the identity nowhere, and every
					// backup it sealed undecryptable.
					if err := persistMigratedKey(keyPath, inlineKey); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: %s holds an inline private_key that could not be moved to %s: %v\n   The config is unchanged. Fix the key file, or set encryption.key_path to a free path.\n", path, keyPath, err)
					} else {
						delete(enc, "private_key")
						enc["key_path"] = keyPath
						strippedData, mErr := yaml.Marshal(rawMap)
						if mErr == nil {
							mErr = writeFileAtomic(path, strippedData, 0600)
						}
						if mErr != nil {
							fmt.Fprintf(os.Stderr, "Warning: moved the inline private_key in %s to %s, but could not rewrite the config without it: %v\n", path, keyPath, mErr)
						} else {
							fmt.Fprintf(os.Stderr, "Warning: moved the inline private_key in %s to %s (0600). It was stored in plain text, so consider rotating it.\n", path, keyPath)
						}
					}
					cfg.Encryption.PrivateKey = inlineKey
				}
			}
		}
	}

	// Resolve PrivateKey from KeyPath if not already populated. Skipped when
	// SAFEGRD_PRIVATE_KEY is set, which replaces it below anyway.
	if cfg.Encryption.PrivateKey == "" && cfg.Encryption.KeyPath != "" && os.Getenv("SAFEGRD_PRIVATE_KEY") == "" {
		key, err := readPrivateKeyFile(cfg.Encryption.KeyPath)
		if err != nil {
			return nil, err
		}
		cfg.Encryption.PrivateKey = key
	}

	// Environment variable overrides
	// SAFEGRD_DATABASE_URL names a database for a run when the file lists
	// no surfaces. With surfaces it would back up something the file does
	// not name, so it is said and left out.
	if dbURL := os.Getenv("SAFEGRD_DATABASE_URL"); dbURL != "" {
		if len(cfg.Surfaces) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: SAFEGRD_DATABASE_URL is ignored: this config lists surfaces. Name a database with --database-url for a one-off backup.\n")
		} else {
			cfg.DatabaseURL = dbURL
		}
	}
	if srvURL := os.Getenv("SAFEGRD_SERVER_URL"); srvURL != "" {
		cfg.ServerURL = srvURL
	}
	if token := os.Getenv("SAFEGRD_SERVER_TOKEN"); token != "" {
		cfg.ServerToken = token
	}
	if pubKey := os.Getenv("SAFEGRD_PUBLIC_KEY"); pubKey != "" {
		cfg.Encryption.PublicKey = pubKey
	}
	if privKey := os.Getenv("SAFEGRD_PRIVATE_KEY"); privKey != "" {
		cfg.Encryption.PrivateKey = privKey
	}
	if bucket := os.Getenv("SAFEGRD_STORAGE_BUCKET"); bucket != "" {
		cfg.Storage.Bucket = bucket
		cfg.Storage.Type = StorageTypeS3
	}
	if region := os.Getenv("SAFEGRD_S3_REGION"); region != "" {
		cfg.Storage.Region = region
	} else if region := os.Getenv("AWS_REGION"); region != "" {
		cfg.Storage.Region = region
	}
	if ep := os.Getenv("SAFEGRD_S3_ENDPOINT"); ep != "" {
		cfg.Storage.Endpoint = ep
	}
	if keyID := os.Getenv("SAFEGRD_S3_ACCESS_KEY"); keyID != "" {
		cfg.Storage.AccessKeyID = keyID
	} else if keyID := os.Getenv("AWS_ACCESS_KEY_ID"); keyID != "" {
		cfg.Storage.AccessKeyID = keyID
	}
	if secKey := os.Getenv("SAFEGRD_S3_SECRET_KEY"); secKey != "" {
		cfg.Storage.SecretAccessKey = secKey
	} else if secKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); secKey != "" {
		cfg.Storage.SecretAccessKey = secKey
	}

	// A database named by SAFEGRD_DATABASE_URL, with no surfaces in the
	// file, is a surface of its own for this run: the Docker image and the
	// Helm chart back up one database that way. It is never written to the
	// file. A node id alone is not a surface: a host enrolled to restore, or
	// not yet given one, has nothing to back up.
	if len(cfg.Surfaces) == 0 && cfg.DatabaseURL != "" {
		sID := cfg.NodeID
		if sID == "" {
			sID = "default-postgres"
		}
		sName := cfg.NodeName
		if sName == "" {
			sName = "Production PostgreSQL"
		}
		ret := cfg.Storage.RetentionDays
		cfg.Surfaces = []SurfaceConfig{
			{
				ID:            sID,
				Type:          topLevelDatabaseType(cfg.DatabaseURL),
				Name:          sName,
				Schedule:      cfg.Defaults.Schedule,
				RetentionDays: ret,
				DatabaseURL:   cfg.DatabaseURL,
				implicit:      true,
			},
		}
	}

	return cfg, nil
}

// SaveCLIConfig writes the config to disk with restricted permissions (0600).
func SaveCLIConfig(cfg *CLIConfig, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config dir %s: %w", dir, err)
	}

	// A key kept beside the config is written relative to it, so the file
	// names no laptop path when it is copied elsewhere: into a CI secret, the
	// config lands in a temporary folder with no key beside it, which reads as
	// a host without the private key.
	out := *cfg
	if rel, ok := keyPathBeside(cfg.Encryption.KeyPath, path); ok {
		out.Encryption.KeyPath = rel
	}
	out.Server = RemoteServerConfig{URL: cfg.ServerURL, Token: cfg.ServerToken}
	out.Node = NodeIdentity{ID: cfg.NodeID, Name: cfg.NodeName, Project: cfg.ProjectID}
	out.Surfaces = nil
	for _, sc := range cfg.Surfaces {
		if !sc.implicit {
			out.Surfaces = append(out.Surfaces, sc)
		}
	}
	data, err := yaml.Marshal(&out)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}

	return nil
}

// keyPathBeside returns keyPath relative to the folder holding configPath,
// when the key is inside that folder.
func keyPathBeside(keyPath, configPath string) (string, bool) {
	if keyPath == "" {
		return "", false
	}
	rel, err := filepath.Rel(filepath.Dir(absOrSelf(configPath)), absOrSelf(keyPath))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

func absOrSelf(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// ResolveWORMMode returns the Object Lock mode this storage configuration asks
// for, and refuses anything it does not recognise.
//
// Empty means compliance. That is the documented default and it is the strict
// one, so defaulting cannot weaken anybody's retention.
//
// Every other value must match a constant exactly, including its case. This is
// deliberately not a normalising comparison and deliberately not an `else`,
// because retention is the one bug class that cannot be undone: under
// compliance mode an object cannot be deleted before it expires, by anyone,
// including us. The two silent outcomes are both wrong. Picking compliance for
// an unrecognised value hands an operator fourteen days of undeletable objects
// they did not ask for; picking none leaves backups with no lock at all while
// Exact casing (COMPLIANCE, GOVERNANCE, NONE) is required to ensure retention
// intent is explicit.
func (c *StorageConfig) ResolveWORMMode() (WORMMode, error) {
	switch c.WORMMode {
	case "":
		return WORMModeCompliance, nil
	case WORMModeCompliance, WORMModeGovernance, WORMModeNone:
		return c.WORMMode, nil
	default:
		return "", fmt.Errorf(
			"storage.worm_mode %q is not recognised: use %q, %q or %q (exact case), or leave it unset for %q. "+
				"It is not defaulted, because an unrecognised value has silently meant compliance-mode "+
				"Object Lock on the CLI side, and objects written under compliance mode cannot be deleted "+
				"before their retention expires, by anyone",
			string(c.WORMMode), string(WORMModeCompliance), string(WORMModeGovernance), string(WORMModeNone), string(WORMModeCompliance))
	}
}

// ResolveStorageClass is storage_class as S3 spells it, "" for STANDARD or
// unset, or an error naming the classes a drill can read back at once.
func (c *StorageConfig) ResolveStorageClass() (string, error) {
	switch v := strings.ToUpper(strings.TrimSpace(c.StorageClass)); v {
	case "", "STANDARD":
		return "", nil
	case "STANDARD_IA", "GLACIER_IR":
		return v, nil
	case "GLACIER", "DEEP_ARCHIVE", "GLACIER_FLEXIBLE_RETRIEVAL":
		return "", fmt.Errorf("storage.storage_class %s takes hours to read back, so a Fire Drill could not restore from it: use STANDARD, STANDARD_IA or GLACIER_IR", c.StorageClass)
	default:
		return "", fmt.Errorf("storage.storage_class %q is not recognised: use STANDARD, STANDARD_IA or GLACIER_IR", c.StorageClass)
	}
}

// Validate validates that essential fields are present.
func (c *CLIConfig) ValidateForBackup() error {
	if c.Storage.Layout != "" {
		return fmt.Errorf("storage.layout: %s only reads a bucket; back up with storage.type: hosted", c.Storage.Layout)
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("no database to back up: pass --database-url, set SAFEGRD_DATABASE_URL, or add the database to the config as a surface")
	}
	if c.Encryption.PublicKey == "" {
		return fmt.Errorf("encryption.public_key is required (run 'safegrd init' or set SAFEGRD_PUBLIC_KEY)")
	}
	if _, err := crypto.ParseRecipient(c.Encryption.PublicKey); err != nil {
		return fmt.Errorf("encryption.public_key: %w (expected age1..., as printed by 'safegrd init')", err)
	}
	if c.Storage.Type == StorageTypeS3 && c.Storage.Bucket == "" {
		return fmt.Errorf("storage.bucket is required for s3 storage")
	}
	if c.Storage.Type == StorageTypeLocal && c.Storage.LocalPath == "" {
		return fmt.Errorf("storage.local_path is required for local storage")
	}
	if _, err := c.Storage.ResolveWORMMode(); err != nil {
		return err
	}
	return nil
}

// ValidateForFileBackup validates that encryption and storage fields are present for file backups.
func (c *CLIConfig) ValidateForFileBackup() error {
	if c.Storage.Layout != "" {
		return fmt.Errorf("storage.layout: %s only reads a bucket; back up with storage.type: hosted", c.Storage.Layout)
	}
	if c.Encryption.PublicKey == "" {
		return fmt.Errorf("encryption.public_key is required (run 'safegrd init' or set SAFEGRD_PUBLIC_KEY)")
	}
	if _, err := crypto.ParseRecipient(c.Encryption.PublicKey); err != nil {
		return fmt.Errorf("encryption.public_key: %w (expected age1..., as printed by 'safegrd init')", err)
	}
	if c.Storage.Type == StorageTypeS3 && c.Storage.Bucket == "" {
		return fmt.Errorf("storage.bucket is required for s3 storage")
	}
	if c.Storage.Type == StorageTypeLocal && c.Storage.LocalPath == "" {
		return fmt.Errorf("storage.local_path is required for local storage")
	}
	if _, err := c.Storage.ResolveWORMMode(); err != nil {
		return err
	}
	return nil
}

// ValidateForEmailBackup validates that encryption and storage fields are present for email backups.
func (c *CLIConfig) ValidateForEmailBackup() error {
	return c.ValidateForFileBackup()
}

// topLevelDatabaseType is the surface type a top-level database_url stands for.
func topLevelDatabaseType(url string) string {
	if strings.HasPrefix(strings.ToLower(url), "sqlite:") {
		return "sqlite"
	}
	if strings.HasPrefix(url, "mongodb://") || strings.HasPrefix(url, "mongodb+srv://") {
		return "mongodb"
	}
	if strings.HasPrefix(url, "mysql://") || strings.HasPrefix(url, "mariadb://") {
		return "mysql"
	}
	return "postgres"
}

// persistMigratedKey makes keyPath hold key, durably. A file already there
// counts only if it holds the same key.
func persistMigratedKey(keyPath, key string) error {
	data, err := os.ReadFile(keyPath)
	switch {
	case err == nil:
		if crypto.IdentityInFile(data) != key {
			return fmt.Errorf("%s already holds a different key", keyPath)
		}
		return nil
	case !os.IsNotExist(err):
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, []byte(key+"\n"), 0600); err != nil {
		return err
	}
	data, err = os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	if crypto.IdentityInFile(data) != key {
		return fmt.Errorf("%s does not read back as the key written", keyPath)
	}
	return nil
}

// writeFileAtomic writes data to a temporary file beside path, syncs it and
// renames it over path, so path holds either the old bytes or the new ones.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // best effort: not every filesystem syncs a directory
		d.Close()
	}
	return nil
}

// CopyConfig is a bucket every backup is written to beside the surface's own:
// a full storage block with a name.
type CopyConfig struct {
	Name          string `yaml:"name" json:"name"`
	StorageConfig `yaml:",inline"`
}

// MaxCopies is how many buckets a surface writes to beside its own.
const MaxCopies = 2

var copyNameRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// ValidateCopies refuses a copies: list that cannot be written: more than
// two, a name used twice or not [a-z0-9-], a type other than s3, no bucket,
// a lock mode not stated, the primary's own bucket, or a surface naming a
// copy the list does not have.
func (c *CLIConfig) ValidateCopies() error {
	if len(c.Copies) > MaxCopies {
		return fmt.Errorf("copies: at most %d buckets beside storage; this config lists %d", MaxCopies, len(c.Copies))
	}
	seen := map[string]bool{}
	for i, cp := range c.Copies {
		where := fmt.Sprintf("copies[%d]", i)
		if !copyNameRe.MatchString(cp.Name) {
			return fmt.Errorf("%s.name %q: use 1 to 32 lowercase letters, digits and dashes", where, cp.Name)
		}
		where = "copies " + cp.Name
		if seen[cp.Name] {
			return fmt.Errorf("%s: the name is used twice", where)
		}
		seen[cp.Name] = true
		if cp.Type != StorageTypeS3 {
			return fmt.Errorf("%s: type must be s3; a copy is an S3-compatible bucket", where)
		}
		if cp.Bucket == "" {
			return fmt.Errorf("%s: bucket is required", where)
		}
		switch cp.WORMMode {
		case "COMPLIANCE", "GOVERNANCE", WORMModeNone:
		default:
			return fmt.Errorf("%s: set worm_mode to COMPLIANCE, GOVERNANCE or NONE; a copy does not take the primary's lock", where)
		}
		if cp.Layout != "" {
			return fmt.Errorf("%s: layout is for reading hosted storage, not for a copy", where)
		}
		if c.Storage.Type == StorageTypeS3 && cp.Bucket == c.Storage.Bucket &&
			strings.TrimRight(cp.Endpoint, "/") == strings.TrimRight(c.Storage.Endpoint, "/") &&
			strings.Trim(cp.Prefix, "/") == strings.Trim(c.Storage.Prefix, "/") {
			return fmt.Errorf("%s: it is the same bucket and prefix as storage", where)
		}
	}
	for _, s := range c.Surfaces {
		if s.Copies == nil {
			continue
		}
		for _, n := range *s.Copies {
			if !seen[n] {
				return fmt.Errorf("surface %s: copies names %q, which copies: does not list", s.ID, n)
			}
		}
		if s.Drill != nil && s.Drill.Source != "" && s.Drill.Source != DrillSourcePrimary && s.Drill.Source != DrillSourceRotate {
			return fmt.Errorf("surface %s: drill.source is primary or rotate", s.ID)
		}
	}
	return nil
}

// CopiesOf is the copies a surface writes to: all of them unless the surface
// names a subset.
func (c *CLIConfig) CopiesOf(s *SurfaceConfig) []CopyConfig {
	if s == nil || s.Copies == nil {
		return append([]CopyConfig(nil), c.Copies...)
	}
	want := map[string]bool{}
	for _, n := range *s.Copies {
		want[n] = true
	}
	var out []CopyConfig
	for _, cp := range c.Copies {
		if want[cp.Name] {
			out = append(out, cp)
		}
	}
	return out
}

// ParseCompression reads a compression setting: "" or "zstd" for the
// default (0), "zstd:N" for level N from 1 to 19.
func ParseCompression(s string) (int, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" || v == "zstd" {
		return 0, nil
	}
	lvl, ok := strings.CutPrefix(v, "zstd:")
	if ok {
		if n, err := strconv.Atoi(lvl); err == nil && n >= 1 && n <= 19 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("compression %q is not zstd:1 to zstd:19", s)
}
