package model

import (
	"time"
)

// OrgPlan defines subscription tiers.
type OrgPlan string

// The identifiers only. What each tier includes is decided by the remote
// server and published at GET /api/v1/plans; the CLI never decides a quota.
const (
	// OrgPlanFree is the floor, not a purchase. Every non-paying state resolves
	// here.
	OrgPlanFree    OrgPlan = "free"
	OrgPlanStarter OrgPlan = "starter"
	OrgPlanGrowth  OrgPlan = "growth"
	OrgPlanScale   OrgPlan = "scale"
)

// OrgRole specifies tenant-level permissions.
type OrgRole string

const (
	OrgRoleOwner  OrgRole = "owner"
	OrgRoleAdmin  OrgRole = "admin"
	OrgRoleMember OrgRole = "member"
	OrgRoleViewer OrgRole = "viewer"
)

// Organization represents a top-level tenant account.
type Organization struct {
	ID           string    `json:"id" yaml:"id"`
	Name         string    `json:"name" yaml:"name"`
	Slug         string    `json:"slug" yaml:"slug"`
	Plan         OrgPlan   `json:"plan" yaml:"plan"`
	MaxSurfaces  int       `json:"max_surfaces" yaml:"max_surfaces"`
	MaxDatabases int       `json:"max_databases" yaml:"max_databases"` // Deprecated backwards-compatibility alias for MaxSurfaces
	OwnerUserID  string    `json:"owner_user_id" yaml:"owner_user_id"`
	CreatedAt    time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" yaml:"updated_at"`
	// KeyCustody decides who can decrypt this organization's backups, and it
	// is the only field here a customer must never be confused about. Empty
	// means KeyCustodyCustomer.
	KeyCustody KeyCustodyMode `json:"key_custody" yaml:"key_custody,omitempty"`
}

// KeyCustodyMode names who holds the Age identity that opens an organization's
// snapshots.
type KeyCustodyMode string

const (
	// KeyCustodyCustomer is the default and the recommended path: the identity
	// is generated on the customer's host and never leaves it. SafeGrd holds
	// the recipient and cannot read a single backup.
	KeyCustodyCustomer KeyCustodyMode = "customer"

	// KeyCustodyManaged means SafeGrd generates and holds the identity,
	// envelope-encrypted, and releases it to the organization's enrolled nodes.
	// It exists because losing a key is the most common way a customer loses
	// their backups, and it costs the claim that a full compromise of SafeGrd
	// reveals nothing. Opt-in, per organization, never a default, and the
	// console must say which mode an org is in without being asked.
	KeyCustodyManaged KeyCustodyMode = "managed"
)

// OrgMember maps user membership and role inside an organization.
type OrgMember struct {
	OrgID     string    `json:"org_id" yaml:"org_id"`
	UserID    string    `json:"user_id" yaml:"user_id"`
	UserEmail string    `json:"user_email" yaml:"user_email"`
	UserName  string    `json:"user_name" yaml:"user_name"`
	Role      OrgRole   `json:"role" yaml:"role"`
	JoinedAt  time.Time `json:"joined_at" yaml:"joined_at"`
}

// S3SinkConfig defines customer-managed S3-compatible storage destination for a project.
type S3SinkConfig struct {
	Bucket      string `json:"bucket" yaml:"bucket"`
	Region      string `json:"region" yaml:"region"`
	Endpoint    string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"` // For MinIO, Cloudflare R2, Wasabi, etc.
	AccessKeyID string `json:"access_key_id" yaml:"access_key_id"`

	// SecretAccessKey is `-` on BOTH tags, and that is the whole defence.
	//
	// Wherever this struct is marshalled (a database column, a state file, the
	// backups of either), a plaintext secret on this field would travel with
	// it to every copy and every machine that ever fetched one. Masking it in
	// API responses would do nothing about any of that.
	//
	// The remote server keeps the value sealed separately and releases it only
	// to an enrolled node at run time. This field carries it in memory between
	// the request body and that sealing, and nowhere else.
	//
	// EncryptionConfig.PrivateKey uses the same trick for the same reason, and
	// has a test asserting the bytes on disk. So does this one.
	SecretAccessKey string `json:"-" yaml:"-"`

	// HasSecret lets the console show that a credential is configured without
	// shipping it. It is derived on read, never stored.
	HasSecret bool `json:"has_secret" yaml:"-"`
	// WORMMode and RetentionDays carry the project's Object Lock intent to the
	// node. They are not decoration: under Journey A the node has no local
	// storage config at all, so an empty StorageConfig reaches
	// ResolveWORMMode, whose zero value is COMPLIANCE. A node given nothing
	// locally would therefore write objects under compliance-mode Object Lock
	// — undeletable until expiry, billable, and the opposite of what anyone
	// asked for. Carrying the configured intent is
	// what makes the centrally-configured sink mean what the console shows.
	//
	// Empty WORMMode still resolves to COMPLIANCE, which is the safe default
	// for a customer who never chose. It is only wrong when someone did.
	WORMMode      string `json:"worm_mode,omitempty" yaml:"worm_mode,omitempty"`
	RetentionDays int    `json:"retention_days,omitempty" yaml:"retention_days,omitempty"`

	IAMRoleARN        string    `json:"iam_role_arn,omitempty" yaml:"iam_role_arn,omitempty"` // AWS STS assume-role
	Prefix            string    `json:"prefix,omitempty" yaml:"prefix,omitempty"`             // Optional path prefix e.g. "backups/"
	ForcePathStyle    bool      `json:"force_path_style,omitempty" yaml:"force_path_style,omitempty"`
	UseWORMObjectLock bool      `json:"use_worm_object_lock,omitempty" yaml:"use_worm_object_lock,omitempty"`
	UpdatedAt         time.Time `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// Project organizes database nodes into environments (e.g. Production, Staging).
type Project struct {
	ID          string        `json:"id" yaml:"id"`
	OrgID       string        `json:"org_id" yaml:"org_id"`
	Name        string        `json:"name" yaml:"name"`
	Slug        string        `json:"slug" yaml:"slug"`
	Description string        `json:"description,omitempty" yaml:"description,omitempty"`
	CreatedAt   time.Time     `json:"created_at" yaml:"created_at"`
	ArchivedAt  *time.Time    `json:"archived_at,omitempty" yaml:"archived_at,omitempty"`
	S3Sink      *S3SinkConfig `json:"s3_sink,omitempty" yaml:"s3_sink,omitempty"`
}

// IsArchived reports whether the project has been archived.
func (p *Project) IsArchived() bool {
	return p.ArchivedAt != nil
}

// Request and Response DTOs

type CreateOrgRequest struct {
	Name string  `json:"name"`
	Slug string  `json:"slug"`
	Plan OrgPlan `json:"plan"`
}

type AddMemberRequest struct {
	Email string  `json:"email"`
	Role  OrgRole `json:"role"`
}

type CreateProjectRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
}

type UpdateProjectRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type ArchiveProjectResponse struct {
	Project        *Project   `json:"project"`
	LastWORMExpiry *time.Time `json:"last_worm_expiry,omitempty"`
	Message        string     `json:"message"`
}

type UpdateProjectSinkRequest struct {
	Bucket            string `json:"bucket"`
	Region            string `json:"region"`
	Endpoint          string `json:"endpoint,omitempty"`
	AccessKeyID       string `json:"access_key_id"`
	SecretAccessKey   string `json:"secret_access_key,omitempty"`
	Prefix            string `json:"prefix,omitempty"`
	ForcePathStyle    bool   `json:"force_path_style,omitempty"`
	UseWORMObjectLock bool   `json:"use_worm_object_lock,omitempty"`
	// Empty WORMMode means COMPLIANCE, which is what ResolveWORMMode does with
	// a zero value. Anything other than COMPLIANCE or GOVERNANCE is refused at
	// the handler rather than stored, because an unrecognised mode that reaches
	// a node resolves to an error there — long after the operator who typed it
	// has gone.
	WORMMode      string `json:"worm_mode,omitempty"`
	RetentionDays int    `json:"retention_days,omitempty"`
}

type TestProjectSinkRequest struct {
	Bucket            string `json:"bucket"`
	Region            string `json:"region"`
	Endpoint          string `json:"endpoint,omitempty"`
	AccessKeyID       string `json:"access_key_id"`
	SecretAccessKey   string `json:"secret_access_key,omitempty"`
	ForcePathStyle    bool   `json:"force_path_style,omitempty"`
	UseWORMObjectLock bool   `json:"use_worm_object_lock,omitempty"`
}

type TestProjectSinkResponse struct {
	Success           bool   `json:"success"`
	Message           string `json:"message"`
	ObjectLockEnabled bool   `json:"object_lock_enabled"`
	Error             string `json:"error,omitempty"`
}

// TransferOwnershipRequest transfers ownership of an organization to another member.
type TransferOwnershipRequest struct {
	NewOwnerUserID string `json:"new_owner_user_id"`
}

// OrgSurfaceBreakdown details surfaces protected under an organization.
type OrgSurfaceBreakdown struct {
	Databases int `json:"databases"`
	FileTrees int `json:"file_trees"`
	Mailboxes int `json:"mailboxes"`
	Total     int `json:"total"`
}
