package model

import (
	"time"
)

// OrgPlan defines subscription tiers.
type OrgPlan string

const (
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
	ID           string         `json:"id" yaml:"id"`
	Name         string         `json:"name" yaml:"name"`
	Slug         string         `json:"slug" yaml:"slug"`
	Plan         OrgPlan        `json:"plan" yaml:"plan"`
	MaxSurfaces  int            `json:"max_surfaces" yaml:"max_surfaces"`
	MaxDatabases int            `json:"max_databases" yaml:"max_databases"` // Deprecated backwards-compatibility alias for MaxSurfaces
	OwnerUserID  string         `json:"owner_user_id" yaml:"owner_user_id"`
	CreatedAt    time.Time      `json:"created_at" yaml:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at" yaml:"updated_at"`
	KeyCustody   KeyCustodyMode `json:"key_custody" yaml:"key_custody,omitempty"`
}

// KeyCustodyMode names who holds the Age identity that opens an organization's
// snapshots.
type KeyCustodyMode string

const (
	// KeyCustodyCustomer means the identity is generated on the customer's host
	// and never leaves it. The remote server holds only the public recipient.
	KeyCustodyCustomer KeyCustodyMode = "customer"

	// KeyCustodyManaged means the remote server holds the identity,
	// envelope-encrypted, and releases it to the organization's enrolled nodes at runtime.
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

	// SecretAccessKey is `-` on both tags so it is never serialized to JSON/YAML.
	SecretAccessKey string `json:"-" yaml:"-"`

	HasSecret bool `json:"has_secret" yaml:"-"`

	// WORMMode and RetentionDays carry the project's Object Lock intent to the node.
	// When using central sink routing, the node has no local storage config,
	// so carrying the configured intent ensures the client uses the correct Object Lock mode.
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
