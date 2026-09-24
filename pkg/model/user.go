package model

import (
	"time"
)

// UserRole specifies permission level.
type UserRole string

const (
	UserRoleAdmin  UserRole = "admin"
	UserRoleMember UserRole = "member"
)

// User represents a registered account on SafeGrd.
type User struct {
	ID           string    `json:"id" yaml:"id"`
	Email        string    `json:"email" yaml:"email"`
	PasswordHash string    `json:"-" yaml:"-"` // Never serialized in JSON
	Name         string    `json:"name" yaml:"name"`
	Role         UserRole  `json:"role" yaml:"role"`
	CreatedAt    time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" yaml:"updated_at"`
}

// APIKey represents a persistent Personal Access Token (PAT) for CLI and API integrations.
type APIKey struct {
	ID         string     `json:"id" yaml:"id"`
	UserID     string     `json:"user_id" yaml:"user_id"`
	OrgID      string     `json:"org_id,omitempty" yaml:"org_id,omitempty"`
	ProjectID  string     `json:"project_id,omitempty" yaml:"project_id,omitempty"`
	Name       string     `json:"name" yaml:"name"`
	KeyPrefix  string     `json:"key_prefix" yaml:"key_prefix"` // e.g. "sg_pat_ab12..." (for identification)
	KeyHash    string     `json:"-" yaml:"-"`                   // SHA-256 hash of the full token (never plaintext)
	CreatedAt  time.Time  `json:"created_at" yaml:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" yaml:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// CLISessionStatus tracks browser login authorization state.
type CLISessionStatus string

const (
	CLISessionStatusPending    CLISessionStatus = "pending"
	CLISessionStatusAuthorized CLISessionStatus = "authorized"
	CLISessionStatusExpired    CLISessionStatus = "expired"
)

// CLISession holds state for interactive browser login device flows.
type CLISession struct {
	SessionID string           `json:"session_id"`
	UserCode  string           `json:"user_code"` // e.g. "SG-9412"
	Status    CLISessionStatus `json:"status"`
	Token     string           `json:"token,omitempty"` // The PAT returned once authorized
	UserID    string           `json:"user_id,omitempty"`
	UserEmail string           `json:"user_email,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
	ExpiresAt time.Time        `json:"expires_at"`
}

// DTOs

type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"` // JWT Token
	User  *User  `json:"user"`
}

type CreateAPIKeyRequest struct {
	Name string `json:"name"`

	// OrgID and ProjectID narrow the token below its owner's own access.
	//
	// A Personal Access Token sits in a config file on a host. Its blast
	// radius should be that host's organization — and ideally that host's
	// project — not every organization its owner happens to belong to. Empty
	// means "the owner's access", which is the old behaviour and is still
	// what a single-organization user gets without asking.
	OrgID     string `json:"org_id,omitempty"`
	ProjectID string `json:"project_id,omitempty"`

	// ExpiresInDays overrides the default lifetime. A pointer so that "not
	// supplied" is distinguishable from a supplied zero, which is refused
	// rather than read as "never expires": a token that never expires is the
	// defect this field exists to close.
	ExpiresInDays *int `json:"expires_in_days,omitempty"`
}

// Personal Access Token lifetimes.
//
// Every token issued before this landed carries no expiry and stays valid —
// revoking a fleet's credentials as a side effect of adding a default would
// stop backups for people who did nothing. New ones always carry a date.
const (
	APIKeyDefaultLifetimeDays = 90
	APIKeyMaxLifetimeDays     = 365
)

type CreateAPIKeyResponse struct {
	Key     *APIKey `json:"key"`
	Token   string  `json:"token"` // Plaintext token returned ONLY once
	Message string  `json:"message"`
}
