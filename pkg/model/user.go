package model

import (
	"time"
)

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
