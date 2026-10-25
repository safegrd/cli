package model

import "time"

// A trial is a first backup taken before an account exists: `safegrd try`
// asks the remote server for one, backs up under it, and `safegrd signup`
// gives it an owner. These are the wire shapes of those requests.

// TryRequest is the body of POST /api/v1/try. It is a register request with
// no organization or project, plus what tells trials from one machine apart.
type TryRequest struct {
	NodeID      string      `json:"node_id"`
	Name        string      `json:"name"`
	SurfaceType SurfaceType `json:"surface_type,omitempty"`
	// Hostname is the machine's own name. Machine is an HMAC of the operating
	// system's machine id keyed by the product name, or "" where the system
	// has none (a container). Neither is a secret, and neither is the id.
	Hostname   string `json:"hostname"`
	Machine    string `json:"machine,omitempty"`
	CLIVersion string `json:"cli_version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`

	// Key material, as NodeRegisterRequest carries it. ManagedIdentity is
	// present when SafeGrd holds the key; see that type for what a server
	// that cannot seal it must do.
	PublicKey       string `json:"public_key"`
	KeyFingerprint  string `json:"key_fingerprint"`
	ManagedIdentity string `json:"managed_identity,omitempty"`
}

// TryResponse is the answer to POST /api/v1/try: a node token for a node
// under an organization nobody owns yet, and the trial's terms.
type TryResponse struct {
	OrgID     string `json:"org_id"`
	ProjectID string `json:"project_id"`
	NodeID    string `json:"node_id"`
	Token     string `json:"token"`
	// KeyEscrowed confirms the server sealed and stored the identity it was
	// sent; false after sending one is an error the CLI reports.
	KeyEscrowed bool `json:"key_escrowed"`
	// StorageKind is "hosted": a trial backs up to the remote server's storage.
	StorageKind string `json:"storage_kind"`
	// TrialUntil is when the backup is deleted unless the trial is signed up.
	TrialUntil time.Time `json:"trial_until"`
	// MaxBytes is the most one trial may upload; Hours how long it is kept.
	MaxBytes int64 `json:"max_bytes"`
	Hours    int   `json:"hours"`
	// ConsoleURL is where the owner will see the backup once signed up.
	ConsoleURL string `json:"console_url,omitempty"`
}

// TrySignupSession is the answer to POST /api/v1/try/signup/session: the
// browser flow a trial's owner-to-be finishes. DeviceCode never leaves the
// CLI; UserCode is shown in both places for the person to compare.
type TrySignupSession struct {
	SessionID  string    `json:"session_id"`
	DeviceCode string    `json:"device_code"`
	UserCode   string    `json:"user_code"`
	SignupURL  string    `json:"signup_url"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// TrySignupPoll is the answer to POST /api/v1/try/signup/poll.
type TrySignupPoll struct {
	// Status is "pending", "claimed" or "expired".
	Status  string `json:"status"`
	OrgID   string `json:"org_id,omitempty"`
	OrgName string `json:"org_name,omitempty"`
	// Verified says whether the owner's address is verified; until it is, the
	// trial's limits stay and the backup is kept until TrialUntil.
	Verified   bool      `json:"verified"`
	TrialUntil time.Time `json:"trial_until,omitempty"`
	ConsoleURL string    `json:"console_url,omitempty"`
}

// TryStatus is what GET /api/v1/try/status answers a trial's node token:
// where the trial stands, for `safegrd status`.
type TryStatus struct {
	// State is "unclaimed", "claimed" (signed up, address not yet verified)
	// or "owned" (no trial limits left).
	State      string    `json:"state"`
	TrialUntil time.Time `json:"trial_until,omitempty"`
	OrgName    string    `json:"org_name,omitempty"`
	Verified   bool      `json:"verified"`
	ConsoleURL string    `json:"console_url,omitempty"`
}
