package model

import "time"

// How a host's safegrd binary was installed, as its daemon reports it. Only
// InstalledByInstaller updates itself: install.sh's versions directory, with a
// current link the daemon can move.
const (
	InstalledByInstaller = "installer"
	InstalledByHomebrew  = "homebrew"
	InstalledByContainer = "container"
	InstalledByOther     = "other"
)

// Daemon update modes (daemon.updates in the config).
const (
	// UpdatesConsole fetches each new release ahead of time and installs it
	// when someone approves it on the remote server. The default.
	UpdatesConsole = "console"
	// UpdatesOff fetches and installs nothing.
	UpdatesOff = "off"
)

// What an UpdateRequest asks of a host.
const (
	UpdateActionInstall = "install"
	UpdateActionRevert  = "revert"
)

// How the release a host runs last changed.
const (
	UpdateChangeInstalled = "installed"
	UpdateChangeReverted  = "reverted"
	// UpdateChangeRolledBack: the new release did not check in, so the host
	// went back on its own.
	UpdateChangeRolledBack = "rolled_back"
)

// UpdateStatus is what a resident daemon says about updating its own binary,
// on every heartbeat. The remote server keeps it on the host's node.
type UpdateStatus struct {
	// Running is the release the daemon runs.
	Running     string `json:"running"`
	Mode        string `json:"mode"`
	InstalledBy string `json:"installed_by"`
	// Blocked is why a host laid out for updates cannot apply one now, in the
	// host's words, with what to run.
	Blocked string `json:"blocked,omitempty"`
	// Previous is the release this host can go back to, the one it ran before
	// the last update. Empty when it has none. NoRevert is set when the
	// release it runs changed the daemon's state in a way Previous cannot read.
	Previous string `json:"previous,omitempty"`
	NoRevert bool   `json:"no_revert,omitempty"`
	// Staged is a release downloaded and checked, ready to install.
	Staged string `json:"staged,omitempty"`
	// FetchError is why the newest release could not be downloaded or did not
	// pass its checks; FetchVersion is that release.
	FetchError   string `json:"fetch_error,omitempty"`
	FetchVersion string `json:"fetch_version,omitempty"`
	// Failed is a release this host installed and left because it did not
	// check in, with why. The host does not install it again until a new
	// request names it.
	Failed       string `json:"failed,omitempty"`
	FailedReason string `json:"failed_reason,omitempty"`
	// The last change of release on this host.
	Change     string     `json:"change,omitempty"`
	ChangeFrom string     `json:"change_from,omitempty"`
	ChangeTo   string     `json:"change_to,omitempty"`
	ChangeAt   *time.Time `json:"change_at,omitempty"`
	// Handled is the id of the last UpdateRequest this host acted on, whether
	// it succeeded or was refused; Refused is the host's words when refused.
	Handled string `json:"handled,omitempty"`
	Refused string `json:"refused,omitempty"`
}

// UpdateRequest is a person's request, made on the remote server, that a host
// install a named release or go back to the one it ran before. It names a
// release and never carries one: the host downloads and checks it itself.
type UpdateRequest struct {
	// ID is unique per request; the host acts on each id once.
	ID      string `json:"id"`
	Action  string `json:"action"`
	Version string `json:"version,omitempty"`
	// RequestedAt and RequestedBy say who asked, for the console.
	RequestedAt time.Time `json:"requested_at"`
	RequestedBy string    `json:"requested_by,omitempty"`
}
