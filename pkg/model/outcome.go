package model

// What a daemon reports about its last backup and its last Fire Drill, as
// codes. The remote server, the console and alerts decide on the code; the
// detail beside it (Node.DaemonLastError, Node.DrillDetail) is the host's own
// words, shown to people and never parsed.

// DrillStatus is how the last Fire Drill on a host went. Empty means nothing
// to report: no drill has been due since the daemon started.
type DrillStatus string

const (
	// DrillStatusPassed: the drill ran as the plan includes it and passed.
	DrillStatusPassed DrillStatus = "passed"
	// DrillStatusShallow: the drill passed, in memory, where the plan
	// includes a drill into a database. DrillReason says why.
	DrillStatusShallow DrillStatus = "shallow"
	// DrillStatusNoKey: a drill is due and this host does not hold the
	// private key, which the daemon never copies.
	DrillStatusNoKey DrillStatus = "no_key"
	// DrillStatusBlocked: this host cannot run the drill for a reason that
	// says nothing about the backup. DrillReason says which.
	DrillStatusBlocked DrillStatus = "blocked"
	// DrillStatusFailed: the last unattended drill did not pass.
	DrillStatusFailed DrillStatus = "failed"
)

// Valid reports whether s is one of the statuses above, or empty.
func (s DrillStatus) Valid() bool {
	switch s {
	case "", DrillStatusPassed, DrillStatusShallow, DrillStatusNoKey, DrillStatusBlocked, DrillStatusFailed:
		return true
	}
	return false
}

// DrillReason says why the last drill was not the drill the plan includes,
// or why it did not pass. Empty when it ran as it should.
type DrillReason string

const (
	// With DrillStatusShallow: why the host could not start a throwaway
	// PostgreSQL to restore into.
	DrillReasonManifestUnreadable   DrillReason = "manifest_unreadable"
	DrillReasonNoPostgresServer     DrillReason = "no_postgres_server"
	DrillReasonPostgresServerBroken DrillReason = "postgres_server_broken"
	DrillReasonPostgresServerOld    DrillReason = "postgres_server_too_old"
	DrillReasonMissingExtensions    DrillReason = "missing_extensions"
	DrillReasonSandboxNoDisk        DrillReason = "sandbox_no_disk"
	DrillReasonSandboxStartFailed   DrillReason = "sandbox_start_failed"

	// With DrillStatusNoKey and DrillStatusBlocked: why it did not run.
	DrillReasonNoKey  DrillReason = "no_key"
	DrillReasonNoDisk DrillReason = "no_disk"

	// With DrillStatusFailed.
	DrillReasonStorage          DrillReason = "storage"
	DrillReasonSandboxRefused   DrillReason = "sandbox_refused"
	DrillReasonInterrupted      DrillReason = "interrupted"
	DrillReasonRestoreFailed    DrillReason = "restore_failed"
	DrillReasonAssertionsFailed DrillReason = "assertions_failed"

	// DrillReasonOther is a reason this version does not name.
	DrillReasonOther DrillReason = "other"
)

var drillReasonWords = map[DrillReason]string{
	DrillReasonManifestUnreadable:   "Drilled in memory: the host could not read the snapshot's manifest to start a sandbox.",
	DrillReasonNoPostgresServer:     "Drilled in memory: this host has no PostgreSQL server to restore into. Install the server package, or set drill.sandbox_url.",
	DrillReasonPostgresServerBroken: "Drilled in memory: the PostgreSQL server on this host does not run.",
	DrillReasonPostgresServerOld:    "Drilled in memory: this host's PostgreSQL server is older than the database the snapshot came from.",
	DrillReasonMissingExtensions:    "Drilled in memory: this host's PostgreSQL server lacks extensions the snapshot uses.",
	DrillReasonSandboxNoDisk:        "Drilled in memory: not enough disk on this host to restore into a sandbox.",
	DrillReasonSandboxStartFailed:   "Drilled in memory: a sandbox on this host did not start.",
	DrillReasonNoKey:                "Fire Drill not run: this host does not hold the private key. Run safegrd verify where the key is.",
	DrillReasonNoDisk:               "Fire Drill not run: not enough disk on this host to restore the snapshot. The backups are not affected.",
	DrillReasonStorage:              "Fire Drill failed: the host could not open the storage the backups are in.",
	DrillReasonSandboxRefused:       "Fire Drill not run: drill.sandbox_url could not be checked, or names the database being backed up.",
	DrillReasonInterrupted:          "Fire Drill failed: the daemon stopped during the drill.",
	DrillReasonRestoreFailed:        "Fire Drill failed: the snapshot did not restore.",
	DrillReasonAssertionsFailed:     "Fire Drill failed: the restored data does not match the snapshot's manifest.",
	DrillReasonOther:                "Fire Drill did not complete.",
}

// Valid reports whether r is one of the reasons above, or empty.
func (r DrillReason) Valid() bool {
	_, ok := drillReasonWords[r]
	return ok || r == ""
}

// Words is r as one sentence for the console and alerts, or "" for none.
func (r DrillReason) Words() string { return drillReasonWords[r] }

// BackupReason says why the last backup failed, or what went wrong after a
// backup that was taken. Empty when the backup ran and was recorded.
type BackupReason string

const (
	// Not backed up.
	BackupReasonPreBackupHook BackupReason = "pre_backup_hook"
	BackupReasonConfig        BackupReason = "config"
	BackupReasonSource        BackupReason = "source"
	BackupReasonStorage       BackupReason = "storage"
	BackupReasonNoDisk        BackupReason = "no_disk"
	BackupReasonQuota         BackupReason = "quota"

	// Backed up, with something to say.
	BackupReasonPostBackupHook BackupReason = "post_backup_hook"
	BackupReasonNotRecorded    BackupReason = "not_recorded"

	// BackupReasonOther is a failure this version does not name.
	BackupReasonOther BackupReason = "other"
)

var backupReasonWords = map[BackupReason]string{
	BackupReasonPreBackupHook:  "Not backed up: the pre_backup hook failed.",
	BackupReasonConfig:         "Not backed up: the surface's settings on the host are incomplete.",
	BackupReasonSource:         "Not backed up: the host could not read this surface's data.",
	BackupReasonStorage:        "Not backed up: the host could not write to storage.",
	BackupReasonNoDisk:         "Not backed up: not enough disk on this host.",
	BackupReasonQuota:          "Not backed up: the organization's hosted storage is full.",
	BackupReasonPostBackupHook: "Backed up. The post_backup hook failed, so the application may still be paused.",
	BackupReasonNotRecorded:    "Backed up. Its record did not reach the server.",
	BackupReasonOther:          "Not backed up.",
}

// Valid reports whether r is one of the reasons above, or empty.
func (r BackupReason) Valid() bool {
	_, ok := backupReasonWords[r]
	return ok || r == ""
}

// Words is r as one sentence for the console and alerts, or "" for none.
func (r BackupReason) Words() string { return backupReasonWords[r] }

// BackupTaken reports whether a backup that ended with r was written.
func (r BackupReason) BackupTaken() bool {
	return r == "" || r == BackupReasonPostBackupHook || r == BackupReasonNotRecorded
}
