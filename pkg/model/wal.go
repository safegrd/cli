package model

import "time"

// WALStatus is what a daemon says about a PostgreSQL surface's WAL
// archive: the window a restore reaches, how much of it is locked, the
// first missing WAL file, archive_command's last failure, and the last
// point-in-time drill.
type WALStatus struct {
	// CheckedAt is when the daemon last read the archive.
	CheckedAt time.Time `json:"checked_at"`
	// SurfaceID is the surface's id in the host's config, which a restore
	// command names, and Major the PostgreSQL major version of the newest
	// base backup, which a restore needs.
	SurfaceID  string     `json:"surface_id,omitempty"`
	Major      int        `json:"major,omitempty"`
	WindowFrom *time.Time `json:"window_from,omitempty"`
	WindowTo   *time.Time `json:"window_to,omitempty"`
	// LockedTo is when the newest bundled WAL file was pushed: the window up
	// to it is locked, the rest is kept unlocked until the next bundle.
	LockedTo *time.Time `json:"locked_to,omitempty"`
	// Gap is the first WAL file missing from the archive; replay from the
	// base backups before it stops there.
	Gap string `json:"gap,omitempty"`
	// ArchiverFailing is the WAL file archive_command is failing on, read
	// from pg_stat_archiver, and ArchiverFailures its failure count.
	ArchiverFailing  string    `json:"archiver_failing,omitempty"`
	ArchiverFailures int64     `json:"archiver_failures,omitempty"`
	Drill            *WALDrill `json:"drill,omitempty"`
}

// WALDrill is one point-in-time drill: a restore to a restore point whose
// per-table row counts were recorded, and a restore to the end of the
// archive.
type WALDrill struct {
	At     time.Time `json:"at"`
	Passed bool      `json:"passed"`
	// RestorePoint is the restore point replayed to, and PointAt when it was
	// created. Empty when the archive held none to drill to.
	RestorePoint string    `json:"restore_point,omitempty"`
	PointAt      time.Time `json:"point_at,omitzero"`
	// Tables is how many tables were counted, Exact how many of them were
	// still between the two counts and so matched exactly.
	Tables int `json:"tables,omitempty"`
	Exact  int `json:"exact,omitempty"`
	// ReachedEnd says the replay to the end of the archive reached its last
	// WAL file.
	ReachedEnd bool `json:"reached_end"`
	// Detail is why it failed, or what it could not check.
	Detail string `json:"detail,omitempty"`
	// Blocked is why the host could not run the drill at all (no server of
	// the base's major version, no key). It says nothing about the archive.
	Blocked string `json:"blocked,omitempty"`
}
