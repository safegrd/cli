package wal

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Archiver is what pg_stat_archiver says about archive_command.
type Archiver struct {
	ArchivedCount int64
	LastArchived  string
	ArchivedAt    time.Time
	FailedCount   int64
	LastFailed    string
	FailedAt      time.Time
}

// Failing says whether the last attempt failed. PostgreSQL keeps every WAL
// file it could not archive, so pg_wal grows until the push works again or
// the disk is full.
func (a Archiver) Failing() bool { return !a.FailedAt.IsZero() && a.FailedAt.After(a.ArchivedAt) }

// ReadArchiver reads pg_stat_archiver, which any role may.
func ReadArchiver(ctx context.Context, connURL string) (Archiver, error) {
	var a Archiver
	conn, err := pgx.Connect(ctx, connURL)
	if err != nil {
		return a, err
	}
	defer conn.Close(context.Background())
	var archived, failed *string
	var archivedAt, failedAt *time.Time
	err = conn.QueryRow(ctx, `SELECT archived_count, last_archived_wal, last_archived_time, failed_count, last_failed_wal, last_failed_time FROM pg_stat_archiver`).
		Scan(&a.ArchivedCount, &archived, &archivedAt, &a.FailedCount, &failed, &failedAt)
	if err != nil {
		return a, fmt.Errorf("reading pg_stat_archiver: %w", err)
	}
	if archived != nil {
		a.LastArchived = *archived
	}
	if archivedAt != nil {
		a.ArchivedAt = archivedAt.UTC()
	}
	if failed != nil {
		a.LastFailed = *failed
	}
	if failedAt != nil {
		a.FailedAt = failedAt.UTC()
	}
	return a, nil
}
