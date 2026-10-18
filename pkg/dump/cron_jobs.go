package dump

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// entryCronJobs is pg_cron's jobs, as the backup's role could read them
// from cron.job. pg_cron owns that table, so the rows are not copied with
// the others: a restore that loaded them would schedule every job the
// moment it committed, from wherever it ran. They travel in this entry
// instead, and a restore creates each job again, turned off unless asked.
const entryCronJobs = "cron-jobs.json"

// CronJob is one of pg_cron's jobs as a backup records it. Database is
// empty for a job of the database backed up, and names the database of one
// pg_cron runs elsewhere (cron.schedule_in_database).
type CronJob struct {
	Name     string `json:"name,omitempty"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Database string `json:"database"`
	Username string `json:"username"`
	Active   bool   `json:"active"`
}

// Label is the job's name, or its schedule and command when it has none.
func (j CronJob) Label() string {
	if j.Name != "" {
		return j.Name
	}
	cmd := j.Command
	if len(cmd) > 40 {
		cmd = cmd[:40] + "..."
	}
	return fmt.Sprintf("(unnamed) %s", cmd)
}

// readCronJobs reads cron.job inside the backup's snapshot, behind a
// savepoint, or returns nil when the database has no pg_cron. pg_cron's row
// security shows a role that is not a superuser only its own jobs, so the
// backup records the jobs its role can see.
func readCronJobs(ctx context.Context, tx pgx.Tx, currentDB string) ([]CronJob, error) {
	var present bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron')").Scan(&present); err != nil || !present {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT safegrd_cron"); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT coalesce(jobname, ''), schedule, command, database, username, active FROM cron.job ORDER BY jobid`)
	var jobs []CronJob
	if err == nil {
		for rows.Next() {
			var j CronJob
			if err = rows.Scan(&j.Name, &j.Schedule, &j.Command, &j.Database, &j.Username, &j.Active); err != nil {
				break
			}
			if j.Database == currentDB {
				j.Database = ""
			}
			jobs = append(jobs, j)
		}
		rows.Close()
		if err == nil {
			err = rows.Err()
		}
	}
	if err != nil {
		rollbackSavepoint(ctx, tx, "safegrd_cron")
		return nil, fmt.Errorf("pg_cron's jobs could not be read (%w), so this backup does not carry them", err)
	}
	_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT safegrd_cron")
	return jobs, nil
}

// CronJobResult is what a restore did with one recorded job: created on the
// target with ID, or not, and why.
type CronJobResult struct {
	CronJob
	ID      int64
	Created bool
	// On is set when the job was created active.
	On bool
	// Why says why the job was not created. Refused is set when pg_cron
	// itself refused it, as opposed to a target where it cannot schedule.
	Why     string
	Refused bool
	// RunsAs is the role the job runs as when it is not the one recorded,
	// because the restoring role could not set that one.
	RunsAs string
}

// restoreCronJobs creates the recorded jobs on the target inside the
// restore's transaction, each behind a savepoint so one pg_cron refuses
// does not stop the rest. A job is created turned off unless active asks
// for it as it was. A job is never created over one of the same name the
// target already has: pg_cron's cron.schedule would rewrite that one.
func restoreCronJobs(ctx context.Context, conn *pgx.Conn, jobs []CronJob, active bool) []CronJobResult {
	out := make([]CronJobResult, len(jobs))
	for i, j := range jobs {
		out[i].CronJob = j
	}
	notCreated := func(why string) []CronJobResult {
		for i := range out {
			out[i].Why = why
		}
		return out
	}
	var hasCron bool
	var cronDB, me, here string
	if err := conn.QueryRow(ctx, `SELECT to_regprocedure('cron.schedule(text,text,text)') IS NOT NULL,
		coalesce(current_setting('cron.database_name', true), ''), current_user, current_database()`).Scan(&hasCron, &cronDB, &me, &here); err != nil {
		return notCreated("the target could not be asked about pg_cron: " + err.Error())
	}
	if !hasCron {
		return notCreated("pg_cron is not installed in the target database")
	}
	if cronDB != "" && cronDB != here {
		return notCreated(fmt.Sprintf("pg_cron on the target schedules jobs from the database %s, not %s", cronDB, here))
	}
	savepoint := func(f func() error) error {
		if _, err := conn.Exec(ctx, "SAVEPOINT safegrd_cron_job"); err != nil {
			return err
		}
		if err := f(); err != nil {
			_, _ = conn.Exec(ctx, "ROLLBACK TO SAVEPOINT safegrd_cron_job")
			return err
		}
		_, err := conn.Exec(ctx, "RELEASE SAVEPOINT safegrd_cron_job")
		return err
	}
	for i := range out {
		r := &out[i]
		if r.Database != "" {
			r.Why = fmt.Sprintf("it ran in the database %s, not the one backed up", r.Database)
			continue
		}
		if r.Name != "" {
			var taken bool
			if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM cron.job WHERE jobname = $1 AND database = current_database())", r.Name).Scan(&taken); err != nil {
				r.Why, r.Refused = err.Error(), true
				continue
			}
			if taken {
				r.Why = "the target already has a job of that name, which was left as it is"
				continue
			}
		}
		err := savepoint(func() error {
			var err error
			if r.Name != "" {
				err = conn.QueryRow(ctx, "SELECT cron.schedule($1, $2, $3)", r.Name, r.Schedule, r.Command).Scan(&r.ID)
			} else {
				err = conn.QueryRow(ctx, "SELECT cron.schedule($1, $2)", r.Schedule, r.Command).Scan(&r.ID)
			}
			if err != nil {
				return err
			}
			r.On = active && r.Active
			if !r.On {
				if _, err := conn.Exec(ctx, "SELECT cron.alter_job($1, active := false)", r.ID); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			r.Why, r.Refused = pgMessage(err), true
			continue
		}
		r.Created = true
		if r.Username != "" && r.Username != me {
			if err := savepoint(func() error {
				_, err := conn.Exec(ctx, "SELECT cron.alter_job($1, username := $2)", r.ID, r.Username)
				return err
			}); err != nil {
				r.RunsAs = me
			}
		}
	}
	return out
}

// pgMessage is a PostgreSQL error's message alone, without the SQLSTATE.
func pgMessage(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Message
	}
	return err.Error()
}
