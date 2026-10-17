package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/runner"
	"github.com/safegrd/cli/pkg/wal"
)

// walRecoveryLimit bounds one replay of a drill.
const walRecoveryLimit = 2 * time.Hour

// walDBURL is the surface's database for the daemon's own reads: the
// archiver, a restore point, a drill's role. A credential the remote server
// holds, or a command prints, is fetched; the caller decides how often.
func walDBURL(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, st *SurfaceState) (string, error) {
	if u, ok := probeDatabaseURL(ctx, c, s); ok {
		return u, nil
	}
	held := *s
	node := s.ID
	if st != nil && st.ServerNodeID != "" {
		node = st.ServerNodeID
	}
	fetchHeldSurfaceSecret(ctx, c, node, &held)
	u, err := resolveSurfaceDatabaseURLAsGiven(ctx, c, &held)
	if err != nil {
		return "", err
	}
	if u == "" {
		return "", fmt.Errorf("surface %s names no database_url", s.ID)
	}
	u, _ = cleanPostgresURL(u)
	return u, nil
}

// runWALDrill restores the surface's archive into throwaway clusters on this
// host: once to the newest restore point it can reach, counting every table
// the point recorded, and once to the end of the archive, checking the
// replay read the last WAL file. A drill this host cannot run says why in
// Blocked and is no failure of the archive.
func runWALDrill(ctx context.Context, c *config.CLIConfig, a *wal.Archive, s *config.SurfaceConfig, st *SurfaceState, stateDir string) *model.WALDrill {
	d := &model.WALDrill{At: time.Now().UTC()}
	blocked := func(why string) *model.WALDrill { d.Blocked = why; return d }
	failed := func(why string) *model.WALDrill { d.Detail = why; return d }

	if a.Identity = daemonPrivateKey(ctx, c); a.Identity == "" {
		return blocked("this host holds no private key to decrypt the archive")
	}
	plan, err := a.PlanDrill(ctx)
	if err != nil {
		return blocked(err.Error())
	}
	srv, err := runner.FindPgServerMajor(ctx, plan.EndBase.Major())
	if err != nil {
		return blocked(err.Error())
	}
	dbURL, err := walDBURL(ctx, c, s, st)
	if err != nil {
		return blocked("could not read the surface's role: " + err.Error())
	}
	pc, err := pgconn.ParseConfig(dbURL)
	if err != nil {
		return blocked("the surface's database URL does not parse")
	}
	role, database := pc.User, pc.Database
	if database == "" {
		database = role
	}

	// Each replay reads its WAL from a directory the daemon filled, so the
	// cluster's user never needs a key.
	start := func(base wal.BaseInfo, files []string, point *wal.RestorePoint) (*runner.LocalPostgres, error) {
		need := base.TarBytes*2 + int64(len(files))*int64(base.SegmentSize)
		return runner.StartRecoveredPostgres(ctx, srv, stateDir, need, func(dataDir, walDir string) error {
			o := wal.RestoreOptions{PGData: dataDir, FetchCommand: "cp " + shellQuote(walDir) + "/%f %p"}
			if point != nil {
				o.Target, o.TargetName = point.At, point.Name
			}
			if _, err := a.Restore(ctx, o); err != nil {
				return err
			}
			_, err := a.StageWAL(ctx, files, walDir)
			return err
		})
	}

	if p := plan.Point; p != nil {
		d.RestorePoint, d.PointAt = p.Name, p.At
		lp, err := start(plan.PointBase, plan.PointFiles, p)
		if err != nil {
			return failed("restoring to restore point " + p.Name + ": " + err.Error())
		}
		url, err := lp.WaitPromoted(ctx, role, database, walRecoveryLimit)
		if err != nil {
			lp.Stop()
			return failed("replaying to restore point " + p.Name + ": " + err.Error())
		}
		got, err := countRestored(ctx, url, p)
		lp.Stop()
		if err != nil {
			return failed("counting the restored tables: " + err.Error())
		}
		exact, wrong := p.CheckCounts(got)
		d.Tables, d.Exact = len(p.Tables), exact
		if len(wrong) > 0 {
			return failed(strings.Join(wrong, "; "))
		}
	}

	lp, err := start(plan.EndBase, plan.EndFiles, nil)
	if err != nil {
		return failed("restoring to the end of the archive: " + err.Error())
	}
	_, err = lp.WaitPromoted(ctx, role, database, walRecoveryLimit)
	redo := lp.RedoDone()
	lp.Stop()
	if err != nil {
		return failed("replaying to the end of the archive: " + err.Error())
	}
	lsn, perr := wal.ParseLSN(redo)
	if perr != nil {
		return failed("the replay to the end did not log where it stopped")
	}
	if d.ReachedEnd = plan.ReachedEnd(lsn); !d.ReachedEnd {
		return failed(fmt.Sprintf("the replay to the end stopped at %s, before the archive's last WAL file %s", redo, plan.LastSegment))
	}
	if plan.Point == nil {
		d.Detail = "no restore point to drill to yet; the replay to the end was drilled"
	}
	d.Passed = true
	return d
}

// countRestored counts each table the restore point recorded, in the
// restored cluster, as the role that counted them.
func countRestored(ctx context.Context, url string, p *wal.RestorePoint) (map[string]int64, error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	out := map[string]int64{}
	for _, t := range p.Tables {
		var n int64
		err := conn.QueryRow(ctx, "SELECT count(*) FROM "+t.Table).Scan(&n)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			continue // missing: CheckCounts names it
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Table, err)
		}
		out[t.Table] = n
	}
	return out, nil
}

// sayWALDrill prints how a drill went.
func sayWALDrill(s *config.SurfaceConfig, d *model.WALDrill) {
	switch {
	case d.Blocked != "":
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: point-in-time drill not run: %s.\n", s.ID, d.Blocked)
	case d.Passed && d.RestorePoint != "":
		fmt.Printf("Surface %s: point-in-time drill passed: restored to %s (%s), %d tables counted, %d exact; the replay to the end reached the last WAL file.\n",
			s.ID, d.RestorePoint, d.PointAt.UTC().Format("2006-01-02 15:04 UTC"), d.Tables, d.Exact)
	case d.Passed:
		fmt.Printf("Surface %s: point-in-time drill passed: the replay to the end reached the last WAL file. No restore point to count against yet.\n", s.ID)
	default:
		fmt.Fprintf(os.Stderr, "Error: Surface %s: point-in-time drill failed: %s\n", s.ID, d.Detail)
	}
}
