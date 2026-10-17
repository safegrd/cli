package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/safegrd/cli/pkg/wal"
)

func newWALPointCmd() *cobra.Command {
	var surfaceID string
	cmd := &cobra.Command{
		Use:   "point",
		Short: "Mark a restore point, with each table's row count, before a risky change",
		Long: `Asks PostgreSQL for a named restore point and records each table's row count
just before and just after it. 'safegrd wal restore --to-point <name>' replays
to it, and a point-in-time drill checks a restore to it against the counts.
The daemon makes one before each daily bundle.

The surface's role needs: GRANT EXECUTE ON FUNCTION pg_create_restore_point(text) TO <role>;`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			a, s, err := walArchive(ctx, cfg, surfaceID, "")
			if err != nil {
				return err
			}
			connURL, srv, err := walServer(ctx, cfg, s)
			if err != nil {
				return err
			}
			a.SystemID = srv.SystemID
			rp, err := a.CreateRestorePoint(ctx, connURL)
			if err != nil {
				return err
			}
			fmt.Printf("Restore point %s at %s (LSN %s), %d tables counted\n", rp.Name, rp.At.Format("2006-01-02 15:04:05 UTC"), rp.LSN, len(rp.Tables))
			if len(rp.Skipped) > 0 {
				fmt.Printf("   Not counted, over %d rows: %s\n", 5_000_000, strings.Join(rp.Skipped, ", "))
			}
			fmt.Printf("   Restore to it: safegrd wal restore --surface %s --to-point %s --pgdata <empty dir>\n", s.ID, rp.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	return cmd
}

func newWALDrillCmd() *cobra.Command {
	var surfaceID string
	cmd := &cobra.Command{
		Use:   "drill",
		Short: "Restore the WAL archive into throwaway clusters on this host and check it",
		Long: `Restores the archive twice, with this host's PostgreSQL server of the base's
major version: to the newest restore point it can reach, counting each table
the point recorded, and to the end of the archive, checking the replay read the
last WAL file. The daemon runs it every wal.drill_every_days. It exits 1 when
the drill fails or cannot run.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			a, s, err := walArchive(ctx, cfg, surfaceID, "")
			if err != nil {
				return err
			}
			sys, err := newestSystem(ctx, a)
			if err != nil {
				return err
			}
			a.SystemID = sys
			st := loadDaemonState(filepath.Join(resolveStateDir("", cfg), "daemon_state.json")).Surfaces[s.ID]
			d := runWALDrill(ctx, cfg, a, s, st, resolveStateDir("", cfg))
			sayWALDrill(s, d)
			switch {
			case d.Blocked != "":
				return errors.New("the point-in-time drill could not run")
			case !d.Passed:
				return errors.New("the point-in-time drill failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	return cmd
}

// newestSystem is the cluster whose newest base backup is the newest: the
// one a surface archives now, when an initdb left an older one beside it.
func newestSystem(ctx context.Context, a *wal.Archive) (string, error) {
	systems, err := walSystems(ctx, a, "")
	if err != nil {
		return "", err
	}
	best, bestAt := systems[0], time.Time{}
	for _, sys := range systems {
		a.SystemID = sys
		bases, _, err := a.Bases(ctx)
		if err != nil {
			return "", storageFailure(err)
		}
		if n := len(bases); n > 0 && bases[n-1].StartedAt.After(bestAt) {
			best, bestAt = sys, bases[n-1].StartedAt
		}
	}
	return best, nil
}
