package cli

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/wal"
)

// sqliteFollowers are the resident daemon's followers, by surface id.
var sqliteFollowers sync.Map

// startSQLiteFollowers follows the WAL of every SQLite surface with a wal:
// block, until ctx ends. Only a resident daemon does: following is
// continuous, and a pass from cron would leave the WAL unwatched between
// runs.
func startSQLiteFollowers(ctx context.Context, c *config.CLIConfig) {
	for i := range c.Surfaces {
		s := c.Surfaces[i]
		if s.WAL == nil || !walIsSQLite(&s) {
			continue
		}
		f, err := newSQLiteFollower(ctx, c, &s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Surface %s: cannot follow its WAL: %v\n", s.ID, err)
			continue
		}
		sqliteFollowers.Store(s.ID, f)
		fmt.Printf("   Following:           %s's WAL (%s)\n", s.ID, f.Path)
		go f.Run(ctx)
	}
}

func newSQLiteFollower(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (*wal.SQLiteFollower, error) {
	a, _, err := walArchive(ctx, c, s.ID, "")
	if err != nil {
		return nil, err
	}
	if a.Recipient == "" {
		return nil, fmt.Errorf("encryption.public_key is not set, and the WAL is encrypted to it")
	}
	u, err := resolveSurfaceDatabaseURLAsGiven(ctx, c, s)
	if err != nil {
		return nil, err
	}
	path, err := dump.SQLitePath(u)
	if err != nil {
		return nil, err
	}
	interval := time.Second
	if s.WAL.IntervalSeconds > 0 {
		interval = time.Duration(s.WAL.IntervalSeconds) * time.Second
	}
	mb := int64(4)
	if s.WAL.CheckpointMB > 0 {
		mb = int64(s.WAL.CheckpointMB)
	}
	id := s.ID
	return &wal.SQLiteFollower{Archive: a, Path: path, Interval: interval, CheckpointBytes: mb << 20,
		PointEvery: 24 * time.Hour, GenerationEvery: walDays(s.WAL.BaseEveryDays),
		Logf: func(format string, args ...any) { fmt.Printf("Surface "+id+": "+format+"\n", args...) },
		Warnf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "Warning: Surface "+id+": "+format+"\n", args...)
		},
	}, nil
}

// warnSQLiteOnce says, for a pass from cron, which SQLite surfaces it
// cannot follow.
func warnSQLiteOnce(c *config.CLIConfig) {
	for i := range c.Surfaces {
		s := c.Surfaces[i]
		if s.WAL != nil && walIsSQLite(&s) {
			fmt.Fprintf(os.Stderr, "Warning: Surface %s: its WAL is followed only by the resident daemon ('safegrd daemon run' without --once); this pass bundles what was archived and copies nothing new.\n", s.ID)
		}
	}
}

// sqliteFollowError is why the daemon is not following a surface's WAL, or
// "".
func sqliteFollowError(id string) string {
	v, ok := sqliteFollowers.Load(id)
	if !ok {
		return ""
	}
	st := v.(*wal.SQLiteFollower).Status()
	if st.Following {
		return ""
	}
	return st.LastError
}
