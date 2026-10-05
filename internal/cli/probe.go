package cli

// The probe between backups: on every daemon tick, before the heartbeat, a
// surface's database is opened and its sink is asked whether it answers, so
// a database that went away at 09:00 is reported at 09:00 and not at the next
// scheduled backup. Read-only: a connection and SELECT 1, a HeadBucket, a
// stat of a local directory. Nothing is written.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/storage"
)

// probeTimeout bounds each half of a probe, so a host that drops packets
// costs one tick ten seconds and not the dialer's default.
const probeTimeout = 10 * time.Second

// probeResult is what a probe found. probed is false when there was nothing
// it could check without fetching a credential the remote server holds; the
// heartbeat then says what the last backup said, as before.
type probeResult struct {
	probed          bool
	dbUp, storageUp bool
	dbErr, storeErr string
}

// words is the probe's failure in one line, or "".
func (r probeResult) words() string {
	var parts []string
	if r.dbErr != "" {
		parts = append(parts, "database: "+r.dbErr)
	}
	if r.storeErr != "" {
		parts = append(parts, "storage: "+r.storeErr)
	}
	return strings.Join(parts, "; ")
}

// probeSurface checks a surface's database and sink. A surface whose
// credential the remote server holds is not opened: the probe never fetches
// a sealed credential, and the daemon fetches one only for a backup or a
// drill. Neither is a credential that comes from a command, which would run
// that command on every tick.
func probeSurface(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) probeResult {
	r := probeResult{dbUp: true, storageUp: true}
	if dbURL, ok := probeDatabaseURL(ctx, c, s); ok {
		r.probed = true
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		err := dump.PingDatabase(pctx, dbURL, nil)
		cancel()
		if err != nil {
			r.dbUp, r.dbErr = false, probeErrorText(err)
		}
	}
	if probed, err := probeSink(ctx, c, s); probed {
		r.probed = true
		if err != nil {
			r.storageUp, r.storeErr = false, probeErrorText(err)
		}
	}
	return r
}

// probeDatabaseURL is the database a probe opens, if it may open one.
func probeDatabaseURL(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (string, bool) {
	switch strings.ToLower(s.Type) {
	case "postgres", "mysql", "mongodb":
	default:
		return "", false
	}
	switch s.CredentialFrom() {
	case config.CredentialFromSafeGrd, config.CredentialFromCommand:
		return "", false
	}
	u, err := resolveSurfaceDatabaseURLAsGiven(ctx, c, s)
	if err != nil || u == "" {
		return "", false
	}
	u, _ = cleanPostgresURL(u)
	return u, true
}

// probeSink asks the surface's sink whether it answers. Only a sink this
// host holds the key for, or a local directory: hosted storage is reached
// through the remote server the heartbeat is already talking to, and a
// bucket whose key the remote server holds would need that key fetched.
func probeSink(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (bool, error) {
	cfg := c.Storage
	if s.Storage != nil {
		cfg = *s.Storage
	}
	switch cfg.Type {
	case config.StorageTypeLocal:
		path := cfg.LocalPath
		if path == "" {
			path = "./safegrd-storage"
		}
		fi, err := os.Stat(path)
		if err != nil {
			return true, err
		}
		if !fi.IsDir() {
			return true, fmt.Errorf("%s is not a directory", path)
		}
		return true, nil
	case config.StorageTypeS3:
		if cfg.Bucket == "" || cfg.SecretAccessKey == "" {
			return false, nil
		}
		if strings.HasPrefix(cfg.SecretAccessKey, "env:") || strings.HasPrefix(cfg.SecretAccessKey, "file:") {
			v, err := resolveConfigSecret("storage.secret_access_key", cfg.SecretAccessKey)
			if err != nil || v == "" {
				return false, nil
			}
			cfg.SecretAccessKey = v
		}
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		p, err := storage.NewS3Storage(pctx, cfg)
		if err != nil {
			return true, err
		}
		_, err = p.BucketNow(pctx)
		return true, err
	}
	return false, nil
}

// probeErrorText is an error in one line, with a deadline said as such.
func probeErrorText(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("no answer within %s", probeTimeout)
	}
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return msg
}

// probeSaid is the probe failure last said for each surface, so a failure is
// said when it starts and when it ends. The daemon's state is read from disk
// on every tick, so this lives for the process instead.
var probeSaid = map[string]string{}

// sayProbe tells the daemon's log when a probe starts or stops failing, and
// not on every tick in between.
func sayProbe(st *SurfaceState, r probeResult) {
	if !r.probed {
		return
	}
	now, before := r.words(), probeSaid[st.SurfaceID]
	if now == before {
		return
	}
	switch {
	case now != "" && before == "":
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: unreachable between backups (%s). "+
			"The console says so after three ticks in a row. Run `safegrd doctor` on this host.\n", st.SurfaceID, now)
	case now != "":
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: still unreachable (%s).\n", st.SurfaceID, now)
	default:
		fmt.Printf("Surface %s: reachable again.\n", st.SurfaceID)
	}
	probeSaid[st.SurfaceID] = now
}
