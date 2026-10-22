package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/erasure"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
)

// The erasure record (pkg/erasure): a surface that names tables under
// erasures: has every row deleted from them recorded by a trigger, moved
// out of the database into sealed objects beside its backups on every
// daemon tick and before every backup, and replayed by a restore of a
// backup that predates the deletion.

// errErasuresOnHosted is why a surface on hosted storage keeps no record.
var errErasuresOnHosted = errors.New("hosted storage cannot keep an erasure record yet: SafeGrd's server signs every object written there and does not know this one. " +
	"Keep this surface on local storage or your own bucket, or remove erasures: from it")

// erasureRecordPath is where a surface's record is kept, relative to its
// storage's root: beside the host's snapshots, under the surface's id.
func erasureRecordPath(nodeID, surfaceID string) string {
	return path.Join(nodeID, "erasures", surfaceID)
}

// erasureObjects opens the storage a record is kept in.
func erasureObjects(ctx context.Context, storageCfg config.StorageConfig) (storage.Objects, error) {
	if storageCfg.Type == config.StorageTypeHosted || hostedLayout(storageCfg) {
		return nil, errErasuresOnHosted
	}
	resolved, err := resolveSFTPSecrets(storageCfg)
	if err != nil {
		return nil, err
	}
	p, err := storage.NewProvider(ctx, resolved)
	if err != nil {
		return nil, err
	}
	objs, ok := p.(storage.Objects)
	if !ok {
		return nil, fmt.Errorf("%s storage cannot keep an erasure record", p.Type())
	}
	return objs, nil
}

// erasureParams are what moving a surface's record out needs.
type erasureParams struct {
	SurfaceID   string
	NodeID      string
	DatabaseURL string
	StorageCfg  config.StorageConfig
	Recipient   string
	Tables      []string
	// RetainUntil is how long a backup taken now could be kept: each
	// object is locked as long, so no older snapshot outlives it.
	RetainUntil time.Time
}

// shipErasures moves what safegrd.erasures holds into the record and
// returns how many rows it moved.
func shipErasures(ctx context.Context, p erasureParams) (int, error) {
	objs, err := erasureObjects(ctx, p.StorageCfg)
	if err != nil {
		return 0, err
	}
	if err := erasure.Start(ctx, objs, erasureRecordPath(p.NodeID, p.SurfaceID), p.SurfaceID, p.RetainUntil); err != nil {
		return 0, fmt.Errorf("could not start the erasure record: %w", err)
	}
	return erasure.Ship(ctx, p.DatabaseURL, objs, erasureRecordPath(p.NodeID, p.SurfaceID), p.SurfaceID, p.Recipient, p.RetainUntil)
}

// prepareErasures runs before a backup of a surface with erasure tables:
// the trigger put in place on each, and the rows waiting moved out. Either
// failing is said on stderr and the backup goes on, because a backup is
// still worth having; the record it names is still read by a restore. It
// returns what goes into the backup's manifest.
func prepareErasures(ctx context.Context, p erasureParams, out io.Writer, label string) *model.ErasureRecord {
	rec := &model.ErasureRecord{Path: erasureRecordPath(p.NodeID, p.SurfaceID), Tables: p.Tables}
	if p.StorageCfg.Type == config.StorageTypeHosted || hostedLayout(p.StorageCfg) {
		fmt.Fprintf(os.Stderr, "Error: %s %v.\n", label, errErasuresOnHosted)
		return nil
	}
	installed, err := erasure.Install(ctx, p.DatabaseURL, p.Tables)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %s the erasure record is not in place (%v). Rows deleted from %s are not recorded until it is.\n",
			label, err, strings.Join(p.Tables, ", "))
	} else if len(installed) > 0 {
		fmt.Fprintf(out, "%s Erasure trigger put in place on %s.\n", label, strings.Join(installed, ", "))
	}
	n, err := shipErasures(ctx, p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %s the erasures waiting in safegrd.erasures were not moved to storage (%v). They stay there and are moved on the next try.\n", label, err)
	} else if n > 0 {
		fmt.Fprintf(out, "%s Moved %d %s to the erasure record.\n", label, n, pluralWord(int64(n), "erasure", "erasures"))
	}
	return rec
}

// erasureReplay is a restore's replay of a snapshot's erasure record:
// loaded before the restore starts, so a record that cannot be read stops
// it before anything is written, and applied inside its transaction.
type erasureReplay struct {
	records []erasure.Record
	window  erasure.Window
	result  erasure.Result
	applied bool
}

// loadErasureReplay reads the record a snapshot names. nil, nil when the
// snapshot names none, or when without is set: then the restore says erased
// rows may be back.
func loadErasureReplay(ctx context.Context, rs *repoSnapshot, identity string, without bool) (*erasureReplay, error) {
	meta := rs.Meta
	if meta.Erasures == nil {
		return nil, nil
	}
	if without {
		fmt.Fprintf(os.Stderr, "Warning: the erasure record was not replayed (--without-erasures). Rows deleted from %s after this backup may be back.\n",
			strings.Join(meta.Erasures.Tables, ", "))
		return nil, nil
	}
	refuse := func(err error) error {
		return fmt.Errorf("%w. This backup records erasures from %s, and a restore that cannot replay them would bring erased rows back, so nothing was restored. "+
			"Restore with --without-erasures to restore anyway", err, strings.Join(meta.Erasures.Tables, ", "))
	}
	if rs.StorageCfg == nil {
		return nil, refuse(errors.New("the storage this snapshot was found in is not known here"))
	}
	objs, err := erasureObjects(ctx, *rs.StorageCfg)
	if err != nil {
		return nil, refuse(err)
	}
	recs, err := erasure.Load(ctx, objs, meta.Erasures.Path, identity)
	if err != nil {
		return nil, refuse(err)
	}
	return &erasureReplay{records: recs, window: erasure.Window{Snapshot: meta.SourceSnapshot, Started: meta.CreatedAt}}, nil
}

// apply is the restorer's InTransaction hook.
func (e *erasureReplay) apply(ctx context.Context, conn *pgx.Conn) error {
	res, err := erasure.Replay(ctx, conn, e.records, e.window)
	if err != nil {
		return err
	}
	if err := erasure.ClearQueue(ctx, conn); err != nil {
		return fmt.Errorf("clearing safegrd.erasures in the restored database: %w", err)
	}
	e.result, e.applied = res, true
	return nil
}

// print says what the replay did, after the restore committed.
func (e *erasureReplay) print() {
	if e == nil || !e.applied {
		return
	}
	if e.result.Applied == 0 {
		fmt.Printf("   Erasures:       none recorded after this backup\n")
		return
	}
	fmt.Printf("   Erasures:       %d recorded after this backup, replayed\n", e.result.Applied)
	for rel, n := range e.result.Deleted {
		fmt.Printf("   Erased again:   %s, %d %s (and what ON DELETE CASCADE removed with them)\n", rel, n, pluralWord(n, "row", "rows"))
	}
	for rel, n := range e.result.Missing {
		fmt.Fprintf(os.Stderr, "Warning: %d %s of %s were not replayed: the restored database has no such table.\n", n, pluralWord(int64(n), "erasure", "erasures"), rel)
	}
}

// shipErasuresOnTick moves a surface's waiting erasures out on a daemon
// tick. A failure is the probe's: the heartbeat carries it and the console
// alerts on it, as for a database or a sink that stopped answering.
func shipErasuresOnTick(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig, nodeID string, st *SurfaceState) {
	if len(s.Erasures) == 0 || !st.probe.dbUp || !st.probe.storageUp {
		return
	}
	dbURL, ok := probeDatabaseURL(ctx, c, s)
	if !ok {
		// The remote server holds the credential: the backup moves them.
		return
	}
	storageCfg := c.Storage
	if s.Storage != nil {
		storageCfg = *s.Storage
	} else if err := routeProjectSink(ctx, c, &storageCfg, false, false); err != nil {
		return
	}
	applyHeldSinkKey(ctx, c, &storageCfg)
	pubKey := c.Encryption.PublicKey
	if s.Encryption != nil && s.Encryption.PublicKey != "" {
		pubKey = s.Encryption.PublicKey
	}
	n, err := shipErasures(ctx, erasureParams{
		SurfaceID: s.ID, NodeID: nodeID, DatabaseURL: dbURL, StorageCfg: storageCfg, Recipient: pubKey,
		Tables: s.Erasures, RetainUntil: erasureRetainUntil(c, s),
	})
	if err != nil {
		st.probe.probed = true
		st.probe.storageUp, st.probe.storeErr = false, "erasure record: "+probeErrorText(err)
		return
	}
	if n > 0 {
		fmt.Printf("Surface %s: moved %d %s to the erasure record.\n", s.ID, n, pluralWord(int64(n), "erasure", "erasures"))
	}
}

// erasureRetainUntil is how long a backup of s taken now could be kept: its
// longest tier.
func erasureRetainUntil(c *config.CLIConfig, s *config.SurfaceConfig) time.Time {
	return planRetention(time.Now(), surfaceRetentionDays(c, s), gfsTiers(c, s), nil).Until
}

// drillErasures opens the storage a drill reads the snapshot's erasure
// record from, or nil, said, when it cannot: the drill then fails the
// record's assertion instead of skipping it.
func drillErasures(ctx context.Context, rs *repoSnapshot) storage.Objects {
	if rs == nil || rs.Meta == nil || rs.Meta.Erasures == nil || rs.StorageCfg == nil {
		return nil
	}
	objs, err := erasureObjects(ctx, *rs.StorageCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: the erasure record of %s cannot be opened: %v\n", rs.Meta.SnapshotID, err)
		return nil
	}
	return objs
}
