package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/safegrd/cli/pkg/storage"
)

// A project that locks only the copies it keeps, written into the
// customer's own bucket. The host asks the remote server which rule its
// project is under and applies it with its own key: the day's first run is
// locked when written, the runs in between are written unlocked and kept for
// the retention, and at a scheduled run's commit every object it references
// is locked to its date. The weekly and monthly copies the server chooses,
// from backups a drill restored, the host locks when it is told they are due.
// A host that cannot ask locks every run, as it always has.

// lockRule is the project's rule as the remote server states it.
type lockRule struct {
	RetentionMode string `json:"retention_mode"`
	Active        bool   `json:"active"`
	RetentionDays int    `json:"retention_days"`
	KeepDaily     int    `json:"keep_daily"`
	KeepWeekly    int    `json:"keep_weekly"`
	KeepMonthly   int    `json:"keep_monthly"`
	SlotHours     int    `json:"slot_hours"`
}

// nodeCall is one request to this host's own node routes.
func nodeCall(ctx context.Context, c *config.CLIConfig, method, sub string, in, out any) error {
	if c.ServerURL == "" || c.ServerToken == "" || c.NodeID == "" {
		return fmt.Errorf("this host is not enrolled")
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.ServerURL, "/")+"/api/v1/nodes/"+c.NodeID+sub, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("%s %s: %s", method, sub, e.Error)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// ownBucketLocked reports whether storage is a bucket this host holds the
// key for, under Object Lock: where the kept rule is this host's to apply.
func ownBucketLocked(sc config.StorageConfig) bool {
	return sc.Type == config.StorageTypeS3 && !hostedLayout(sc) && repoLocked(sc)
}

// ownKeptRule is the rule this run writes under in the host's own bucket, or
// nil when every run is locked: the storage is not such a bucket, the host
// is not enrolled, the project locks every backup, or the server could not
// be asked. The daemon's own slot decision (planRetention) says whether the
// run is the day's first.
func ownKeptRule(ctx context.Context, c *config.CLIConfig, sc config.StorageConfig, plan retentionPlan, now time.Time) *sink.KeptRule {
	if !ownBucketLocked(sc) || !hostIsEnrolled(c) {
		return nil
	}
	var rule lockRule
	if err := nodeCall(ctx, c, http.MethodGet, "/lock-rule", nil, &rule); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not ask the remote server which backups this project locks (%v); every object of this run is locked.\n", err)
		return nil
	}
	if !rule.Active {
		return nil
	}
	days := rule.RetentionDays
	if days < 1 {
		days = 1
	}
	if plan.Tier != "base" {
		return &sink.KeptRule{Scheduled: true, LockUntil: plan.Until.UTC(), KeptUntil: plan.Until.UTC()}
	}
	return &sink.KeptRule{Scheduled: false, KeptUntil: now.UTC().AddDate(0, 0, days)}
}

// keptCopyDue is one copy the remote server says to lock.
type keptCopyDue struct {
	SnapshotID string    `json:"snapshot_id"`
	Tier       string    `json:"tier"`
	Until      time.Time `json:"until"`
	Drilled    bool      `json:"drilled"`
	StorageURI string    `json:"storage_uri"`
	Format     string    `json:"format"`
	EpochID    string    `json:"epoch_id"`
}

// keepOwnCopies locks, in the host's own bucket, every weekly or monthly
// copy the remote server says is due, and confirms each. Said line by line;
// a copy that cannot be locked is a warning, and the server lists it again
// next time.
func keepOwnCopies(ctx context.Context, c *config.CLIConfig, sc config.StorageConfig, key string, out io.Writer) {
	if !ownBucketLocked(sc) || !hostIsEnrolled(c) {
		return
	}
	var due struct {
		Due []keptCopyDue `json:"due"`
	}
	if err := nodeCall(ctx, c, http.MethodGet, "/kept-copies", nil, &due); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not ask the remote server which weekly or monthly copies are due: %v\n", err)
		return
	}
	for _, d := range due.Due {
		if err := lockOwnCopy(ctx, sc, key, d); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: the %s copy %s was not locked until %s: %v\n", d.Tier, d.SnapshotID, d.Until.UTC().Format("2006-01-02"), err)
			continue
		}
		if err := nodeCall(ctx, c, http.MethodPost, "/kept-copies", map[string]any{"snapshot_id": d.SnapshotID, "tier": d.Tier, "until": d.Until, "drilled": d.Drilled}, nil); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: the %s copy %s is locked until %s, and the remote server did not record it: %v\n", d.Tier, d.SnapshotID, d.Until.UTC().Format("2006-01-02"), err)
			continue
		}
		what := "drilled"
		if !d.Drilled {
			what = "not drilled"
		}
		fmt.Fprintf(out, "Kept %s as the %s copy, locked until %s (%s).\n", d.SnapshotID, d.Tier, d.Until.UTC().Format("2006-01-02"), what)
	}
}

// lockOwnCopy locks one copy's objects: a repository snapshot's references,
// read from the snapshot object with this host's key, or an archive with its
// sidecars.
func lockOwnCopy(ctx context.Context, sc config.StorageConfig, key string, d keptCopyDue) error {
	if d.EpochID == "" {
		prov, err := storage.NewS3Storage(ctx, sc)
		if err != nil {
			return err
		}
		return prov.ExtendRetention(ctx, d.SnapshotID, d.Until)
	}
	if key == "" {
		return fmt.Errorf("this host holds no key to read the snapshot's object list with")
	}
	ids, err := unseal.Identities(key)
	if err != nil {
		return err
	}
	rs, err := locateRepoSnapshot(ctx, sc, d.SnapshotID)
	if err != nil {
		return err
	}
	if rs == nil {
		return fmt.Errorf("snapshot %s is not in this storage", d.SnapshotID)
	}
	direct, ok := rs.Backend.(*sink.Direct)
	if !ok {
		return fmt.Errorf("the snapshot's storage is not a bucket this host writes directly")
	}
	ext, ok := direct.S.(sink.Extender)
	if !ok {
		return nil
	}
	snap, err := read.Open(rs.Backend, rs.Epoch, ids).Snapshot(ctx, d.SnapshotID)
	if err != nil {
		return err
	}
	var keys []string
	add := func(kind sink.Kind, name string) {
		if k, err := sink.ObjectKey(rs.Epoch.Prefix, kind, name); err == nil {
			keys = append(keys, k)
		}
	}
	add(sink.KindEpoch, "")
	for _, p := range snap.Packs {
		add(sink.KindPack, p)
	}
	for _, r := range snap.Runs {
		add(sink.KindIndex, r)
	}
	add(sink.KindIndex, snap.RunID)
	add(sink.KindCatalog, snap.RunID)
	add(sink.KindSnapshot, snap.SnapshotID)
	add(sink.KindMeta, snap.SnapshotID)
	for _, k := range keys {
		if err := ext.Extend(ctx, k, d.Until); err != nil {
			return err
		}
	}
	// The recovery document, whichever was written; one that is absent is
	// not an error.
	for _, kind := range []sink.Kind{sink.KindRecovery, sink.KindRecoverySealed} {
		if k, err := sink.ObjectKey(rs.Epoch.Prefix, kind, snap.SnapshotID); err == nil {
			_ = ext.Extend(ctx, k, d.Until) // absent on one of the two by design
		}
	}
	return nil
}
