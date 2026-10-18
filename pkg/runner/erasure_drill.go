package runner

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/safegrd/cli/pkg/erasure"
	"github.com/safegrd/cli/pkg/model"
)

// erasureAssertion reads the erasure record a snapshot names and, in a
// sandbox, replays it there after the row counts were checked against the
// manifest: a drill is how a customer learns the record cannot be read
// before the day a restore needs it. ok is false for a snapshot that names
// no record.
func (v *Verifier) erasureAssertion(ctx context.Context, meta *model.SnapshotMetadata, privateKey, sandboxURL string) (a model.AssertionResult, ok bool) {
	if meta.Erasures == nil {
		return a, false
	}
	a = model.AssertionResult{Name: "ErasuresReplayed", Expected: "the erasure record opens and replays"}
	if sandboxURL == "" {
		a.Name, a.Expected = "ErasureRecordReadable", "the erasure record opens"
	}
	if v.Erasures == nil {
		a.Actual = "no storage to read it from"
		a.Message = "The erasure record could not be read: this drill was not given the storage it is kept in"
		return a, true
	}
	recs, err := erasure.Load(ctx, v.Erasures, meta.Erasures.Path, privateKey)
	if err != nil {
		a.Actual, a.Message = "unreadable", err.Error()
		return a, true
	}
	w := erasure.Window{Snapshot: meta.SourceSnapshot, Started: meta.CreatedAt}
	after := 0
	for _, r := range recs {
		if w.Replays(r) {
			after++
		}
	}
	if sandboxURL == "" {
		a.Passed = true
		a.Actual = fmt.Sprintf("%d erasures, %d after this backup", len(recs), after)
		return a, true
	}
	res, err := replayInSandbox(ctx, sandboxURL, recs, w)
	if err != nil {
		a.Actual, a.Message = "replay failed", err.Error()
		return a, true
	}
	a.Passed = true
	a.Actual = fmt.Sprintf("%d replayed, %d rows deleted", res.Applied, res.Rows())
	if len(res.Missing) > 0 {
		a.Message = fmt.Sprintf("%d erasures name tables the sandbox does not have", len(res.Missing))
	}
	return a, true
}

func replayInSandbox(ctx context.Context, sandboxURL string, recs []erasure.Record, w erasure.Window) (erasure.Result, error) {
	conn, err := pgx.Connect(ctx, sandboxURL)
	if err != nil {
		return erasure.Result{}, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(ctx)
	if err != nil {
		return erasure.Result{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	res, err := erasure.Replay(ctx, conn, recs, w)
	if err != nil {
		return res, err
	}
	return res, tx.Commit(ctx)
}
