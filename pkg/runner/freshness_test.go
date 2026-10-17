package runner

import (
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

func TestTheNewestRowInTheSandboxIsHeldToTheOneRecorded(t *testing.T) {
	meta := &model.SnapshotMetadata{TableStats: []model.TableStat{
		{Schema: "public", TableName: "orders", FreshnessColumn: "updated_at", FreshnessMax: "2026-10-01T15:20:00.000000Z"},
		{Schema: "public", TableName: "events", FreshnessColumn: "created_at", FreshnessMax: "2026-10-02T00:00:00.000000Z"},
		{Schema: "public", TableName: "plain"},
	}}
	restored := &model.SnapshotMetadata{TableStats: []model.TableStat{
		{Schema: "public", TableName: "orders", FreshnessColumn: "updated_at", FreshnessMax: "2026-10-01T15:20:00.000000Z"},
		{Schema: "public", TableName: "events", FreshnessColumn: "created_at", FreshnessMax: "2026-09-30T00:00:00.000000Z"},
		{Schema: "public", TableName: "plain"},
	}}
	got, passed := newestRowAssertions(meta, restored)
	if passed {
		t.Fatal("a sandbox whose events table ends two days early passed")
	}
	if len(got) != 2 {
		t.Fatalf("%d assertions, want one per table with a recorded newest row: %+v", len(got), got)
	}
	if !got[0].Passed || got[0].Name != "Newest Row: public.orders" {
		t.Errorf("orders: %+v", got[0])
	}
	if got[1].Passed || got[1].Actual != "created_at 2026-09-30T00:00:00.000000Z" || got[1].Message == "" {
		t.Errorf("events: %+v", got[1])
	}

	restored.TableStats[1].FreshnessMax = ""
	if got, passed := newestRowAssertions(meta, restored); passed || got[1].Actual != "no rows" {
		t.Errorf("an empty table in the sandbox: passed %v, %+v", passed, got[1])
	}
}
