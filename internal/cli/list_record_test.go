package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// list reads the server's record of every snapshot in pages of 200. A page
// passed 1 MiB once records named their tables (an organization with 4,165
// snapshots sent pages of up to 1.5 MB), getJSON cut it at 1 MiB, and list
// warned the answer "does not parse" and fell back to reading each
// snapshot's sidecar from storage one at a time.
func TestListReadsARecordPageLargerThanOneMebibyte(t *testing.T) {
	pad := strings.Repeat("t", 8<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/snapshots" {
			http.NotFound(w, r)
			return
		}
		items := make([]string, 200)
		for i := range items {
			items[i] = fmt.Sprintf(`{"snapshot_id":"snap-20261102-000000-%06d","node_id":"node-1","tables_padding":%q}`, i, pad)
		}
		fmt.Fprintf(w, `{"items":[%s],"next_cursor":""}`, strings.Join(items, ","))
	}))
	defer srv.Close()

	saved := cfg
	defer func() { cfg = saved }()
	cfg = &config.CLIConfig{ServerURL: srv.URL, NodeID: "node-1", ServerToken: "sg_tok_x"}

	r, err := recordedSnapshots(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if r.by == nil {
		t.Fatal("the record page over 1 MiB was not read: list falls back to every sidecar")
	}
	if len(r.by) != 200 || r.by["snap-20261102-000000-000199"] == nil {
		t.Fatalf("read %d of 200 records", len(r.by))
	}
}

// An answer past the cap is refused in words that say so, not as JSON that
// "does not parse".
func TestGetJSONSaysWhenAnAnswerIsTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items":["`))
		w.Write([]byte(strings.Repeat("x", maxGetJSONBytes)))
		w.Write([]byte(`"]}`))
	}))
	defer srv.Close()

	var out struct{}
	_, err := getJSON(context.Background(), &config.CLIConfig{ServerURL: srv.URL, ServerToken: "sg_tok_x"}, "/api/v1/snapshots?limit=200", &out)
	if err == nil || !strings.Contains(err.Error(), "/api/v1/snapshots is larger than 64 MiB") {
		t.Fatalf("got %v, want the answer refused as too large", err)
	}
}

// list shows the newest of both tables, each in its own order, and counts
// the rest. A snapshot's time is read from its id; an id that names none
// (a tagged backup) takes the remote server's record of it.
func TestListKeepsTheNewestOfBothTables(t *testing.T) {
	ids := []string{"snap-20261001-000000-aaaaaa", "snap-20261005-000000-bbbbbb", "snap-release-v2-cccccc"}
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	rows := []repoSnapshot{
		{Meta: &model.SnapshotMetadata{SnapshotID: "snap-20261002-000000-dddddd", CreatedAt: at("2026-10-02T00:00:00Z")}},
		{Meta: &model.SnapshotMetadata{SnapshotID: "snap-20261007-000000-eeeeee", CreatedAt: at("2026-10-07T00:00:00Z")}},
	}
	recorded := &recordedList{by: map[string]*model.SnapshotMetadata{
		"snap-release-v2-cccccc": {SnapshotID: "snap-release-v2-cccccc", CreatedAt: at("2026-10-06T00:00:00Z")},
	}}
	gotIDs, gotRows, older := newestListed(ids, rows, recorded, 3)
	if strings.Join(gotIDs, ",") != "snap-20261005-000000-bbbbbb,snap-release-v2-cccccc" {
		t.Errorf("kept %v of the archives", gotIDs)
	}
	if len(gotRows) != 1 || gotRows[0].Meta.SnapshotID != "snap-20261007-000000-eeeeee" {
		t.Errorf("kept %+v of the repository runs", gotRows)
	}
	if older != 2 {
		t.Errorf("%d left out, want 2", older)
	}
	if i, r, o := newestListed(ids, rows, recorded, 5); len(i) != 3 || len(r) != 2 || o != 0 {
		t.Errorf("with room for all five: %d, %d, %d left out", len(i), len(r), o)
	}
}

// A backup locked a day and kept a week says both: the record's lock, and
// the week hosted storage keeps it, which the list carries beside the
// record and the sidecar list once read had.
func TestAListedRecordKeepsTheDateStorageDeletesIt(t *testing.T) {
	lock := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	kept := lock.AddDate(0, 0, 6)
	r := &listedRecord{SnapshotMetadata: model.SnapshotMetadata{SnapshotID: "snap-1", WORMRetentionUntil: lock, WORMMode: "COMPLIANCE"}, StorageKeptUntil: &kept}
	if m := r.metadata(); m.KeptUntil == nil || !m.KeptUntil.Equal(kept) {
		t.Fatalf("kept until %v, want %v", m.KeptUntil, kept)
	}
	if got := describeRetention(r.metadata(), config.StorageConfig{Type: config.StorageTypeHosted}); !strings.Contains(got, ", kept until 2026-11-09 10:00 UTC") {
		t.Errorf("list says %q", got)
	}
	early := lock.Add(-time.Hour)
	r.StorageKeptUntil = &early
	if m := r.metadata(); m.KeptUntil != nil {
		t.Errorf("a keep date before the lock ends is shown: %v", m.KeptUntil)
	}
}

// Two runs in the same second: the one listed later is the newer.
func TestListBreaksATieByWhichWasListedLater(t *testing.T) {
	at := time.Date(2026, 11, 2, 10, 31, 26, 0, time.UTC)
	rows := []repoSnapshot{
		{Meta: &model.SnapshotMetadata{SnapshotID: "snap-20261102-103126-aaaaaa", CreatedAt: at}},
		{Meta: &model.SnapshotMetadata{SnapshotID: "snap-20261102-103126-bbbbbb", CreatedAt: at}},
	}
	_, kept, older := newestListed(nil, rows, &recordedList{}, 1)
	if len(kept) != 1 || kept[0].Meta.SnapshotID != "snap-20261102-103126-bbbbbb" || older != 1 {
		t.Fatalf("kept %+v, %d older", kept, older)
	}
}
