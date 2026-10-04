package dump

import (
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// The document names where the snapshot is, what a restore needs and the
// commands, and nothing its renderer was never given: Location carries no
// credential, so none can appear.
func TestRecoveryDocSaysWhereWhatAndHow(t *testing.T) {
	meta := &model.SnapshotMetadata{
		SnapshotID: "snap-20261005-010203-abcdef", NodeID: "node-1", SurfaceType: model.SurfaceTypePostgres,
		DatabaseName: "shop", CreatedAt: time.Date(2026, 10, 5, 1, 2, 3, 0, time.UTC), PostgresVersion: "PostgreSQL 16.4 on x86_64",
		Extensions: []string{"pgcrypto", "vector"}, RolesNamed: []string{"app_owner", "app_user"}, RolesSource: "pg_dumpall 16.4",
		EncryptedSizeBytes: 3 << 20, Sha256Checksum: "deadbeef", WORMMode: "COMPLIANCE",
		WORMRetentionUntil: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC),
		TableStats:         []model.TableStat{{Schema: "public", TableName: "orders", RowCount: 3, RowSecurity: true}},
	}
	doc := string(RenderRecoveryDoc(meta, Location{Kind: "s3", Bucket: "acme-backups", Endpoint: "https://s3.eu.example", Region: "eu-central-1", Prefix: "safegrd/snapshots/node-1"}))
	for _, want := range []string{
		"snapshot snap-20261005-010203-abcdef", "PostgreSQL database shop", "Bucket acme-backups at https://s3.eu.example",
		"snap-20261005-010203-abcdef.safegrd, 3.0 MiB", "Locked until 2026-10-19 (COMPLIANCE)",
		"PostgreSQL 16 or newer", "pgcrypto, vector", "app_owner, app_user", "with their passwords",
		"safegrd restore --snapshot snap-20261005-010203-abcdef --target env:TARGET_URL", "--to-sql ./out", "psql",
		"    bucket: acme-backups", "    prefix: safegrd/snapshots", "  node_id: node-1",
		"public.orders: only the rows row-level security showed",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the document lacks %q:\n%s", want, doc)
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if len(line) > 100 {
			t.Errorf("a line is %d columns: %q", len(line), line)
		}
	}
	hosted := string(RenderRecoveryDoc(&model.SnapshotMetadata{SnapshotID: "snap-x", SurfaceType: model.SurfaceTypeFiles, Format: model.SnapshotFormatRepo, EpochID: "ep-1"}, Location{Kind: "hosted"}))
	if !strings.Contains(hosted, "SafeGrd hosted storage") || !strings.Contains(hosted, "epoch ep-1") || !strings.Contains(hosted, "--target-dir ./recovered") {
		t.Errorf("the hosted files document:\n%s", hosted)
	}
}
