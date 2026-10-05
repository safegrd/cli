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
	doc := string(RenderRecoveryDoc(meta, Location{Kind: "s3", Bucket: "acme-backups", Endpoint: "https://s3.eu.example", Region: "eu-central-1",
		Prefix: "safegrd/snapshots/node-1", ConfigPrefix: "safegrd/snapshots"}))
	for _, want := range []string{
		"recovery document: snap-20261005-010203-abcdef", "PostgreSQL database shop", "Bucket:   acme-backups", "Endpoint: https://s3.eu.example",
		"Folder:   safegrd/snapshots/node-1/", "snap-20261005-010203-abcdef.safegrd (3.0 MiB", "Locked until 2026-10-19 (Object Lock, compliance mode)",
		"PostgreSQL 16 or newer", "pgcrypto, vector", "app_owner, app_user", "with their passwords",
		"curl -fsSL https://safegrd.dev/install.sh | sh", "https://github.com/safegrd/cli/releases",
		"SafeGrd-managed key: SafeGrd keeps your key sealed", "Customer-managed key:",
		"safegrd restore --snapshot snap-20261005-010203-abcdef --target env:TARGET_URL", "--to-sql ./out", "psql",
		"    bucket: acme-backups", "    prefix: safegrd/snapshots", "  node_id: node-1",
		"public.orders: only the 3 rows row-level security showed",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the document lacks %q:\n%s", want, doc)
		}
	}
	for _, banned := range []string{"go build", "\u2014", "Without SafeGrd's restore code"} {
		if strings.Contains(doc, banned) {
			t.Errorf("the document says %q:\n%s", banned, doc)
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if len(line) > 100 {
			t.Errorf("a line is %d columns: %q", len(line), line)
		}
	}
	hosted := string(RenderRecoveryDoc(&model.SnapshotMetadata{SnapshotID: "snap-x", SurfaceType: model.SurfaceTypeFiles, Format: model.SnapshotFormatRepo, EpochID: "ep-1"}, Location{Kind: "hosted"}))
	for _, want := range []string{"SafeGrd hosted storage", "Backup:   incremental", "snapshots/snap-x.meta.json", "--target-dir ./recovered", "On an enrolled host"} {
		if !strings.Contains(hosted, want) {
			t.Errorf("the hosted incremental document lacks %q:\n%s", want, hosted)
		}
	}
}

// Every surface gets its own needs, restore command and gaps.
func TestRecoveryDocCoversEverySurface(t *testing.T) {
	for surface, want := range map[model.SurfaceType]string{
		model.SurfaceTypePostgres: "--to-sql", model.SurfaceTypeMySQL: "mysql client", model.SurfaceTypeMongoDB: "mongorestore",
		model.SurfaceTypeSQLite: "sqlite:///", model.SurfaceTypeFiles: "--target-dir", model.SurfaceTypeEmail: ".eml",
	} {
		doc := string(RenderRecoveryDoc(&model.SnapshotMetadata{SnapshotID: "snap-" + string(surface), SurfaceType: surface}, Location{Kind: "local", Prefix: "/srv/backups/node-1"}))
		if !strings.Contains(doc, want) || !strings.Contains(doc, "Directory: /srv/backups/node-1") {
			t.Errorf("%s: the document lacks %q:\n%s", surface, want, doc)
		}
	}
}
