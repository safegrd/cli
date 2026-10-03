package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
)

func TestTheDestructiveListMatchesWhatItNames(t *testing.T) {
	for _, c := range []string{
		`psql "$DATABASE_URL" -c 'DROP TABLE sessions'`,
		`psql -c "drop database app"`,
		`psql -c 'ALTER TABLE users DROP COLUMN email'`,
		`echo 'DROP SCHEMA public CASCADE;' | psql`,
		`psql -c 'TRUNCATE users'`,
		`psql -c "truncate table orders restart identity"`,
		`psql -c 'DELETE FROM users;'`,
		`dropdb app_production`,
		`terraform destroy -auto-approve`,
		`terraform -chdir=infra destroy`,
		`terraform apply -destroy`,
		`tofu destroy`,
		`npx prisma migrate reset --force`,
		`pnpm prisma db push --force-reset`,
		`supabase db reset --linked`,
		`bin/rails db:drop`,
		`bundle exec rake db:reset`,
		`python manage.py flush --noinput`,
	} {
		if matchDestructive(c) == nil {
			t.Errorf("not matched: %s", c)
		}
	}
	for _, c := range []string{
		`psql -c 'SELECT * FROM drop_log'`,
		`psql -c "DELETE FROM sessions WHERE expires_at < now()"`,
		`terraform plan`,
		`terraform apply`,
		`npx prisma migrate deploy`,
		`supabase db push`,
		`ls -la`,
		`git reset --hard`,
		`bin/rails db:migrate`,
	} {
		if r := matchDestructive(c); r != nil {
			t.Errorf("matched %q as %s", c, r.Name)
		}
	}
}

func TestOnlyAnObjectLockedSnapshotCountsAsLocked(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	later := now.Add(24 * time.Hour)
	for _, c := range []struct {
		name string
		meta model.SnapshotMetadata
		want bool
	}{
		{"s3 compliance", model.SnapshotMetadata{StorageURI: "s3://b/k", WORMMode: "COMPLIANCE", WORMRetentionUntil: later}, true},
		{"s3 governance", model.SnapshotMetadata{StorageURI: "s3://b/k", WORMMode: "GOVERNANCE", WORMRetentionUntil: later}, true},
		{"worm none", model.SnapshotMetadata{StorageURI: "s3://b/k", WORMMode: "NONE", WORMRetentionUntil: later}, false},
		{"local directory", model.SnapshotMetadata{StorageURI: "file:///var/x", WORMMode: "COMPLIANCE", WORMRetentionUntil: later}, false},
		{"expired", model.SnapshotMetadata{StorageURI: "s3://b/k", WORMMode: "COMPLIANCE", WORMRetentionUntil: now}, false},
		{"no date", model.SnapshotMetadata{StorageURI: "s3://b/k", WORMMode: "COMPLIANCE"}, false},
	} {
		got, why := snapshotLocked(&c.meta, now)
		if got != c.want {
			t.Errorf("%s: locked = %v (%s), want %v", c.name, got, why, c.want)
		}
		if !got && strings.Contains(why, "until") {
			t.Errorf("%s: an unlocked snapshot is described with a lock date: %s", c.name, why)
		}
	}
}

// guardConfig points cfg at a files surface on local storage.
func guardConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := cfg
	t.Cleanup(func() { cfg = old })
	cfg = config.NewDefaultCLIConfig()
	cfg.ServerURL, cfg.ServerToken = "", ""
	cfg.NodeID = "node-guard"
	cfg.Storage.LocalPath = filepath.Join(dir, "store")
	cfg.Encryption.PublicKey = kp.PublicKey
	cfg.Daemon.StateDir = filepath.Join(dir, "state")
	cfg.Surfaces = []config.SurfaceConfig{{ID: "docs", Type: "files", Format: "tar", Roots: []string{src}}}
	return dir
}

// A backup to a directory on the host is not locked: whoever runs the
// destructive command can delete it too. Guard refuses unless told otherwise.
func TestGuardRefusesAnUnlockedSnapshotUnlessAllowed(t *testing.T) {
	guardConfig(t)
	ctx := context.Background()

	var err error
	_, errOut, _ := captureStdoutErr(t, func() error {
		_, err = guardSnapshot(ctx, "", false, "'rm -rf data'")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "not locked") {
		t.Fatalf("guard accepted a snapshot on local storage: %v", err)
	}
	if strings.Contains(errOut, "🔒") {
		t.Errorf("an unlocked snapshot was announced as locked:\n%s", errOut)
	}

	var meta *model.SnapshotMetadata
	out, _, _ := captureStdoutErr(t, func() error {
		meta, err = guardSnapshot(ctx, "docs", true, "'rm -rf data'")
		return nil
	})
	if err != nil || meta == nil || meta.Status != model.SnapshotStatusCompleted {
		t.Fatalf("with --allow-unlocked: meta=%v err=%v", meta, err)
	}
	if out != "" {
		t.Errorf("guard wrote to stdout, which belongs to the wrapped command:\n%s", out)
	}
}

// A backup that fails leaves nothing to restore, so the command does not run.
func TestGuardRefusesWhenTheBackupFails(t *testing.T) {
	dir := guardConfig(t)
	cfg.Surfaces[0].Roots = []string{filepath.Join(dir, "missing")}
	var err error
	captureStdoutErr(t, func() error {
		_, err = guardSnapshot(context.Background(), "", true, "")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "backup of docs failed") {
		t.Fatalf("a failed backup did not refuse: %v", err)
	}
}

func TestGuardNeedsASurfaceWhenTheConfigHasSeveral(t *testing.T) {
	guardConfig(t)
	cfg.Surfaces = append(cfg.Surfaces, config.SurfaceConfig{ID: "mail", Type: "email"})
	if _, _, err := guardSurface(""); err == nil || !strings.Contains(err.Error(), "docs, mail") {
		t.Errorf("two surfaces and no --surface: %v", err)
	}
	if _, _, err := guardSurface("nope"); err == nil || !strings.Contains(err.Error(), `no surface "nope"`) {
		t.Errorf("an unknown surface: %v", err)
	}
	s, standalone, err := guardSurface("mail")
	if err != nil || s.ID != "mail" || standalone {
		t.Errorf("--surface mail: %v %v %v", s, standalone, err)
	}
}

// guard echoes the command it is about to run, and a database URL in it
// carries a password that must not reach the terminal or an agent's log.
func TestGuardEchoHidesAPasswordInAURL(t *testing.T) {
	got := describeCommand([]string{"psql", "postgres://app:s3cret@db:5432/shop", "-c", "DROP TABLE x"})
	if strings.Contains(got, "s3cret") {
		t.Errorf("describeCommand printed the password: %s", got)
	}
	if !strings.Contains(got, "postgres://app:xxxxx@db:5432/shop") {
		t.Errorf("describeCommand = %s, want the URL with the password replaced", got)
	}
}
