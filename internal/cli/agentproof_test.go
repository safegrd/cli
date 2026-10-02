package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

func TestTheAccountCheckComparesProviders(t *testing.T) {
	for _, c := range []struct {
		name, db, endpoint string
		st                 config.StorageType
		want               string
	}{
		{"supabase db, aws bucket", "postgres://u:p@db.abcd.supabase.co:5432/postgres", "", config.StorageTypeS3, "PASS"},
		{"rds db, aws bucket", "postgres://u:p@app.cluster-x.us-east-1.rds.amazonaws.com/app", "", config.StorageTypeS3, "WARN"},
		{"rds db, r2 bucket", "postgres://u:p@app.cluster-x.us-east-1.rds.amazonaws.com/app", "https://acct.r2.cloudflarestorage.com", config.StorageTypeS3, "PASS"},
		{"localhost db", "postgres://u:p@localhost/app", "", config.StorageTypeS3, "WARN"},
		{"local storage", "postgres://u:p@db.abcd.supabase.co/postgres", "", config.StorageTypeLocal, "FAIL"},
		{"hosted storage", "postgres://u:p@localhost/app", "", config.StorageTypeHosted, "PASS"},
	} {
		t.Run(c.name, func(t *testing.T) {
			conf := config.NewDefaultCLIConfig()
			conf.DatabaseURL = c.db
			got := accountCheck(conf, config.StorageConfig{Type: c.st, Bucket: "b", Endpoint: c.endpoint, LocalPath: "/var/lib/safegrd"})
			if got.Status != c.want {
				t.Errorf("status %s, want %s: %s", got.Status, c.want, got.Message)
			}
			if got.Status == "FAIL" && got.Fix == "" {
				t.Errorf("a failure names no fix: %+v", got)
			}
			if strings.Contains(got.Message, "u:p") {
				t.Errorf("the message carries the credential: %s", got.Message)
			}
		})
	}
}

func TestLocalStorageIsNotAgentProof(t *testing.T) {
	res := storageAgentChecks(context.Background(), config.NewDefaultCLIConfig(), config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: "/srv/b"})
	for _, r := range res {
		if r.Status != "FAIL" || r.Fix == "" {
			t.Errorf("local storage: %+v", r)
		}
	}
}

func TestADrillIsNeededOnRecord(t *testing.T) {
	conf := config.NewDefaultCLIConfig()
	conf.ServerToken = ""
	res := drillChecks(context.Background(), conf)
	if len(res) != 1 || res[0].Status != "FAIL" || !strings.Contains(res[0].Fix, "safegrd enroll") {
		t.Errorf("an unenrolled host: %+v", res)
	}
}

func TestTheAgentTokenCheckNeverPrintsTheToken(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	node := write("node.json", `{"mcpServers":{"safegrd":{"type":"http","url":"https://safegrd.dev/mcp","headers":{"Authorization":"Bearer sg_tok_secretnodetoken"}}}}`)
	pat := write("pat.json", `{"mcpServers":{"safegrd":{"type":"http","url":"https://safegrd.dev/mcp","headers":{"Authorization":"Bearer sg_pat_secretpersonal"}}}}`)
	local := write("local.json", `{"mcpServers":{"safegrd":{"command":"safegrd","args":["mcp"]}}}`)
	other := write("other.json", `{"mcpServers":{"github":{"command":"gh"}}}`)

	for _, c := range []struct {
		files []string
		want  string
	}{
		{[]string{pat, node}, "FAIL"},
		{[]string{pat}, "PASS"},
		{[]string{local}, "PASS"},
		{[]string{other}, "WARN"},
		{nil, "WARN"},
	} {
		got := agentTokenCheckIn(c.files)
		if got.Status != c.want {
			t.Errorf("%v: %s, want %s (%s)", c.files, got.Status, c.want, got.Message)
		}
		if strings.Contains(got.Message+got.Fix, "secret") {
			t.Errorf("the token is printed: %s", got.Message)
		}
	}
}
