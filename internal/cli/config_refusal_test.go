package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
	"github.com/spf13/cobra"
)

// withRefusedConfig writes a complete, correct configuration at group-readable
// permissions and runs the real load path over it, exactly as a command
// invocation does. The file is deliberately valid: the whole point is that
// nothing was wrong with its contents.
func withRefusedConfig(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "server_url: https://safegrd.dev\n" +
		"database_url: postgres://user:pass@localhost:5432/mydb\n" +
		"encryption:\n" +
		"  public_key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n" +
		"storage:\n" +
		"  type: local\n" +
		"  local_path: ./store\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	savedFile, savedCfg, savedErr := cfgFile, cfg, cfgLoadErr
	t.Cleanup(func() { cfgFile, cfg, cfgLoadErr = savedFile, savedCfg, savedErr })

	cfgFile, cfgLoadErr = path, nil
	initConfig()
	if cfgLoadErr == nil {
		t.Fatalf("a 0644 config was accepted; the permission check is what this test rests on")
	}
	return path
}

// A refused config must fail the command with the refusal, not with a symptom
// of the empty config that replaced it.
//
// The defect this pins: a 0644 file reported `database_url is required` about a
// config whose database_url was on line 4, and the operator's next hour went
// into the connection string.
func TestARefusedConfigFailsTheCommandWithTheRefusal(t *testing.T) {
	withRefusedConfig(t)

	err := requireUsableConfig(newBackupCmd())
	if err == nil {
		t.Fatal("backup ran on the defaults that were substituted for a refused config")
	}

	got := err.Error()
	if !strings.Contains(got, "insecure config file permissions") {
		t.Errorf("the refusal is not in the error the operator sees: %q", got)
	}
	for _, symptom := range []string{"database_url is required", "public_key is required"} {
		if strings.Contains(got, symptom) {
			t.Errorf("the error reports %q, which is about the empty config rather than the real one: %q", symptom, got)
		}
	}
}

// The usage block is suppressed for anything raised past flag parsing. The
// warning was previously printed and then buried under forty lines of flag help.
func TestPastFlagParsingNoFailureDragsTheUsageBlockWithIt(t *testing.T) {
	withRefusedConfig(t)

	cmd := newBackupCmd()
	_ = requireUsableConfig(cmd)
	if !cmd.SilenceUsage {
		t.Error("usage is still printed for an error that is not a usage error")
	}
}

// The commands that exist to report or repair this state must still run, or an
// operator with a bad config has no command that will talk to them about it.
func TestTheCommandsThatDiagnoseTheConfigStillRun(t *testing.T) {
	withRefusedConfig(t)

	configCmd := newConfigCmd()
	validate, _, err := configCmd.Find([]string{"validate"})
	if err != nil {
		t.Fatalf("config validate is not reachable: %v", err)
	}

	for _, c := range []*cobra.Command{
		validate,
		newDoctorCmd(),
		newInitCmd(),
		newVersionCmd(),
	} {
		if err := requireUsableConfig(c); err != nil {
			t.Errorf("%q was blocked by the refused config it exists to report: %v", c.Name(), err)
		}
	}
}

// `config validate` must not describe the substituted defaults as if they were
// the operator's file: it previously reported "encryption.public_key is missing
// (run 'safegrd init')" about a file whose public key was present and unread.
func TestConfigValidateDoesNotJudgeTheDefaultsItSubstituted(t *testing.T) {
	path := withRefusedConfig(t)

	results := runValidationChecks(path, cfg)

	var sawLoadFailure bool
	for _, r := range results {
		if r.Name == "Configuration Load" && r.Status == "FAIL" {
			sawLoadFailure = true
		}
		if r.Name == "Encryption Public Key" {
			t.Errorf("the public key was judged from defaults: %s: %s", r.Status, r.Message)
		}
	}
	if !sawLoadFailure {
		t.Error("the refusal itself was never reported as a check")
	}
}

// An alert block in the host config was never read, so a host that set one
// believed it was alerting. Validation now says so.
func TestAnUnusedAlertBlockIsNamed(t *testing.T) {
	c := config.NewDefaultCLIConfig()
	if unusedAlertBlock(c) != "" {
		t.Error("an empty alert block was reported")
	}
	c.Alert.SlackWebhookURL = "https://hooks.slack.com/services/T/B/x"
	if msg := unusedAlertBlock(c); !strings.Contains(msg, "Settings → Alerts") {
		t.Errorf("a set alert block was not explained: %q", msg)
	}
}

// Keys the agent accepts and ignores are named when set, and only then.
func TestIgnoredConfigKeysAreNamed(t *testing.T) {
	c := config.NewDefaultCLIConfig()
	c.Agent.LogFormat, c.Agent.LogLevel, c.Defaults.Timezone = "text", "info", "UTC"
	if got := ignoredConfigKeys(c); len(got) != 0 {
		t.Errorf("defaults were reported as ignored: %v", got)
	}
	c.Agent.MaxConcurrent = 4
	c.Agent.MetricsAddr = "127.0.0.1:9847"
	c.Defaults.Timezone = "Asia/Kolkata"
	got := strings.Join(ignoredConfigKeys(c), "\n")
	for _, want := range []string{"agent.max_concurrent", "agent.metrics_addr", "defaults.timezone"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s not named:\n%s", want, got)
		}
	}
}

// A key the config does not know is named, with its line: YAML ignores it,
// so a misspelt retention_days silently fell back to the default.
func TestUnknownConfigKeysAreNamed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("storage:\n  type: local\n  retention_day: 90\nencryption:\n  private_key: legacy\nsurfaces:\n  - id: a\n    type: files\n    root: [/srv]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadCLIConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(c.UnknownKeys, " | ")
	for _, want := range []string{"line 3: storage.retention_day", "line 9: surfaces[].root"} {
		if !strings.Contains(got, want) {
			t.Errorf("unknown keys %q do not name %q", got, want)
		}
	}
	if strings.Contains(got, "private_key") {
		t.Errorf("the migrated private_key was reported as unknown: %s", got)
	}
	var saw bool
	for _, r := range runValidationChecks(path, c) {
		if r.Name == "Unknown Key" && strings.Contains(r.Message, "storage.retention_day") {
			saw = true
		}
	}
	if !saw {
		t.Error("config validate does not report the unknown key")
	}
}
