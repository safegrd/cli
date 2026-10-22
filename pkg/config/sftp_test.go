package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sftpBlock = `storage:
  type: sftp
%s  retention_days: 7
  sftp:
    host: backup.example.com
    user: backup
    path: upload
    password: env:SFTP_PASSWORD
    host_key: SHA256:2QJ5oGyc4Yd8QOUo7aHgKJ0kD0tq3bW8jE3m1n0p4rs
`

func loadSFTP(t *testing.T, worm string) (*CLIConfig, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(strings.Replace(sftpBlock, "%s", worm, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadCLIConfig(p)
}

// An SFTP server has no Object Lock. A config that asks for a lock there, or
// leaves worm_mode to its default (COMPLIANCE), is refused when it is read,
// before any command can print a lock nothing enforces.
func TestAnSFTPStorageTakesOnlyWormModeNone(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"unset", ""},
		{"COMPLIANCE", "  worm_mode: COMPLIANCE\n"},
		{"GOVERNANCE", "  worm_mode: GOVERNANCE\n"},
		{"lowercase none", "  worm_mode: none\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadSFTP(t, tc.line)
			if err == nil || !strings.Contains(err.Error(), "SFTP server has no Object Lock") || !strings.Contains(err.Error(), "worm_mode: NONE") {
				t.Fatalf("worm_mode %s on sftp storage was not refused with the fix: %v", tc.name, err)
			}
		})
	}
	cfg, err := loadSFTP(t, "  worm_mode: NONE\n")
	if err != nil {
		t.Fatalf("worm_mode NONE on sftp storage was refused: %v", err)
	}
	if cfg.Storage.Type != StorageTypeSFTP || cfg.Storage.SFTP == nil || cfg.Storage.SFTP.Host != "backup.example.com" {
		t.Fatalf("the sftp block did not load: %+v", cfg.Storage)
	}
	if len(cfg.UnknownKeys) != 0 {
		t.Fatalf("the sftp block's keys read as unknown: %v", cfg.UnknownKeys)
	}
}

func TestAnSFTPStorageNamesWhatIsMissing(t *testing.T) {
	base := func() StorageConfig {
		return StorageConfig{Type: StorageTypeSFTP, WORMMode: WORMModeNone, SFTP: &SFTPConfig{
			Host: "h", User: "u", Path: "p", Password: "env:X", HostKey: "SHA256:abc"}}
	}
	for _, tc := range []struct {
		name string
		edit func(*StorageConfig)
		want string
	}{
		{"no block", func(c *StorageConfig) { c.SFTP = nil }, "no storage.sftp block"},
		{"no host", func(c *StorageConfig) { c.SFTP.Host = "" }, "sftp.host is required"},
		{"no user", func(c *StorageConfig) { c.SFTP.User = "" }, "sftp.user is required"},
		{"no path", func(c *StorageConfig) { c.SFTP.Path = "" }, "sftp.path is required"},
		{"no credential", func(c *StorageConfig) { c.SFTP.Password = "" }, "password or private_key"},
		{"no host key", func(c *StorageConfig) { c.SFTP.HostKey = "" }, "known_hosts or host_key"},
		{"md5 host key", func(c *StorageConfig) { c.SFTP.HostKey = "aa:bb" }, "not a SHA256 fingerprint"},
		{"block on s3", func(c *StorageConfig) { c.Type = StorageTypeS3 }, "set type: sftp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.edit(&c)
			err := c.ValidateSFTP("storage")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error saying %q", err, tc.want)
			}
		})
	}
	c := base()
	if err := c.ValidateSFTP("storage"); err != nil {
		t.Fatalf("a complete sftp block was refused: %v", err)
	}
}
