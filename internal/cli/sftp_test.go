package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// The secrets are resolved on a copy: the config a command may write back
// keeps the reference, never the password it names.
func TestSFTPSecretsResolveOnACopy(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("the key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SFTP_TEST_PASSWORD", "the password")
	st := config.StorageConfig{Type: config.StorageTypeSFTP, SFTP: &config.SFTPConfig{
		Password: "env:SFTP_TEST_PASSWORD", PrivateKey: "file:" + keyFile}}
	got, err := resolveSFTPSecrets(st)
	if err != nil {
		t.Fatal(err)
	}
	if got.SFTP.Password != "the password" || got.SFTP.PrivateKey != "the key" {
		t.Fatalf("resolved to %q and %q", got.SFTP.Password, got.SFTP.PrivateKey)
	}
	if st.SFTP.Password != "env:SFTP_TEST_PASSWORD" || st.SFTP.PrivateKey != "file:"+keyFile {
		t.Fatalf("resolving changed the config's own block: %+v", st.SFTP)
	}
	st.SFTP.Password = "env:SFTP_TEST_UNSET_VARIABLE"
	if _, err := resolveSFTPSecrets(st); err == nil {
		t.Fatal("an unset variable resolved")
	}
}
