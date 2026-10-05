package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
)

var fromSafeGrd = &config.CredentialConfig{From: config.CredentialFromSafeGrd}

// A surface whose credential the remote server holds is written into the
// config as credential.from: safegrd, with no secret and no variable name;
// one whose credential stays on the host names its variable.
func TestAClaimedSurfaceIsWrittenWithWhereItsCredentialComesFrom(t *testing.T) {
	var s claimSurface
	s.Key, s.Name, s.SurfaceType = "app-db", "App DB", "postgres"
	s.Config.CredentialHeld = true
	sc := surfaceConfigFor(s)
	if !sc.FromSafeGrd() || sc.Credential.Name != "" || sc.DatabaseURL != "" {
		t.Errorf("a held database credential was written as %+v", sc)
	}
	s.SurfaceType = "email"
	if sc := surfaceConfigFor(s); !sc.FromSafeGrd() {
		t.Errorf("a held mailbox password was written as %+v", sc)
	}
	s.Config.CredentialHeld, s.Config.CredentialEnv, s.SurfaceType = false, "APP_DATABASE_URL", "postgres"
	if sc := surfaceConfigFor(s); sc.CredentialFrom() != config.CredentialFromEnv || sc.Credential.Name != "APP_DATABASE_URL" {
		t.Errorf("a host credential was written as %+v", sc.Credential)
	}
}

// A credential from SafeGrd is used as it is, and a surface that also names
// one on the host is refused: a credential has one origin.
func TestASurfaceCredentialHasOneOrigin(t *testing.T) {
	ctx := context.Background()
	c := &config.CLIConfig{DatabaseURL: "postgres://host-default"}
	s := &config.SurfaceConfig{ID: "app-db", Type: "postgres", Credential: fromSafeGrd, HeldSecret: "postgres://held"}
	if got, err := resolveSurfaceDatabaseURL(ctx, c, s); err != nil || got != "postgres://held" {
		t.Errorf("a held database URL resolved to %q (%v), not the held one", got, err)
	}
	if credentialSourceOf(s) != "held" {
		t.Errorf("a held surface reports its source as %q", credentialSourceOf(s))
	}
	s.DatabaseURL = "postgres://also-here"
	if _, err := resolveSurfaceDatabaseURL(ctx, c, s); err == nil || !strings.Contains(err.Error(), "one origin") {
		t.Errorf("a surface both from SafeGrd and with a database_url was not refused: %v", err)
	}
	m := &config.SurfaceConfig{ID: "support", Type: "email", Credential: fromSafeGrd, HeldSecret: "held-pass"}
	if got, _ := surfaceEmailPassword(ctx, m); got != "held-pass" {
		t.Errorf("a held mailbox password resolved to %q", got)
	}
	host := &config.SurfaceConfig{ID: "db", Type: "mysql", Credential: &config.CredentialConfig{From: "env", Name: "DB_URL"}}
	if credentialSourceOf(host) != "host" || credentialSourceOf(&config.SurfaceConfig{Type: "files"}) != "" {
		t.Error("the credential source is not reported as the config says")
	}
}

// A credential block that is incomplete or names an unknown source is
// refused in words, before anything is fetched or run.
func TestACredentialBlockSaysWhatIsMissing(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		cred *config.CredentialConfig
		want string
	}{
		{&config.CredentialConfig{}, "has no from"},
		{&config.CredentialConfig{From: "vault"}, `"vault"; it must be safegrd, env, command or file`},
		{&config.CredentialConfig{From: "env"}, "credential.name must name"},
		{&config.CredentialConfig{From: "command"}, "credential.run must be"},
		{&config.CredentialConfig{From: "file"}, "credential.path must be"},
	} {
		s := &config.SurfaceConfig{ID: "db", Type: "postgres", Credential: tc.cred}
		if _, err := resolveSurfaceDatabaseURL(ctx, &config.CLIConfig{}, s); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want an error saying %q", tc.cred, err, tc.want)
		}
	}
}

// A variable or file the block names and cannot deliver is an error that says
// which, never a quiet fall back to the host's own database_url.
func TestACredentialOnTheHostDoesNotFallBack(t *testing.T) {
	ctx := context.Background()
	c := &config.CLIConfig{DatabaseURL: "postgres://host-default/other"}
	t.Setenv("SAFEGRD_TEST_DB_URL", "")
	s := &config.SurfaceConfig{ID: "db", Type: "postgres", Credential: &config.CredentialConfig{From: "env", Name: "SAFEGRD_TEST_DB_URL"}}
	if got, err := resolveSurfaceDatabaseURL(ctx, c, s); err == nil || got != "" || !strings.Contains(err.Error(), "SAFEGRD_TEST_DB_URL") {
		t.Errorf("an unset variable resolved to %q (%v); want an error naming it", got, err)
	}
	t.Setenv("SAFEGRD_TEST_DB_URL", "postgres://from-env/app")
	if got, err := resolveSurfaceDatabaseURL(ctx, c, s); err != nil || got != "postgres://from-env/app" {
		t.Errorf("from env: %q, %v", got, err)
	}
	path := filepath.Join(t.TempDir(), "db-url")
	if err := os.WriteFile(path, []byte("postgres://from-file/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Credential = &config.CredentialConfig{From: "file", Path: path}
	if got, err := resolveSurfaceDatabaseURL(ctx, c, s); err != nil || got != "postgres://from-file/app" {
		t.Errorf("from file: %q, %v", got, err)
	}
	s.Credential.Path = filepath.Join(t.TempDir(), "missing")
	if _, err := resolveSurfaceDatabaseURL(ctx, c, s); err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("a missing file: %v", err)
	}
}

// The fetched credential lives in memory only. Saving the config, which
// several commands do, must not write it: a credential on disk would keep
// working after the remote server withdrew it.
func TestAHeldSurfaceCredentialNeverReachesTheConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.CLIConfig{Surfaces: []config.SurfaceConfig{{ID: "app-db", Type: "postgres",
		Credential: fromSafeGrd, HeldSecret: "postgres://app:s3cret@db/app"}}}
	if err := config.SaveCLIConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret") {
		t.Fatalf("the held credential was written to the config file:\n%s", raw)
	}
	if !strings.Contains(string(raw), "from: safegrd") {
		t.Errorf("the config does not say the credential comes from SafeGrd:\n%s", raw)
	}
}

// A host whose key the customer holds, in an organization where SafeGrd holds
// keys for other hosts, drilling with its key file gone: SafeGrd holds no key
// for this host's recipient, so nothing comes back, and stderr says where the
// key was looked for and which key it is (M91: the organization's other keys
// used to come back, for snapshots they could never open).
func TestAHostWithACustomerHeldKeyIsToldToPassIt(t *testing.T) {
	other, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	mine, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("recipient") != other.PublicKey {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "This is sealed to " + crypto.Fingerprint(r.URL.Query().Get("recipient")) + ", a key SafeGrd does not hold."})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"org_id":      "org-1",
			"identities":  []map[string]string{{"public_key": other.PublicKey, "identity": other.PrivateKey}},
			"key_custody": "safegrd",
			"notice":      "SafeGrd keeps your key sealed",
		})
	}))
	defer srv.Close()
	cfg := &config.CLIConfig{ServerURL: srv.URL, NodeID: "node-1", ServerToken: "sg_tok_x",
		Encryption: config.EncryptionConfig{PublicKey: mine.PublicKey, KeyPath: "/srv/keys/daemon.key"}}

	var got string
	stdout := captureStdout(t, func() {
		stderr := captureStderr(t, func() { got = resolveManagedIdentity(context.Background(), cfg, true) })
		if !strings.Contains(stderr, crypto.Fingerprint(mine.PublicKey)) || !strings.Contains(stderr, "/srv/keys/daemon.key") ||
			!strings.Contains(stderr, "SAFEGRD_PRIVATE_KEY") {
			t.Errorf("stderr does not say which key, where it was looked for, and how to pass it:\n%s", stderr)
		}
	})
	if got != "" {
		t.Error("a customer-held host was given the organization's other keys")
	}
	if strings.Contains(stdout, "SafeGrd-managed") || strings.Contains(stdout, "sealed") {
		t.Errorf("a customer-held host was told SafeGrd holds its key:\n%s", stdout)
	}

	// A managed host: its own key comes back, said where from, and no warning.
	cfg.Encryption.PublicKey = other.PublicKey
	stdout = captureStdout(t, func() {
		if stderr := captureStderr(t, func() { got = resolveManagedIdentity(context.Background(), cfg, true) }); stderr != "" {
			t.Errorf("a managed host was warned:\n%s", stderr)
		}
	})
	if got != other.PrivateKey || !strings.Contains(stdout, crypto.Fingerprint(other.PublicKey)+", SafeGrd-managed key of org org-1") {
		t.Errorf("a managed host was not given its key and told where it came from:\n%s", stdout)
	}
}
