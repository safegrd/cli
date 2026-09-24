package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// ResolveSecretRef resolves a secret value from a reference (e.g. "env:VAR_NAME" or "file:/path/to/secret")
// or directly from a raw value while emitting a security warning to stderr.
func ResolveSecretRef(flagName, val string) (string, error) {
	if val == "" {
		return "", nil
	}

	if strings.HasPrefix(val, "env:") {
		envVar := strings.TrimPrefix(val, "env:")
		resolved := os.Getenv(envVar)
		if resolved == "" {
			return "", fmt.Errorf("secret reference %s: environment variable %q is not set or empty", flagName, envVar)
		}
		return resolved, nil
	}

	if strings.HasPrefix(val, "file:") {
		filePath := strings.TrimPrefix(val, "file:")
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("secret reference %s: failed to read file %q: %w", flagName, filePath, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	// Raw secret passed as flag - warn operator about process table exposure
	fmt.Fprintf(os.Stderr, "⚠️  Security Warning: Passing credentials via --%s exposes secrets in `ps` and shell history. Use 'env:VAR' or 'file:/path' reference instead.\n", flagName)
	return val, nil
}

// credentialCommandTimeout bounds a secret manager that hangs, which under a
// daemon would otherwise stall every surface behind it.
const credentialCommandTimeout = 30 * time.Second

// runCredentialCommand runs a surface's credential_command and returns its
// stdout, less trailing newlines, as the secret. The command is a
// config value, so a writable config is code execution: that is why the config
// loader refuses a file anyone but its owner can read. Stdout is the secret and
// never appears in an error; stderr does, since that is where a secret manager
// explains itself ("not signed in").
func runCredentialCommand(ctx context.Context, surfaceID, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, credentialCommandTimeout)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("surface %s: credential_command did not finish within %s", surfaceID, credentialCommandTimeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		if msg != "" {
			return "", fmt.Errorf("surface %s: credential_command failed: %v: %s", surfaceID, err, msg)
		}
		return "", fmt.Errorf("surface %s: credential_command failed: %v", surfaceID, err)
	}
	secret := strings.TrimRight(stdout.String(), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("surface %s: credential_command printed nothing", surfaceID)
	}
	return secret, nil
}

// surfaceEmailPassword resolves a mailbox password in this order:
// credential_command, then password_env, then SAFEGRD_EMAIL_PASSWORD. A
// command that is set and fails is the answer: it is never papered over by an
// environment variable left behind from an older setup.
func surfaceEmailPassword(ctx context.Context, s *config.SurfaceConfig) (string, error) {
	if s.CredentialCommand != "" {
		return runCredentialCommand(ctx, s.ID, s.CredentialCommand)
	}
	if s.PasswordEnv != "" {
		if v := os.Getenv(s.PasswordEnv); v != "" {
			return v, nil
		}
	}
	return os.Getenv("SAFEGRD_EMAIL_PASSWORD"), nil
}

// resolveSurfaceDatabaseURL is the database a Postgres surface backs up:
// database_url, database_url_env, then credential_command (whose output is
// the whole URL), then the host's database_url.
func resolveSurfaceDatabaseURL(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (string, error) {
	url := s.DatabaseURL
	if url == "" && s.DatabaseURLEnv != "" {
		url = os.Getenv(s.DatabaseURLEnv)
	}
	if url == "" && s.CredentialCommand != "" {
		return runCredentialCommand(ctx, s.ID, s.CredentialCommand)
	}
	if url == "" {
		url = c.DatabaseURL
	}
	if strings.HasPrefix(url, "env:") || strings.HasPrefix(url, "file:") {
		return ResolveSecretRef("database_url", url)
	}
	return url, nil
}
