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

// runCredentialCommand runs a surface's credential.run command and returns its
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
			return "", fmt.Errorf("surface %s: credential.run did not finish within %s", surfaceID, credentialCommandTimeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		if msg != "" {
			return "", fmt.Errorf("surface %s: credential.run failed: %v: %s", surfaceID, err, msg)
		}
		return "", fmt.Errorf("surface %s: credential.run failed: %v", surfaceID, err)
	}
	secret := strings.TrimRight(stdout.String(), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("surface %s: credential.run printed nothing", surfaceID)
	}
	return secret, nil
}

// validCredential checks a surface's credential block: a known source, the
// one field that source needs, and one origin. A credential that comes from
// SafeGrd and a database_url that could also win is how a host backs up
// something other than what the console shows, so it is refused, never
// resolved quietly.
func validCredential(s *config.SurfaceConfig) error {
	c := s.Credential
	if c == nil {
		return nil
	}
	switch c.From {
	case config.CredentialFromSafeGrd:
		if s.DatabaseURL != "" {
			return fmt.Errorf("surface %s: credential.from is safegrd and database_url is set as well. A credential has one origin: "+
				"remove database_url to use the one SafeGrd holds, or set credential.from to where it is on this host", s.ID)
		}
	case config.CredentialFromEnv:
		if c.Name == "" {
			return fmt.Errorf("surface %s: credential.from is env, so credential.name must name the environment variable", s.ID)
		}
	case config.CredentialFromCommand:
		if c.Run == "" {
			return fmt.Errorf("surface %s: credential.from is command, so credential.run must be the command to run", s.ID)
		}
	case config.CredentialFromFile:
		if c.Path == "" {
			return fmt.Errorf("surface %s: credential.from is file, so credential.path must be the file to read", s.ID)
		}
	case "":
		return fmt.Errorf("surface %s: credential has no from. Set it to safegrd, env, command or file", s.ID)
	default:
		return fmt.Errorf("surface %s: credential.from is %q; it must be safegrd, env, command or file", s.ID, c.From)
	}
	if c.From != config.CredentialFromSafeGrd && s.DatabaseURL != "" {
		return fmt.Errorf("surface %s: credential.from is %s and database_url is set as well. A credential has one origin: remove one", s.ID, c.From)
	}
	return nil
}

// credentialOnHost says where on the host a surface's credential comes
// from, for messages, or "" when the host supplies none of its own.
func credentialOnHost(s *config.SurfaceConfig) string {
	switch from := s.CredentialFrom(); {
	case from != "" && from != config.CredentialFromSafeGrd:
		return "credential.from: " + from
	case s.DatabaseURL != "":
		return "database_url"
	}
	return ""
}

// credentialSourceOf is what the host tells the remote server about where a
// surface's credential comes from: "held", "host", or "" for a surface that
// names none.
func credentialSourceOf(s *config.SurfaceConfig) string {
	if s.FromSafeGrd() {
		return "held"
	}
	switch strings.ToLower(s.Type) {
	case "postgres", "mysql", "mongodb", "email":
		if credentialOnHost(s) != "" {
			return "host"
		}
	}
	return ""
}

// credentialFromHost resolves a credential block that points at the host:
// an environment variable, a command's output, or a file. What it names and
// cannot deliver is an error that says which, never a fallback: a missing
// variable once backed up whatever the host's own database_url pointed at.
func credentialFromHost(ctx context.Context, s *config.SurfaceConfig) (string, error) {
	c := s.Credential
	switch c.From {
	case config.CredentialFromEnv:
		v := os.Getenv(c.Name)
		if v == "" {
			return "", fmt.Errorf("surface %s: credential.name is %s, and that environment variable is not set for this process. "+
				"Under a service, set it in the service's environment (see safegrd.dev/docs/agent)", s.ID, c.Name)
		}
		return v, nil
	case config.CredentialFromCommand:
		return runCredentialCommand(ctx, s.ID, c.Run)
	case config.CredentialFromFile:
		data, err := os.ReadFile(c.Path)
		if err != nil {
			return "", fmt.Errorf("surface %s: credential.path %s could not be read: %w", s.ID, c.Path, err)
		}
		v := strings.TrimRight(string(data), "\r\n")
		if v == "" {
			return "", fmt.Errorf("surface %s: credential.path %s is empty", s.ID, c.Path)
		}
		return v, nil
	}
	return "", nil
}

// surfaceEmailPassword resolves a mailbox password: the one SafeGrd holds,
// the credential block's source on the host, or SAFEGRD_EMAIL_PASSWORD when
// the surface names none.
func surfaceEmailPassword(ctx context.Context, s *config.SurfaceConfig) (string, error) {
	if err := validCredential(s); err != nil {
		return "", err
	}
	switch s.CredentialFrom() {
	case config.CredentialFromSafeGrd:
		return s.HeldSecret, nil
	case "":
		return os.Getenv("SAFEGRD_EMAIL_PASSWORD"), nil
	}
	return credentialFromHost(ctx, s)
}

// resolveSurfaceDatabaseURL is the database a surface backs up. A surface
// whose credential comes from SafeGrd uses only the URL SafeGrd holds.
// Otherwise the credential block's source on the host, then the surface's
// database_url, then the host's.
func resolveSurfaceDatabaseURL(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (string, error) {
	u, err := resolveSurfaceDatabaseURLAsGiven(ctx, c, s)
	if err != nil {
		return "", err
	}
	u, dropped := cleanPostgresURL(u)
	sayDroppedURLParams("Surface "+s.ID, dropped)
	return u, nil
}

func resolveSurfaceDatabaseURLAsGiven(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (string, error) {
	if err := validCredential(s); err != nil {
		return "", err
	}
	switch s.CredentialFrom() {
	case config.CredentialFromSafeGrd:
		// Never the host's database_url behind it.
		return s.HeldSecret, nil
	case "":
	default:
		return credentialFromHost(ctx, s)
	}
	url := s.DatabaseURL
	if url == "" {
		url = c.DatabaseURL
	}
	if strings.HasPrefix(url, "env:") || strings.HasPrefix(url, "file:") {
		return ResolveSecretRef("database_url", url)
	}
	return url, nil
}
