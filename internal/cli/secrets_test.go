package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSecretRef(t *testing.T) {
	// Empty string
	res, err := ResolveSecretRef("test", "")
	if err != nil || res != "" {
		t.Fatalf("expected empty result, got %q, err %v", res, err)
	}

	// Environment variable reference
	t.Setenv("TEST_SAFEGRD_SECRET", "super-secret-pw")
	res, err = ResolveSecretRef("email-password", "env:TEST_SAFEGRD_SECRET")
	if err != nil {
		t.Fatalf("unexpected error resolving env ref: %v", err)
	}
	if res != "super-secret-pw" {
		t.Fatalf("expected 'super-secret-pw', got %q", res)
	}

	// Missing env var
	_, err = ResolveSecretRef("email-password", "env:NON_EXISTENT_VAR_12345")
	if err == nil {
		t.Fatalf("expected error on non-existent env var")
	}

	// File reference
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.key")
	if err := os.WriteFile(secretFile, []byte("  secret-from-file\n"), 0600); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	res, err = ResolveSecretRef("private-key", "file:"+secretFile)
	if err != nil {
		t.Fatalf("unexpected error resolving file ref: %v", err)
	}
	if res != "secret-from-file" {
		t.Fatalf("expected 'secret-from-file', got %q", res)
	}

	// Non-existent file
	_, err = ResolveSecretRef("private-key", "file:/path/does/not/exist/ever")
	if err == nil {
		t.Fatalf("expected error on non-existent file")
	}

	// Raw value (with warning to stderr)
	res, err = ResolveSecretRef("database-url", "postgres://user:pass@localhost:5432/db")
	if err != nil {
		t.Fatalf("unexpected error on raw value: %v", err)
	}
	if res != "postgres://user:pass@localhost:5432/db" {
		t.Fatalf("expected raw value preserved, got %q", res)
	}
}
