package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// KeyPair holds an Age X25519 recipient (public key) and identity (private key).
type KeyPair struct {
	PublicKey  string // age1...
	PrivateKey string // AGE-SECRET-KEY-1...
}

// GenerateKeyPair generates a fresh X25519 Age asymmetric keypair.
func GenerateKeyPair() (*KeyPair, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 keypair: %w", err)
	}

	return &KeyPair{
		PublicKey:  identity.Recipient().String(),
		PrivateKey: identity.String(),
	}, nil
}

// SavePrivateKey writes the private key to a file with 0600 permissions.
// SavePrivateKey writes an Age identity, and REFUSES to overwrite one.
//
// The refusal is the whole function. This file is the only thing that can ever
// decrypt a snapshot, and it used to be written with a plain os.WriteFile, so
// anything that decided to generate a keypair silently replaced it. A guard
// stopped `init` from destroying a *config*, which made this worse rather than
// better: the guard people now trust does not cover the one file that cannot be
// regenerated. `safegrd init --config some-other-file.yaml` passed that check
// and clobbered ~/.safegrd/keys/agent.key on the way past, and `enroll` did the
// same for any config whose public_key was empty.
//
// After that, every snapshot ever written was sealed to a recipient nothing on
// the machine could open, and nothing said so — the next backup succeeded, the
// console stayed green, and the loss only surfaced at the restore.
//
// Callers that genuinely mean to replace an identity call OverwritePrivateKey
// and say so to the operator first.
func SavePrivateKey(privateKey, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory %s: %w", dir, err)
	}

	content := strings.TrimSpace(privateKey) + "\n"

	// O_EXCL rather than a stat-then-write: the check and the write have to be
	// one operation, or two processes racing both believe they created it and
	// one silently wins.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf(
				"refusing to overwrite the existing Age identity at %s.\n\n"+
					"  That file is the only thing that can decrypt snapshots already written.\n"+
					"  Replacing it would leave every one of them sealed to a key nothing here\n"+
					"  holds, and nothing would report it until a restore failed.\n\n"+
					"  Back it up, then remove it deliberately if you really mean to start over",
				path)
		}
		return fmt.Errorf("failed to write private key to %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return fmt.Errorf("failed to write private key to %s: %w", path, err)
	}
	return nil
}

// OverwritePrivateKey replaces an identity that is already there.
//
// Separate from SavePrivateKey so that replacing a key is something a caller
// has to ask for by name. The only legitimate caller is a command that has
// already told the operator what they are about to lose.
func OverwritePrivateKey(privateKey, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory %s: %w", dir, err)
	}
	content := strings.TrimSpace(privateKey) + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write private key to %s: %w", path, err)
	}
	return nil
}

// LoadPrivateKey loads an Age identity string from a file.
func LoadPrivateKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file %s: %w", path, err)
	}

	key := strings.TrimSpace(string(data))
	if !strings.HasPrefix(key, "AGE-SECRET-KEY-1") {
		return "", fmt.Errorf("file %s does not contain a valid Age private key", path)
	}

	return key, nil
}

// ParseRecipient parses an Age public key recipient.
func ParseRecipient(publicKey string) (age.Recipient, error) {
	publicKey = strings.TrimSpace(publicKey)
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid Age public key recipient: %w", err)
	}
	return recipient, nil
}

// ParseIdentity parses an Age private key identity.
func ParseIdentity(privateKey string) (age.Identity, error) {
	privateKey = strings.TrimSpace(privateKey)
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid Age private key identity: %w", err)
	}
	return identity, nil
}

// Fingerprint returns a stable, displayable identifier for an Age recipient.
//
// It is SHA-256 over the recipient string, hex, grouped for reading:
//
//	SG:a1b2c3d4:e5f6a7b8
//
// Its job is comparison, not secrecy — an Age recipient is public by
// construction. It exists so a person can answer "is the key on this host the
// same one that sealed that snapshot?" by eye, before a restore fails rather
// than after, and so the console can name a key it does not hold.
//
// Sixteen hex characters of a SHA-256 is 64 bits. That is far too little for a
// security decision and entirely adequate for telling a handful of keys apart,
// which is all this is for. Never branch on a fingerprint where you could
// compare the recipient itself.
func Fingerprint(publicKey string) string {
	trimmed := strings.TrimSpace(publicKey)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	hexed := hex.EncodeToString(sum[:])
	return "SG:" + hexed[0:8] + ":" + hexed[8:16]
}
