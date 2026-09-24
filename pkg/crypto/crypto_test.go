package crypto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestKeyPairGeneration(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if !strings.HasPrefix(kp.PublicKey, "age1") {
		t.Errorf("expected public key to start with 'age1', got %s", kp.PublicKey)
	}
	if !strings.HasPrefix(kp.PrivateKey, "AGE-SECRET-KEY-1") {
		t.Errorf("expected private key to start with 'AGE-SECRET-KEY-1', got %s", kp.PrivateKey)
	}

	rec, err := ParseRecipient(kp.PublicKey)
	if err != nil {
		t.Fatalf("ParseRecipient failed: %v", err)
	}
	if rec == nil {
		t.Fatal("expected non-nil recipient")
	}

	ident, err := ParseIdentity(kp.PrivateKey)
	if err != nil {
		t.Fatalf("ParseIdentity failed: %v", err)
	}
	if ident == nil {
		t.Fatal("expected non-nil identity")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	sampleSQL := `
	-- PostgreSQL Database Dump Test
	CREATE TABLE users (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);
	INSERT INTO users (name, email) VALUES ('Alice Agent', 'alice@safegrd.dev');
	INSERT INTO users (name, email) VALUES ('Bob Admin', 'bob@safegrd.dev');
	`
	// Repeat to test compression
	largeSQL := strings.Repeat(sampleSQL, 500)
	src := strings.NewReader(largeSQL)

	var encryptedBuffer bytes.Buffer
	encMetrics, err := EncryptStream(src, &encryptedBuffer, kp.PublicKey)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	if encMetrics.RawBytes != int64(len(largeSQL)) {
		t.Errorf("expected RawBytes %d, got %d", len(largeSQL), encMetrics.RawBytes)
	}
	if encMetrics.EncryptedBytes >= encMetrics.RawBytes {
		t.Errorf("expected compression to reduce size: raw=%d, encrypted=%d", encMetrics.RawBytes, encMetrics.EncryptedBytes)
	}
	if encMetrics.CompressionRatio <= 1.0 {
		t.Errorf("expected compression ratio > 1.0, got %f", encMetrics.CompressionRatio)
	}

	// Decrypt
	var decryptedBuffer bytes.Buffer
	decMetrics, err := DecryptStream(&encryptedBuffer, &decryptedBuffer, kp.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}

	if decMetrics.RawBytes != encMetrics.RawBytes {
		t.Errorf("decrypted raw bytes mismatch: %d vs %d", decMetrics.RawBytes, encMetrics.RawBytes)
	}
	if decMetrics.RawSha256 != encMetrics.RawSha256 {
		t.Errorf("raw sha256 checksum mismatch: %s vs %s", decMetrics.RawSha256, encMetrics.RawSha256)
	}

	if decryptedBuffer.String() != largeSQL {
		t.Fatal("decrypted payload does not match original SQL content")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	var encrypted bytes.Buffer
	_, err = EncryptStream(strings.NewReader("secret database contents"), &encrypted, kp.PublicKey)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	tampered := encrypted.Bytes()
	// Tamper with middle byte
	tampered[len(tampered)/2] ^= 0xFF

	var decrypted bytes.Buffer
	_, err = DecryptStream(bytes.NewReader(tampered), &decrypted, kp.PrivateKey)
	if err == nil {
		t.Fatal("expected error when decrypting tampered ciphertext, but got nil")
	}
}

func TestWrongPrivateKeyFails(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	var encrypted bytes.Buffer
	_, err := EncryptStream(strings.NewReader("confidential data"), &encrypted, kp1.PublicKey)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	var decrypted bytes.Buffer
	_, err = DecryptStream(&encrypted, &decrypted, kp2.PrivateKey)
	if err == nil {
		t.Fatal("expected error decrypting with mismatched private key, but got nil")
	}
}

func TestLargeStreamIntegrity(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	// 2 MB of random data
	payload := make([]byte, 2*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to generate random bytes: %v", err)
	}

	var cipherBuf bytes.Buffer
	encMetrics, err := EncryptStream(bytes.NewReader(payload), &cipherBuf, kp.PublicKey)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var plainBuf bytes.Buffer
	decMetrics, err := DecryptStream(&cipherBuf, &plainBuf, kp.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}

	if decMetrics.RawSha256 != encMetrics.RawSha256 {
		t.Errorf("sha256 mismatch: %s vs %s", decMetrics.RawSha256, encMetrics.RawSha256)
	}
	if !bytes.Equal(plainBuf.Bytes(), payload) {
		t.Fatal("decrypted payload differs from original random bytes")
	}
}
