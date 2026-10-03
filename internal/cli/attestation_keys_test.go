package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// A chain that spans a key rotation verifies under the key each record names,
// and a record under the retired key that sits after one under the new key,
// or that was completed after the retirement, is refused.
func TestHistoryChecksEachRecordUnderTheKeyItNames(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(nil)
	newPub, newPriv, _ := ed25519.GenerateKey(nil)
	retiredAt := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	oldID, newID := "sgd_attest_"+hex.EncodeToString(oldPub[:8]), "sgd_attest_"+hex.EncodeToString(newPub[:8])

	record := func(id string, priv ed25519.PrivateKey, keyID string, completed time.Time) *model.VerificationReport {
		r := &model.VerificationReport{VerificationID: id, SnapshotID: "snap-" + id, NodeID: "node-1",
			Status: model.VerificationStatusPassed, CertificateHash: "cert_" + id, PrevHash: "genesis",
			StartedAt: completed.Add(-time.Minute), CompletedAt: completed, SigningKeyID: keyID}
		r.Signature = hex.EncodeToString(ed25519.Sign(priv, r.CanonicalBytes()))
		return r
	}
	published := func() publishedAttestationKeys {
		pk := publishedAttestationKeys{KeyID: newID, PublicKey: hex.EncodeToString(newPub)}
		pk.Retired = append(pk.Retired, struct {
			KeyID     string    `json:"key_id"`
			PublicKey string    `json:"public_key"`
			RetiredAt time.Time `json:"retired_at"`
		}{KeyID: oldID, PublicKey: hex.EncodeToString(oldPub), RetiredAt: retiredAt})
		return pk
	}

	underOld := record("v1", oldPriv, oldID, retiredAt.Add(-time.Hour))
	underNew := record("v2", newPriv, newID, retiredAt.Add(time.Hour))

	t.Run("old then new verifies and names both keys", func(t *testing.T) {
		keys, err := keySetFromPublished(published())
		if err != nil {
			t.Fatal(err)
		}
		for i, r := range []*model.VerificationReport{underOld, underNew} {
			if err := keys.verify(i, r); err != nil {
				t.Fatalf("record %d: %v", i, err)
			}
		}
		line := keys.usedLine()
		if !strings.Contains(line, newID+" (active, 1 record)") || !strings.Contains(line, oldID+" (retired 2026-10-03, 1 record)") {
			t.Errorf("signing keys line: %q", line)
		}
		if used := keys.used(); len(used) != 2 || used[0]["status"] != "retired" || used[1]["status"] != "active" {
			t.Errorf("--json signing_keys: %v", used)
		}
	})

	t.Run("a retired-key record after a new-key record is refused", func(t *testing.T) {
		keys, _ := keySetFromPublished(published())
		if err := keys.verify(0, underNew); err != nil {
			t.Fatal(err)
		}
		err := keys.verify(1, underOld)
		if err == nil || !strings.Contains(err.Error(), "RETIRED KEY OUT OF ORDER") {
			t.Errorf("got %v", err)
		}
	})

	t.Run("a retired-key record completed after the retirement is refused", func(t *testing.T) {
		keys, _ := keySetFromPublished(published())
		late := record("v3", oldPriv, oldID, retiredAt.Add(time.Minute))
		err := keys.verify(0, late)
		if err == nil || !strings.Contains(err.Error(), "RETIRED KEY at index 0") {
			t.Errorf("got %v", err)
		}
	})

	t.Run("a key the server does not publish is refused", func(t *testing.T) {
		keys, _ := keySetFromPublished(published())
		_, strayPriv, _ := ed25519.GenerateKey(nil)
		stray := record("v4", strayPriv, "sgd_attest_0000000000000000", retiredAt)
		err := keys.verify(0, stray)
		if err == nil || !strings.Contains(err.Error(), "UNKNOWN SIGNING KEY") {
			t.Errorf("got %v", err)
		}
	})

	t.Run("a record naming no key is checked under the active one", func(t *testing.T) {
		keys, _ := keySetFromPublished(published())
		unnamed := record("v5", newPriv, "", retiredAt.Add(time.Hour))
		if err := keys.verify(0, unnamed); err != nil {
			t.Error(err)
		}
		forged := record("v6", oldPriv, "", retiredAt.Add(time.Hour))
		if err := keys.verify(1, forged); err == nil || !strings.Contains(err.Error(), "INVALID SIGNATURE") {
			t.Errorf("an unnamed record under the retired key passed: %v", err)
		}
	})

	t.Run("a pinned key is checked against every record whatever it names", func(t *testing.T) {
		keys, err := loadAttestationKeys(t.Context(), "", hex.EncodeToString(oldPub), "", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := keys.verify(0, underOld); err != nil {
			t.Error(err)
		}
		if err := keys.verify(1, underNew); err == nil || !strings.Contains(err.Error(), "INVALID SIGNATURE") {
			t.Errorf("a record under another key passed the pinned key: %v", err)
		}
		if keys.usedLine() != "" {
			t.Errorf("a pinned key printed a signing-keys line: %q", keys.usedLine())
		}
	})

	t.Run("a wrong-length key is refused before any record is checked", func(t *testing.T) {
		if _, err := loadAttestationKeys(t.Context(), "", "abcd", "", ""); err == nil {
			t.Error("a 2-byte --key was accepted")
		}
		pk := published()
		pk.PublicKey = "abcd"
		if _, err := keySetFromPublished(pk); err == nil {
			t.Error("a 2-byte server key was accepted")
		}
	})
}
