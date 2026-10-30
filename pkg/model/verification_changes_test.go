package model

import (
	"strings"
	"testing"
)

// The signed bytes of a record without table changes are the ten fields
// they always were, so every record signed before the field existed keeps
// verifying. A record with changes carries their digest as an eleventh
// field, in a text form the verifier page computes the same way, so the
// form is pinned here.
func TestTableChangesAreSignedThroughADigest(t *testing.T) {
	rep := &VerificationReport{VerificationID: "ver-1", SnapshotID: "snap-b", NodeID: "node-1", SurfaceType: SurfaceTypePostgres,
		Status: VerificationStatusPassed, TablesRestored: 2, RowsRestored: 230, DurationMs: 1200, CertificateHash: "cert_1", PrevHash: "genesis"}
	plain := "ver-1|snap-b|node-1|postgres|passed|2|230|1200|cert_1|genesis"
	if got := string(rep.CanonicalBytes()); got != plain {
		t.Fatalf("without changes: %q, want %q", got, plain)
	}
	rep.TableChangesFrom = "snap-a"
	rep.TablesUnchanged = 1
	rep.TableChanges = []TableChange{
		{Schema: "public", TableName: "orders", RowsBefore: 200, RowsAfter: 230},
		{Schema: "public", TableName: "old", RowsBefore: 5, Gone: true},
	}
	const digest = "da46e103999a40ea5018e7310512c131b0c02984ac08e557fd769dff1bff3bf6"
	if got := rep.TableChangesDigest(); got != digest {
		t.Errorf("digest %s, want %s (sha256 of \"tables|snap-a|1|0\\npublic.orders|200|230|\\npublic.old|5|0|gone\\n\")", got, digest)
	}
	if got := string(rep.CanonicalBytes()); got != plain+"|"+digest {
		t.Errorf("with changes: %q", got)
	}
	// Any change to the list changes the bytes.
	rep.TableChanges[0].RowsAfter = 231
	if strings.HasSuffix(string(rep.CanonicalBytes()), digest) {
		t.Error("a changed row count left the digest as it was")
	}
}
