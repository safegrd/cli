package cli

import (
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

// A drill marks its epoch damaged only for a failure that names stored
// objects: a pass, or a host that could not write the restore, says nothing
// about what is in storage and must not cost a full upload.
func TestOnlyStorageDamageMarksAnEpoch(t *testing.T) {
	failed := func(name, actual string) *model.VerificationReport {
		return &model.VerificationReport{Status: model.VerificationStatusFailed,
			Assertions: []model.AssertionResult{{Name: name, Passed: false, Actual: actual}}}
	}
	for _, c := range []struct {
		report *model.VerificationReport
		want   bool
	}{
		{failed("RepositoryIntegrity", "pack p, which snapshot s needs, is missing"), true},
		{failed("RestoreIntegrity", "f: pack p: blob b does not authenticate: it was altered"), true},
		{failed("RestoreIntegrity", "pack p is shorter than its index says (1 of 2 bytes at 0)"), true},
		{failed("RestoreIntegrity", "hosted storage: No such object in hosted storage: k"), true},
		{failed("RestoreIntegrity", "write /scratch/f: no space left on device"), false},
		{failed("DigestIntegrity", "abc"), false},
		{&model.VerificationReport{Status: model.VerificationStatusPassed}, false},
		{nil, false},
	} {
		if _, got := drillFoundDamage(c.report); got != c.want {
			t.Errorf("%+v: damage %v, want %v", c.report, got, c.want)
		}
	}
}
