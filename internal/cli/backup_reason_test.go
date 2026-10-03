package cli

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/safegrd/cli/pkg/diskspace"
	"github.com/safegrd/cli/pkg/model"
)

// The reason a failed backup reports comes from where it failed, never from
// its words. A full disk and a full hosted quota win over the stage.
func TestBackupReasonOf(t *testing.T) {
	disk := &diskspace.NotEnoughDiskError{Dir: "/var", What: "a backup"}
	for _, c := range []struct {
		err  error
		want model.BackupReason
	}{
		{stageErr(model.BackupReasonSource, errors.New("connection refused")), model.BackupReasonSource},
		{fmt.Errorf("wrapped: %w", stageErr(model.BackupReasonConfig, errors.New("no roots"))), model.BackupReasonConfig},
		{stageErr(model.BackupReasonStorage, fmt.Errorf("upload: %w", disk)), model.BackupReasonNoDisk},
		{stageErr(model.BackupReasonStorage, &hostedError{Status: http.StatusInsufficientStorage, Msg: "full"}), model.BackupReasonQuota},
		{errors.New("storage upload failed: database is down"), model.BackupReasonOther},
	} {
		if got := backupReasonOf(c.err); got != c.want {
			t.Errorf("%v: %q, want %q", c.err, got, c.want)
		}
	}
}

// An upload that failed because the stream it read stopped is the source's
// failure: a database that cannot be reached is not a storage problem.
func TestAnUploadThatFailedForItsSourceSaysSource(t *testing.T) {
	producer := make(chan error, 1)
	producer <- errors.New("could not connect to the database")
	err := uploadErr(errors.New("io: read/write on closed pipe"), producer, "database dump failed")
	if backupReasonOf(err) != model.BackupReasonSource || err.Error() != "database dump failed: could not connect to the database" {
		t.Errorf("got %q (%s)", err, backupReasonOf(err))
	}
	quiet := make(chan error)
	if err := uploadErr(errors.New("403 Forbidden"), quiet, "database dump failed"); backupReasonOf(err) != model.BackupReasonStorage {
		t.Errorf("an upload refused by storage reads %q (%s)", err, backupReasonOf(err))
	}
}
