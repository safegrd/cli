package cli

import (
	"sync/atomic"

	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/runner"
)

// Exit codes that say which side a failure is on, so a script, or whatever
// runs the CLI, can tell its own mistake from an outage without reading the
// message. 1 is every failure not classified here. guard keeps 3 for "no
// snapshot was taken", and passes the wrapped command's own code through.
const (
	// exitSource: the database, mailbox or directory being backed up
	// refused the connection or the credential, or is not there.
	exitSource = 10
	// exitServer: the remote server could not be reached, answered 5xx, or
	// sent an answer this CLI cannot read.
	exitServer = 11
	// exitStorage: the storage the backups are in could not be opened,
	// written or read.
	exitStorage = 12
)

// classedError carries one of the exit codes above to Execute.
type classedError struct {
	code int
	err  error
}

func (e *classedError) Error() string { return e.err.Error() }
func (e *classedError) Unwrap() error { return e.err }

func classed(code int, err error) error {
	if err == nil {
		return nil
	}
	return &classedError{code: code, err: err}
}

func serverFailure(err error) error  { return classed(exitServer, err) }
func storageFailure(err error) error { return classed(exitStorage, err) }

// serverTrouble is set when a request to the remote server failed in a way
// that is the server's (no answer, 5xx, an unreadable answer) on a path that
// only warns and carries on. A command that then fails for want of what the
// server did not send (a credential, a key) exits exitServer, not 1. It is
// never reset: it is meant for one command per process. A daemon that saw a
// 5xx once exits 11 on a later unclassified error.
var serverTrouble atomic.Bool

// noteServerStatus records serverTrouble for a status the server answered.
func noteServerStatus(status int) {
	if status >= 500 {
		serverTrouble.Store(true)
	}
}

// noteServerUnreachable records serverTrouble for a request that got no
// answer, or one that could not be read.
func noteServerUnreachable() { serverTrouble.Store(true) }

// exitCodeOf is the exit code for a command that failed with err.
func exitCodeOf(err error) int {
	if c := classOf(err); c != 0 {
		return c
	}
	if serverTrouble.Load() {
		return exitServer
	}
	return 1
}

// classOf walks err's chain from the outside in and returns the first class
// it finds, or 0 for none.
func classOf(err error) int {
	for err != nil {
		switch e := err.(type) {
		case *exitError:
			return e.code
		case *classedError:
			return e.code
		case *runner.StorageError:
			return exitStorage
		case *backupStageError:
			switch e.reason {
			case model.BackupReasonSource:
				return exitSource
			case model.BackupReasonStorage:
				return exitStorage
			}
		case *hostedError:
			// Hosted storage is reached through the remote server; a 5xx is
			// the server or the bucket behind it. 507 is the organization's
			// quota, which is not an outage.
			if e.Status >= 500 && e.Status != 507 {
				return exitStorage
			}
		}
		switch u := err.(type) {
		case interface{ Unwrap() []error }:
			for _, inner := range u.Unwrap() {
				if c := classOf(inner); c != 0 {
					return c
				}
			}
			return 0
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		default:
			return 0
		}
	}
	return 0
}

// isClassed reports whether err already carries a class, so a caller does
// not wrap it in a broader one.
func isClassed(err error) bool { return classOf(err) != 0 }
