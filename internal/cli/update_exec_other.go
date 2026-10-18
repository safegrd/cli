//go:build !unix

package cli

import "errors"

func execSelf(bin string, args []string) error {
	return errors.New("this platform does not update the daemon in place")
}
