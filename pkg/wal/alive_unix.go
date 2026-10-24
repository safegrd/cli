//go:build unix

package wal

import (
	"errors"
	"syscall"
)

// processAlive says process pid exists, whoever owns it.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
