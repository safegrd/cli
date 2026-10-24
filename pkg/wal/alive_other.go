//go:build !unix

package wal

// processAlive cannot tell here, so a postmaster.pid is taken as a running
// server.
func processAlive(int) bool { return true }
