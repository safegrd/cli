//go:build !unix

package read

func canChown() bool { return false }
