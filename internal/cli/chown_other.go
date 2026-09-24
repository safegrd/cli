//go:build !unix

package cli

func chownLike(path, like string) error { return nil }
