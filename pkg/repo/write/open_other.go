//go:build !unix

package write

import "os"

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
