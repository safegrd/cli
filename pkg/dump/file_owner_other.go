//go:build !unix

package dump

import "os"

func ownerOf(os.FileInfo) (uid, gid *int) { return nil, nil }

func canChown() bool { return false }
