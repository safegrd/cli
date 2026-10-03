//go:build darwin || freebsd || netbsd || openbsd

package write

import (
	"os"
	"syscall"
)

func sysStat(fi os.FileInfo) (st statInfo) {
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return st
	}
	uid, gid := s.Uid, s.Gid
	return statInfo{ok: true, dev: uint64(s.Dev), ino: uint64(s.Ino), ctimeNs: s.Ctimespec.Nano(), uid: &uid, gid: &gid}
}
