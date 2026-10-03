//go:build linux

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
	return statInfo{ok: true, dev: uint64(s.Dev), ino: s.Ino, ctimeNs: s.Ctim.Nano(), uid: &uid, gid: &gid}
}
