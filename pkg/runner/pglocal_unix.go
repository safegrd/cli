//go:build linux || darwin

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// runAs is the user a local sandbox runs as: nil for the daemon's own.
type runAs struct{ uid, gid uint32 }

// sandboxCredential picks who runs the cluster. PostgreSQL refuses root, and
// `safegrd daemon install` without --user runs the daemon as root with the
// enrolling user's state directory, so the cluster runs as that directory's
// owner. A state directory root owns leaves nobody to run it as.
func sandboxCredential(stateDir string) (*runAs, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}
	fi, err := os.Stat(stateDir)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("cannot read the owner of %s", stateDir)
	}
	if st.Uid == 0 {
		return nil, fmt.Errorf("the daemon runs as root and root owns its state directory %s, and PostgreSQL will not run as root. "+
			"Run the daemon as an ordinary user ('safegrd daemon install --user'), or point drill.sandbox_url at a database", stateDir)
	}
	return &runAs{uid: st.Uid, gid: st.Gid}, nil
}

// own hands path to the sandbox's user.
func (r *runAs) own(path string) error {
	if r == nil {
		return nil
	}
	if err := os.Chown(path, int(r.uid), int(r.gid)); err != nil {
		return fmt.Errorf("cannot give %s to the local sandbox's user: %w", path, err)
	}
	return nil
}

// apply runs cmd as the sandbox's user.
func (r *runAs) apply(cmd *exec.Cmd) {
	if r == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: r.uid, Gid: r.gid, NoSetGroups: true}}
}

// diskSpace is what an ordinary user may still write under dir, and the
// filesystem's size.
func diskSpace(dir string) (avail, total int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize), nil
}
