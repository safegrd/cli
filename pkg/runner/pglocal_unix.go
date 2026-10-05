//go:build linux || darwin

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// runAs is the user a local sandbox runs as: nil for the daemon's own. base,
// when set, is where its clusters go instead of the state directory.
type runAs struct {
	uid, gid uint32
	base     string
}

// dir is where the sandbox's clusters go, or "" for stateDir/drill.
func (r *runAs) dir() string {
	if r == nil {
		return ""
	}
	return r.base
}

// sandboxCredential picks who runs the cluster. PostgreSQL refuses root, and
// `safegrd daemon install` without --user runs the daemon as root with the
// enrolling user's state directory, so the cluster runs as that directory's
// owner. A state directory root owns (the install as root that the console's
// command gives) runs it as nobody, in rootSandboxBase: nobody cannot enter
// /root. It used to fall back to a drill in memory, below the depth the paid
// plans sell.
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
		nobody, err := user.Lookup("nobody")
		if err != nil {
			return nil, fmt.Errorf("the daemon runs as root and root owns its state directory %s, PostgreSQL will not run as root, "+
				"and this host has no user nobody to run it as. Run the daemon as an ordinary user ('safegrd daemon install --user'), "+
				"or point drill.sandbox_url at a database", stateDir)
		}
		uid, err1 := strconv.ParseUint(nobody.Uid, 10, 32)
		gid, err2 := strconv.ParseUint(nobody.Gid, 10, 32)
		if err1 != nil || err2 != nil || uid == 0 {
			return nil, fmt.Errorf("the user nobody on this host is not one a local sandbox can run as (uid %s)", nobody.Uid)
		}
		return &runAs{uid: uint32(uid), gid: uint32(gid), base: rootSandboxBase}, nil
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
