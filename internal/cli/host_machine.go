package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// hostMachineHeader names the machine a report comes from, so the remote
// server can say when two machines report as one host: a config copied to a
// second machine sends that machine's backups and drills under the first
// one's node id.
const hostMachineHeader = "X-Safegrd-Host-Machine"

var (
	machineOnce  sync.Once
	machineLabel string
	ioregUUIDRe  = regexp.MustCompile(`"IOPlatformUUID" = "([^"]+)"`)
)

// hostMachine is this machine's hostname and, where the system has one, the
// first 12 hex digits of a SHA-256 of its machine id, which tells apart two
// machines with one hostname without sending the id itself.
func hostMachine() string {
	machineOnce.Do(func() {
		name, _ := os.Hostname()
		name = strings.TrimSpace(name)
		if id := machineID(); id != "" {
			sum := sha256.Sum256([]byte(id))
			name += " (" + hex.EncodeToString(sum[:])[:12] + ")"
		}
		machineLabel = name
	})
	return machineLabel
}

// machineID is the operating system's id for this machine, or "" when it has
// none to give. A container usually has none, and its hostname is its own.
func machineID() string {
	switch runtime.GOOS {
	case "linux":
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := os.ReadFile(p); err == nil {
				if id := strings.TrimSpace(string(b)); id != "" {
					return id
				}
			}
		}
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err == nil {
			if m := ioregUUIDRe.FindSubmatch(out); m != nil {
				return string(m[1])
			}
		}
	}
	return ""
}
