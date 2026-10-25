package cli

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"

	"github.com/denisbrodbeck/machineid"
)

// hostMachineHeader names the machine a report comes from, so the remote
// server can say when two machines report as one host: a config copied to a
// second machine sends that machine's backups and drills under the first
// one's node id.
const hostMachineHeader = "X-Safegrd-Host-Machine"

var (
	machineOnce  sync.Once
	machineLabel string
	machineHMAC  string
)

// hostMachine is this machine's hostname and, where the system has one, the
// first 12 hex digits of a SHA-256 of its machine id, which tells apart two
// machines with one hostname without sending the id itself.
func hostMachine() string {
	machineOnce.Do(readMachine)
	return machineLabel
}

// machineFingerprint is an HMAC-SHA256 of the operating system's machine id
// keyed by the product name, as hex, or "" where the system has none to give
// (a container usually has none). It is stable across reboots and updates,
// names no hardware, and cannot be turned back into the id. `safegrd try`
// sends it so the remote server can tell one machine's trials from another's.
func machineFingerprint() string {
	machineOnce.Do(readMachine)
	return machineHMAC
}

func readMachine() {
	name, _ := os.Hostname()
	name = strings.TrimSpace(name)
	// Linux reads /etc/machine-id or D-Bus's copy, macOS the IOPlatformUUID,
	// Windows the MachineGuid, the BSDs kern.hostuuid; none needs privileges.
	// SAFEGRD_MACHINE_ID stands in for the system's id on machines cloned
	// from one image, which share it.
	id, err := machineid.ID()
	if override := strings.TrimSpace(os.Getenv("SAFEGRD_MACHINE_ID")); override != "" {
		id, err = override, nil
	}
	if err == nil && strings.TrimSpace(id) != "" {
		sum := sha256.Sum256([]byte(id))
		name += " (" + hex.EncodeToString(sum[:])[:12] + ")"
		mac := hmac.New(sha256.New, []byte(id))
		mac.Write([]byte("safegrd"))
		machineHMAC = hex.EncodeToString(mac.Sum(nil))
	}
	machineLabel = name
}
