package storage

import (
	"fmt"
	"strings"
)

// maxSnapshotIDLen bounds a snapshot ID well under any object-key limit.
const maxSnapshotIDLen = 200

// ValidateSnapshotID refuses a snapshot ID that is not a single path segment.
//
// Every provider builds a file path or object key from the ID, and
// filepath.Join and path.Join both collapse "..", so an ID such as
// "../../x" wrote outside the storage root. Checked here, at the boundary,
// so no caller has to remember to.
func ValidateSnapshotID(id string) error {
	if id == "" || len(id) > maxSnapshotIDLen {
		return fmt.Errorf("snapshot ID %q must be 1 to %d characters", id, maxSnapshotIDLen)
	}
	if strings.HasPrefix(id, ".") {
		return fmt.Errorf("snapshot ID %q must not start with a dot", id)
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return fmt.Errorf("snapshot ID %q may contain only letters, digits, '-', '_' and '.'", id)
		}
	}
	return nil
}
