package cli

import (
	"errors"
	"strings"
	"testing"
)

// DigitalOcean Spaces answers GetObjectLockConfiguration with 403 AccessDenied,
// not "not configured". The backup refused with that error and nothing in it
// named worm_mode: NONE, so the operator had to find the setting in the docs.
func TestALockCheckDeniedBySpacesNamesWormModeNone(t *testing.T) {
	denied := errors.New("operation error S3: GetObjectLockConfiguration, https response error StatusCode: 403, api error AccessDenied: Access Denied.")
	if got := objectLockAdvice(denied); !strings.Contains(got, "worm_mode: NONE") || !strings.Contains(got, "DigitalOcean Spaces") {
		t.Errorf("advice for a 403 does not name worm_mode: NONE: %q", got)
	}
	if got := objectLockAdvice(errors.New("dial tcp: no such host")); strings.Contains(got, "worm_mode") {
		t.Errorf("an unreachable endpoint is advised to drop the lock: %q", got)
	}
}
