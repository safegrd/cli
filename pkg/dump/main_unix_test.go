//go:build linux || darwin

package dump

import (
	"testing"

	"github.com/safegrd/cli/internal/sqlitelocktest"
)

func TestMain(m *testing.M) { sqlitelocktest.Main(m) }
