package config

import (
	"os"
	"testing"

	"github.com/safegrd/cli/internal/testhome"
)

// No test reads the ~/.safegrd of the machine running it (internal/testhome).
func TestMain(m *testing.M) { os.Exit(testhome.Main(m)) }
