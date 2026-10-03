package cli

import (
	"fmt"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/repo/sink"
)

// hostedRepoReady is set once hosted storage takes repository backups.
const hostedRepoReady = false

func newHostedRepo(c *config.CLIConfig, storageCfg config.StorageConfig) (sink.Backend, error) {
	return nil, fmt.Errorf("hosted storage does not take repository backups yet")
}
