package cli

import (
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// Logging in on an enrolled host would write a personal token over the node's
// own, and the daemon could then no longer fetch what only a node may fetch.
func TestLoginRefusesToReplaceANodeToken(t *testing.T) {
	err := refuseOverNodeToken(&config.CLIConfig{NodeID: "node-abc", ServerToken: "sg_tok_123"})
	if err == nil || !strings.Contains(err.Error(), "node-abc") || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("got %v, want a refusal naming the node and the --config way out", err)
	}
	for _, c := range []*config.CLIConfig{nil, {}, {ServerToken: "sg_pat_123"}} {
		if err := refuseOverNodeToken(c); err != nil {
			t.Fatalf("refused %+v: %v", c, err)
		}
	}
}
