package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// keyCustodyWords is the key custody mode and the protection it gives, as
// doctor says it. A backup prints the remote server's notice only when it
// fetches something from the server, so a host whose credential is local was
// never told which mode it is in; doctor always says.
func keyCustodyWords(escrowed bool, keyPath string) string {
	if escrowed {
		return "SafeGrd-managed key. SafeGrd keeps your key sealed and releases it only to your " +
			"enrolled hosts, so you can restore even after losing a host"
	}
	where := "the private key"
	if keyPath != "" {
		where = keyPath
	}
	return "customer-managed key. Only you can decrypt these backups. Keep a copy of " + where + " somewhere safe"
}

// fetchNodeRecord reads this host's node record from the remote server.
func fetchNodeRecord(ctx context.Context, c *config.CLIConfig) (*model.Node, error) {
	if err := refuseInsecureServerURLFor(c.ServerURL, "read this host's record from",
		"this request carries a node token"); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(c.ServerURL, "/")+"/api/v1/nodes/"+url.PathEscape(c.NodeID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	req.Header.Set("User-Agent", UserAgent())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, httpStatusError{resp.StatusCode}
	}
	var n model.Node
	if err := json.NewDecoder(resp.Body).Decode(&n); err != nil {
		return nil, err
	}
	return &n, nil
}

// httpStatusError is an answer from the remote server other than 200.
type httpStatusError struct{ code int }

func (e httpStatusError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

// keyCustodyCheck is doctor's line for the custody mode. A host that never
// enrolled sent its key nowhere, so it is customer-managed without asking.
func keyCustodyCheck(ctx context.Context, c *config.CLIConfig) CheckResult {
	return nodeRecordChecks(ctx, c)[0]
}

// nodeRecordChecks reads this host's record once and says three things from
// it: the key custody mode, whether the remote server still accepts this
// host's token, and whether a newer CLI is out. A revoked token reported as
// "online" is how one went unnoticed.
func nodeRecordChecks(ctx context.Context, c *config.CLIConfig) []CheckResult {
	name := "Key Custody"
	if c.ServerToken == "" || c.NodeID == "" {
		return []CheckResult{{Name: name, Status: "PASS", Message: keyCustodyWords(false, c.Encryption.KeyPath)}}
	}
	n, err := fetchNodeRecord(ctx, c)
	var hs httpStatusError
	if errors.As(err, &hs) && (hs.code == http.StatusUnauthorized || hs.code == http.StatusForbidden) {
		return []CheckResult{{Name: "Node Token", Status: "FAIL",
			Message: fmt.Sprintf("%s refused this host's token (HTTP %d)", c.ServerURL, hs.code),
			Fix:     "run 'safegrd enroll' again with a token from the console"}}
	}
	if err != nil {
		return []CheckResult{{Name: name, Status: "WARN",
			Message: fmt.Sprintf("could not ask %s which key custody this host uses: %v", c.ServerURL, err),
			Fix:     "run 'safegrd doctor' again once the remote server is reachable"}}
	}
	out := []CheckResult{{Name: name, Status: "PASS", Message: keyCustodyWords(n.KeyEscrowed, c.Encryption.KeyPath)}}
	if n.UpgradeAvailable {
		out = append(out, CheckResult{Name: "CLI Update", Status: "WARN",
			Message: fmt.Sprintf("v%s is available (installed: %s)", n.LatestCLIVersion, Version),
			Fix:     "install it the way this one was installed (safegrd.dev/docs/install)"})
	}
	return out
}
