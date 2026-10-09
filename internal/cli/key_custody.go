package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// keyCustodyWords is the key custody mode and the protection it gives, as
// status and doctor say it. A backup prints the remote server's notice only
// when it fetches something from the server, so a host whose credential is
// local was never told which mode it is in; these two commands always say.
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
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var n model.Node
	if err := json.NewDecoder(resp.Body).Decode(&n); err != nil {
		return nil, err
	}
	return &n, nil
}

// keyCustodyCheck is doctor's line for the custody mode. A host that never
// enrolled sent its key nowhere, so it is customer-managed without asking.
func keyCustodyCheck(ctx context.Context, c *config.CLIConfig) CheckResult {
	name := "Key Custody"
	if c.ServerToken == "" || c.NodeID == "" {
		return CheckResult{Name: name, Status: "PASS", Message: keyCustodyWords(false, c.Encryption.KeyPath)}
	}
	n, err := fetchNodeRecord(ctx, c)
	if err != nil {
		return CheckResult{Name: name, Status: "WARN",
			Message: fmt.Sprintf("could not ask %s which key custody this host uses: %v", c.ServerURL, err),
			Fix:     "run 'safegrd status' once the remote server is reachable"}
	}
	return CheckResult{Name: name, Status: "PASS", Message: keyCustodyWords(n.KeyEscrowed, c.Encryption.KeyPath)}
}
