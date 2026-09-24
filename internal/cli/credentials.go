package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// nodeCredentialsResponse mirrors the remote server's credential release
// payload.
//
// Every field here is a live secret except PublicKey. None of them is ever
// written back to the config file: SaveCLIConfig is not called on this path,
// and the values live in the CLIConfig struct in memory for the length of one
// command. That is the whole point of fetching them — a credential that lands
// on disk makes central revocation stop being revocation, because the host
// keeps working after the remote server has withdrawn it.
type nodeCredentialsResponse struct {
	NodeID      string `json:"node_id"`
	ProjectID   string `json:"project_id"`
	DatabaseURL string `json:"database_url"`
	Sink        *struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	} `json:"sink"`
	PublicKey string `json:"public_key"`
	Notice    string `json:"notice"`
}

// fetchNodeCredentials asks the remote server for the secrets this node is
// entitled to at run time.
//
// It refuses to send a node token over plain HTTP to anything but loopback. The
// server refuses too, but the client refusing is what stops the token itself
// from crossing the wire in the clear: by the time the server can object, the
// credential that authenticates the request has already been transmitted.
func fetchNodeCredentials(ctx context.Context, serverURL, nodeID, token string) (*nodeCredentialsResponse, error) {
	if err := refuseInsecureServerURL(serverURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/api/v1/nodes/%s/credentials", strings.TrimRight(serverURL, "/"), nodeID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if body.Error != "" {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body.Error)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var res nodeCredentialsResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// refuseInsecureServerURL rejects a plaintext server URL that is not loopback.
//
// Loopback is allowed because it is how the E2E suite and a developer's own
// server run, and there is no network between the two ends of a loopback socket
// to intercept. Anything else carrying a node token and returning a database
// password over http:// is a mistake worth failing loudly on, not a warning.
func refuseInsecureServerURL(serverURL string) error {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return fmt.Errorf("server_url is not a URL: %w", err)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to fetch credentials from %s over %s: this request carries a node "+
		"token and returns database and storage secrets. Use https:// (or run the remote server on loopback)",
		u.Host, u.Scheme)
}

// credentialSource records where each secret came from, so `--verbose` and a
// future `safegrd doctor` can answer "why is it using that password?" without
// printing the password.
type credentialSource struct {
	DatabaseURL string
	SinkSecret  string
	PublicKey   string
}

// resolveRuntimeCredentials fills in secrets the local config does not carry,
// applying the same precedence rule as storage routing: what is
// already local wins, the remote server fills the gaps, and an unreachable
// remote server is not fatal if the host can proceed on its own.
//
// The asymmetry with resolveStorageRouting is deliberate. Routing is a
// preference the remote server may override, because repointing a fleet's
// bucket centrally is the feature. A credential is not: a node that already has
// one keeps using it, so enabling central custody can never silently swap the
// database a host backs up.
//
// cfg is mutated in memory only. Nothing on this path calls SaveCLIConfig.
func resolveRuntimeCredentials(ctx context.Context, cfg *config.CLIConfig, storageCfg *config.StorageConfig, verbose bool) credentialSource {
	src := credentialSource{DatabaseURL: "local config", SinkSecret: "local config", PublicKey: "local config"}
	if cfg.DatabaseURL == "" {
		src.DatabaseURL = "not configured"
	}
	if storageCfg.SecretAccessKey == "" {
		src.SinkSecret = "not configured"
	}
	if cfg.Encryption.PublicKey == "" {
		src.PublicKey = "not configured"
	}

	needsSomething := cfg.DatabaseURL == "" || storageCfg.SecretAccessKey == "" || cfg.Encryption.PublicKey == ""
	if !needsSomething || cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return src
	}

	creds, err := fetchNodeCredentials(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
	if err != nil {
		if verbose {
			fmt.Printf("   Credentials:     remote server unavailable (%v); using local configuration only\n", err)
		}
		return src
	}

	if cfg.DatabaseURL == "" && creds.DatabaseURL != "" {
		cfg.DatabaseURL = creds.DatabaseURL
		src.DatabaseURL = "remote server"
	}
	if storageCfg.SecretAccessKey == "" && creds.Sink != nil && creds.Sink.SecretAccessKey != "" {
		storageCfg.AccessKeyID = creds.Sink.AccessKeyID
		storageCfg.SecretAccessKey = creds.Sink.SecretAccessKey
		src.SinkSecret = "remote server"
	}
	if cfg.Encryption.PublicKey == "" && creds.PublicKey != "" {
		cfg.Encryption.PublicKey = creds.PublicKey
		src.PublicKey = "remote server (managed custody)"
	}

	if verbose {
		fmt.Printf("   Credentials:     database=%s sink=%s recipient=%s\n",
			src.DatabaseURL, src.SinkSecret, src.PublicKey)
		if creds.Notice != "" {
			fmt.Printf("   Notice:          %s\n", creds.Notice)
		}
	}
	return src
}

// managedIdentityFetchResponse is the payload of GET /nodes/{id}/identity.
type managedIdentityFetchResponse struct {
	OrgID      string `json:"org_id"`
	PublicKey  string `json:"public_key"`
	Identity   string `json:"identity"`
	KeyCustody string `json:"key_custody"`
	Notice     string `json:"notice"`
}

// fetchManagedIdentity asks the remote server for the Age identity it holds for
// this node's organization.
//
// The returned key is never written anywhere. It is not saved to key_path, not
// written into the config, and not logged — it exists in one local variable for
// the length of one restore. Writing it to key_path would quietly convert a
// managed-custody organization into a customer-held one on that host, which is
// the opposite of what the operator chose and would survive revocation.
//
// A 404 here is an ordinary answer, not a fault: it means the organization
// holds its own key and the remote server has no copy. The caller reports the
// original "no key" error in that case, because that is the true situation.
func fetchManagedIdentity(ctx context.Context, serverURL, nodeID, token string) (*managedIdentityFetchResponse, error) {
	if err := refuseInsecureServerURL(serverURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/api/v1/nodes/%s/identity", strings.TrimRight(serverURL, "/"), nodeID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var res managedIdentityFetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// resolveManagedIdentity is the last fallback for restore and verify: when no
// key is on this host, ask whether SafeGrd holds one for this organization.
//
// Returns "" whenever it cannot, including for a customer-held org, so the
// caller's existing "decryption key required" error stands unchanged.
func resolveManagedIdentity(ctx context.Context, cfg *config.CLIConfig, verbose bool) string {
	if cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return ""
	}
	res, err := fetchManagedIdentity(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
	if err != nil || res == nil || res.Identity == "" {
		return ""
	}
	if verbose {
		// The fingerprint, never the key. An operator needs to know which key
		// opened the archive and where it came from; printing the identity
		// itself would put it in a terminal scrollback and a CI log.
		fmt.Printf("   Decryption Key:  SafeGrd-managed identity for org %s (fetched, not stored)\n", res.OrgID)
		if res.Notice != "" {
			fmt.Printf("   Notice:          %s\n", res.Notice)
		}
	}
	return res.Identity
}
