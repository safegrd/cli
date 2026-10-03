package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
)

// nodeCredentialsResponse mirrors the remote server's credential release
// payload.
//
// Every field here is a live secret except PublicKey. None of them is ever
// written back to the config file: SaveCLIConfig is not called on this path,
// and the values live in the CLIConfig struct in memory for the length of one
// command. That is the whole point of fetching them: a credential that lands
// on disk makes central revocation stop being revocation, because the host
// keeps working after the remote server has withdrawn it.
type nodeCredentialsResponse struct {
	NodeID      string `json:"node_id"`
	ProjectID   string `json:"project_id"`
	DatabaseURL string `json:"database_url"`
	Password    string `json:"password"`
	Sink        *struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	} `json:"sink"`
	PublicKey string `json:"public_key"`
	Notice    string `json:"notice"`
}

// runningCommand is the name of the command this process is running,
// recorded by the root command before it runs.
var runningCommand string

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
	// The command asking is named, so the remote server's record of who took
	// a credential can tell a `doctor` check from a backup. It is still a
	// release either way: doctor really does fetch the secret to prove it
	// resolves.
	u := fmt.Sprintf("%s/api/v1/nodes/%s/credentials", strings.TrimRight(serverURL, "/"), nodeID)
	if runningCommand != "" {
		u += "?purpose=" + url.QueryEscape(runningCommand)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", UserAgent())

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
// to intercept. host.docker.internal is allowed for the same reason: inside a
// container it names the machine the container runs on, so a container
// reaching a server on its own host crosses no network either. Anything else
// carrying a node token and returning a database password over http:// is a
// mistake worth failing loudly on, not a warning.
func refuseInsecureServerURL(serverURL string) error {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return fmt.Errorf("server_url is not a URL: %w", err)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "host.docker.internal") {
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
	return resolveCredentials(ctx, cfg, storageCfg, verbose, true)
}

// resolveSinkCredentials fills in only the storage sink's secret. A command
// that reads backups (verify, restore) needs neither the database URL nor
// the recipient key, so it does not ask for them: a token that may read
// backups but not the surface's credentials, such as the one a drill run on
// the remote server gets, is not refused for something it never needed.
func resolveSinkCredentials(ctx context.Context, cfg *config.CLIConfig, storageCfg *config.StorageConfig) credentialSource {
	return resolveCredentials(ctx, cfg, storageCfg, false, false)
}

func resolveCredentials(ctx context.Context, cfg *config.CLIConfig, storageCfg *config.StorageConfig, verbose, surface bool) credentialSource {
	src := credentialSource{DatabaseURL: "local config", SinkSecret: "local config", PublicKey: "local config"}
	if cfg.DatabaseURL == "" {
		src.DatabaseURL = "not configured"
	}
	// Hosted storage is leased per command, never held, so it needs no secret.
	hosted := storageCfg.Type == config.StorageTypeHosted
	if hosted {
		src.SinkSecret = "hosted lease"
	} else if storageCfg.SecretAccessKey == "" {
		src.SinkSecret = "not configured"
	}
	if cfg.Encryption.PublicKey == "" {
		src.PublicKey = "not configured"
	}

	needsSomething := storageCfg.SecretAccessKey == "" && !hosted
	if surface {
		needsSomething = needsSomething || cfg.DatabaseURL == "" || cfg.Encryption.PublicKey == ""
	}
	if !needsSomething || cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return src
	}

	creds, err := fetchNodeCredentials(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
	if err != nil {
		// On stderr whatever verbose says: it is a warning, and --json
		// keeps stdout for the JSON.
		fmt.Fprintf(os.Stderr, "Warning: could not fetch credentials from the remote server (%v). Using this host's config only.\n", err)
		return src
	}

	if surface && cfg.DatabaseURL == "" && creds.DatabaseURL != "" {
		cfg.DatabaseURL = creds.DatabaseURL
		src.DatabaseURL = "remote server"
	}
	if storageCfg.SecretAccessKey == "" && !hosted && creds.Sink != nil && creds.Sink.SecretAccessKey != "" {
		storageCfg.AccessKeyID = creds.Sink.AccessKeyID
		storageCfg.SecretAccessKey = creds.Sink.SecretAccessKey
		src.SinkSecret = "remote server"
	}
	if surface && cfg.Encryption.PublicKey == "" && creds.PublicKey != "" {
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
	OrgID string `json:"org_id"`
	// One per key the organization holds: each managed host that enrolled
	// added its own. A snapshot opens with the one it was sealed to.
	Identities []struct {
		PublicKey string `json:"public_key"`
		Identity  string `json:"identity"`
	} `json:"identities"`
	KeyCustody string `json:"key_custody"`
	Notice     string `json:"notice"`
}

// errNoManagedKey is the remote server's 404: every host in the organization
// keeps its own key, so there is nothing to fetch. An ordinary answer, not a fault.
var errNoManagedKey = errors.New("the remote server holds no key for this organization")

// fetchManagedIdentity asks the remote server for the Age identity it holds for
// this node's organization.
//
// The returned key is never written anywhere. It is not saved to key_path, not
// written into the config, and not logged; it exists in one local variable for
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
	req.Header.Set("User-Agent", UserAgent())

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNoManagedKey
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		if e.Error != "" {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Error)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var res managedIdentityFetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// resolveManagedIdentity asks whether SafeGrd holds keys for this
// organization, for restore and verify when no key is on this host.
//
// Returns "" whenever it cannot, including for a customer-held org, so the
// caller's existing "decryption key required" error stands unchanged. In an
// organization that holds keys for some hosts but not this one, it returns
// those keys (an older snapshot may be sealed to one) and says on stderr that
// this host's own key has to be passed in.
func resolveManagedIdentity(ctx context.Context, cfg *config.CLIConfig, verbose bool) string {
	return fetchManagedKeys(ctx, cfg, verbose, true)
}

// withManagedIdentities is the key set restore and verify decrypt with: the
// host's own key, plus every key SafeGrd holds for the organization when the
// host is enrolled. A host that replaced a lost one has a key of its own that
// cannot open the lost host's snapshots; the held key for that host can, and
// trying the local key alone failed the restore managed custody exists for.
// An organization whose hosts all keep their own key answers 404, and only
// the local key is used. A
// failed fetch is not reported while a local key exists: an offline restore
// with the host's own key is the normal case, not a warning.
func withManagedIdentities(ctx context.Context, cfg *config.CLIConfig, local string, verbose bool) string {
	if local == "" {
		return fetchManagedKeys(ctx, cfg, verbose, true)
	}
	held := fetchManagedKeys(ctx, cfg, verbose, false)
	if held == "" {
		return local
	}
	return local + "\n" + held
}

func fetchManagedKeys(ctx context.Context, cfg *config.CLIConfig, verbose, reportFailure bool) string {
	if cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return ""
	}
	res, err := fetchManagedIdentity(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
	if err != nil && !errors.Is(err, errNoManagedKey) && reportFailure {
		// The caller goes on to report that no key was found, which is true
		// but not why. Say why first.
		fmt.Fprintf(os.Stderr, "Warning: could not fetch the key the remote server holds: %v\n", err)
	}
	if err != nil || res == nil {
		return ""
	}
	var keys []string
	ownHeld := cfg.Encryption.PublicKey == ""
	for _, id := range res.Identities {
		if id.Identity != "" {
			keys = append(keys, id.Identity)
			ownHeld = ownHeld || id.PublicKey == cfg.Encryption.PublicKey
		}
	}
	if len(keys) == 0 {
		return ""
	}
	if !ownHeld {
		// The organization holds keys for its other hosts, but this host's
		// key is the customer's. Those keys open only snapshots sealed to
		// them, so the decrypt error that follows needs this said first.
		fmt.Fprintf(os.Stderr, "Warning: you hold this host's key (%s), and it is not on this host.\n"+
			"   Pass it with --private-key or SAFEGRD_PRIVATE_KEY. Trying the keys the remote server holds for other hosts.\n",
			crypto.Fingerprint(cfg.Encryption.PublicKey))
		return strings.Join(keys, "\n")
	}
	if verbose {
		// The fingerprint, never the key. An operator needs to know which key
		// opened the archive and where it came from; printing the identity
		// itself would put it in a terminal scrollback and a CI log.
		fmt.Printf("   Decryption key:  SafeGrd-managed identity for org %s (fetched, not stored)\n", res.OrgID)
		if res.Notice != "" {
			fmt.Printf("   Notice:          %s\n", res.Notice)
		}
	}
	// One per line; the decryptor uses whichever the snapshot was sealed to.
	return strings.Join(keys, "\n")
}

// fetchHeldSurfaceSecret fills in the credential the remote server holds for
// a surface, when its config says so. A surface that also names a credential
// on the host is refused when it resolves (validCredential), not fetched. It asks
// as the host, for the surface's own node: the server releases a surface's
// credential to the host that registered it and to nothing else. A failure is
// said out loud and the backup goes on to fail on the missing credential,
// rather than on a guess.
func fetchHeldSurfaceSecret(ctx context.Context, c *config.CLIConfig, nodeID string, s *config.SurfaceConfig) {
	if !s.FromSafeGrd() || s.HeldSecret != "" || credentialOnHost(s) != "" {
		return
	}
	if c.ServerURL == "" || c.ServerToken == "" || nodeID == "" || nodeID == s.ID {
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: its credential is held by the remote server, but this surface is not registered with it yet.\n", s.ID)
		return
	}
	creds, err := fetchNodeCredentials(ctx, c.ServerURL, nodeID, c.ServerToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: could not fetch the credential the remote server holds for it: %v\n", s.ID, err)
		return
	}
	if strings.ToLower(s.Type) == "email" {
		s.HeldSecret = creds.Password
	} else {
		s.HeldSecret = creds.DatabaseURL
	}
	if s.HeldSecret == "" {
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: the remote server holds no credential for it. Set one in the console, or name a variable on this host.\n", s.ID)
	}
}
