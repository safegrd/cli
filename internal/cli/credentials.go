package cli

import (
	"context"
	"encoding/json"
	"errors"
	"filippo.io/age"
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
	return refuseInsecureServerURLFor(serverURL, "fetch credentials from", "this request carries a node "+
		"token and returns database and storage secrets")
}

// refuseInsecurePersonalToken is the same rule for the commands that send a
// personal access token or receive a session: login, enroll, whoami, org and
// projects. A PAT reaches every project the person can see, and a typed
// http:// URL would send it in the clear once before the server could object.
func refuseInsecurePersonalToken(serverURL string) error {
	return refuseInsecureServerURLFor(serverURL, "sign in to", "this request carries a personal access token")
}

func refuseInsecureServerURLFor(serverURL, verb, why string) error {
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
	return fmt.Errorf("refusing to %s %s over %s: %s. Use https:// (or run the remote server on loopback)",
		verb, u.Host, u.Scheme, why)
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
		src.PublicKey = "remote server (SafeGrd-managed key)"
	}

	if verbose {
		// Only what SafeGrd supplied is news: "database=not configured"
		// printed before every --database-url backup read like a fault.
		var from []string
		for _, f := range []struct{ name, src string }{{"database URL", src.DatabaseURL}, {"bucket key", src.SinkSecret}, {"public key", src.PublicKey}} {
			if strings.HasPrefix(f.src, "remote server") {
				from = append(from, f.name)
			}
		}
		if len(from) > 0 {
			fmt.Printf("   From SafeGrd:    %s\n", strings.Join(from, ", "))
		}
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

// errNoManagedKey is the remote server's 404: it holds no key for what was
// asked, because the host that took it keeps its own. An ordinary answer.
var errNoManagedKey = errors.New("the remote server holds no key for this")

// errHeldLocally is the remote server's 204: the key asked for is one this
// host already has, so nothing was released.
var errHeldLocally = errors.New("this host already holds the key")

// heldKeyQuery names what a restore needs: the snapshot, or for a whole
// repository the recipient it is sealed to; and the keys this host already
// holds, so the server releases nothing when one of them is the key.
type heldKeyQuery struct {
	snapshotID string
	recipient  string
	have       []string
}

// fetchManagedIdentity asks the remote server for the one Age identity it
// holds for what the query names (M91: one key per release, never every key
// the organization holds).
//
// The returned key is never written anywhere. It is not saved to key_path, not
// written into the config, and not logged; it exists in one local variable for
// the length of one restore. Writing it to key_path would quietly convert a
// managed-custody organization into a customer-held one on that host, which is
// the opposite of what the operator chose and would survive revocation.
func fetchManagedIdentity(ctx context.Context, serverURL, nodeID, token string, hq heldKeyQuery) (*managedIdentityFetchResponse, error) {
	if err := refuseInsecureServerURL(serverURL); err != nil {
		return nil, err
	}
	q := url.Values{}
	if hq.snapshotID != "" {
		q.Set("snapshot", hq.snapshotID)
	} else {
		q.Set("recipient", hq.recipient)
	}
	for _, h := range hq.have {
		q.Add("have", h)
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/api/v1/nodes/%s/identity?%s", strings.TrimRight(serverURL, "/"), nodeID, q.Encode()), nil)
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
	if resp.StatusCode == http.StatusNoContent {
		return nil, errHeldLocally
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		if resp.StatusCode == http.StatusNotFound {
			if e.Error != "" {
				return nil, fmt.Errorf("%w: %s", errNoManagedKey, e.Error)
			}
			return nil, errNoManagedKey
		}
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

// resolveManagedIdentity is the key a daemon drill of this host's own surfaces
// needs when the host has none: the one its own recipient names. "" when the
// server holds no such key (customer-held), so the caller's error stands.
func resolveManagedIdentity(ctx context.Context, cfg *config.CLIConfig, verbose bool) string {
	return withManagedIdentity(ctx, cfg, "", heldKeyQuery{recipient: strings.TrimSpace(cfg.Encryption.PublicKey)}, verbose)
}

// withManagedIdentity is the key set restore, verify, check and find decrypt
// with: the host's own key, plus the one key SafeGrd holds for what is being
// read, when the host's own key is not it. A host that replaced a lost one
// has a key of its own that cannot open the lost host's snapshots; the held
// key for that host can. The server is told which keys the host has, so a
// host whose own key opens the snapshot is released nothing (M91; it used to
// be sent every key the organization held on every restore).
//
// A failed fetch is said out loud only when the host has no key of its own:
// an offline restore with the host's own key is the normal case.
func withManagedIdentity(ctx context.Context, cfg *config.CLIConfig, local string, hq heldKeyQuery, verbose bool) string {
	if cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return local
	}
	if hq.snapshotID == "" && hq.recipient == "" {
		return local
	}
	if local != "" {
		ids, err := crypto.ParseIdentities(local)
		if err == nil {
			for _, id := range ids {
				if x, ok := id.(*age.X25519Identity); ok {
					hq.have = append(hq.have, x.Recipient().String())
				}
			}
		}
	}
	res, err := fetchManagedIdentity(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken, hq)
	switch {
	case errors.Is(err, errHeldLocally):
		return local
	case err != nil && local == "":
		if errors.Is(err, errNoManagedKey) {
			// Says which key it is and where it could be: the decrypt error
			// that follows would only say no identity matched.
			fmt.Fprintf(os.Stderr, "Warning: this host has no key that opens it (%s). %s\n",
				keyLocation(cfg), strings.TrimPrefix(err.Error(), errNoManagedKey.Error()+": "))
		} else {
			fmt.Fprintf(os.Stderr, "Warning: could not fetch the key the remote server holds: %v\n", err)
		}
		return ""
	case err != nil:
		return local
	}
	var keys []string
	for _, id := range res.Identities {
		if id.Identity != "" {
			keys = append(keys, id.Identity)
		}
	}
	if len(keys) == 0 {
		return local
	}
	if verbose {
		// The fingerprint, never the key. An operator needs to know which key
		// opened the archive and where it came from; printing the identity
		// itself would put it in a terminal scrollback and a CI log.
		fmt.Printf("   Decryption key:  %s, SafeGrd-managed key of org %s (fetched, not stored)\n",
			crypto.Fingerprint(res.Identities[0].PublicKey), res.OrgID)
		if res.Notice != "" {
			fmt.Printf("   Notice:          %s\n", res.Notice)
		}
	}
	if local == "" {
		return strings.Join(keys, "\n")
	}
	return local + "\n" + strings.Join(keys, "\n")
}

// keyLocation is where this host looks for its own key, for an error that
// says the key is missing.
func keyLocation(cfg *config.CLIConfig) string {
	if cfg.Encryption.KeyPath != "" {
		return "looked in " + cfg.Encryption.KeyPath + "; pass another with --key-path or SAFEGRD_PRIVATE_KEY"
	}
	return "pass it with --key-path or SAFEGRD_PRIVATE_KEY"
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
