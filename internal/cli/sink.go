package cli

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

type nodeSinkResponse struct {
	NodeID      string `json:"node_id"`
	ProjectID   string `json:"project_id"`
	ProjectName string `json:"project_name"`
	Configured  bool   `json:"configured"`
	Sink        *struct {
		Bucket            string `json:"bucket"`
		Region            string `json:"region"`
		Endpoint          string `json:"endpoint"`
		Prefix            string `json:"prefix"`
		ForcePathStyle    bool   `json:"force_path_style"`
		UseWORMObjectLock bool   `json:"use_worm_object_lock"`
		WORMMode          string `json:"worm_mode"`
		RetentionDays     int    `json:"retention_days"`
	} `json:"sink"`
	// Origin is who set the project's bucket up: "console", or "cli" for one
	// a host registered from its own config, which routes nobody. KeyHeld is
	// whether the remote server holds a console bucket's key.
	Origin     string `json:"origin"`
	KeyHeld    bool   `json:"key_held"`
	Registered *struct {
		Bucket   string `json:"bucket"`
		Endpoint string `json:"endpoint"`
		NodeID   string `json:"node_id"`
	} `json:"registered"`
	// FingerprintSalt keys the fingerprint of this host's own bucket key.
	FingerprintSalt string `json:"fingerprint_salt"`
}

func fetchNodeSink(ctx context.Context, serverURL, nodeID, token string) (*nodeSinkResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/v1/nodes/%s/sink", serverURL, nodeID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		noteServerUnreachable()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		noteServerStatus(resp.StatusCode)
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var res nodeSinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		noteServerUnreachable()
		return nil, err
	}
	return &res, nil
}

// resolveStorageRouting applies the storage routing precedence rule:
// CLI flags, then the project's bucket on the remote server, then the host's
// own config. It fails only when the remote server's bucket and this host's
// own config are two origins for one project (routeProjectSink).
func resolveStorageRouting(ctx context.Context, cfg *config.CLIConfig, flagBucket, flagPrefix, flagRegion, flagEndpoint string, verbose bool) (config.StorageConfig, error) {
	return routeStorage(ctx, cfg, flagBucket, flagPrefix, flagRegion, flagEndpoint, verbose, false)
}

// routeStorage is resolveStorageRouting for a command that writes: with
// register, a host naming its own bucket reports it (routeProjectSink).
func routeStorage(ctx context.Context, cfg *config.CLIConfig, flagBucket, flagPrefix, flagRegion, flagEndpoint string, verbose, register bool) (config.StorageConfig, error) {
	storageCfg := cfg.Storage
	if err := routeProjectSink(ctx, cfg, &storageCfg, verbose, register); err != nil {
		return storageCfg, err
	}

	// 1. CLI flags override everything
	if flagBucket != "" {
		storageCfg.Bucket = flagBucket
		storageCfg.Type = config.StorageTypeS3
	}
	if flagPrefix != "" {
		storageCfg.Prefix = flagPrefix
	}
	if flagRegion != "" {
		storageCfg.Region = flagRegion
	}
	if flagEndpoint != "" {
		storageCfg.Endpoint = flagEndpoint
	}

	if cfg.NodeID != "" && storageCfg.NodeID == "" {
		storageCfg.NodeID = cfg.NodeID
	}

	return storageCfg, nil
}

// routeProjectSink points storageCfg at the project's bucket when the remote
// server has one for this host's project. Every command that opens storage
// for this host goes through it, the daemon included: a host whose project
// has a bucket must not back up to its own disk while the console shows the
// bucket. Not for hosted storage: that is an explicit choice, leased
// separately (hosted.go), and a project sink must not silently redirect it.
//
// A project's bucket has one origin. Only a bucket set up in the console
// routes; one a host registered from its own config is that host's, and every
// host names it itself. A host whose own config names a different bucket than
// the console's, or sets its own key where the remote server holds it, is
// refused rather than quietly overridden either way. With register, a host
// naming its own bucket in a project with none reports it: the bucket and a
// fingerprint of its key, never the key. An unreachable server leaves the
// host's own config in place, and says so.
func routeProjectSink(ctx context.Context, cfg *config.CLIConfig, storageCfg *config.StorageConfig, verbose, register bool) error {
	if storageCfg.Type == config.StorageTypeHosted || cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return nil
	}
	sinkResp, err := fetchNodeSink(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not ask the remote server where this project's backups go (%v); using this host's storage config\n", err)
		return nil
	}
	ownBucket := storageCfg.Type == config.StorageTypeS3 && storageCfg.Bucket != ""
	if !sinkResp.Configured || sinkResp.Sink == nil || sinkResp.Sink.Bucket == "" {
		if ownBucket && register {
			return registerOwnBucket(ctx, cfg, storageCfg, sinkResp.FingerprintSalt)
		}
		return nil
	}
	if err := secondOrigin(sinkResp, storageCfg); err != nil {
		return err
	}
	storageCfg.Type = config.StorageTypeS3
	storageCfg.Bucket = sinkResp.Sink.Bucket
	if sinkResp.Sink.Region != "" {
		storageCfg.Region = sinkResp.Sink.Region
	}
	if sinkResp.Sink.Endpoint != "" {
		storageCfg.Endpoint = sinkResp.Sink.Endpoint
	}
	if sinkResp.Sink.Prefix != "" {
		storageCfg.Prefix = sinkResp.Sink.Prefix
	}
	storageCfg.ForcePathStyle = sinkResp.Sink.ForcePathStyle
	// Object Lock intent: a node enrolled with a centrally-managed sink has
	// no local storage config, so storageCfg.WORMMode is empty here and
	// ResolveWORMMode defaults to COMPLIANCE. The sink's mode is applied so
	// governance, or NONE on a bucket with no Object Lock, is respected.
	if sinkResp.Sink.WORMMode != "" {
		storageCfg.WORMMode = config.WORMMode(sinkResp.Sink.WORMMode)
	}
	if sinkResp.Sink.RetentionDays > 0 {
		storageCfg.RetentionDays = sinkResp.Sink.RetentionDays
	}
	if verbose {
		fmt.Printf("   Storage:         project '%s' -> s3://%s\n", sinkResp.ProjectName, storageCfg.Bucket)
	}
	return nil
}

// secondOrigin refuses a host's own storage that would be a second origin for
// a bucket set up on the remote server: another bucket, or its own key where
// the server holds the key. Only a bucket the server says is the console's
// is judged.
func secondOrigin(sinkResp *nodeSinkResponse, st *config.StorageConfig) error {
	if sinkResp.Origin != "console" || sinkResp.Sink == nil || st.Type != config.StorageTypeS3 || st.Bucket == "" {
		return nil
	}
	if !sameBucket(sinkResp.Sink.Bucket, sinkResp.Sink.Endpoint, st.Bucket, st.Endpoint) {
		return fmt.Errorf("project '%s' keeps its backups in s3://%s, set up on the remote server, and this host's config "+
			"names s3://%s. A project's bucket has one origin: remove the bucket from this host's storage config so it "+
			"uses the project's, or change the project's bucket on the remote server",
			sinkResp.ProjectName, sinkResp.Sink.Bucket, st.Bucket)
	}
	if sinkResp.KeyHeld && st.SecretAccessKey != "" {
		return fmt.Errorf("the remote server holds the key for project '%s''s bucket, and this host's storage config sets "+
			"its own secret_access_key. A bucket's key has one origin: remove it from this host's config, and the host "+
			"fetches the held key when it backs up", sinkResp.ProjectName)
	}
	return nil
}

// checkSurfaceStorage applies the same refusal to a surface's own storage
// section, which is never rerouted: it is the surface's explicit choice, and
// may still not be a second origin for its project's bucket.
func checkSurfaceStorage(ctx context.Context, cfg *config.CLIConfig, st *config.StorageConfig) error {
	if st.Type != config.StorageTypeS3 || cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return nil
	}
	sinkResp, err := fetchNodeSink(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not ask the remote server where this project's backups go (%v); using this surface's storage config\n", err)
		return nil
	}
	return secondOrigin(sinkResp, st)
}

// sameBucket is whether two storage configs name one bucket. An endpoint
// left out is the provider's default, the same place only as another left out.
func sameBucket(bucketA, endpointA, bucketB, endpointB string) bool {
	return bucketA == bucketB && strings.TrimRight(endpointA, "/") == strings.TrimRight(endpointB, "/")
}

// bucketKeyFingerprint identifies a bucket key without revealing it: an HMAC
// under the salt the remote server gives this project's hosts, so the same
// key on two hosts matches and a guessable key cannot be looked up.
func bucketKeyFingerprint(salt, secret string) string {
	if salt == "" || secret == "" {
		return ""
	}
	m := hmac.New(sha256.New, []byte(salt))
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// registerOwnBucket reports the bucket this host's own config names to the
// remote server, which records it as the project's, owned by its hosts. A
// refusal fails the command, because the server has said this bucket would be
// a second origin for the project. Any other failure is said and the host's
// own config is used: protection never waits on the remote server.
func registerOwnBucket(ctx context.Context, cfg *config.CLIConfig, st *config.StorageConfig, salt string) error {
	if err := refuseInsecureServerURL(cfg.ServerURL); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: not registering this host's bucket with the remote server: %v\n", err)
		return nil
	}
	body, _ := json.Marshal(model.NodeSinkRegisterRequest{
		Bucket: st.Bucket, Region: st.Region, Endpoint: st.Endpoint, Prefix: st.Prefix,
		AccessKeyID: st.AccessKeyID, ForcePathStyle: st.ForcePathStyle, WORMMode: string(st.WORMMode),
		KeyFingerprint: bucketKeyFingerprint(salt, st.SecretAccessKey),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		fmt.Sprintf("%s/api/v1/nodes/%s/sink", strings.TrimRight(cfg.ServerURL, "/"), cfg.NodeID), bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ServerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent())
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not register this host's bucket with the remote server (%v); backing up to it anyway\n", err)
		return nil
	}
	defer resp.Body.Close()
	var answer struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&answer)
	switch {
	case resp.StatusCode == http.StatusConflict:
		return fmt.Errorf("the remote server refused this host's bucket: %s", answer.Error)
	case resp.StatusCode/100 != 2:
		fmt.Fprintf(os.Stderr, "Warning: the remote server did not record this host's bucket (HTTP %d %s); backing up to it anyway\n",
			resp.StatusCode, answer.Error)
	}
	return nil
}

// applyHeldSinkKey fills in the bucket key the remote server holds for this
// host's project, when the host's config has none. Only the key: the daemon
// resolves its surfaces' own credentials separately, per surface. A failure
// is said out loud; the backup then fails on the missing key, not on a guess.
func applyHeldSinkKey(ctx context.Context, cfg *config.CLIConfig, storageCfg *config.StorageConfig) {
	if storageCfg.Type != config.StorageTypeS3 || storageCfg.SecretAccessKey != "" ||
		cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return
	}
	creds, err := fetchNodeCredentials(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not fetch the bucket key the remote server holds (%v)\n", err)
		return
	}
	if creds.Sink != nil && creds.Sink.SecretAccessKey != "" {
		storageCfg.AccessKeyID = creds.Sink.AccessKeyID
		storageCfg.SecretAccessKey = creds.Sink.SecretAccessKey
	}
}
