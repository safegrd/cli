package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/safegrd/cli/pkg/config"
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
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var res nodeSinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// resolveStorageRouting applies the storage routing precedence rule:
// CLI flags, then the project's bucket on the remote server, then the host's
// own config.
func resolveStorageRouting(ctx context.Context, cfg *config.CLIConfig, flagBucket, flagPrefix, flagRegion, flagEndpoint string, verbose bool) config.StorageConfig {
	storageCfg := cfg.Storage
	routeProjectSink(ctx, cfg, &storageCfg, verbose)

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

	return storageCfg
}

// routeProjectSink points storageCfg at the project's bucket when the remote
// server has one for this host's project. Every command that opens storage
// for this host goes through it, the agent included: a host whose project
// has a bucket must not back up to its own disk while the console shows the
// bucket. Not for hosted storage: that is an explicit choice, leased
// separately (hosted.go), and a project sink must not silently redirect it.
// An unreachable server leaves the host's own config in place, and says so.
func routeProjectSink(ctx context.Context, cfg *config.CLIConfig, storageCfg *config.StorageConfig, verbose bool) {
	if storageCfg.Type == config.StorageTypeHosted || cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return
	}
	sinkResp, err := fetchNodeSink(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Could not ask the remote server where this project's backups go (%v); using this host's storage config\n", err)
		return
	}
	if !sinkResp.Configured || sinkResp.Sink == nil || sinkResp.Sink.Bucket == "" {
		return
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
		fmt.Printf("   Sink Routing:    Project '%s' -> s3://%s\n", sinkResp.ProjectName, storageCfg.Bucket)
	}
}

// applyHeldSinkKey fills in the bucket key the remote server holds for this
// host's project, when the host's config has none. Only the key: the agent
// resolves its surfaces' own credentials separately, per surface. A failure
// is said out loud; the backup then fails on the missing key, not on a guess.
func applyHeldSinkKey(ctx context.Context, cfg *config.CLIConfig, storageCfg *config.StorageConfig) {
	if storageCfg.Type != config.StorageTypeS3 || storageCfg.SecretAccessKey != "" ||
		cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return
	}
	creds, err := fetchNodeCredentials(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Could not fetch the bucket key the remote server holds (%v)\n", err)
		return
	}
	if creds.Sink != nil && creds.Sink.SecretAccessKey != "" {
		storageCfg.AccessKeyID = creds.Sink.AccessKeyID
		storageCfg.SecretAccessKey = creds.Sink.SecretAccessKey
	}
}
