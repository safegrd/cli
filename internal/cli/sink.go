package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
//  1. CLI flags (highest precedence)
//  2. Remote server project sink routing (if node enrolled and remote server reachable)
//  3. Local config file / environment variables (offline fallback)
func resolveStorageRouting(ctx context.Context, cfg *config.CLIConfig, flagBucket, flagPrefix, flagRegion, flagEndpoint string, verbose bool) config.StorageConfig {
	storageCfg := cfg.Storage

	// 2. Remote server project sink routing. Not for hosted storage: that is an
	// explicit choice, leased separately (hosted.go), and a project sink must not
	// silently redirect it.
	if storageCfg.Type != config.StorageTypeHosted && cfg.ServerURL != "" && cfg.NodeID != "" && cfg.ServerToken != "" {
		sinkResp, err := fetchNodeSink(ctx, cfg.ServerURL, cfg.NodeID, cfg.ServerToken)
		if err == nil && sinkResp != nil && sinkResp.Configured && sinkResp.Sink != nil {
			if sinkResp.Sink.Bucket != "" {
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
				// Object Lock intent: a node enrolled with a centrally-managed sink
				// has no local storage config, so storageCfg.WORMMode is empty here
				// and ResolveWORMMode defaults to COMPLIANCE. Applying the sink's
				// configured WORMMode ensures governance mode is respected if configured.
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
		} else if verbose && err != nil && cfg.ServerURL != "" {
			fmt.Printf("   Sink Routing:    Remote server offline (%v); falling back to local storage config\n", err)
		}
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

	return storageCfg
}
