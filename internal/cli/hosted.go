package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// hostedLease is the remote server's answer to "where may this host write, and
// as whom": a short-lived credential confined to the organization's prefix in
// SafeGrd's own locked bucket, and the retention to use when the config sets
// none. It lives in memory for one command and is never written to disk.
type hostedLease struct {
	Bucket          string    `json:"bucket"`
	Endpoint        string    `json:"endpoint"`
	Region          string    `json:"region"`
	ForcePathStyle  bool      `json:"force_path_style"`
	Prefix          string    `json:"prefix"`
	WORMMode        string    `json:"worm_mode"`
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	ExpiresAt       time.Time `json:"expires_at"`
	RetentionDays   int       `json:"retention_days"`
	KeepDaily       int       `json:"keep_daily"`
	KeepWeekly      int       `json:"keep_weekly"`
	KeepMonthly     int       `json:"keep_monthly"`
	QuotaBytes      int64     `json:"quota_bytes"`
	UsedBytes       int64     `json:"used_bytes"`
	Warning         string    `json:"warning"`
}

// gfs is the lease's retention tiers, used where the config sets none.
func (l *hostedLease) gfs() gfs {
	if l == nil {
		return gfs{}
	}
	return gfs{Days: l.KeepDaily, Weeks: l.KeepWeekly, Months: l.KeepMonthly}
}

// resolveHostedStorage turns storage.type: hosted into a working S3 config by
// leasing a credential from the remote server. It does nothing for any other
// storage type.
//
// write asks for a lease that can upload; the server refuses one when the
// organization's hosted storage is full or its owner has not verified an email,
// and that refusal is the command's error. A read lease is never refused for
// either, so list, verify, restore and export always work.
//
// There is no fallback. The bytes are in SafeGrd's bucket, so without the
// remote server there is nowhere else to write them; saying so is the only
// honest outcome.
func resolveHostedStorage(ctx context.Context, cfg *config.CLIConfig, storageCfg *config.StorageConfig, write bool) (*hostedLease, error) {
	if storageCfg.Type != config.StorageTypeHosted {
		return nil, nil
	}
	if cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return nil, fmt.Errorf("storage.type is hosted, which needs this host enrolled with the remote server " +
			"(node_id and server_token): run `safegrd enroll`")
	}
	if err := refuseInsecureServerURL(cfg.ServerURL); err != nil {
		return nil, err
	}
	mode := "read"
	if write {
		mode = "write"
	}
	url := fmt.Sprintf("%s/api/v1/nodes/%s/hosted-storage?mode=%s", strings.TrimRight(cfg.ServerURL, "/"), cfg.NodeID, mode)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ServerToken)
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("hosted storage: the remote server could not be reached: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if body.Error == "" {
			body.Error = resp.Status
		}
		return nil, fmt.Errorf("hosted storage: %s", body.Error)
	}
	var l hostedLease
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		return nil, fmt.Errorf("hosted storage: unreadable lease: %w", err)
	}
	if l.Bucket == "" || l.AccessKeyID == "" || l.SecretAccessKey == "" || l.Prefix == "" {
		return nil, fmt.Errorf("hosted storage: the remote server's lease is incomplete")
	}

	storageCfg.Type = config.StorageTypeS3
	storageCfg.Bucket = l.Bucket
	storageCfg.Endpoint = l.Endpoint
	storageCfg.Region = l.Region
	storageCfg.ForcePathStyle = l.ForcePathStyle
	storageCfg.Prefix = l.Prefix
	storageCfg.AccessKeyID = l.AccessKeyID
	storageCfg.SecretAccessKey = l.SecretAccessKey
	storageCfg.SessionToken = l.SessionToken
	// Hosted storage is always locked: the mode is the bucket's, not the host's
	// to choose.
	storageCfg.WORMMode = config.WORMMode(l.WORMMode)
	if storageCfg.RetentionDays == 0 {
		storageCfg.RetentionDays = l.RetentionDays
	}
	if l.Warning != "" {
		fmt.Fprintf(os.Stderr, "⚠️  %s At 100%% new backups are refused; existing ones stay restorable.\n", l.Warning)
	}
	return &l, nil
}

// formatBytes renders a byte count in binary units, for quota messages.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
