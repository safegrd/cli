package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// StorageType enumerates supported storage backends.
type StorageType string

const (
	StorageTypeS3    StorageType = "s3"
	StorageTypeLocal StorageType = "local"
)

// WORMMode specifies Object Lock enforcement level.
type WORMMode string

const (
	WORMModeCompliance WORMMode = "COMPLIANCE"
	WORMModeGovernance WORMMode = "GOVERNANCE"

	// WORMModeNone writes objects with no Object Lock at all.
	//
	// It exists because several S3-compatible providers — DigitalOcean Spaces
	// among them — do not implement Object Lock, and until this value existed
	// SafeGrd could not write to them at all: every PutObject carried a
	// retain-until date and the bucket rejected it. The alternative was
	// silently dropping the lock when a bucket refused one, which is the worst
	// option on the list, because the CLI would keep printing "WORM Locked"
	// over objects anyone can delete.
	//
	// So it is opt-in, spelled out, and never a default or a fallback. A
	// backup written under it is a copy, not a proof: it is still encrypted and
	// still attested, but nothing stops an attacker who reaches the bucket from
	// deleting it, and `safegrd backup` says so on every run.
	WORMModeNone WORMMode = "NONE"
)

// StorageConfig holds settings for immutable snapshot storage.
type StorageConfig struct {
	Type            StorageType `yaml:"type" json:"type"`
	Bucket          string      `yaml:"bucket" json:"bucket"`
	Region          string      `yaml:"region" json:"region"`
	Endpoint        string      `yaml:"endpoint,omitempty" json:"endpoint,omitempty"` // For MinIO / R2
	Prefix          string      `yaml:"prefix" json:"prefix"`
	RetentionDays   int         `yaml:"retention_days" json:"retention_days"`
	WORMMode        WORMMode    `yaml:"worm_mode" json:"worm_mode"`
	LocalPath       string      `yaml:"local_path,omitempty" json:"local_path,omitempty"` // For local filesystem WORM
	AccessKeyID     string      `yaml:"access_key_id,omitempty" json:"access_key_id,omitempty"`
	SecretAccessKey string      `yaml:"secret_access_key,omitempty" json:"secret_access_key,omitempty"`
	ForcePathStyle  bool        `yaml:"force_path_style,omitempty" json:"force_path_style,omitempty"`
	NodeID          string      `yaml:"node_id,omitempty" json:"node_id,omitempty"`
	IAMRoleARN      string      `yaml:"iam_role_arn,omitempty" json:"iam_role_arn,omitempty"`
}

// EncryptionConfig holds Age asymmetric keypair configuration.
type EncryptionConfig struct {
	PublicKey  string `yaml:"public_key" json:"public_key"` // Age recipient: age1...
	PrivateKey string `yaml:"-" json:"-"`                   // Age identity: AGE-SECRET-KEY-1... (held in-memory, resolved from key_path or SAFEGRD_PRIVATE_KEY)
	KeyPath    string `yaml:"key_path" json:"key_path"`     // Path to identity file
}

// AlertConfig contains webhook notification channels.
type AlertConfig struct {
	SlackWebhookURL   string `yaml:"slack_webhook_url,omitempty" json:"slack_webhook_url,omitempty"`
	DiscordWebhookURL string `yaml:"discord_webhook_url,omitempty" json:"discord_webhook_url,omitempty"`
}

// AgentConfig configures the resident unattended daemon.
type AgentConfig struct {
	Interval        string `yaml:"interval,omitempty" json:"interval,omitempty"`                   // Poll interval, default "5m"
	MaxConcurrent   int    `yaml:"max_concurrent,omitempty" json:"max_concurrent,omitempty"`       // Max concurrent backups, default 1
	RetryBackoffMin string `yaml:"retry_backoff_min,omitempty" json:"retry_backoff_min,omitempty"` // Min retry backoff, default "5m"
	RetryBackoffMax string `yaml:"retry_backoff_max,omitempty" json:"retry_backoff_max,omitempty"` // Max retry backoff, default "1h"
	StateDir        string `yaml:"state_dir,omitempty" json:"state_dir,omitempty"`                 // Directory for state & locks
	LogFormat       string `yaml:"log_format,omitempty" json:"log_format,omitempty"`               // "text" or "json"
	LogLevel        string `yaml:"log_level,omitempty" json:"log_level,omitempty"`                 // "info", "warn", "debug"
	MetricsAddr     string `yaml:"metrics_addr,omitempty" json:"metrics_addr,omitempty"`           // e.g. "127.0.0.1:9847"
}

// DefaultsConfig defines fallback values inherited by surfaces.
type DefaultsConfig struct {
	Schedule      string `yaml:"schedule,omitempty" json:"schedule,omitempty"`             // "@daily", "@hourly", "6h", cron
	Timezone      string `yaml:"timezone,omitempty" json:"timezone,omitempty"`             // e.g. "UTC"
	RetentionDays int    `yaml:"retention_days,omitempty" json:"retention_days,omitempty"` // Default WORM retention days
	// KeepWeekly and KeepMonthly are the grandfather-father-son tiers: the
	// first backup of each ISO week is locked for KeepWeekly weeks, the first
	// of each month for KeepMonthly months, and every other backup for
	// RetentionDays. Zero turns a tier off.
	KeepWeekly  int `yaml:"keep_weekly,omitempty" json:"keep_weekly,omitempty"`
	KeepMonthly int `yaml:"keep_monthly,omitempty" json:"keep_monthly,omitempty"`
}

// SurfaceConfig defines a protected surface on a host.
type SurfaceConfig struct {
	ID            string `yaml:"id" json:"id"`     // Stable identifier
	Type          string `yaml:"type" json:"type"` // "postgres", "files", "email"
	Name          string `yaml:"name,omitempty" json:"name,omitempty"`
	Schedule      string `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	RetentionDays int    `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	KeepWeekly    int    `yaml:"keep_weekly,omitempty" json:"keep_weekly,omitempty"`
	KeepMonthly   int    `yaml:"keep_monthly,omitempty" json:"keep_monthly,omitempty"`

	// PreBackup runs before each of the agent's backups of this surface and
	// must succeed for the backup to happen; PostBackup runs after every
	// attempt, successful or not. Both are shell commands, run as the agent.
	PreBackup  string `yaml:"pre_backup,omitempty" json:"pre_backup,omitempty"`
	PostBackup string `yaml:"post_backup,omitempty" json:"post_backup,omitempty"`

	// Postgres fields
	DatabaseURL    string `yaml:"database_url,omitempty" json:"database_url,omitempty"`
	DatabaseURLEnv string `yaml:"database_url_env,omitempty" json:"database_url_env,omitempty"`

	// Files fields
	Roots    []string `yaml:"roots,omitempty" json:"roots,omitempty"`
	Excludes []string `yaml:"excludes,omitempty" json:"excludes,omitempty"`

	// Email fields
	Host              string   `yaml:"host,omitempty" json:"host,omitempty"`
	Port              int      `yaml:"port,omitempty" json:"port,omitempty"`
	Username          string   `yaml:"username,omitempty" json:"username,omitempty"`
	Folders           []string `yaml:"folders,omitempty" json:"folders,omitempty"`
	CredentialCommand string   `yaml:"credential_command,omitempty" json:"credential_command,omitempty"`
	PasswordEnv       string   `yaml:"password_env,omitempty" json:"password_env,omitempty"`

	// Storage & Encryption overrides
	Storage    *StorageConfig    `yaml:"storage,omitempty" json:"storage,omitempty"`
	Encryption *EncryptionConfig `yaml:"encryption,omitempty" json:"encryption,omitempty"`

	// Drill configures how the agent proves this surface restores.
	Drill *DrillConfig `yaml:"drill,omitempty" json:"drill,omitempty"`
}

// DrillConfig gives a Postgres surface a scratch database for its Fire Drills.
// With one, an unattended drill restores the snapshot into it for real and
// counts what came back; without one it replays the snapshot in memory. The
// database must hold nothing: a drill refuses a sandbox with tables in it, and
// empties it again afterwards.
type DrillConfig struct {
	SandboxURL    string `yaml:"sandbox_url,omitempty" json:"sandbox_url,omitempty"`
	SandboxURLEnv string `yaml:"sandbox_url_env,omitempty" json:"sandbox_url_env,omitempty"`
}

// CLIConfig is the complete configuration for the `safegrd` CLI.
type CLIConfig struct {
	NodeID      string           `yaml:"node_id" json:"node_id"`
	NodeName    string           `yaml:"node_name" json:"node_name"`
	ProjectID   string           `yaml:"project_id,omitempty" json:"project_id,omitempty"`
	ServerURL   string           `yaml:"server_url" json:"server_url"`
	ServerToken string           `yaml:"server_token,omitempty" json:"server_token,omitempty"`
	DatabaseURL string           `yaml:"database_url" json:"database_url"`
	Storage     StorageConfig    `yaml:"storage" json:"storage"`
	Encryption  EncryptionConfig `yaml:"encryption" json:"encryption"`
	Alert       AlertConfig      `yaml:"alert,omitempty" json:"alert,omitempty"`

	// Agent & Multi-Surface Unattended Protection
	Agent    AgentConfig     `yaml:"agent,omitempty" json:"agent,omitempty"`
	Defaults DefaultsConfig  `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Surfaces []SurfaceConfig `yaml:"surfaces,omitempty" json:"surfaces,omitempty"`

	// UnknownKeys are the keys in the file that are not settings, as
	// "line 12: storage.retention_day". YAML ignores them, so a typo used to
	// fall back to a default without a word; the commands say them instead.
	UnknownKeys []string `yaml:"-" json:"-"`
}

var unknownFieldRe = regexp.MustCompile(`line (\d+): field (\S+) not found in type config\.(\w+)`)

// sectionOfType names the block a type decodes. YAML reports only the type,
// so a key inside a surface's own storage block is named "storage." too; the
// line number says which.
var sectionOfType = map[string]string{
	"CLIConfig": "", "StorageConfig": "storage.", "EncryptionConfig": "encryption.", "AlertConfig": "alert.",
	"AgentConfig": "agent.", "DefaultsConfig": "defaults.", "SurfaceConfig": "surfaces[].", "DrillConfig": "surfaces[].drill.",
}

// unknownKeys decodes the file again, strictly, and names every key the
// lenient decode skipped.
func unknownKeys(data []byte) []string {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var probe CLIConfig
	err := dec.Decode(&probe)
	te, ok := err.(*yaml.TypeError)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range te.Errors {
		m := unknownFieldRe.FindStringSubmatch(e)
		if m == nil || m[2] == "private_key" { // private_key is migrated out below
			continue
		}
		out = append(out, "line "+m[1]+": "+sectionOfType[m[3]]+m[2])
	}
	return out
}

// DefaultConfigDir returns ~/.safegrd.
func DefaultConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".safegrd"), nil
}

// DefaultConfigFile returns ~/.safegrd/config.yaml.
func DefaultConfigFile() (string, error) {
	dir, err := DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// DefaultServerURL points to the production SafeGrd remote server.
const DefaultServerURL = "https://safegrd.dev"

// NewDefaultCLIConfig creates a sensible default configuration.
func NewDefaultCLIConfig() *CLIConfig {
	return &CLIConfig{
		ServerURL: DefaultServerURL,
		Storage: StorageConfig{
			Type:          StorageTypeLocal,
			LocalPath:     "./safegrd-storage",
			Prefix:        "safegrd/snapshots",
			RetentionDays: 14,
			WORMMode:      WORMModeCompliance,
		},
	}
}

// LoadCLIConfig loads configuration from a path with environment variable overrides.
func LoadCLIConfig(path string) (*CLIConfig, error) {
	cfg := NewDefaultCLIConfig()

	if path == "" {
		defPath, err := DefaultConfigFile()
		if err == nil {
			path = defPath
		}
	}

	if fi, err := os.Stat(path); err == nil {
		// Enforce secure permissions on POSIX:
		// Refuse to load if group- or world-readable (0077 mask).
		if runtime.GOOS != "windows" && (fi.Mode().Perm()&0077 != 0) {
			return nil, fmt.Errorf("insecure config file permissions (%04o): %s must be readable only by its owner (0600)", fi.Mode().Perm(), path)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
		}
		cfg.UnknownKeys = unknownKeys(data)

		// Security migration:
		// Check for legacy inline private_key in config.yaml.
		// Move it to key_path with 0600 permissions, strip from config.yaml, and warn operator.
		var rawMap map[string]interface{}
		if err := yaml.Unmarshal(data, &rawMap); err == nil {
			if enc, ok := rawMap["encryption"].(map[string]interface{}); ok {
				if inlineKey, hasKey := enc["private_key"].(string); hasKey && strings.TrimSpace(inlineKey) != "" {
					inlineKey = strings.TrimSpace(inlineKey)
					keyPath := cfg.Encryption.KeyPath
					if keyPath == "" {
						keyPath = filepath.Join(filepath.Dir(path), "keys", "agent.key")
						cfg.Encryption.KeyPath = keyPath
					}
					// Persist key to keyPath with 0600 permissions if not already present
					if _, statErr := os.Stat(keyPath); os.IsNotExist(statErr) {
						if mkErr := os.MkdirAll(filepath.Dir(keyPath), 0700); mkErr == nil {
							_ = os.WriteFile(keyPath, []byte(inlineKey+"\n"), 0600)
						}
					}
					// Strip inline key from config file
					delete(enc, "private_key")
					enc["key_path"] = keyPath
					if strippedData, mErr := yaml.Marshal(rawMap); mErr == nil {
						_ = os.WriteFile(path, strippedData, 0600)
					}
					fmt.Fprintf(os.Stderr, "⚠️  WARNING: Insecure inline private_key detected in %s. Migrated to %s (0600) and stripped from config. Please treat this key as exposed and consider rotating it.\n", path, keyPath)
					cfg.Encryption.PrivateKey = inlineKey
				}
			}
		}
	}

	// Resolve PrivateKey from KeyPath if not already populated
	if cfg.Encryption.PrivateKey == "" && cfg.Encryption.KeyPath != "" {
		if keyBytes, err := os.ReadFile(cfg.Encryption.KeyPath); err == nil {
			cfg.Encryption.PrivateKey = strings.TrimSpace(string(keyBytes))
		}
	}

	// Environment variable overrides
	if dbURL := os.Getenv("SAFEGRD_DATABASE_URL"); dbURL != "" {
		cfg.DatabaseURL = dbURL
	}
	if srvURL := os.Getenv("SAFEGRD_SERVER_URL"); srvURL != "" {
		cfg.ServerURL = srvURL
	}
	if token := os.Getenv("SAFEGRD_SERVER_TOKEN"); token != "" {
		cfg.ServerToken = token
	}
	if pubKey := os.Getenv("SAFEGRD_PUBLIC_KEY"); pubKey != "" {
		cfg.Encryption.PublicKey = pubKey
	}
	if privKey := os.Getenv("SAFEGRD_PRIVATE_KEY"); privKey != "" {
		cfg.Encryption.PrivateKey = privKey
	}
	if bucket := os.Getenv("SAFEGRD_STORAGE_BUCKET"); bucket != "" {
		cfg.Storage.Bucket = bucket
		cfg.Storage.Type = StorageTypeS3
	}
	if region := os.Getenv("SAFEGRD_S3_REGION"); region != "" {
		cfg.Storage.Region = region
	} else if region := os.Getenv("AWS_REGION"); region != "" {
		cfg.Storage.Region = region
	}
	if ep := os.Getenv("SAFEGRD_S3_ENDPOINT"); ep != "" {
		cfg.Storage.Endpoint = ep
	}
	if keyID := os.Getenv("SAFEGRD_S3_ACCESS_KEY"); keyID != "" {
		cfg.Storage.AccessKeyID = keyID
	} else if keyID := os.Getenv("AWS_ACCESS_KEY_ID"); keyID != "" {
		cfg.Storage.AccessKeyID = keyID
	}
	if secKey := os.Getenv("SAFEGRD_S3_SECRET_KEY"); secKey != "" {
		cfg.Storage.SecretAccessKey = secKey
	} else if secKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); secKey != "" {
		cfg.Storage.SecretAccessKey = secKey
	}

	// Backwards compatibility:
	// A v1 config with top-level database_url and no surfaces: loads as a single implicit postgres surface.
	if len(cfg.Surfaces) == 0 && (cfg.DatabaseURL != "" || cfg.NodeID != "") {
		sID := cfg.NodeID
		if sID == "" {
			sID = "default-postgres"
		}
		sName := cfg.NodeName
		if sName == "" {
			sName = "Production PostgreSQL"
		}
		ret := cfg.Storage.RetentionDays
		if ret == 0 {
			ret = cfg.Defaults.RetentionDays
		}
		cfg.Surfaces = []SurfaceConfig{
			{
				ID:            sID,
				Type:          topLevelDatabaseType(cfg.DatabaseURL),
				Name:          sName,
				Schedule:      cfg.Defaults.Schedule,
				RetentionDays: ret,
				DatabaseURL:   cfg.DatabaseURL,
			},
		}
	}

	return cfg, nil
}

// SaveCLIConfig writes the config to disk with restricted permissions (0600).
func SaveCLIConfig(cfg *CLIConfig, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config dir %s: %w", dir, err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}

	return nil
}

// ResolveWORMMode returns the Object Lock mode this storage configuration asks
// for, and refuses anything it does not recognise.
//
// Empty means compliance. That is the documented default and it is the strict
// one, so defaulting cannot weaken anybody's retention.
//
// Every other value must match a constant exactly, including its case. This is
// deliberately not a normalising comparison and deliberately not an `else`,
// because retention is the one bug class that cannot be undone: under
// compliance mode an object cannot be deleted before it expires, by anyone,
// including us. The two silent outcomes are both wrong. Picking compliance for
// an unrecognised value hands an operator fourteen days of undeletable objects
// they did not ask for; picking none leaves backups with no lock at all while
// the config claims otherwise. Accepting a lowercase `governance` would be a
// third kind of wrong — the CLI has been applying *compliance* for that spelling,
// so quietly honouring it now would weaken live retention without anyone saying so.
//
// So: say the value is wrong, name the two that are right, and let a human choose.
func (c *StorageConfig) ResolveWORMMode() (WORMMode, error) {
	switch c.WORMMode {
	case "":
		return WORMModeCompliance, nil
	case WORMModeCompliance, WORMModeGovernance, WORMModeNone:
		return c.WORMMode, nil
	default:
		return "", fmt.Errorf(
			"storage.worm_mode %q is not recognised: use %q, %q or %q (exact case), or leave it unset for %q. "+
				"It is not defaulted, because an unrecognised value has silently meant compliance-mode "+
				"Object Lock on the CLI side, and objects written under compliance mode cannot be deleted "+
				"before their retention expires, by anyone",
			string(c.WORMMode), string(WORMModeCompliance), string(WORMModeGovernance), string(WORMModeNone), string(WORMModeCompliance))
	}
}

// Validate validates that essential fields are present.
func (c *CLIConfig) ValidateForBackup() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("database_url is required (set via config or SAFEGRD_DATABASE_URL)")
	}
	if c.Encryption.PublicKey == "" {
		return fmt.Errorf("encryption.public_key is required (run 'safegrd init' or set SAFEGRD_PUBLIC_KEY)")
	}
	if c.Storage.Type == StorageTypeS3 && c.Storage.Bucket == "" {
		return fmt.Errorf("storage.bucket is required for s3 storage")
	}
	if c.Storage.Type == StorageTypeLocal && c.Storage.LocalPath == "" {
		return fmt.Errorf("storage.local_path is required for local storage")
	}
	if _, err := c.Storage.ResolveWORMMode(); err != nil {
		return err
	}
	return nil
}

// ValidateForFileBackup validates that encryption and storage fields are present for file backups.
func (c *CLIConfig) ValidateForFileBackup() error {
	if c.Encryption.PublicKey == "" {
		return fmt.Errorf("encryption.public_key is required (run 'safegrd init' or set SAFEGRD_PUBLIC_KEY)")
	}
	if c.Storage.Type == StorageTypeS3 && c.Storage.Bucket == "" {
		return fmt.Errorf("storage.bucket is required for s3 storage")
	}
	if c.Storage.Type == StorageTypeLocal && c.Storage.LocalPath == "" {
		return fmt.Errorf("storage.local_path is required for local storage")
	}
	if _, err := c.Storage.ResolveWORMMode(); err != nil {
		return err
	}
	return nil
}

// ValidateForEmailBackup validates that encryption and storage fields are present for email backups.
func (c *CLIConfig) ValidateForEmailBackup() error {
	return c.ValidateForFileBackup()
}

// topLevelDatabaseType is the surface type a top-level database_url stands for.
func topLevelDatabaseType(url string) string {
	if strings.HasPrefix(url, "mongodb://") || strings.HasPrefix(url, "mongodb+srv://") {
		return "mongodb"
	}
	if strings.HasPrefix(url, "mysql://") || strings.HasPrefix(url, "mariadb://") {
		return "mysql"
	}
	return "postgres"
}
