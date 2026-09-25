package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

type CheckResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "PASS", "WARN", "FAIL"
	Message string `json:"message"`
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage and validate SafeGrd configuration files",
	}

	cmd.AddCommand(newConfigValidateCmd())
	return cmd
}

func newConfigValidateCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration syntax, permissions, and surface definitions",
		RunE: func(cmd *cobra.Command, args []string) error {
			results := runValidationChecks(cfgFile, cfg)
			return printAndEvaluateResults("SafeGrd Config Validation", results, jsonOut)
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output results in JSON format")
	return cmd
}

func newDoctorCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose configuration, cryptographic keys, storage sinks, and surface targets",
		Long: `Performs deep preflight diagnostics of your SafeGrd environment:
- Configuration file permissions (enforces 0600 on POSIX)
- Age keypair integrity and presence
- Immutable WORM storage connectivity and S3 Object Lock compliance
- Remote server reachability and host clock skew
- Surface reachability (PostgreSQL, Filesystem roots, IMAP email)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			results := runDoctorChecks(cfgFile, cfg)
			return printAndEvaluateResults("SafeGrd Doctor Diagnostic Report", results, jsonOut)
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output diagnostic report in JSON format")
	return cmd
}

func runValidationChecks(path string, c *config.CLIConfig) []CheckResult {
	var results []CheckResult

	// 1. Config file check
	resolvedPath := path
	if resolvedPath == "" {
		resolvedPath, _ = config.DefaultConfigFile()
	}
	if fi, err := os.Stat(resolvedPath); err == nil {
		if runtime.GOOS != "windows" && (fi.Mode().Perm()&0077 != 0) {
			results = append(results, CheckResult{
				Name:    "Config Permissions",
				Status:  "FAIL",
				Message: fmt.Sprintf("insecure mode %04o for %s: must be 0600; run: chmod 0600 %s", fi.Mode().Perm(), resolvedPath, resolvedPath),
			})
		} else {
			results = append(results, CheckResult{
				Name:    "Config Permissions",
				Status:  "PASS",
				Message: fmt.Sprintf("0600 verified at %s", resolvedPath),
			})
		}
	} else {
		results = append(results, CheckResult{
			Name:    "Config File",
			Status:  "WARN",
			Message: fmt.Sprintf("config file not found at %s, using defaults/environment", resolvedPath),
		})
	}

	// The file was refused, so c holds defaults rather than anything the
	// operator wrote. Every check below reads c, and reporting on it here would
	// say "encryption.public_key is missing (run 'safegrd init')" about a file
	// whose public key is present and unread. Stop at the refusal and name it.
	if cfgLoadErr != nil {
		results = append(results, CheckResult{
			Name:   "Configuration Load",
			Status: "FAIL",
			Message: "the file was refused, so nothing in it was read and no check below " +
				"this one could run. Fix the failure above first.",
		})
		return results
	}

	// The alert block has never been read by anything: alerts come from the
	// remote server. A host config that sets it believes it is alerting and is
	// not.
	if c.Storage.ExpireAfterLock {
		msg := "on: the agent deletes snapshots from this bucket a day after their lock ends (never the newest, " +
			"never the last known good one). The key needs s3:DeleteObjectVersion and s3:GetObjectRetention; " +
			"run 'safegrd prune --dry-run' to see what it would do"
		status := "PASS"
		if c.Storage.Type != config.StorageTypeS3 {
			status, msg = "WARN", "set, but storage.type is not s3: only your own S3 bucket is pruned"
		}
		results = append(results, CheckResult{Name: "Expire after lock", Status: status, Message: msg})
	}
	if msg := unusedAlertBlock(c); msg != "" {
		results = append(results, CheckResult{Name: "Alert Webhooks", Status: "WARN", Message: msg})
	}
	for _, msg := range ignoredConfigKeys(c) {
		results = append(results, CheckResult{Name: "Ignored Setting", Status: "WARN", Message: msg})
	}
	for _, k := range c.UnknownKeys {
		results = append(results, CheckResult{Name: "Unknown Key", Status: "WARN",
			Message: k + " is not a SafeGrd setting and is ignored (a typo falls back to the default; see safegrd.dev/docs/config)"})
	}

	// 2. Encryption Public Key
	if c.Encryption.PublicKey == "" {
		results = append(results, CheckResult{
			Name:    "Encryption Public Key",
			Status:  "FAIL",
			Message: "encryption.public_key is missing (run 'safegrd init')",
		})
	} else if !strings.HasPrefix(c.Encryption.PublicKey, "age1") {
		results = append(results, CheckResult{
			Name:    "Encryption Public Key",
			Status:  "FAIL",
			Message: "encryption.public_key is not a valid Age recipient key",
		})
	} else {
		results = append(results, CheckResult{
			Name:    "Encryption Public Key",
			Status:  "PASS",
			Message: fmt.Sprintf("valid Age public key (%s...)", c.Encryption.PublicKey[:12]),
		})
	}

	// 3. Storage Config
	if c.Storage.Type == config.StorageTypeS3 {
		if c.Storage.Bucket == "" {
			results = append(results, CheckResult{
				Name:    "Storage Configuration",
				Status:  "FAIL",
				Message: "storage.bucket is required for S3 storage",
			})
		} else {
			results = append(results, CheckResult{
				Name:    "Storage Configuration",
				Status:  "PASS",
				Message: fmt.Sprintf("S3 bucket %s configured", c.Storage.Bucket),
			})
		}
	} else {
		results = append(results, CheckResult{
			Name:    "Storage Configuration",
			Status:  "PASS",
			Message: fmt.Sprintf("Local storage at %s", c.Storage.LocalPath),
		})
	}

	// Schedules are checked on their own line per surface, and fail rather than
	// warn: a schedule the agent cannot run as written is either a surface on
	// a cadence nobody chose or, below the floor, a bill in undeletable
	// objects. The agent still runs it safely; this is where the
	// operator finds out.
	if strings.TrimSpace(c.Defaults.Schedule) != "" {
		results = append(results, scheduleCheck("defaults.schedule", c.Defaults.Schedule))
	}
	for _, s := range c.Surfaces {
		if strings.TrimSpace(s.Schedule) != "" {
			results = append(results, scheduleCheck(fmt.Sprintf("Surface %s schedule", s.ID), s.Schedule))
		}
	}

	// 4. Surfaces check
	if len(c.Surfaces) == 0 {
		results = append(results, CheckResult{
			Name:    "Surfaces Defined",
			Status:  "WARN",
			Message: "no surfaces defined in config (0 protected targets)",
		})
	} else {
		for _, s := range c.Surfaces {
			switch strings.ToLower(s.Type) {
			case "postgres", "mysql", "mongodb", "sqlite":
				if s.DatabaseURL == "" && s.DatabaseURLEnv == "" && s.CredentialCommand == "" && c.DatabaseURL == "" {
					results = append(results, CheckResult{
						Name:    fmt.Sprintf("Surface %s (%s)", s.ID, strings.ToLower(s.Type)),
						Status:  "FAIL",
						Message: "missing database_url, database_url_env or credential_command",
					})
				} else {
					results = append(results, CheckResult{
						Name:    fmt.Sprintf("Surface %s (%s)", s.ID, strings.ToLower(s.Type)),
						Status:  "PASS",
						Message: "configured",
					})
				}
			case "files":
				if len(s.Roots) == 0 {
					results = append(results, CheckResult{
						Name:    fmt.Sprintf("Surface %s (files)", s.ID),
						Status:  "FAIL",
						Message: "missing roots directory list",
					})
				} else {
					results = append(results, CheckResult{
						Name:    fmt.Sprintf("Surface %s (files)", s.ID),
						Status:  "PASS",
						Message: fmt.Sprintf("%d root path(s) specified", len(s.Roots)),
					})
				}
			case "email":
				if s.Username == "" {
					results = append(results, CheckResult{
						Name:    fmt.Sprintf("Surface %s (email)", s.ID),
						Status:  "FAIL",
						Message: "missing username/mailbox address",
					})
				} else {
					results = append(results, CheckResult{
						Name:    fmt.Sprintf("Surface %s (email)", s.ID),
						Status:  "PASS",
						Message: fmt.Sprintf("configured for %s", s.Username),
					})
				}
			default:
				results = append(results, CheckResult{
					Name:    fmt.Sprintf("Surface %s", s.ID),
					Status:  "FAIL",
					Message: fmt.Sprintf("unknown surface type: %s", s.Type),
				})
			}
		}
	}

	return results
}

func scheduleCheck(name, schedule string) CheckResult {
	d, err := model.ParseSchedule(schedule)
	if err != nil {
		return CheckResult{Name: name, Status: "FAIL", Message: err.Error()}
	}
	return CheckResult{Name: name, Status: "PASS", Message: fmt.Sprintf("%q runs every %s", schedule, model.ShortDuration(d))}
}

func runDoctorChecks(path string, c *config.CLIConfig) []CheckResult {
	results := runValidationChecks(path, c)
	results = append(results, credentialProvenanceCheck(c)...)
	results = append(results, surfaceCredentialChecks(c)...)
	results = append(results, pgDumpChecks(c)...)

	// 1. Private Key Decryption check
	resolvedKey := c.Encryption.PrivateKey
	if resolvedKey == "" && c.Encryption.KeyPath != "" {
		if k, err := crypto.LoadPrivateKey(c.Encryption.KeyPath); err == nil {
			resolvedKey = k
		}
	}
	if resolvedKey == "" {
		resolvedKey = os.Getenv("SAFEGRD_PRIVATE_KEY")
	}

	if resolvedKey == "" {
		results = append(results, CheckResult{
			Name:    "Decryption Private Key",
			Status:  "WARN",
			Message: "private key not configured on host; restores & Fire Drills disabled",
		})
	} else if strings.HasPrefix(resolvedKey, "AGE-SECRET-KEY-1") {
		results = append(results, CheckResult{
			Name:    "Decryption Private Key",
			Status:  "PASS",
			Message: "valid Age private identity key present",
		})
	} else {
		results = append(results, CheckResult{
			Name:    "Decryption Private Key",
			Status:  "FAIL",
			Message: "configured private key is invalid Age format",
		})
	}

	// 2. Storage Sink Writability & Object Lock check
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Hosted storage is checked the way a command uses it: with a lease.
	stCfg := c.Storage
	if stCfg.Type == config.StorageTypeHosted {
		probe := *c
		if l, err := resolveHostedStorage(ctx, &probe, &stCfg, false); err != nil {
			results = append(results, CheckResult{Name: "Hosted Storage", Status: "FAIL", Message: err.Error()})
		} else {
			status := "PASS"
			if l.QuotaBytes > 0 && l.UsedBytes*5 >= l.QuotaBytes*4 {
				status = "WARN"
			}
			results = append(results, CheckResult{Name: "Hosted Storage", Status: status,
				Message: fmt.Sprintf("%s of %s locked in s3://%s/%s (compliance mode)",
					formatBytes(l.UsedBytes), formatBytes(l.QuotaBytes), l.Bucket, l.Prefix)})
		}
	}

	stProvider, err := openStorage(ctx, c, stCfg)
	if err != nil {
		results = append(results, CheckResult{
			Name:    "Storage Provider Init",
			Status:  "FAIL",
			Message: fmt.Sprintf("failed to init storage: %v", err),
		})
	} else {
		results = append(results, CheckResult{
			Name:    "Storage Provider Init",
			Status:  "PASS",
			Message: fmt.Sprintf("initialized %s backend", stProvider.Type()),
		})

		// The check its heading always promised: whether the bucket locks.
		// Under worm_mode NONE the answer is known and chosen, so it is
		// reported rather than failed.
		if locker, ok := stProvider.(interface {
			VerifyBucketObjectLock(ctx context.Context) error
		}); ok {
			mode, _ := c.Storage.ResolveWORMMode()
			switch err := locker.VerifyBucketObjectLock(ctx); {
			case mode == config.WORMModeNone:
				results = append(results, CheckResult{Name: "Object Lock", Status: "WARN",
					Message: "worm_mode is NONE: snapshots in this bucket can be deleted by anyone with delete permission"})
			case err != nil:
				results = append(results, CheckResult{Name: "Object Lock", Status: "FAIL",
					Message: fmt.Sprintf("bucket %s cannot be confirmed to lock: %v", c.Storage.Bucket, err)})
			default:
				results = append(results, CheckResult{Name: "Object Lock", Status: "PASS",
					Message: fmt.Sprintf("enabled on bucket %s", c.Storage.Bucket)})
			}
		}
		if c.Storage.Type == config.StorageTypeLocal {
			testDir := c.Storage.LocalPath
			if err := os.MkdirAll(testDir, 0700); err != nil {
				results = append(results, CheckResult{
					Name:    "Local Storage Writability",
					Status:  "FAIL",
					Message: fmt.Sprintf("cannot create local storage dir: %v", err),
				})
			} else {
				testFile := filepath.Join(testDir, ".writetest")
				if err := os.WriteFile(testFile, []byte("ok"), 0600); err != nil {
					results = append(results, CheckResult{
						Name:    "Local Storage Writability",
						Status:  "FAIL",
						Message: fmt.Sprintf("cannot write to storage dir: %v", err),
					})
				} else {
					_ = os.Remove(testFile)
					results = append(results, CheckResult{
						Name:    "Local Storage Writability",
						Status:  "PASS",
						Message: "writable",
					})
				}
			}
		}
	}

	// 3. Remote Server Reachability & Clock Skew
	serverURL := resolveServerURLFor(c)
	resp, err := http.Get(serverURL + "/health")
	if err != nil {
		// Fallback to /api/v1/plans
		resp, err = http.Get(serverURL + "/api/v1/plans")
	}
	if err != nil {
		results = append(results, CheckResult{
			Name:    "Remote Server Reachability",
			Status:  "WARN",
			Message: fmt.Sprintf("cannot reach %s: %v (offline mode operates normally)", serverURL, err),
		})
	} else {
		defer resp.Body.Close()
		results = append(results, CheckResult{
			Name:    "Remote Server Reachability",
			Status:  "PASS",
			Message: fmt.Sprintf("connected to %s (HTTP %d)", serverURL, resp.StatusCode),
		})

		// Clock skew check
		if dateStr := resp.Header.Get("Date"); dateStr != "" {
			if srvTime, err := http.ParseTime(dateStr); err == nil {
				skew := time.Since(srvTime)
				if math.Abs(skew.Seconds()) > 30 {
					results = append(results, CheckResult{
						Name:    "Host Clock Skew",
						Status:  "WARN",
						Message: fmt.Sprintf("clock is skewed by %.1fs compared to remote server", skew.Seconds()),
					})
				} else {
					results = append(results, CheckResult{
						Name:    "Host Clock Skew",
						Status:  "PASS",
						Message: fmt.Sprintf("in sync (skew %.2fs)", skew.Seconds()),
					})
				}
			}
		}
	}

	// 4. Surface Target Reachability
	for _, s := range c.Surfaces {
		if strings.ToLower(s.Type) == "files" {
			for _, root := range s.Roots {
				if fi, err := os.Stat(root); err != nil {
					results = append(results, CheckResult{
						Name:    fmt.Sprintf("Files Target (%s)", root),
						Status:  "FAIL",
						Message: fmt.Sprintf("path does not exist or cannot be accessed: %v", err),
					})
				} else if !fi.IsDir() {
					results = append(results, CheckResult{
						Name:    fmt.Sprintf("Files Target (%s)", root),
						Status:  "FAIL",
						Message: "target path is not a directory",
					})
				} else {
					results = append(results, CheckResult{
						Name:    fmt.Sprintf("Files Target (%s)", root),
						Status:  "PASS",
						Message: "accessible",
					})
				}
			}
		}
	}

	return results
}

func printAndEvaluateResults(title string, results []CheckResult, jsonOut bool) error {
	var hasFailure bool
	for _, r := range results {
		if r.Status == "FAIL" {
			hasFailure = true
			break
		}
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"title":   title,
			"status":  map[bool]string{true: "FAIL", false: "PASS"}[hasFailure],
			"results": results,
		})
		if hasFailure {
			return fmt.Errorf("one or more critical checks failed")
		}
		return nil
	}

	fmt.Printf("🔍 %s\n\n", title)
	for _, r := range results {
		icon := "✅"
		if r.Status == "WARN" {
			icon = "⚠️ "
		} else if r.Status == "FAIL" {
			icon = "❌"
		}
		fmt.Printf("   [%s] %-30s : %s\n", icon, r.Name, r.Message)
	}
	fmt.Println()

	if hasFailure {
		return fmt.Errorf("one or more critical checks failed")
	}
	fmt.Println("🎉 All critical checks passed.")
	return nil
}

// credentialProvenanceCheck reports where each credential would resolve from
// if a backup ran right now.
//
// "It works on this host" and "it will work on a fresh host" are different
// claims, and nothing else distinguishes them: a backup succeeds identically
// whether the database URL came from the config file or from the remote server,
// so an operator moving a node has no way to know what they need to carry with
// it. This answers that without printing secrets, showing where each one
// came from.
//
// It runs the same resolution the backup path runs, against a copy, so it
// cannot report a source that a real run would not use.
func credentialProvenanceCheck(c *config.CLIConfig) []CheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	probe := *c
	storageCfg := probe.Storage
	src := resolveRuntimeCredentials(ctx, &probe, &storageCfg, false)

	status := func(source string) string {
		if source == "not configured" {
			return "WARN"
		}
		return "PASS"
	}

	out := []CheckResult{
		{Name: "Database Credential Source", Status: status(src.DatabaseURL), Message: src.DatabaseURL},
		{Name: "Encryption Recipient Source", Status: status(src.PublicKey), Message: src.PublicKey},
	}
	// Local WORM storage has no credential to have a source, so reporting one
	// missing would be a warning about something that is not wrong.
	if storageCfg.Type == config.StorageTypeS3 {
		out = append(out, CheckResult{
			Name: "Sink Credential Source", Status: status(src.SinkSecret), Message: src.SinkSecret,
		})
	}
	return out
}

// unusedAlertBlock explains, when this config sets alert webhooks, that the
// CLI does not send them.
func unusedAlertBlock(c *config.CLIConfig) string {
	if c.Alert.SlackWebhookURL == "" && c.Alert.DiscordWebhookURL == "" {
		return ""
	}
	return "alert: webhooks in this file are not used; the remote server sends alerts: " +
		"set the Slack, Discord or plain webhook in the console under Settings → Alerts " +
		"(safegrd.dev/docs/alerts)"
}

// surfaceCredentialChecks resolves each surface's secret the way the agent
// will, so a credential_command that is not signed in, or a password_env that
// names an unset variable, is found at the terminal rather than at 3am by a
// daemon. Only doctor runs these: `config validate` stays free of side effects.
func surfaceCredentialChecks(c *config.CLIConfig) []CheckResult {
	var results []CheckResult
	for i := range c.Surfaces {
		s := &c.Surfaces[i]
		name := fmt.Sprintf("Surface %s credentials", s.ID)
		ctx, cancel := context.WithTimeout(context.Background(), credentialCommandTimeout)
		var secret string
		var err error
		switch strings.ToLower(s.Type) {
		case "postgres", "mysql", "mongodb", "sqlite":
			secret, err = resolveSurfaceDatabaseURL(ctx, c, s)
		case "email":
			secret, err = surfaceEmailPassword(ctx, s)
		default:
			cancel()
			continue
		}
		cancel()
		switch {
		case err != nil:
			results = append(results, CheckResult{Name: name, Status: "FAIL", Message: err.Error()})
		case secret == "":
			results = append(results, CheckResult{Name: name, Status: "FAIL", Message: "resolve to nothing: set credential_command, or name a variable in password_env or database_url_env that is set in the agent's environment"})
		default:
			source := "config"
			if s.CredentialCommand != "" && (s.Type == "email" || (s.DatabaseURL == "" && s.DatabaseURLEnv == "")) {
				source = "credential_command"
			}
			results = append(results, CheckResult{Name: name, Status: "PASS", Message: "resolve (from " + source + ")"})
		}
	}
	return results
}

// ignoredConfigKeys names each key this config sets that the agent accepts and
// does not yet act on. The config reference says so too, but a person who set
// max_concurrent: 4 believes four surfaces run at once, and only a message at
// the moment it matters corrects that.
func ignoredConfigKeys(c *config.CLIConfig) []string {
	var out []string
	add := func(set bool, key, what string) {
		if set {
			out = append(out, key+" is not acted on yet: "+what)
		}
	}
	add(c.Agent.MaxConcurrent > 1, "agent.max_concurrent", "surfaces run one at a time")
	add(c.Agent.RetryBackoffMin != "" || c.Agent.RetryBackoffMax != "", "agent.retry_backoff_min/max",
		"a failing surface retries after 5 minutes, doubling to at most 1 hour")
	add(c.Agent.LogFormat != "" && c.Agent.LogFormat != "text", "agent.log_format", "logs are plain text")
	add(c.Agent.LogLevel != "" && c.Agent.LogLevel != "info", "agent.log_level", "the agent logs at one level")
	add(c.Agent.MetricsAddr != "", "agent.metrics_addr", "there is no metrics endpoint")
	add(c.Defaults.Timezone != "" && !strings.EqualFold(c.Defaults.Timezone, "UTC"), "defaults.timezone",
		"schedules are intervals from the last success, not wall-clock times")
	return out
}

// pgDumpChecks finds, for every Postgres database this host backs up, a
// pg_dump that can capture its schema. Without one the backup still
// runs, but the snapshot restores without foreign keys, views, triggers or
// enum types and its drill fails, so doctor fails first.
func pgDumpChecks(c *config.CLIConfig) []CheckResult {
	urls := map[string]string{}
	if c.DatabaseURL != "" {
		urls["database_url"] = c.DatabaseURL
	}
	for i := range c.Surfaces {
		s := &c.Surfaces[i]
		if !model.SurfaceType(strings.ToLower(s.Type)).IsDatabase() {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), credentialCommandTimeout)
		u, err := resolveSurfaceDatabaseURL(ctx, c, s)
		cancel()
		if err == nil && u != "" {
			urls["surface "+s.ID] = u
		}
	}
	var results []CheckResult
	for name, u := range urls {
		if r, err := ResolveSecretRef("database_url", u); err == nil && r != "" && (strings.HasPrefix(u, "env:") || strings.HasPrefix(u, "file:")) {
			u = r
		}
		if dump.IsSQLiteURL(u) {
			results = append(results, sqliteCheck(name, u))
			continue
		}
		if dump.IsMySQLURL(u) {
			results = append(results, mysqlToolCheck(name, u))
			continue
		}
		if dump.IsMongoURL(u) {
			check := CheckResult{Name: "mongodump for " + name}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			dumpTool, restoreTool, server, err := dump.MongoToolsFor(ctx, u)
			cancel()
			if err != nil {
				check.Status, check.Message = "FAIL", err.Error()
			} else {
				check.Status, check.Message = "PASS", fmt.Sprintf("%s and %s for the MongoDB %s server", dumpTool, restoreTool, server)
			}
			results = append(results, check)
			continue
		}
		check := CheckResult{Name: "pg_dump for " + name}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		major := 0
		if conn, err := pgx.Connect(ctx, u); err == nil {
			var num int
			if conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&num) == nil {
				major = num / 10000
			}
			_ = conn.Close(ctx)
		}
		pd, err := dump.FindPgDump(ctx, major)
		cancel()
		switch {
		case err != nil:
			check.Status, check.Message = "FAIL", err.Error()
		case major == 0:
			check.Status = "WARN"
			check.Message = fmt.Sprintf("found pg_dump %s (%s), but could not reach the server to check it is new enough", pd.Version, pd.Path)
		default:
			check.Status = "PASS"
			check.Message = fmt.Sprintf("pg_dump %s (%s) can dump this PostgreSQL %d server", pd.Version, pd.Path, major)
		}
		results = append(results, check)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return results
}

// mysqlToolCheck finds the dump tool and client a MySQL surface needs.
func mysqlToolCheck(name, databaseURL string) CheckResult {
	check := CheckResult{Name: "mysqldump for " + name}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dumpTool, client, server, err := dump.MySQLToolsFor(ctx, databaseURL)
	switch {
	case err != nil:
		check.Status, check.Message = "FAIL", err.Error()
	default:
		check.Status = "PASS"
		check.Message = fmt.Sprintf("%s and %s for the %s server", dumpTool, client, server)
	}
	return check
}

// sqliteCheck opens a SQLite surface read-only, the way a backup does, and
// says whether writers will wait while it is copied.
func sqliteCheck(name, databaseURL string) CheckResult {
	check := CheckResult{Name: "SQLite database for " + name}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := dump.PingSQLite(ctx, databaseURL); err != nil {
		check.Status, check.Message = "FAIL", err.Error()
		return check
	}
	mode, err := dump.SQLiteJournalMode(ctx, databaseURL)
	switch {
	case err != nil:
		check.Status, check.Message = "WARN", "opened, but its journal mode could not be read: "+err.Error()
	case !strings.EqualFold(mode, "wal"):
		check.Status, check.Message = "WARN", fmt.Sprintf("readable; journal mode %s, so writers wait while a backup reads it. "+
			"PRAGMA journal_mode=WAL lets them carry on", mode)
	default:
		check.Status, check.Message = "PASS", "readable, WAL mode: backups copy it without blocking writers"
	}
	return check
}
