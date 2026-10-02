package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
)

// drillFreshness is how recent a passed drill has to be for --agent-proof.
const drillFreshness = 7 * 24 * time.Hour

// runAgentProofChecks answers one question: if an AI agent on this host ran a
// destructive command, or was handed this host's credentials, could the
// backups still be restored? Each check that fails names the fix.
func runAgentProofChecks(c *config.CLIConfig) []CheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stCfg := c.Storage
	var results []CheckResult
	if err := routeProjectSink(ctx, c, &stCfg, false, false); err != nil {
		return append(results, CheckResult{Name: "Storage", Status: "FAIL", Message: err.Error(),
			Fix: "safegrd doctor"})
	}
	applyHeldSinkKey(ctx, c, &stCfg)
	resolveRuntimeCredentials(ctx, c, &stCfg, false)
	if c.NodeID != "" && stCfg.NodeID == "" {
		stCfg.NodeID = c.NodeID
	}

	results = append(results, accountCheck(c, stCfg))
	results = append(results, storageAgentChecks(ctx, c, stCfg)...)
	results = append(results, drillChecks(ctx, c)...)
	results = append(results, agentTokenCheck())
	return results
}

// accountCheck compares where the database is with where the bucket is. A
// credential that reaches both is one leak away from losing both, and the
// cheapest separation to see is a different provider.
func accountCheck(c *config.CLIConfig, st config.StorageConfig) CheckResult {
	const name = "Bucket in another account"
	switch st.Type {
	case config.StorageTypeHosted:
		return CheckResult{Name: name, Status: "PASS",
			Message: "backups go to SafeGrd's hosted bucket, which no database credential of yours can reach"}
	case config.StorageTypeLocal:
		return CheckResult{Name: name, Status: "FAIL",
			Message: fmt.Sprintf("backups are in a directory on this host (%s), which anything running here can reach", st.LocalPath),
			Fix:     "safegrd enroll --storage hosted, or a bucket with Object Lock in another account (safegrd.dev/docs/storage)"}
	}
	bucketHost := "s3.amazonaws.com"
	if st.Endpoint != "" {
		if u, err := url.Parse(st.Endpoint); err == nil && u.Hostname() != "" {
			bucketHost = u.Hostname()
		}
	}
	bucketProvider := providerDomain(bucketHost)
	dbProviders := map[string]bool{}
	for _, u := range databaseURLs(c) {
		if p := providerDomain(urlHost(u)); p != "" {
			dbProviders[p] = true
		}
	}
	if bucketProvider == "" || len(dbProviders) == 0 {
		return CheckResult{Name: name, Status: "WARN",
			Message: "could not tell from the config which provider holds the database or the bucket; " +
				"check that the bucket's account is not one the database credentials can reach"}
	}
	if dbProviders[bucketProvider] {
		return CheckResult{Name: name, Status: "WARN",
			Message: fmt.Sprintf("the database and the bucket are both on %s; the config cannot show whether they are separate accounts. "+
				"Check that no credential on this host reaches both", bucketProvider)}
	}
	var dbs []string
	for p := range dbProviders {
		dbs = append(dbs, p)
	}
	sort.Strings(dbs)
	return CheckResult{Name: name, Status: "PASS",
		Message: fmt.Sprintf("database on %s, bucket on %s: different providers", strings.Join(dbs, ", "), bucketProvider)}
}

// databaseURLs is every database URL the config names in the clear. One that
// comes from a secret store or the remote server is not read here.
func databaseURLs(c *config.CLIConfig) []string {
	var out []string
	add := func(u string) {
		if u != "" && !strings.HasPrefix(u, "env:") && !strings.HasPrefix(u, "file:") {
			out = append(out, u)
		}
	}
	add(c.DatabaseURL)
	if v := os.Getenv("SAFEGRD_DATABASE_URL"); v != "" {
		add(v)
	}
	for _, s := range c.Surfaces {
		if s.CredentialFrom() == "" {
			add(s.DatabaseURL)
		} else if s.CredentialFrom() == config.CredentialFromEnv && s.Credential.Name != "" {
			add(os.Getenv(s.Credential.Name))
		}
	}
	return out
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// providerDomain is the last two labels of a host name ("supabase.co",
// "amazonaws.com"), or "" for an address or a single-label name, which say
// nothing about whose account they are in.
func providerDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return ""
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// deleteProber is the S3 provider's DeleteProbe.
type deleteProber interface {
	DeleteProbe(ctx context.Context) (canDelete, canDeleteVersions bool, marker string, err error)
}

// storageAgentChecks asks the bucket whether this host's key can delete, and
// whether snapshots are locked in compliance mode.
func storageAgentChecks(ctx context.Context, c *config.CLIConfig, st config.StorageConfig) []CheckResult {
	const (
		keyName  = "Storage key cannot delete"
		lockName = "Object Lock in compliance mode"
	)
	switch st.Type {
	case config.StorageTypeHosted:
		return []CheckResult{
			{Name: keyName, Status: "PASS", Message: "this host holds no key to the hosted bucket; it uploads through short-lived write URLs from the remote server"},
			{Name: lockName, Status: "PASS", Message: "hosted storage locks every snapshot in compliance mode"},
		}
	case config.StorageTypeLocal:
		fix := "safegrd enroll --storage hosted, or a bucket with Object Lock (safegrd.dev/docs/storage)"
		return []CheckResult{
			{Name: keyName, Status: "FAIL", Message: fmt.Sprintf("any process on this host that can write %s can delete the backups in it", st.LocalPath), Fix: fix},
			{Name: lockName, Status: "FAIL", Message: "a directory on this host has no Object Lock", Fix: fix},
		}
	}

	provider, err := openStorage(ctx, c, st)
	if err != nil {
		msg := fmt.Sprintf("could not open the bucket: %v", err)
		return []CheckResult{
			{Name: keyName, Status: "FAIL", Message: msg, Fix: "safegrd doctor"},
			{Name: lockName, Status: "FAIL", Message: msg, Fix: "safegrd doctor"},
		}
	}
	var results []CheckResult

	policyFix := "give this host's key the backup policy from the console's bucket setup, which allows no delete"
	if prober, ok := provider.(deleteProber); !ok {
		results = append(results, CheckResult{Name: keyName, Status: "WARN", Message: "this storage cannot be asked what its key may do"})
	} else {
		canDelete, canDeleteVersions, marker, err := prober.DeleteProbe(ctx)
		switch {
		case err != nil:
			results = append(results, CheckResult{Name: keyName, Status: "WARN", Message: fmt.Sprintf("could not tell: %v", err)})
		case canDeleteVersions:
			results = append(results, CheckResult{Name: keyName, Status: "FAIL",
				Message: "the key may delete object versions, so it can remove a backup for good once its lock ends, " +
					"or at once under governance mode",
				Fix: policyFix})
		case canDelete:
			msg := "the key may place delete markers, which hide snapshots from a restore until 'safegrd undelete' clears them"
			if marker != "" {
				msg += fmt.Sprintf(". The check left one on %s, which holds no backup", marker)
			}
			results = append(results, CheckResult{Name: keyName, Status: "FAIL", Message: msg, Fix: policyFix})
		default:
			results = append(results, CheckResult{Name: keyName, Status: "PASS", Message: "the bucket refused this key's delete requests"})
		}
	}

	mode, err := st.ResolveWORMMode()
	switch {
	case err != nil:
		results = append(results, CheckResult{Name: lockName, Status: "FAIL", Message: err.Error()})
	case mode == config.WORMModeNone:
		results = append(results, CheckResult{Name: lockName, Status: "FAIL",
			Message: "worm_mode is NONE, so nothing locks the snapshots",
			Fix:     "use a bucket created with Object Lock, and set storage.worm_mode: COMPLIANCE"})
	case mode == config.WORMModeGovernance:
		results = append(results, CheckResult{Name: lockName, Status: "FAIL",
			Message: "worm_mode is GOVERNANCE: a key with s3:BypassGovernanceRetention can delete a locked snapshot",
			Fix:     "set storage.worm_mode: COMPLIANCE"})
	default:
		locker, ok := provider.(interface{ VerifyBucketObjectLock(context.Context) error })
		if ok {
			if err := locker.VerifyBucketObjectLock(ctx); err != nil {
				results = append(results, CheckResult{Name: lockName, Status: "FAIL", Message: err.Error(),
					Fix: "use a bucket created with Object Lock enabled; it cannot be turned on later"})
				break
			}
		}
		results = append(results, newestSnapshotLock(ctx, provider, lockName))
	}
	return results
}

// newestSnapshotLock checks the mode the newest snapshot was written under,
// which is what protects the backup an agent's mistake would need.
func newestSnapshotLock(ctx context.Context, provider storage.StorageProvider, name string) CheckResult {
	ok := CheckResult{Name: name, Status: "PASS", Message: "worm_mode is COMPLIANCE and the bucket has Object Lock enabled"}
	ids, err := provider.ListSnapshots(ctx)
	if err != nil || len(ids) == 0 {
		return ok
	}
	sort.Strings(ids)
	newest := ids[len(ids)-1]
	if loc, isLoc := provider.(storage.NodeLocator); isLoc {
		if nodes, err := loc.SnapshotNodes(ctx); err == nil && nodes[newest] != "" {
			if s, can := provider.(interface{ SetNodeID(string) }); can {
				s.SetNodeID(nodes[newest])
			}
		}
	}
	meta, err := provider.DownloadMetadata(ctx, newest)
	if err != nil {
		return ok
	}
	if meta.WORMMode != "" && meta.WORMMode != string(config.WORMModeCompliance) {
		return CheckResult{Name: name, Status: "WARN",
			Message: fmt.Sprintf("the bucket locks in compliance mode now, but the newest snapshot %s was written under %s", newest, meta.WORMMode),
			Fix:     "safegrd backup"}
	}
	ok.Message += fmt.Sprintf("; newest snapshot %s is locked until %s", newest, meta.WORMRetentionUntil.UTC().Format("2006-01-02"))
	return ok
}

// drillChecks asks the remote server when each of this host's surfaces last
// passed a Fire Drill.
func drillChecks(ctx context.Context, c *config.CLIConfig) []CheckResult {
	const name = "Drill passed in 7 days"
	if c.ServerURL == "" || c.ServerToken == "" || c.NodeID == "" {
		return []CheckResult{{Name: name, Status: "FAIL",
			Message: "this host is not enrolled, so no drill is on record",
			Fix:     "safegrd enroll, then safegrd verify --snapshot <id>"}}
	}
	nodes := map[string]string{}
	state := loadDaemonState(filepath.Join(resolveStateDir("", c), "daemon_state.json"))
	for id, st := range state.Surfaces {
		if st.ServerNodeID != "" {
			nodes[st.ServerNodeID] = id
		}
	}
	if len(nodes) == 0 {
		nodes[c.NodeID] = c.NodeName
	}
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var results []CheckResult
	for _, nodeID := range ids {
		label := name
		if len(ids) > 1 {
			label = fmt.Sprintf("%s (%s)", name, nodes[nodeID])
		}
		last, err := lastPassedDrill(ctx, c, nodeID)
		switch {
		case err != nil:
			results = append(results, CheckResult{Name: label, Status: "WARN", Message: fmt.Sprintf("could not ask the remote server: %v", err)})
		case last.IsZero():
			results = append(results, CheckResult{Name: label, Status: "FAIL", Message: "no drill has passed",
				Fix: "safegrd list, then safegrd verify --snapshot <id>"})
		case time.Since(last) > drillFreshness:
			results = append(results, CheckResult{Name: label, Status: "FAIL",
				Message: fmt.Sprintf("the last drill passed on %s", last.UTC().Format("2006-01-02")),
				Fix:     "safegrd list, then safegrd verify --snapshot <id>"})
		default:
			results = append(results, CheckResult{Name: label, Status: "PASS",
				Message: fmt.Sprintf("passed %s", last.UTC().Format("2006-01-02 15:04 MST"))})
		}
	}
	return results
}

func lastPassedDrill(ctx context.Context, c *config.CLIConfig, nodeID string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(c.ServerURL, "/")+"/api/v1/verifications?node_id="+url.QueryEscape(nodeID), nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	req.Header.Set("User-Agent", UserAgent())
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var reports []model.VerificationReport
	if err := json.NewDecoder(resp.Body).Decode(&reports); err != nil {
		return time.Time{}, err
	}
	var last time.Time
	for _, r := range reports {
		if r.Status == model.VerificationStatusPassed && r.CompletedAt.After(last) {
			last = r.CompletedAt
		}
	}
	return last, nil
}

var tokenInFile = regexp.MustCompile(`sg_(tok|pat)_[A-Za-z0-9_-]+`)

// agentConfigFiles are where Claude Code, Cursor, Codex and VS Code keep MCP
// servers, in the project and in the home directory.
func agentConfigFiles() []string {
	var files []string
	if cwd, err := os.Getwd(); err == nil {
		for _, f := range []string{".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".codex/config.toml"} {
			files = append(files, filepath.Join(cwd, f))
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, f := range []string{".claude.json", ".cursor/mcp.json", ".codex/config.toml"} {
			files = append(files, filepath.Join(home, f))
		}
	}
	return files
}

// agentTokenCheck looks at the agent configurations on this host for the
// token they give SafeGrd. A personal access token can be scoped and revoked
// on its own, and cannot delete a backup. A node token acts as this host. The
// token itself is never printed.
func agentTokenCheck() CheckResult {
	return agentTokenCheckIn(agentConfigFiles())
}

func agentTokenCheckIn(files []string) CheckResult {
	const name = "Agent uses a personal token"
	var pat, local, mentioned []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		text := string(data)
		if !strings.Contains(strings.ToLower(text), "safegrd") {
			continue
		}
		mentioned = append(mentioned, f)
		for _, m := range tokenInFile.FindAllStringSubmatch(text, -1) {
			if m[1] == "tok" {
				return CheckResult{Name: name, Status: "FAIL",
					Message: fmt.Sprintf("%s gives an agent a node token, which acts as this host", f),
					Fix:     "create a personal access token under Tokens in the console and use it in " + f}
			}
			pat = append(pat, f)
		}
		if strings.Contains(text, "safegrd mcp") || strings.Contains(text, `"mcp"`) {
			local = append(local, f)
		}
	}
	switch {
	case len(pat) > 0:
		return CheckResult{Name: name, Status: "PASS", Message: "the agent's token in " + pat[0] + " is a personal access token"}
	case len(local) > 0:
		return CheckResult{Name: name, Status: "PASS",
			Message: "the agent uses the local server (safegrd mcp) in " + local[0] + ", which cannot delete a backup and never sees a key"}
	case len(mentioned) > 0:
		return CheckResult{Name: name, Status: "WARN",
			Message: mentioned[0] + " names SafeGrd but holds no token; check the one it reads is a personal access token (sg_pat_)"}
	}
	return CheckResult{Name: name, Status: "WARN",
		Message: "found no agent configuration naming SafeGrd; give an agent a personal access token (sg_pat_), never this host's node token",
		Fix:     "create one under Tokens in the console"}
}
