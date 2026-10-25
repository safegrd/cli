package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

// `safegrd try` is the first command after install. It takes a real backup of
// one database or directory before any account exists: the remote server
// lends this host a node under an organization nobody owns yet, the backup
// goes to the server's storage through the ordinary pipeline, and it is
// drilled at once by restoring it in memory from there. The backup is kept
// for a day unless `safegrd signup` gives the organization an owner.
//
// The host is an ordinary enrolled host from then on: list, status, verify
// and restore work against the trial with nothing more to run. The backup
// and the drill run as the commands a customer runs (this binary, as a
// child process), so what this prints is what those print.

func newTryCmd() *cobra.Command {
	var (
		keyCustody string
		name       string
		noBrowser  bool
	)
	cmd := &cobra.Command{
		Use:   "try <database-url | directory>",
		Short: "Back up a database or directory now, before signing up, and restore it to check",
		Long: `Takes a real backup of one database or directory with no account: the remote
server lends this host a place to put it, the backup is encrypted here, uploaded,
and then restored in memory from the server's storage to check it.

The backup is kept for a day. To keep it, back it up on a schedule and see it in
the console, run: safegrd signup

The connection string stays on this host. Give it as the URL, or as env:VAR or
file:/path to keep the password out of the config file.

  safegrd try postgres://app:secret@db.example.com/app
  safegrd try env:DATABASE_URL
  safegrd try mysql://root@127.0.0.1/shop
  safegrd try /srv/uploads`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTry(cmd.Context(), args[0], keyCustody, name, noBrowser)
		},
	}
	cmd.Flags().StringVar(&keyCustody, "key-custody", "safegrd",
		"Who holds the key that opens this backup: safegrd (SafeGrd keeps it sealed and releases it only to this host, so you can restore after losing the host) or local (only this host can decrypt it)")
	cmd.Flags().StringVar(&name, "name", "", "This host's name in the console (default: the hostname)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the sign-up link without opening a browser")
	cmd.AddCommand(newTryStatusCmd())
	return cmd
}

func runTry(ctx context.Context, source, keyCustody, name string, noBrowser bool) error {
	serverURL := resolveServerURL()
	switch keyCustody {
	case "safegrd", "local":
	default:
		return fmt.Errorf("--key-custody must be 'safegrd' or 'local', got %q", keyCustody)
	}

	// A host that is enrolled already needs no trial. One with a live trial
	// signs up; any other backs up as itself.
	if cfg != nil && cfg.ServerToken != "" && cfg.NodeID != "" {
		if st, err := fetchTryStatus(ctx, serverURL, cfg.ServerToken); err == nil && st.State == "unclaimed" {
			return fmt.Errorf("this host already has a trial backup, kept until %s. Keep it with: safegrd signup",
				st.TrialUntil.Local().Format("2006-01-02 15:04"))
		}
		return fmt.Errorf("this host is enrolled with %s already. Back up with: safegrd backup --database-url <url>, or safegrd backup --files <dir>", serverURL)
	}

	surface, err := trySurface(source)
	if err != nil {
		return err
	}

	keyExisted := cfg != nil && cfg.Encryption.PublicKey != ""
	created, adopted, err := ensureLocalSetup(name)
	if err != nil {
		return err
	}
	_ = created
	if adopted {
		keyExisted = true
	}
	// A key already on the host is never sent: its custody was settled
	// before SafeGrd was involved.
	escrow := keyCustody == "safegrd" && !keyExisted
	if keyCustody == "safegrd" && keyExisted {
		fmt.Printf("The key at %s was already here, so it stays here: only you can decrypt this backup.\n", cfg.Encryption.KeyPath)
	}

	hostname, _ := os.Hostname()
	req := model.TryRequest{
		NodeID:         cfg.NodeID,
		Name:           cfg.NodeName,
		SurfaceType:    model.SurfaceType(surface.Type),
		Hostname:       strings.TrimSpace(hostname),
		Machine:        machineFingerprint(),
		CLIVersion:     Version,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		PublicKey:      cfg.Encryption.PublicKey,
		KeyFingerprint: crypto.Fingerprint(cfg.Encryption.PublicKey),
	}
	if escrow {
		req.ManagedIdentity = cfg.Encryption.PrivateKey
	}
	fmt.Printf("Asking %s for a trial.\n", serverURL)
	resp, err := postTry(ctx, serverURL, req)
	if err != nil {
		return err
	}
	if escrow && !resp.KeyEscrowed {
		fmt.Fprintf(os.Stderr, "Error: the remote server did not store the encryption key. It is only at %s; keep a copy.\n", cfg.Encryption.KeyPath)
		return serverFailure(fmt.Errorf("the trial was opened but the key was not stored; nothing was backed up"))
	}

	cfg.ServerURL = serverURL
	cfg.ServerToken = resp.Token
	cfg.ProjectID = resp.ProjectID
	cfg.Storage = config.StorageConfig{Type: config.StorageTypeHosted, WORMMode: config.WORMModeCompliance}
	cfg.Surfaces = []config.SurfaceConfig{surface}
	target, err := saveConfig()
	if err != nil {
		return err
	}
	fmt.Printf("Trial opened: this host is %s, kept for %d hours.\n", cfg.NodeName, resp.Hours)
	fmt.Printf("   Config: %s\n", target)
	switch {
	case resp.KeyEscrowed:
		fmt.Printf("   Custody: SafeGrd-managed key. SafeGrd keeps your key sealed and releases it only to this host,\n")
		fmt.Printf("            so you can restore even after losing the host. For a customer-managed key, run try --key-custody local.\n")
	default:
		fmt.Printf("   Custody: customer-managed key. Only you can decrypt this backup. Keep a copy of %s somewhere safe.\n", cfg.Encryption.KeyPath)
	}
	fmt.Println()

	// The backup and the drill, as the commands a customer runs.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	configArgs := []string{}
	if cfgFile != "" {
		configArgs = append(configArgs, "--config", cfgFile)
	}
	backupOut, err := runSelfTee(ctx, self, append(configArgs, "backup")...)
	if err != nil {
		return fmt.Errorf("the backup failed: %w. The trial stays open for %d hours; fix the cause and run safegrd backup", err, resp.Hours)
	}
	snapshotID := firstMatch(snapshotIDRe, backupOut)
	if snapshotID == "" {
		return fmt.Errorf("the backup printed no snapshot id, so it cannot be drilled. Run safegrd list")
	}
	fmt.Println()
	fmt.Printf("Restoring %s in memory from the remote server's storage to check it.\n", snapshotID)
	verifyOut, verr := runSelfTee(ctx, self, append(configArgs, "verify", "--snapshot", snapshotID, "--in-memory")...)
	if verr != nil {
		fmt.Fprintf(os.Stderr, "Error: the drill failed: %v\n", verr)
	}
	verificationID := firstMatch(verificationIDRe, verifyOut)

	fmt.Println()
	fmt.Printf("Backed up and checked %s from this host.\n", surface.Name)
	fmt.Printf("   Snapshot:  %s\n", snapshotID)
	if verificationID != "" {
		fmt.Printf("   Drill:     %s (restored in memory from the remote server's storage)\n", verificationID)
	}
	fmt.Printf("   Kept until %s, not locked. Once you sign up, every backup is locked by your plan.\n",
		resp.TrialUntil.Local().Format("2006-01-02 15:04"))
	fmt.Printf("   See it:    safegrd list\n")
	fmt.Println()

	// The sign-up link, so a person who never runs `signup` can still finish
	// in the browser.
	sess, err := openTrySignupSession(ctx, serverURL, resp.Token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not open a sign-up link: %v. Run safegrd signup to get one.\n", err)
	} else {
		fmt.Printf("Keep this backup, back it up every day and see it in the console: safegrd signup\n")
		fmt.Printf("   Or open %s\n", sess.SignupURL)
		fmt.Printf("   and check the code there is %s.\n", sess.UserCode)
		if !noBrowser && !isRemoteSession() {
			_ = openBrowser(sess.SignupURL)
		}
	}
	if verr != nil {
		return verr
	}
	return nil
}

var (
	snapshotIDRe     = regexp.MustCompile(`(?m)^\s*Snapshot ID:\s+(\S+)`)
	verificationIDRe = regexp.MustCompile(`(?m)^\s*Verification ID:\s+(\S+)`)
)

func firstMatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// runSelfTee runs this binary with args, streaming its output to the terminal
// and keeping a copy of stdout to read the ids it printed.
func runSelfTee(ctx context.Context, self string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, self, args...)
	var out bytes.Buffer
	c.Stdout = io.MultiWriter(os.Stdout, &out)
	c.Stderr = os.Stderr
	c.Stdin = nil
	c.Env = os.Environ()
	err := c.Run()
	return out.String(), err
}

// trySurface is the one surface a trial backs up: a database by URL (or a
// reference to one), or a directory tree.
func trySurface(source string) (config.SurfaceConfig, error) {
	resolved, err := resolveConfigSecret("source", source)
	if err != nil {
		return config.SurfaceConfig{}, err
	}
	if resolved == "" {
		return config.SurfaceConfig{}, fmt.Errorf("%s is empty. Give a database URL (postgres://, mysql://, mongodb://, sqlite:///path) or a directory", source)
	}
	isURL := strings.Contains(resolved, "://") || strings.HasPrefix(strings.ToLower(resolved), "sqlite:") || dump.SurfaceTypeOfURL(resolved) != ""
	if !isURL {
		abs, err := filepath.Abs(resolved)
		if err != nil {
			return config.SurfaceConfig{}, err
		}
		st, err := os.Stat(abs)
		if err != nil || !st.IsDir() {
			return config.SurfaceConfig{}, fmt.Errorf("%s is neither a database URL nor a directory. Give postgres://, mysql://, mariadb://, mongodb:// or sqlite:///path, or a directory to back up", source)
		}
		id := surfaceIDCleaner.ReplaceAllString(strings.ToLower(filepath.Base(abs)), "-")
		if id == "" || id == "-" {
			id = "files"
		}
		return config.SurfaceConfig{ID: id, Type: string(model.SurfaceTypeFiles), Name: id, Roots: []string{abs}}, nil
	}
	s, err := initDatabaseSurface(source)
	if err != nil {
		return config.SurfaceConfig{}, err
	}
	return s, nil
}

func postTry(ctx context.Context, serverURL string, req model.TryRequest) (*model.TryResponse, error) {
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(serverURL, "/")+"/api/v1/try", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", UserAgent())
	httpReq.Header.Set(hostMachineHeader, hostMachine())
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(httpReq)
	if err != nil {
		return nil, serverFailure(fmt.Errorf("could not reach %s: %w", serverURL, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode >= 500 {
			return nil, serverFailure(fmt.Errorf("%s could not open a trial: %s", serverURL, e.Error))
		}
		return nil, fmt.Errorf("%s did not open a trial: %s", serverURL, e.Error)
	}
	var out model.TryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, serverFailure(fmt.Errorf("could not read the trial %s answered: %w", serverURL, err))
	}
	if out.Token == "" || out.NodeID == "" || out.ProjectID == "" {
		return nil, serverFailure(fmt.Errorf("%s answered a trial with no token or ids", serverURL))
	}
	return &out, nil
}

// tryCall is one authenticated call under the trial's node token.
func tryCall(ctx context.Context, serverURL, token, method, sub string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(serverURL, "/")+"/api/v1/try"+sub, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", UserAgent())
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return 0, serverFailure(fmt.Errorf("could not reach %s: %w", serverURL, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return resp.StatusCode, fmt.Errorf("%s", e.Error)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, serverFailure(fmt.Errorf("could not read the answer from %s: %w", serverURL, err))
		}
	}
	return resp.StatusCode, nil
}

func fetchTryStatus(ctx context.Context, serverURL, token string) (*model.TryStatus, error) {
	var st model.TryStatus
	if _, err := tryCall(ctx, serverURL, token, http.MethodGet, "/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func openTrySignupSession(ctx context.Context, serverURL, token string) (*model.TrySignupSession, error) {
	var s model.TrySignupSession
	if _, err := tryCall(ctx, serverURL, token, http.MethodPost, "/signup/session", map[string]string{}, &s); err != nil {
		return nil, err
	}
	if s.SessionID == "" || s.DeviceCode == "" || s.SignupURL == "" {
		return nil, fmt.Errorf("the remote server answered a sign-up session with fields missing")
	}
	return &s, nil
}

// newTryStatusCmd is `safegrd try status`: where this host's trial stands.
func newTryStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Say whether this host's trial backup is kept, signed up, or gone",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg == nil || cfg.ServerToken == "" || cfg.NodeID == "" {
				fmt.Println("No trial on this host. Start one: safegrd try <database-url | directory>")
				return nil
			}
			st, err := fetchTryStatus(cmd.Context(), resolveServerURL(), cfg.ServerToken)
			if err != nil {
				return fmt.Errorf("could not read the trial's state: %w", err)
			}
			printTryStatus(st)
			return nil
		},
	}
}

func printTryStatus(st *model.TryStatus) {
	switch st.State {
	case "unclaimed":
		fmt.Printf("Trial backup kept until %s, not signed up.\n", st.TrialUntil.Local().Format("2006-01-02 15:04"))
		fmt.Println("   Keep it: safegrd signup")
	case "claimed":
		fmt.Printf("Signed up as %s; the address is not verified yet.\n", st.OrgName)
		fmt.Printf("   The backup is kept until %s. Verify the address from the email to lift the trial's limits.\n", st.TrialUntil.Local().Format("2006-01-02 15:04"))
	case "owned":
		fmt.Printf("This host is enrolled in %s. No trial limits apply.\n", st.OrgName)
		if st.ConsoleURL != "" {
			fmt.Printf("   Console: %s\n", st.ConsoleURL)
		}
		fmt.Println("   Back up on a schedule: sudo safegrd daemon install")
	default:
		fmt.Printf("Trial state: %s\n", st.State)
	}
}
