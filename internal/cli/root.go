package cli

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/safegrd/cli/pkg/config"
	"github.com/spf13/cobra"
)

var (
	cfgFile       string
	serverURLFlag string
	cfg           *config.CLIConfig

	// cfgLoadErr is why the configuration file on disk was refused, if it was.
	//
	// initConfig substitutes defaults when the load fails, so without this the
	// refusal becomes invisible and the next error is about a field the refused
	// file supplies. That happened: a 0644 config produced
	// "database_url is required" about a config whose database_url was on line
	// 4, and the operator's next hour went into the connection string. The
	// warning was printed, but 25 lines of usage text came after it.
	//
	// A command must not run on defaults that were silently substituted for a
	// file the operator explicitly pointed at, so this is checked before any
	// command body runs.
	cfgLoadErr error

	// Version is the semantic release version of SafeGrd CLI, injected via
	// -ldflags at build time. A `go install ...@vX.Y.Z` build has no ldflags,
	// so stampFromBuildInfo fills it from the module version instead.
	Version = "dev"
	// Commit is the git commit SHA, injected via -ldflags at build time.
	Commit = "dev"
	// Date is the build timestamp, injected via -ldflags at build time.
	Date = "unknown"
)

// RootCmd is the base command for the safegrd CLI.
var RootCmd = &cobra.Command{
	Use:   "safegrd",
	Short: "SafeGrd: Immutable Postgres Backup & Verification Engine",
	Long: `SafeGrd (https://safegrd.dev)
Agent-safe, cryptographically air-gapped PostgreSQL backups with
client-side Age encryption and WORM storage immutability.`,
}

func Execute() {
	// Execute is the one place an error is printed. Cobra prints it too unless
	// told not to, which put every failure on the screen twice with the usage
	// block between the copies.
	RootCmd.SilenceErrors = true
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// stampFromBuildInfo fills in what -ldflags did not. Without it a binary from
// `go install github.com/safegrd/cli/cmd/safegrd@v0.0.3` reported the
// placeholder version, which is what the heartbeat then told the console.
func stampFromBuildInfo() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if Version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		Version = strings.TrimPrefix(info.Main.Version, "v")
	}
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision" && Commit == "dev" && len(s.Value) >= 7:
			Commit = s.Value[:7]
		case s.Key == "vcs.time" && Date == "unknown":
			Date = s.Value
		}
	}
}

func init() {
	stampFromBuildInfo()
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		return requireUsableConfig(cmd)
	}
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ~/.safegrd/config.yaml)")
	RootCmd.PersistentFlags().StringVar(&serverURLFlag, "server-url", "", "Remote server URL (default: https://safegrd.dev, or $SAFEGRD_SERVER_URL)")

	RootCmd.Version = Version
	RootCmd.SetVersionTemplate(fmt.Sprintf("safegrd version {{.Version}} (commit: %s, built: %s)\n", Commit, Date))

	RootCmd.AddCommand(newVersionCmd())
	RootCmd.AddCommand(newInitCmd())
	RootCmd.AddCommand(newBackupCmd())
	RootCmd.AddCommand(newRestoreCmd())
	RootCmd.AddCommand(newStatusCmd())
	RootCmd.AddCommand(newListCmd())
	RootCmd.AddCommand(newUndeleteCmd())
	RootCmd.AddCommand(newVerifyCmd())
	RootCmd.AddCommand(newEnrollCmd())
	RootCmd.AddCommand(newLoginCmd())
	RootCmd.AddCommand(newWhoamiCmd())
	RootCmd.AddCommand(newOrgsCmd())
	RootCmd.AddCommand(newProjectsCmd())
	RootCmd.AddCommand(newAgentCmd())
	RootCmd.AddCommand(newDoctorCmd())
	RootCmd.AddCommand(newConfigCmd())
	RootCmd.AddCommand(newVerifyHistoryCmd())
	RootCmd.AddCommand(newExportCmd())
	RootCmd.AddCommand(newPruneCmd())
	RootCmd.AddCommand(newMCPCmd())
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print safegrd CLI version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("safegrd version %s (commit: %s, built: %s)\n", Version, Commit, Date)
		},
	}
}

func initConfig() {
	var err error
	cfg, err = config.LoadCLIConfig(cfgFile)
	if err != nil {
		// Remembered rather than merely printed: requireUsableConfig turns it
		// into the error the command fails with, and the diagnostic commands
		// read it so they do not describe defaults as if they were the file.
		cfgLoadErr = err
		cfg = config.NewDefaultCLIConfig()
	}
	if serverURLFlag != "" {
		cfg.ServerURL = serverURLFlag
	}
}

// requireUsableConfig stops a command that would otherwise run on substituted
// defaults, and makes the refusal itself the error.
//
// The exempt commands are the ones whose job is to report or repair this exact
// state, plus the ones that read no configuration at all. Gating those would
// leave an operator with a bad config file and no command that would talk to
// them about it.
func requireUsableConfig(cmd *cobra.Command) error {
	// Flags are parsed and arguments validated by the time this runs, so no
	// error raised from here on is a usage error. Printing forty lines of flag
	// help after one is how the permissions warning came to be unreadable: it
	// was on screen, with the usage block after it and a second copy of the
	// error after that.
	cmd.SilenceUsage = true

	if cfgLoadErr == nil && cfg != nil && len(cfg.UnknownKeys) > 0 && !diagnosesConfig(cmd) {
		fmt.Fprintf(os.Stderr, "⚠️  Your config file has keys SafeGrd does not know, and they are ignored: %s.\n"+
			"   A misspelt setting falls back to its default. See safegrd.dev/docs/config\n", strings.Join(cfg.UnknownKeys, "; "))
	}
	if cfgLoadErr == nil || diagnosesConfig(cmd) {
		return nil
	}
	return fmt.Errorf("the configuration file was not loaded: %w\n"+
		"       No error after this one is about your configuration; it was never read, "+
		"so every setting in it is missing. Run 'safegrd config validate' for the full picture", cfgLoadErr)
}

// diagnosesConfig reports whether cmd, or any command it sits under, exists to
// inspect or repair the configuration.
func diagnosesConfig(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		switch c.Name() {
		case "config", "doctor", "init", "version", "help", "completion":
			return true
		}
	}
	return false
}

// resolveServerURL returns the remote server this invocation talks to.
//
// Precedence is settled before we get here: initConfig has already layered
// --server-url over SAFEGRD_SERVER_URL over ~/.safegrd/config.yaml. All that is
// left is the floor, and the floor is the hosted remote server.
//
// Every command resolving that floor for itself is how they came to disagree
// about it, so this is the only copy. A command that needs a server URL calls
// it; it does not write out a default of its own.
func resolveServerURL() string {
	return resolveServerURLFor(cfg)
}

// resolveServerURLFor is the same rule for a config the caller holds itself,
// rather than the process-wide one; doctor is handed the config it just
// validated, which may have come from an explicit --config path.
func resolveServerURLFor(c *config.CLIConfig) string {
	if c != nil && c.ServerURL != "" {
		return c.ServerURL
	}
	return config.DefaultServerURL
}
