package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

// `safegrd signup` gives the trial `safegrd try` opened an owner. It is the
// sign-in flow reversed: the CLI opens a session under its node token, prints
// a URL and a code, opens the browser, and waits. The person signs up (or in)
// on that page, checks the code, and the organization holding this host's
// backup becomes theirs. The node token in the config keeps working, so the
// host is enrolled with nothing more to run.

func newSignupCmd() *cobra.Command {
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "signup",
		Short: "Keep this host's trial backup: sign up in a browser, and the host is enrolled",
		Long: `Opens the sign-up page for the backup safegrd try took. Sign up there (or sign
in, if you have an account), check that the code on the page matches the one
printed here, and this host's backup, its host and its daily schedule are yours.

Nothing changes on this host: the config already holds what it needs.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg == nil || cfg.ServerToken == "" || cfg.NodeID == "" {
				return fmt.Errorf("no trial backup on this host to sign up with. Start one: safegrd try <database-url | directory>")
			}
			return runSignup(cmd.Context(), resolveServerURL(), cfg.ServerToken, noBrowser)
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the link without opening a browser")
	return cmd
}

func runSignup(ctx context.Context, serverURL, token string, noBrowser bool) error {
	st, err := fetchTryStatus(ctx, serverURL, token)
	if err != nil {
		return fmt.Errorf("could not read the trial's state: %w", err)
	}
	if st.State != "unclaimed" {
		printTryStatus(st)
		return nil
	}

	sess, err := openTrySignupSession(ctx, serverURL, token)
	if err != nil {
		return fmt.Errorf("could not open a sign-up session: %w", err)
	}
	fmt.Printf("Open this URL in a browser on any device:\n\n   %s\n\n", sess.SignupURL)
	fmt.Printf("Check that the page shows this code: %s\n", sess.UserCode)
	fmt.Printf("Sign up there, or sign in if you have an account. Waiting here until %s.\n\n",
		sess.ExpiresAt.Local().Format("15:04"))
	if !noBrowser && !isRemoteSession() {
		if err := openBrowser(sess.SignupURL); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open a browser: %v\n", err)
		}
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		var poll model.TrySignupPoll
		status, err := tryCall(ctx, serverURL, token, http.MethodPost, "/signup/poll",
			map[string]string{"session_id": sess.SessionID, "device_code": sess.DeviceCode}, &poll)
		if err != nil {
			if status == http.StatusTooManyRequests {
				continue
			}
			return fmt.Errorf("the sign-up could not be checked: %w", err)
		}
		switch poll.Status {
		case "pending":
			continue
		case "expired":
			return fmt.Errorf("the sign-up link expired before it was used. Run safegrd signup again for a new one")
		case "claimed":
			fmt.Printf("Signed up. This host and its backup belong to %s.\n", poll.OrgName)
			if poll.Verified {
				fmt.Println("   The trial's limits are lifted: every backup from the next one is locked by your plan.")
				if poll.ConsoleURL != "" {
					fmt.Printf("   Console: %s\n", poll.ConsoleURL)
				}
				fmt.Println("   Back up every day: sudo safegrd daemon install")
			} else {
				fmt.Println("   Verify your address from the email to finish; the backup is kept until then.")
				fmt.Printf("   Until %s. Check with: safegrd try status\n", poll.TrialUntil.Local().Format("2006-01-02 15:04"))
			}
			return nil
		default:
			return fmt.Errorf("the remote server answered an unknown sign-up state %q", poll.Status)
		}
	}
}
