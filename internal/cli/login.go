package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	var (
		token     string
		noBrowser bool
	)

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to the remote server, in a browser or with an access token",
		Long: `Signs this CLI in to the remote server and saves the token in the config.

By default it prints a URL and a confirmation code, and opens the URL in a
browser. In CI or on a host with no browser, pass a personal access token from
Tokens in the console: --token env:SAFEGRD_TOKEN (or file:/path, or the token itself).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			serverURL := resolveServerURL()

			if err := refuseInsecurePersonalToken(serverURL); err != nil {
				return err
			}

			// An enrolled host authenticates as its node. Writing a personal
			// token over that one would leave the daemon unable to fetch the
			// credentials and key the remote server holds for it, which only a
			// node token may fetch.
			if err := refuseOverNodeToken(cfg); err != nil {
				return err
			}

			// Mode 1: Direct API Key / Personal Access Token provided
			token, err := ResolveSecretRef("token", token)
			if err != nil {
				return err
			}
			if token != "" {
				fmt.Printf("Checking the token with %s\n", serverURL)
				profile, err := fetchProfile(serverURL, token)
				if err != nil {
					return fmt.Errorf("token verification failed: %w", err)
				}

				cfg.ServerURL = serverURL
				cfg.ServerToken = token
				targetConfig, err := saveConfig()
				if err != nil {
					return err
				}

				fmt.Printf("Signed in as '%s'\n", profile)
				fmt.Printf("Saved to %s\n", targetConfig)
				return nil
			}

			// Mode 2: Interactive Browser Device Flow
			fmt.Printf("Signing in to %s\n", serverURL)

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/api/v1/auth/cli/session", nil)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("could not reach %s: %w", serverURL, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("%s refused to start a sign-in (HTTP %d)", serverURL, resp.StatusCode)
			}

			var session model.CLISession
			if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
				return fmt.Errorf("could not read the sign-in session from %s: %w", serverURL, err)
			}

			authURL := fmt.Sprintf("%s/auth/cli?session=%s&code=%s", serverURL, session.SessionID, session.UserCode)

			remote := isRemoteSession()

			fmt.Printf("\nConfirmation code: %s\n\n", ansi("1;36", session.UserCode))
			if remote {
				// Over SSH or PuTTY the browser is on the operator's own
				// machine, not this one, so say where to open it.
				fmt.Printf("Open this URL in a browser on any device, such as the machine you are\n")
				fmt.Printf("connecting from, and check the code matches:\n\n  %s\n\n", ansi("4;34", authURL))
			} else {
				fmt.Printf("Open this URL in your browser and check the code matches:\n\n  %s\n\n", ansi("4;34", authURL))
			}

			// Never launch a browser on a remote host: xdg-open there either
			// fails or starts a text browser such as w3m inside the SSH
			// session, which takes over the terminal the code is printed in.
			if !noBrowser && !remote {
				if err := openBrowser(authURL); err != nil {
					fmt.Fprintf(os.Stderr, "Could not open a browser here (%v). Open the URL above by hand.\n\n", err)
				}
			}

			fmt.Print("Waiting for you to approve the sign-in in the browser")

			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					fmt.Println()
					if cmd.Context().Err() != nil {
						return cmd.Context().Err()
					}
					return fmt.Errorf("the sign-in was not approved within 5 minutes. Run 'safegrd login' again")
				case <-ticker.C:
					fmt.Print(".")
					pollReq, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/v1/auth/cli/session?session_id=%s", serverURL, session.SessionID), nil)
					pollResp, err := client.Do(pollReq)
					if err != nil {
						continue
					}

					var pollSession model.CLISession
					_ = json.NewDecoder(pollResp.Body).Decode(&pollSession)
					pollResp.Body.Close()

					if pollSession.Status == model.CLISessionStatusAuthorized && pollSession.Token != "" {
						fmt.Println("\n\nSigned in.")

						cfg.ServerURL = serverURL
						cfg.ServerToken = pollSession.Token

						targetConfig, err := saveConfig()
						if err != nil {
							return err
						}

						fmt.Printf("   User:   %s\n", pollSession.UserEmail)
						fmt.Printf("   Token:  %s\n", maskToken(pollSession.Token))
						if pollSession.TokenExpiresAt != nil {
							fmt.Printf("   Expires: %s. Run 'safegrd login' again after that.\n", pollSession.TokenExpiresAt.Local().Format("2006-01-02"))
						}
						fmt.Printf("Saved to %s\n", targetConfig)
						return nil
					}
				}
			}
		},
	}

	cmd.Flags().StringVar(&token, "token", "", "Personal access token (sg_pat_...), as env:VAR, file:/path or the token")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Do not attempt to open browser automatically")

	return cmd
}

// refuseOverNodeToken stops a login from replacing the node token of an
// enrolled host. The login still works from a separate config.
func refuseOverNodeToken(c *config.CLIConfig) error {
	if c == nil || !strings.HasPrefix(c.ServerToken, "sg_tok_") {
		return nil
	}
	node := c.NodeID
	if node == "" {
		node = "a node"
	}
	return fmt.Errorf("this host is enrolled as %s, and its config holds that node's token.\n"+
		"  Logging in would replace it, and the daemon could no longer fetch the credentials\n"+
		"  and key the remote server holds for this host.\n"+
		"  To use your account here, keep it in its own config:\n"+
		"    safegrd --config ~/.safegrd/operator.yaml login\n"+
		"  Nothing was changed", node)
}

func fetchProfile(serverURL, token string) (string, error) {
	req, err := http.NewRequest("GET", serverURL+"/api/v1/auth/me", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("invalid token (HTTP %d)", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	if email, ok := data["email"].(string); ok {
		return email, nil
	}
	if name, ok := data["name"].(string); ok {
		return name, nil
	}
	return "authenticated user", nil
}

// isRemoteSession reports whether there is no local browser to open: a login
// over SSH, or a Linux host with no graphical session (a server, a container).
func isRemoteSession() bool {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" || os.Getenv("SSH_CLIENT") != "" {
		return true
	}
	if runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return true
	}
	return false
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return nil
	}
	return cmd.Start()
}
