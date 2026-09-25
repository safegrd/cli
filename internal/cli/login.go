package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
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
		Short: "Authenticate the CLI with the remote server via browser or API key",
		Long: `Authenticates the local environment with SafeGrd.
By default, launches an interactive browser confirmation flow.
For CI/CD or headless environments, pass your Personal Access Token via '--token sg_pat_...'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			serverURL := resolveServerURL()

			// Mode 1: Direct API Key / Personal Access Token provided
			if token != "" {
				fmt.Printf("🔑 Verifying provided token with %s...\n", serverURL)
				profile, err := fetchProfile(serverURL, token)
				if err != nil {
					return fmt.Errorf("token verification failed: %w", err)
				}

				cfg.ServerURL = serverURL
				cfg.ServerToken = token
				targetConfig := cfgFile
				if targetConfig == "" {
					targetConfig, _ = config.DefaultConfigFile()
				}
				if err := config.SaveCLIConfig(cfg, targetConfig); err != nil {
					return fmt.Errorf("failed saving config: %w", err)
				}

				fmt.Printf("✅ Authenticated successfully as '%s'!\n", profile)
				fmt.Printf("💾 Config updated: %s\n", targetConfig)
				return nil
			}

			// Mode 2: Interactive Browser Device Flow
			fmt.Printf("🛡️  Initiating SafeGrd CLI authentication with %s...\n", serverURL)

			req, err := http.NewRequest("POST", serverURL+"/api/v1/auth/cli/session", nil)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("failed connecting to SafeGrd server: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("server rejected CLI session request (HTTP %d)", resp.StatusCode)
			}

			var session model.CLISession
			if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
				return fmt.Errorf("failed parsing server session: %w", err)
			}

			authURL := fmt.Sprintf("%s/auth/cli?session=%s&code=%s", serverURL, session.SessionID, session.UserCode)

			remote := isRemoteSession()

			fmt.Println("\n==================================================")
			fmt.Printf("Confirmation Code:  \033[1;36m%s\033[0m\n", session.UserCode)
			fmt.Println("==================================================")
			if remote {
				// Over SSH or PuTTY the browser is on the operator's own
				// machine, not this one, so say where to open it.
				fmt.Printf("Open this URL in a browser on any device, such as the machine you are\n")
				fmt.Printf("connecting from, and check the code matches:\n\n  \033[4;34m%s\033[0m\n\n", authURL)
			} else {
				fmt.Printf("Open the following URL in your browser to authorize:\n\n  \033[4;34m%s\033[0m\n\n", authURL)
			}

			// Never launch a browser on a remote host: xdg-open there either
			// fails or starts a text browser such as w3m inside the SSH
			// session, which takes over the terminal the code is printed in.
			if !noBrowser && !remote {
				if err := openBrowser(authURL); err != nil {
					fmt.Printf("(Could not open a browser here: %v. Open the URL above by hand.)\n\n", err)
				}
			}

			fmt.Print("⏳ Waiting for browser authorization...")

			// Poll for authorization
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					fmt.Println("\n❌ Login timed out. Please run 'safegrd login' again.")
					return fmt.Errorf("authorization timed out")
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
						fmt.Println("\n\n✅ Authorization successful!")

						cfg.ServerURL = serverURL
						cfg.ServerToken = pollSession.Token

						targetConfig := cfgFile
						if targetConfig == "" {
							targetConfig, _ = config.DefaultConfigFile()
						}
						if err := config.SaveCLIConfig(cfg, targetConfig); err != nil {
							return fmt.Errorf("failed saving config: %w", err)
						}

						fmt.Printf("   User:   %s\n", pollSession.UserEmail)
						fmt.Printf("   Token:  %s...\n", pollSession.Token[:14])
						fmt.Printf("💾 Config updated: %s\n", targetConfig)
						return nil
					}
				}
			}
		},
	}

	cmd.Flags().StringVar(&token, "token", "", "Personal Access Token (sg_pat_...) for non-interactive / CI login")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Do not attempt to open browser automatically")

	return cmd
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
