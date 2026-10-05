package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show who you are signed in as, and on which server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.ServerToken == "" {
				fmt.Println("Not logged in. Run 'safegrd login' to sign in.")
				return nil
			}

			serverURL := resolveServerURL()

			if err := refuseInsecurePersonalToken(serverURL); err != nil {
				return err
			}

			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, serverURL+"/api/v1/auth/me", nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+cfg.ServerToken)
			req.Header.Set("User-Agent", UserAgent())

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("could not reach %s: %w", serverURL, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%s refused the saved token (HTTP %d). It may have expired: run 'safegrd login'", serverURL, resp.StatusCode)
			}

			var data map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				return fmt.Errorf("could not read the account from %s: %w", serverURL, err)
			}

			fmt.Println("Signed in")
			fmt.Printf("   Server: %s\n", serverURL)
			if email, ok := data["email"]; ok {
				fmt.Printf("   User:   %v\n", email)
			}
			if name, ok := data["name"]; ok && name != "" {
				fmt.Printf("   Name:   %v\n", name)
			}
			// "role" is the account's role on the server, not in an
			// organization: every customer is "member", owners included, so
			// it is printed only where it says something.
			switch data["role"] {
			case "admin":
				fmt.Println("   Role:   server administrator")
			case "node_daemon":
				fmt.Println("   Role:   this host's node token")
			}
			if id, ok := data["id"]; ok {
				fmt.Printf("   ID:     %v\n", id)
			}

			return nil
		},
	}
}
