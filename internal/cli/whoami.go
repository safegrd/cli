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
		Short: "Display the currently authenticated user and active server session",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.ServerToken == "" {
				fmt.Println("Not logged in. Run 'safegrd login' to authenticate with the SafeGrd Remote Server.")
				return nil
			}

			serverURL := resolveServerURL()

			req, err := http.NewRequest("GET", serverURL+"/api/v1/auth/me", nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+cfg.ServerToken)

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("could not connect to server at %s: %w", serverURL, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				fmt.Printf("⚠️  Token rejected by server (HTTP %d). Session may have expired.\n", resp.StatusCode)
				fmt.Println("Run 'safegrd login' to refresh your session.")
				return nil
			}

			var data map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&data)

			fmt.Println("👤 SafeGrd Authentication Status")
			fmt.Printf("   Server: %s\n", serverURL)
			if email, ok := data["email"]; ok {
				fmt.Printf("   User:   %v\n", email)
			}
			if name, ok := data["name"]; ok && name != "" {
				fmt.Printf("   Name:   %v\n", name)
			}
			if role, ok := data["role"]; ok {
				fmt.Printf("   Role:   %v\n", role)
			}
			if id, ok := data["id"]; ok {
				fmt.Printf("   ID:     %v\n", id)
			}

			return nil
		},
	}
}
