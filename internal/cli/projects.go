package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

func newProjectsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "Manage projects within an organization",
	}

	cmd.AddCommand(newListProjectsCmd())
	// Projects are created in the web console.
	return cmd
}

func newListProjectsCmd() *cobra.Command {
	var orgID string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List projects inside an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.ServerToken == "" {
				return fmt.Errorf("not logged in. Run 'safegrd login' first")
			}

			serverURL := resolveServerURL()

			// If orgID not provided, fetch user's first org
			if orgID == "" {
				firstOrgID, err := getFirstOrgID(serverURL, cfg.ServerToken)
				if err != nil {
					return err
				}
				orgID = firstOrgID
			}

			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/orgs/%s/projects", serverURL, orgID), nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+cfg.ServerToken)

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("failed connecting to server: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("server returned status %d", resp.StatusCode)
			}

			var projects []*model.Project
			if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
				return err
			}

			if len(projects) == 0 {
				fmt.Printf("No projects found in organization %s.\n", orgID)
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "PROJECT ID\tNAME\tSLUG\tCREATED AT")
			for _, p := range projects {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.ID, p.Name, p.Slug, p.CreatedAt.Format("2006-01-02"))
			}
			w.Flush()

			return nil
		},
	}

	cmd.Flags().StringVar(&orgID, "org", "", "Organization ID (defaults to primary organization)")
	return cmd
}

func getFirstOrgID(serverURL, token string) (string, error) {
	req, err := http.NewRequest("GET", serverURL+"/api/v1/orgs", nil)
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

	var orgs []*model.Organization
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil || len(orgs) == 0 {
		return "", fmt.Errorf("this credential belongs to no organization, so there are no projects to list. " +
			"Check your login session with 'safegrd whoami'")
	}

	return orgs[0].ID, nil
}
