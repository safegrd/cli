package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

func newOrgsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "org",
		Aliases: []string{"orgs"},
		Short:   "Show your organization, plan and quotas",
		Long: `Shows the organization you belong to: its plan, price and surface quota.
Billing and quotas belong to the organization. Projects inside it separate
environments such as production and staging.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showCurrentOrg()
		},
	}

	cmd.AddCommand(newListOrgsCmd())
	cmd.AddCommand(newOrgMembersCmd())
	// Project creation and member invitations are managed in the web console.
	return cmd
}

func showCurrentOrg() error {
	if cfg.ServerToken == "" {
		return fmt.Errorf("not logged in. Run 'safegrd login' first")
	}

	serverURL := resolveServerURL()

	org, err := fetchUserOrg(serverURL, cfg.ServerToken)
	if err != nil {
		return err
	}

	// The catalogue comes from the remote server, which is the only place it
	// is decided.
	var planCost, overage string
	var planDisplayName string
	catalogue, err := fetchPlansCatalogue(serverURL)
	if err != nil {
		// The price is the remote server's to state; without it, say so
		// rather than print one that may be out of date.
		fmt.Fprintf(os.Stderr, "Warning: %v.\n", err)
		planDisplayName = strings.ToUpper(string(org.Plan))
		planCost = "price unavailable"
	} else {
		var matchedPlan *model.Plan
		for i := range catalogue {
			if catalogue[i].ID == org.Plan {
				matchedPlan = &catalogue[i]
				break
			}
		}
		if matchedPlan != nil {
			planDisplayName = matchedPlan.Name
			if matchedPlan.MonthlyUSD > 0 {
				planCost = fmt.Sprintf("$%d/mo", matchedPlan.MonthlyUSD)
				if c := matchedPlan.OverageCentsPerGBMonth; c > 0 {
					overage = fmt.Sprintf("$%d.%02d per GB-month", c/100, c%100)
				}
			} else {
				planCost = "Free"
			}
		} else {
			planDisplayName = strings.ToUpper(string(org.Plan))
			planCost = "Free"
		}
	}

	fmt.Println("Organization")
	fmt.Printf("   Name:          %s\n", org.Name)
	fmt.Printf("   Org ID:        %s\n", org.ID)
	fmt.Printf("   Slug:          %s\n", org.Slug)
	fmt.Printf("   Plan:          %s (%s)\n", planDisplayName, planCost)
	fmt.Printf("   Quota:         %d protected surfaces\n", org.MaxDatabases)
	if overage != "" {
		fmt.Printf("   Extra hosted storage: %s\n", overage)
	}
	fmt.Printf("   Created:       %s\n\n", org.CreatedAt.Format("2006-01-02 15:04:05 MST"))

	fmt.Println("Projects and members:")
	fmt.Println("   safegrd projects list")
	fmt.Println("   safegrd org members")
	// Projects are created in the console.
	fmt.Println("   Create projects in the console at " + resolveServerURL() + "/dashboard")

	return nil
}

func newListOrgsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the organizations you belong to",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.ServerToken == "" {
				return fmt.Errorf("not logged in. Run 'safegrd login' first")
			}

			serverURL := resolveServerURL()

			req, err := http.NewRequest("GET", serverURL+"/api/v1/orgs", nil)
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
				return serverStatusError(resp.StatusCode)
			}

			var orgs []*model.Organization
			if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
				return err
			}

			if len(orgs) == 0 {
				fmt.Println("No organization found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ORG ID\tNAME\tSLUG\tPLAN\tMAX SURFACES")
			for _, o := range orgs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", o.ID, o.Name, o.Slug, strings.ToUpper(string(o.Plan)), o.MaxDatabases)
			}
			w.Flush()

			return nil
		},
	}
}

func newOrgMembersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "members",
		Short: "List team members in your organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.ServerToken == "" {
				return fmt.Errorf("not logged in. Run 'safegrd login' first")
			}

			serverURL := resolveServerURL()

			org, err := fetchUserOrg(serverURL, cfg.ServerToken)
			if err != nil {
				return err
			}

			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/orgs/%s/members", serverURL, org.ID), nil)
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
				return serverStatusError(resp.StatusCode)
			}

			var members []*model.OrgMember
			if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "NAME\tEMAIL\tROLE\tJOINED")
			for _, m := range members {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.UserName, m.UserEmail, strings.ToUpper(string(m.Role)), m.JoinedAt.Format("2006-01-02"))
			}
			w.Flush()

			return nil
		},
	}
}

func fetchUserOrg(serverURL, token string) (*model.Organization, error) {
	req, err := http.NewRequest("GET", serverURL+"/api/v1/orgs", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverStatusError(resp.StatusCode)
	}

	var orgs []*model.Organization
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, err
	}

	if len(orgs) == 0 {
		return nil, fmt.Errorf("no organization found for current user")
	}

	return orgs[0], nil
}

var (
	cachedPlans   []model.Plan
	cachedPlansAt time.Time
)

func fetchPlansCatalogue(serverURL string) ([]model.Plan, error) {
	if time.Since(cachedPlansAt) < 5*time.Minute && len(cachedPlans) > 0 {
		return cachedPlans, nil
	}

	if serverURL == "" {
		serverURL = config.DefaultServerURL
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(serverURL + "/api/v1/plans")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch billing plan catalogue from remote server (%s): %w", serverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote server returned status %d fetching plan catalogue", resp.StatusCode)
	}

	var payload struct {
		Plans []model.Plan `json:"plans"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to decode plan catalogue: %w", err)
	}

	cachedPlans = payload.Plans
	cachedPlansAt = time.Now()
	return cachedPlans, nil
}

// serverStatusError says what an HTTP status means for the person at the
// terminal. A revoked access token used to end in "server returned status 401"
// and nothing about logging in again.
func serverStatusError(code int) error {
	switch code {
	case http.StatusUnauthorized:
		return fmt.Errorf("the remote server rejected this login (HTTP 401): it expired or was revoked. Run 'safegrd login'")
	case http.StatusForbidden:
		return fmt.Errorf("the remote server refused this (HTTP 403): your role in the organization does not allow it")
	}
	return fmt.Errorf("server returned status %d", code)
}
