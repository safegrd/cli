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
		Short:   "View organization details, subscription billing plan, and quotas",
		Long: `In SafeGrd, a user belongs to an Organization where billing, subscription tier,
and database quotas are attached (similar to GCP). Multiple projects can be created
under your organization to segment environments (production, staging, etc.).`,
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
	var planCost string
	var planDisplayName string
	catalogue, err := fetchPlansCatalogue(serverURL)
	if err != nil {
		// The price is the remote server's to state; without it, say so
		// rather than print one that may be out of date.
		fmt.Fprintf(os.Stderr, "⚠️  Notice: %v.\n", err)
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
			} else {
				planCost = "Free"
			}
		} else {
			planDisplayName = strings.ToUpper(string(org.Plan))
			planCost = "Free"
		}
	}

	fmt.Println("🏢 SafeGrd Organization")
	fmt.Printf("   Name:          %s\n", org.Name)
	fmt.Printf("   Org ID:        %s\n", org.ID)
	fmt.Printf("   Slug:          %s\n", org.Slug)
	fmt.Printf("   Billing Plan:  %s (%s)\n", planDisplayName, planCost)
	fmt.Printf("   Quota:         %d protected surfaces\n", org.MaxDatabases)
	fmt.Printf("   Created:       %s\n\n", org.CreatedAt.Format("2006-01-02 15:04:05 MST"))

	fmt.Println("💡 To manage environments or databases under this organization:")
	fmt.Println("   safegrd projects list")
	fmt.Println("   safegrd org members")
	// Projects are created in the console.
	fmt.Println("   New projects are created in the console at " + resolveServerURL() + "/dashboard")

	return nil
}

func newListOrgsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Display your organization profile and quota status",
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
				return fmt.Errorf("server returned status %d", resp.StatusCode)
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
			fmt.Fprintln(w, "ORG ID\tNAME\tSLUG\tPLAN\tMAX DATABASES")
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
				return fmt.Errorf("server returned status %d", resp.StatusCode)
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
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
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
