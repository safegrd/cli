package cli

// safegrd estimate: what a backup schedule costs in database egress, before
// the first schedule is set. A managed database bills the bytes that leave
// it, and every logical backup reads every row, so the cadence decides the
// bill. Storage is priced by the cost tool on the website; this prices the
// read.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

// egressPricesRead is when the prices below were read from each provider's
// pricing page. Check them again when it is more than a few months old.
const egressPricesRead = "2026-10-05"

// egressProvider is one provider's egress price and the egress each of its
// plans includes a month.
type egressProvider struct {
	Name        string
	Source      string
	USDPerGB    float64
	Included    map[string]float64 // GB a month, by the provider's plan
	DefaultPlan string
	HostSuffix  []string // how a connection string names it
}

var egressProviders = map[string]egressProvider{
	"supabase": {
		Name: "Supabase", Source: "supabase.com/pricing", USDPerGB: 0.09,
		Included:    map[string]float64{"free": 5, "pro": 250, "team": 250},
		DefaultPlan: "pro", HostSuffix: []string{".supabase.co", ".supabase.com"},
	},
	"neon": {
		Name: "Neon", Source: "neon.com/pricing", USDPerGB: 0.10,
		Included:    map[string]float64{"free": 5, "launch": 500, "scale": 500},
		DefaultPlan: "launch", HostSuffix: []string{".neon.tech"},
	},
	// AWS: data transfer out to the internet, the first 10 TB a month in
	// us-east-1, and the 100 GB a month free across the whole account.
	"rds": {
		Name: "Amazon RDS", Source: "aws.amazon.com/ec2/pricing/on-demand", USDPerGB: 0.09,
		Included:    map[string]float64{"default": 100},
		DefaultPlan: "default", HostSuffix: []string{".rds.amazonaws.com"},
	},
}

// cadence is one schedule the estimate prices.
type cadence struct {
	Name     string  `json:"schedule"`
	PerMonth float64 `json:"backups_per_month"`
	GB       float64 `json:"gb_per_month"`
	USD      float64 `json:"egress_usd_per_month"`
}

type estimateResult struct {
	Database         string    `json:"database"`
	Provider         string    `json:"provider"`
	ProviderPlan     string    `json:"provider_plan,omitempty"`
	DatabaseBytes    int64     `json:"database_bytes"`
	ReadBytes        int64     `json:"read_bytes_per_backup"`
	USDPerGB         float64   `json:"egress_usd_per_gb"`
	IncludedGB       float64   `json:"included_gb_per_month"`
	PricesRead       string    `json:"prices_read,omitempty"`
	Cadences         []cadence `json:"cadences"`
	ComparedPlan     string    `json:"compared_plan,omitempty"`
	ComparedPlanUSD  int       `json:"compared_plan_usd_per_month,omitempty"`
	OverPlanSchedule []string  `json:"over_plan,omitempty"`
}

func newEstimateCmd() *cobra.Command {
	var (
		dbURL, surfaceID, provider, providerPlan, schedule, plan string
		pricePerGB, includedGB                                   float64
		jsonOut                                                  bool
	)
	cmd := &cobra.Command{
		Use:   "estimate",
		Short: "Price a backup schedule's database egress before you set it",
		Long: `Measures a PostgreSQL database and prints what backing it up weekly, daily
and hourly costs a month in egress at its provider: every backup reads every
row, and a managed database bills the bytes that leave it.

The provider is read from the host name (Supabase, Neon, Amazon RDS); name it
with --provider, or use --provider other with --egress-price-per-gb. The
included egress is the provider plan's whole allowance; your application uses
it too, so pass what is left with --included-gb.

A warning says when a schedule's egress costs more a month than the SafeGrd
plan you compare it with (--plan), at the price the remote server publishes.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			u := dbURL
			if u == "" {
				for i := range cfg.Surfaces {
					s := &cfg.Surfaces[i]
					if (surfaceID == "" && surfaceIsPostgres(s)) || s.ID == surfaceID {
						var err error
						if u, err = resolveSurfaceDatabaseURLAsGiven(ctx, cfg, s); err != nil {
							return err
						}
						break
					}
				}
			}
			if u == "" {
				return fmt.Errorf("no database to measure: pass --database-url postgres://..., or --surface <id> for a PostgreSQL surface in this config")
			}
			u, _ = cleanPostgresURL(u)

			res := estimateResult{Database: databaseTargetWords(u)}
			if provider == "" {
				provider = providerOfURL(u)
			}
			switch p, ok := egressProviders[provider]; {
			case ok:
				if providerPlan == "" {
					providerPlan = p.DefaultPlan
				}
				inc, ok := p.Included[providerPlan]
				if !ok {
					return fmt.Errorf("%s has no plan %q here; use one of %s, or pass --included-gb", p.Name, providerPlan, planNames(p.Included))
				}
				res.Provider, res.ProviderPlan, res.USDPerGB, res.IncludedGB, res.PricesRead = p.Name, providerPlan, p.USDPerGB, inc, egressPricesRead+", "+p.Source
				if pricePerGB > 0 {
					res.USDPerGB, res.PricesRead = pricePerGB, ""
				}
			case provider == "other" || provider == "":
				if pricePerGB <= 0 {
					return fmt.Errorf("the provider of %s is not one this command knows: pass --egress-price-per-gb (and --included-gb), or --provider supabase|neon|rds", res.Database)
				}
				res.Provider, res.USDPerGB = "other", pricePerGB
			default:
				return fmt.Errorf("unknown --provider %q: use supabase, neon, rds or other", provider)
			}
			if cmd.Flags().Changed("included-gb") {
				res.IncludedGB = includedGB
			}

			var err error
			if res.DatabaseBytes, res.ReadBytes, err = measureForEgress(ctx, u); err != nil {
				return fmt.Errorf("could not measure %s: %w", res.Database, err)
			}

			schedules := []struct {
				name string
				d    time.Duration
			}{{"weekly", 7 * 24 * time.Hour}, {"daily", 24 * time.Hour}, {"hourly", time.Hour}}
			if schedule != "" {
				d, err := model.ParseSchedule(schedule)
				if err != nil {
					return err
				}
				schedules = append(schedules, struct {
					name string
					d    time.Duration
				}{schedule, d})
			}
			gbPerBackup := float64(res.ReadBytes) / 1e9
			for _, s := range schedules {
				per := (30 * 24 * time.Hour).Hours() / s.d.Hours()
				gb := per * gbPerBackup
				usd := math.Max(0, gb-res.IncludedGB) * res.USDPerGB
				res.Cadences = append(res.Cadences, cadence{Name: s.name, PerMonth: math.Round(per*100) / 100,
					GB: math.Round(gb*100) / 100, USD: math.Round(usd*100) / 100})
			}

			// The plan's price comes from the remote server, never from here.
			var planErr error
			if plans, err := fetchPlansCatalogue(cfg.ServerURL); err != nil {
				planErr = err
			} else {
				for _, p := range plans {
					if string(p.ID) == plan {
						res.ComparedPlan, res.ComparedPlanUSD = p.Name, p.MonthlyUSD
					}
				}
				if res.ComparedPlan == "" {
					planErr = fmt.Errorf("the remote server publishes no plan %q", plan)
				}
			}
			if res.ComparedPlan != "" {
				for _, c := range res.Cadences {
					if c.USD > float64(res.ComparedPlanUSD) {
						res.OverPlanSchedule = append(res.OverPlanSchedule, c.Name)
					}
				}
			}

			if jsonOut {
				if planErr != nil {
					fmt.Fprintf(os.Stderr, "Warning: not compared with a SafeGrd plan: %v\n", planErr)
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			printEstimate(res)
			if planErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: not compared with a SafeGrd plan: %v\n", planErr)
			}
			for _, c := range res.Cadences {
				if c.USD > float64(res.ComparedPlanUSD) && res.ComparedPlan != "" {
					fmt.Fprintf(os.Stderr, "Warning: %s backups cost $%.2f a month in egress, more than the %s plan ($%d a month).\n",
						c.Name, c.USD, res.ComparedPlan, res.ComparedPlanUSD)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbURL, "database-url", "", "The PostgreSQL database to measure (default: the first PostgreSQL surface in the config)")
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Measure this surface's database")
	cmd.Flags().StringVar(&provider, "provider", "", "supabase, neon, rds or other (default: read from the host name)")
	cmd.Flags().StringVar(&providerPlan, "provider-plan", "", "The provider plan whose included egress applies: supabase free|pro|team, neon free|launch|scale")
	cmd.Flags().Float64Var(&pricePerGB, "egress-price-per-gb", 0, "Egress price in US dollars per GB, for --provider other or to override the price here")
	cmd.Flags().Float64Var(&includedGB, "included-gb", 0, "Egress a month that is free and not used by your application, in GB")
	cmd.Flags().StringVar(&schedule, "schedule", "", "Price this schedule as well: @hourly, @daily, @weekly, a duration (6h) or N days")
	cmd.Flags().StringVar(&plan, "plan", string(model.OrgPlanGrowth), "The SafeGrd plan to compare the egress with: starter, growth or scale")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the estimate as JSON")
	return cmd
}

// providerOfURL names the provider a connection string's host belongs to,
// or "".
func providerOfURL(raw string) string {
	host := ""
	if u, err := url.Parse(raw); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	for key, p := range egressProviders {
		for _, suffix := range p.HostSuffix {
			if strings.HasSuffix(host, suffix) {
				return key
			}
		}
	}
	return ""
}

func planNames(m map[string]float64) string {
	var names []string
	for k := range m {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

// measureForEgress returns the database's size on disk and what one backup
// reads out of it: the tables and their TOAST without indexes, which a
// backup does not copy. That is about what COPY sends; it leaves the database
// uncompressed and is compressed only on this host, so egress is billed on it.
func measureForEgress(ctx context.Context, databaseURL string) (dbBytes, readBytes int64, err error) {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close(ctx)
	err = conn.QueryRow(ctx, `SELECT pg_database_size(current_database()),
		COALESCE((SELECT sum(pg_table_size(c.oid)) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('r', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
			AND n.nspname NOT LIKE 'pg_toast%'), 0)::bigint`).Scan(&dbBytes, &readBytes)
	return dbBytes, readBytes, err
}

func printEstimate(r estimateResult) {
	fmt.Printf("Database:         %s (%s", r.Database, r.Provider)
	if r.ProviderPlan != "" && r.ProviderPlan != "default" {
		fmt.Printf(", %s plan", r.ProviderPlan)
	}
	fmt.Println(")")
	fmt.Printf("Database size:    %s\n", formatBytes(r.DatabaseBytes))
	fmt.Printf("Read per backup:  %s (tables without indexes, before compression)\n", formatBytes(r.ReadBytes))
	fmt.Printf("Egress price:     $%.2f/GB after %s GB a month", r.USDPerGB, trimFloat(r.IncludedGB))
	if r.PricesRead != "" {
		fmt.Printf(" (read %s)", r.PricesRead)
	}
	fmt.Println()
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "Schedule\tBackups/month\tGB/month\tEgress/month\t")
	for _, c := range r.Cadences {
		fmt.Fprintf(w, "%s\t%s\t%s\t$%.2f\t\n", c.Name, trimFloat(c.PerMonth), trimFloat(c.GB), c.USD)
	}
	_ = w.Flush()
	fmt.Println()
	fmt.Println("The included egress is shared with your application's own traffic; pass what is left with --included-gb.")
}

func trimFloat(f float64) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.2f", f), "0"), ".")
}
