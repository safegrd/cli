// Package egress prices what backing a managed database up costs in egress:
// every logical backup reads every row, and a managed database bills the
// bytes that leave it.
package egress

import (
	"context"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// PricesRead is when the prices below were read from each provider's
// pricing page. Check them again when it is more than a few months old.
const PricesRead = "2026-10-05"

// Provider is one provider's egress price and the egress each of its plans
// includes a month.
type Provider struct {
	Key         string
	Name        string
	Source      string
	USDPerGB    float64
	Included    map[string]float64 // GB a month, by the provider's plan
	DefaultPlan string
	HostSuffix  []string // how a connection string names it
}

// Providers is every provider priced here, by key.
var Providers = map[string]Provider{
	"supabase": {
		Key: "supabase", Name: "Supabase", Source: "supabase.com/pricing", USDPerGB: 0.09,
		Included:    map[string]float64{"free": 5, "pro": 250, "team": 250},
		DefaultPlan: "pro", HostSuffix: []string{".supabase.co", ".supabase.com"},
	},
	"neon": {
		Key: "neon", Name: "Neon", Source: "neon.com/pricing", USDPerGB: 0.10,
		Included:    map[string]float64{"free": 5, "launch": 500, "scale": 500},
		DefaultPlan: "launch", HostSuffix: []string{".neon.tech"},
	},
	// AWS: data transfer out to the internet, the first 10 TB a month in
	// us-east-1, and the 100 GB a month free across the whole account.
	"rds": {
		Key: "rds", Name: "Amazon RDS", Source: "aws.amazon.com/ec2/pricing/on-demand", USDPerGB: 0.09,
		Included:    map[string]float64{"default": 100},
		DefaultPlan: "default", HostSuffix: []string{".rds.amazonaws.com"},
	},
}

// ProviderOf is the provider a connection string's host belongs to.
func ProviderOf(raw string) (Provider, bool) {
	host := ""
	if u, err := url.Parse(raw); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	for _, p := range Providers {
		for _, suffix := range p.HostSuffix {
			if strings.HasSuffix(host, suffix) {
				return p, true
			}
		}
	}
	return Provider{}, false
}

// Measure returns the database's size on disk and what one backup reads out
// of it: the tables and their TOAST without indexes, which a backup does not
// copy. That is about what COPY sends; it leaves the database uncompressed
// and is compressed only where the backup runs, so egress is billed on it.
func Measure(ctx context.Context, conn *pgx.Conn) (dbBytes, readBytes int64, err error) {
	err = conn.QueryRow(ctx, `SELECT pg_database_size(current_database()),
		COALESCE((SELECT sum(pg_table_size(c.oid)) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('r', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
			AND n.nspname NOT LIKE 'pg_toast%'), 0)::bigint`).Scan(&dbBytes, &readBytes)
	return dbBytes, readBytes, err
}

// Cadence is one schedule priced.
type Cadence struct {
	Name     string  `json:"schedule"`
	PerMonth float64 `json:"backups_per_month"`
	GB       float64 `json:"gb_per_month"`
	USD      float64 `json:"egress_usd_per_month"`
}

// Price is the egress a month of backing up readBytes every interval, at
// usdPerGB after includedGB a month (30 days).
func Price(name string, interval time.Duration, readBytes int64, usdPerGB, includedGB float64) Cadence {
	per := (30 * 24 * time.Hour).Hours() / interval.Hours()
	gb := per * float64(readBytes) / 1e9
	usd := math.Max(0, gb-includedGB) * usdPerGB
	return Cadence{Name: name, PerMonth: math.Round(per*100) / 100, GB: math.Round(gb*100) / 100, USD: math.Round(usd*100) / 100}
}
