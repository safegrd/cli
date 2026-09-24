package model

// Plan is one tier as the remote server publishes it at GET /api/v1/plans.
//
// Only the fields the CLI shows. The catalogue, the quotas it grants and the
// rules that decide an organization's tier live on the remote server; the CLI
// reads them and never decides one.
type Plan struct {
	ID         OrgPlan `json:"id"`
	Name       string  `json:"name"`
	MonthlyUSD int     `json:"monthly_usd"`
	Surfaces   int     `json:"surfaces"`
}
