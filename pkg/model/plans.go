package model

// Plan is one tier as returned by the remote server at GET /api/v1/plans.
type Plan struct {
	ID         OrgPlan `json:"id"`
	Name       string  `json:"name"`
	MonthlyUSD int     `json:"monthly_usd"`
	Surfaces   int     `json:"surfaces"`
	// OverageCentsPerGBMonth is what hosted storage above the plan's included
	// amount costs, in US cents per GB-month. Zero where the plan has none.
	OverageCentsPerGBMonth int `json:"overage_cents_per_gb_month,omitempty"`
}
