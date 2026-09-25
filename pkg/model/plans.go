package model

// Plan is one tier as returned by the remote server at GET /api/v1/plans.
type Plan struct {
	ID         OrgPlan `json:"id"`
	Name       string  `json:"name"`
	MonthlyUSD int     `json:"monthly_usd"`
	Surfaces   int     `json:"surfaces"`
}
