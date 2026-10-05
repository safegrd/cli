package egress

import (
	"testing"
	"time"
)

// A month is 30 days: 720 hourly backups, 30 daily. The allowance comes off
// the GB before the price applies, and egress under it costs nothing.
func TestPriceAfterTheAllowance(t *testing.T) {
	gb := int64(1e9)
	if c := Price("hourly", time.Hour, gb, 0.09, 250); c.PerMonth != 720 || c.GB != 720 || c.USD != 42.3 {
		t.Errorf("hourly: %+v", c)
	}
	if c := Price("daily", 24*time.Hour, gb, 0.09, 250); c.GB != 30 || c.USD != 0 {
		t.Errorf("daily under the allowance: %+v", c)
	}
	if p, ok := ProviderOf("postgres://u:p@db.abc.supabase.co:5432/postgres"); !ok || p.Key != "supabase" || p.Included[p.DefaultPlan] != 250 {
		t.Errorf("supabase: %+v %v", p, ok)
	}
	if _, ok := ProviderOf("postgres://u:p@supabase.co.example.net/app"); ok {
		t.Error("a host that only contains a provider's name was read as that provider")
	}
}
