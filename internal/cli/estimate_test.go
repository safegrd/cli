package cli

import "testing"

// The provider is read from the connection string's host, and nothing else.
func TestEstimateReadsTheProviderFromTheHost(t *testing.T) {
	for raw, want := range map[string]string{
		"postgres://u:p@db.abcdefgh.supabase.co:5432/postgres":                 "supabase",
		"postgres://u:p@aws-0-eu-west-1.pooler.supabase.com:6543/postgres":     "supabase",
		"postgres://u:p@ep-cool-name-123.us-east-2.aws.neon.tech/neondb":       "neon",
		"postgres://u:p@prod.cluster-abc.us-east-1.rds.amazonaws.com:5432/app": "rds",
		"postgres://u:p@db.internal:5432/app":                                  "",
		"postgres://u:p@supabase.co.attacker.example/app":                      "",
	} {
		if got := providerOfURL(raw); got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
	if trimFloat(250) != "250" || trimFloat(4.2857) != "4.29" || trimFloat(0.004) != "0" {
		t.Errorf("trimFloat: %s %s %s", trimFloat(250), trimFloat(4.2857), trimFloat(0.004))
	}
}
