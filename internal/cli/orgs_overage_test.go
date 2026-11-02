package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// The price of hosted storage above a paid plan's included amount comes from
// the remote server's catalogue, like every other price, and the free plan
// shows none.
func TestOrgShowsTheHostedOverageOnPaidPlans(t *testing.T) {
	for _, c := range []struct {
		plan, want string
	}{
		{"growth", "Extra hosted storage: $0.20 per GB-month"},
		{"free", ""},
	} {
		t.Run(c.plan, func(t *testing.T) {
			api := newFakeAPI(t, "sg_pat_test", map[string]http.HandlerFunc{
				"GET /api/v1/orgs": jsonReply(http.StatusOK, `[{"id":"org-1","name":"Acme","slug":"acme","plan":"`+c.plan+`","max_databases":5}]`),
				"public GET /api/v1/plans": jsonReply(http.StatusOK, `{"plans":[{"id":"free","name":"Free","monthly_usd":0,"surfaces":1},`+
					`{"id":"growth","name":"Growth","monthly_usd":49,"surfaces":10,"overage_cents_per_gb_month":20}]}`),
			})
			old := cfg
			t.Cleanup(func() { cfg = old })
			cfg = config.NewDefaultCLIConfig()
			cfg.ServerURL, cfg.ServerToken = api.URL(), "sg_pat_test"

			out, _, err := captureStdoutErr(t, showCurrentOrg)
			if err != nil {
				t.Fatal(err)
			}
			if c.want != "" && !strings.Contains(out, c.want) {
				t.Errorf("no overage line:\n%s", out)
			}
			if c.want != "" && len(api.Calls("/api/v1/plans")) == 0 {
				t.Fatal("the price was not read from the remote server's catalogue")
			}
			if c.want == "" && strings.Contains(out, "per GB-month") {
				t.Errorf("the free plan shows an overage:\n%s", out)
			}
		})
	}
}
