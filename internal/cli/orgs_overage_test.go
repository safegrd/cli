package cli

import (
	"net/http"
	"net/http/httptest"
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
		{"growth", "Hosted storage above the included amount: $0.20 per GB-month"},
		{"free", ""},
	} {
		t.Run(c.plan, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/orgs":
					_, _ = w.Write([]byte(`[{"id":"org-1","name":"Acme","slug":"acme","plan":"` + c.plan + `","max_databases":5}]`))
				case "/api/v1/plans":
					_, _ = w.Write([]byte(`{"plans":[{"id":"free","name":"Free","monthly_usd":0,"surfaces":1},` +
						`{"id":"growth","name":"Growth","monthly_usd":49,"surfaces":10,"overage_cents_per_gb_month":20}]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			old := cfg
			t.Cleanup(func() { cfg = old })
			cfg = config.NewDefaultCLIConfig()
			cfg.ServerURL, cfg.ServerToken = srv.URL, "sg_pat_test"

			out, _, err := captureStdoutErr(t, showCurrentOrg)
			if err != nil {
				t.Fatal(err)
			}
			if c.want != "" && !strings.Contains(out, c.want) {
				t.Errorf("no overage line:\n%s", out)
			}
			if c.want == "" && strings.Contains(out, "per GB-month") {
				t.Errorf("the free plan shows an overage:\n%s", out)
			}
		})
	}
}
