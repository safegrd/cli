package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// Metrics and pings let a team watch the daemon with what it already runs:
// Prometheus scrapes daemon.metrics_addr, and a Healthchecks.io or Cronitor
// check takes a ping around each backup and after each pass.

// startMetricsServer serves /metrics on addr until ctx ends. Each scrape
// reads the state file the daemon writes after every backup, so what it
// shows is what the daemon last recorded, whichever process recorded it.
func startMetricsServer(ctx context.Context, addr, statePath string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("daemon.metrics_addr %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", metricsHandler(statePath))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut) // the daemon is stopping; nothing to report to
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "Error: the metrics endpoint on %s stopped: %v\n", addr, err)
		}
	}()
	return nil
}

func metricsHandler(statePath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write(renderMetrics(loadDaemonState(statePath), time.Now())) // a scraper that hung up gets nothing either way
	})
}

// renderMetrics is the Prometheus text format of a daemon's state. A time
// never reached (no success yet, no drill yet) is left out rather than
// written as 0, which a rule would read as 1970.
func renderMetrics(st *DaemonState, now time.Time) []byte {
	var b bytes.Buffer
	gauge := func(name, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	fmt.Fprintf(&b, "# HELP safegrd_daemon_info The daemon's version.\n# TYPE safegrd_daemon_info gauge\nsafegrd_daemon_info{version=%q} 1\n", Version)
	if !st.UpdatedAt.IsZero() {
		gauge("safegrd_daemon_state_updated_timestamp_seconds", "When the daemon last wrote its state.")
		fmt.Fprintf(&b, "safegrd_daemon_state_updated_timestamp_seconds %d\n", st.UpdatedAt.Unix())
	}
	ids := make([]string, 0, len(st.Surfaces))
	for id := range st.Surfaces {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	type series struct {
		name, help string
		value      func(s *SurfaceState) (float64, bool)
	}
	at := func(t time.Time) (float64, bool) { return float64(t.Unix()), !t.IsZero() }
	passed := func(s *SurfaceState) (float64, bool) {
		if s.DrillStatus == "" {
			return 0, false
		}
		if s.DrillStatus == model.DrillStatusPassed {
			return 1, true
		}
		return 0, true
	}
	for _, m := range []series{
		{"safegrd_surface_last_attempt_timestamp_seconds", "When the last backup of the surface started.", func(s *SurfaceState) (float64, bool) { return at(s.LastAttempt) }},
		{"safegrd_surface_last_success_timestamp_seconds", "When the last backup of the surface succeeded.", func(s *SurfaceState) (float64, bool) { return at(s.LastSuccess) }},
		{"safegrd_surface_consecutive_failures", "Backups of the surface that failed since the last success.", func(s *SurfaceState) (float64, bool) { return float64(s.ConsecutiveFailures), true }},
		{"safegrd_surface_next_due_timestamp_seconds", "When the next scheduled backup of the surface is due.", func(s *SurfaceState) (float64, bool) { return at(s.NextDue) }},
		{"safegrd_surface_last_backup_duration_seconds", "How long the last successful backup took.", func(s *SurfaceState) (float64, bool) {
			return float64(s.LastDurationMs) / 1000, s.LastDurationMs > 0
		}},
		{"safegrd_surface_last_backup_size_bytes", "What the last successful backup stored, encrypted.", func(s *SurfaceState) (float64, bool) {
			return float64(s.LastSizeBytes), s.LastSizeBytes > 0
		}},
		{"safegrd_surface_last_drill_timestamp_seconds", "When the last Fire Drill of the surface ran.", func(s *SurfaceState) (float64, bool) { return at(s.LastDrillAttempt) }},
		{"safegrd_surface_drill_passed", "1 when the last Fire Drill of the surface passed, else 0.", passed},
	} {
		written := false
		for _, id := range ids {
			s := st.Surfaces[id]
			v, ok := m.value(s)
			if !ok {
				continue
			}
			if !written {
				gauge(m.name, m.help)
				written = true
			}
			fmt.Fprintf(&b, "%s{surface=\"%s\",type=\"%s\"} %s\n", m.name, labelValue(id), labelValue(s.SurfaceType), strconv.FormatFloat(v, 'f', -1, 64))
		}
	}
	return b.Bytes()
}

// labelValue escapes a label value as the text format wants it.
func labelValue(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// pingTimeout bounds one ping: a check service that hangs must not hold a
// backup up.
const pingTimeout = 10 * time.Second

// ping sends one Healthchecks.io-style ping: POST to the check URL with
// suffix ("", "/start" or "/fail") and body as text. raw is the config's
// value (a URL, env:VAR or file:/path). The URL is a credential for the
// check, so no error names it.
func ping(ctx context.Context, field, raw, suffix, body string) error {
	if raw == "" {
		return nil
	}
	target, err := resolveConfigSecret(field, raw)
	if err != nil {
		return err
	}
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%s is not an http or https URL", field)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + suffix
	if len(body) > 10000 {
		body = body[:10000]
	}
	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("User-Agent", "safegrd/"+Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s: %w", field, err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %s", field, resp.Status)
	}
	return nil
}

// warnPing says a ping that failed. The backup's own outcome stands.
func warnPing(surfaceID string, err error) {
	if err == nil {
		return
	}
	if surfaceID == "" {
		fmt.Fprintf(os.Stderr, "Warning: the daemon's ping was not sent: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "Warning: Surface %s: its ping was not sent: %v\n", surfaceID, err)
}
