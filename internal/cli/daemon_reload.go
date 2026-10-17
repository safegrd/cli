package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// configWatch reloads the config file when it changes, so a surface that
// `safegrd claim` or a person adds reaches the running daemon on its next
// pass instead of at its next restart.
type configWatch struct {
	path    string
	modTime time.Time
	size    int64
}

func newConfigWatch() *configWatch {
	path := cfgFile
	if path == "" {
		if p, err := config.DefaultConfigFile(); err == nil {
			path = p
		}
	}
	w := &configWatch{path: path}
	if fi, err := os.Stat(path); err == nil {
		w.modTime, w.size = fi.ModTime(), fi.Size()
	}
	return w
}

// reload loads the config again when the file changed since the last look,
// and replaces the running one. A config that does not load leaves the
// running one in place, and says why; the next change is tried again.
func (w *configWatch) reload() {
	if w == nil || w.path == "" {
		return
	}
	fi, err := os.Stat(w.path)
	if err != nil || (fi.ModTime().Equal(w.modTime) && fi.Size() == w.size) {
		return
	}
	w.modTime, w.size = fi.ModTime(), fi.Size()
	next, err := config.LoadCLIConfig(w.path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %s changed and does not load (%v). The daemon keeps running the config it had.\n", w.path, err)
		return
	}
	if serverURLFlag != "" {
		next.ServerURL = serverURLFlag
	}
	added, removed := surfaceChanges(cfg, next)
	cfg = next
	switch {
	case len(added) == 0 && len(removed) == 0:
		fmt.Printf("Config reloaded from %s.\n", w.path)
	default:
		var parts []string
		if len(added) > 0 {
			parts = append(parts, "added "+strings.Join(added, ", "))
		}
		if len(removed) > 0 {
			parts = append(parts, "removed "+strings.Join(removed, ", "))
		}
		fmt.Printf("Config reloaded from %s: %s.\n", w.path, strings.Join(parts, "; "))
	}
	for _, msg := range ignoredConfigKeys(cfg) {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
	}
}

// surfaceChanges names the surfaces next has that prev did not, and the
// reverse.
func surfaceChanges(prev, next *config.CLIConfig) (added, removed []string) {
	had := map[string]bool{}
	for _, s := range prev.Surfaces {
		had[s.ID] = true
	}
	has := map[string]bool{}
	for _, s := range next.Surfaces {
		has[s.ID] = true
		if !had[s.ID] {
			added = append(added, s.ID)
		}
	}
	for id := range had {
		if !has[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
