package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// `safegrd claim` adds to an enrolled host's config the surfaces named for it
// in the console. A surface exists because the host's config names it, and
// the config has one writer at a time: the console only names a surface, and
// this command, run by someone on the host, is what makes it real. It only
// adds. An id the config already has is left as it is, the file is copied to
// config.yaml.bak first, its comments are kept, and running it again adds
// nothing.

type hostPending struct {
	HostID      string         `json:"host_id"`
	ProjectName string         `json:"project_name"`
	Surfaces    []claimSurface `json:"surfaces"`
}

func newClaimCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "claim",
		Short: "Add the surfaces named for this host in the console to its config",
		Long: `Adds to this host's config the surfaces named for it in the console
(Protect a Surface, for an enrolled host). Nothing changes on the host until
this runs, and it only adds: a surface the config already has is left as it is.
The previous config is kept as config.yaml.bak.

The daemon reads its config when it starts, so restart it afterwards.

A new host enrolls with a claim code instead: safegrd enroll --claim <code>.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !hostIsEnrolled(cfg) || cfg.NodeID == "" {
				return fmt.Errorf("this host is not enrolled, so nothing can be named for it yet. " +
					"A new host enrolls with the command the console shows: safegrd enroll --claim <code>")
			}
			path := cfgFile
			if path == "" {
				var err error
				if path, err = config.DefaultConfigFile(); err != nil {
					return err
				}
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			pending, err := fetchHostPending(ctx, cfg)
			if err != nil {
				return fmt.Errorf("could not ask the remote server what is named for this host: %w", err)
			}
			if len(pending.Surfaces) == 0 {
				fmt.Println("Nothing is named for this host in the console. Add a surface there first (Protect a Surface, for this host).")
				return nil
			}

			have := map[string]bool{}
			for _, s := range cfg.Surfaces {
				have[s.ID] = true
			}
			var add []claimSurface
			fmt.Printf("📋 Surfaces named for this host in the console")
			if pending.ProjectName != "" {
				fmt.Printf(" (project '%s')", pending.ProjectName)
			}
			fmt.Println(":")
			for _, s := range pending.Surfaces {
				if have[s.Key] {
					fmt.Printf("   %-20s already in this config; left as it is\n", s.Key)
					continue
				}
				add = append(add, s)
				fmt.Printf("   %-20s %s\n", s.Key, claimedSurfaceWords(s))
			}
			if len(add) == 0 {
				fmt.Println("\nNothing to add: every surface named for this host is already in its config.")
				fmt.Println("   If the daemon is running, restart it so it reads the config: safegrd daemon restart")
				return nil
			}

			backup, err := appendSurfacesToConfig(path, add)
			if err != nil {
				return err
			}
			fmt.Printf("\n💾 Added %d surface%s to %s (the previous config is at %s).\n", len(add), plural(len(add)), path, backup)
			fmt.Println("   The daemon reads its config when it starts. Restart it: safegrd daemon restart")
			fmt.Println("   or take the first backups now: safegrd daemon run --once")
			return nil
		},
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// claimedSurfaceWords says what the host must provide for a claimed surface.
func claimedSurfaceWords(s claimSurface) string {
	switch {
	case s.Config.CredentialHeld:
		return s.SurfaceType + ": SafeGrd holds its credential; the daemon fetches it when it backs up"
	case s.Config.CredentialEnv != "":
		return s.SurfaceType + ": set " + s.Config.CredentialEnv + " where the daemon runs (the credential never leaves this host)"
	}
	return s.SurfaceType
}

// fetchHostPending asks the remote server, as this host, what is named for it.
func fetchHostPending(ctx context.Context, c *config.CLIConfig) (*hostPending, error) {
	if err := refuseInsecureServerURL(c.ServerURL); err != nil {
		return nil, err
	}
	u := strings.TrimRight(c.ServerURL, "/") + "/api/v1/nodes/" + url.PathEscape(c.NodeID) + "/pending-surfaces"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	req.Header.Set("User-Agent", UserAgent())
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Error)
	}
	var out hostPending
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// appendSurfacesToConfig appends surfaces to the config file's surfaces list,
// keeping everything else in the file, comments included, as it was. The
// previous file is copied beside it first, and the result must load, or the
// previous file is put back. It returns where the copy is.
func appendSurfacesToConfig(path string, add []claimSurface) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("%s could not be read as YAML: %w", path, err)
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return "", fmt.Errorf("%s does not hold a config (its top level is not a mapping)", path)
	}
	var list *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "surfaces" {
			list = root.Content[i+1]
			if list.Kind != yaml.SequenceNode {
				// "surfaces:" with nothing under it.
				*list = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			}
		}
	}
	if list == nil {
		list = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "surfaces"}, list)
	}
	for _, s := range add {
		var n yaml.Node
		if err := n.Encode(surfaceConfigFor(s)); err != nil {
			return "", err
		}
		list.Content = append(list.Content, &n)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}

	backup := path + ".bak"
	if err := os.WriteFile(backup, raw, 0o600); err != nil {
		return "", fmt.Errorf("could not keep a copy of the config before changing it: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.yaml")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	// What was written must load, as the daemon will load it.
	if _, err := config.LoadCLIConfig(path); err != nil {
		if rerr := os.WriteFile(path, raw, 0o600); rerr != nil {
			return "", fmt.Errorf("the new config does not load (%v), and putting the previous one back failed (%v); it is at %s", err, rerr, backup)
		}
		return "", fmt.Errorf("the new config does not load, so the previous one was put back: %w", err)
	}
	return backup, nil
}
