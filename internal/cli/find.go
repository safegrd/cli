package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/repo/catalog"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/spf13/cobra"
)

// findResult is one path's history in `find --json`. Add fields, never rename
// them.
type findResult struct {
	Surface string `json:"surface"`
	catalog.History
}

// searchRepos runs a catalog search over every repository surface in this
// storage, or the one named.
func searchRepos(ctx context.Context, storageCfg config.StorageConfig, key, surface string, patterns []string, deleted bool) ([]findResult, error) {
	ids, err := unseal.Identities(key)
	if err != nil {
		return nil, err
	}
	bs, err := repoBackendsAll(ctx, storageCfg)
	if err != nil {
		return nil, err
	}
	var out []findResult
	found := false
	for _, b := range bs {
		l, ok := b.(lister)
		if !ok {
			continue
		}
		surfaces, err := l.Surfaces(ctx)
		if err != nil {
			return nil, err
		}
		for _, s := range surfaces {
			if surface != "" && s != surface {
				continue
			}
			found = true
			es, err := b.Epochs(ctx, s)
			if err != nil {
				return nil, err
			}
			src := catalog.Source{Backend: b, Epochs: es, IDs: ids,
				CacheDir: filepath.Join(resolveStateDir("", cfg), "cache", "catalog", s)}
			hs, _, err := src.Find(ctx, patterns, deleted)
			if err != nil {
				return nil, fmt.Errorf("surface %s: %w", s, err)
			}
			for _, h := range hs {
				out = append(out, findResult{Surface: s, History: h})
			}
		}
	}
	if surface != "" && !found {
		return nil, fmt.Errorf("no incremental repository for surface %s in this storage", surface)
	}
	return out, nil
}

func cleanPatterns(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, strings.TrimPrefix(strings.TrimSpace(p), "/"))
	}
	return out
}

// repoStorage resolves the storage a repository command reads, as list does.
func repoStorage(ctx context.Context) (config.StorageConfig, error) {
	storageCfg, err := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
	if err != nil {
		return storageCfg, err
	}
	if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, false); err != nil {
		return storageCfg, err
	}
	resolveRuntimeCredentials(ctx, cfg, &storageCfg, false)
	if cfg.NodeID != "" && storageCfg.NodeID == "" {
		storageCfg.NodeID = cfg.NodeID
	}
	return storageCfg, nil
}

func newFindCmd() *cobra.Command {
	var (
		surface          string
		deleted, jsonOut bool
		keyPath, privKey string
	)
	cmd := &cobra.Command{
		Use:   "find <pattern>...",
		Short: "Find every kept version of a file in incremental backups",
		Long: `Lists every version of the matching files that a retained snapshot of an
incremental (--format repo) backup holds: when each was first and last seen, its size
and SHA-256, and how many snapshots hold it.

Patterns are paths relative to /, matched segment by segment: '*' and '?' within a
segment, '**' across any number of them. A directory selects everything below it.
--deleted lists only files the newest snapshot no longer holds.

Restore a version with: safegrd restore --path <path> --version <n> --target-dir <dir>`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			key, err := resolveIdentity(ctx, keyPath, privKey)
			if err != nil {
				return err
			}
			storageCfg, err := repoStorage(ctx)
			if err != nil {
				return err
			}
			res, err := searchRepos(ctx, storageCfg, key, surface, cleanPatterns(args), deleted)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if res == nil {
					res = []findResult{}
				}
				return enc.Encode(res)
			}
			if len(res) == 0 {
				fmt.Println("No kept version of a file matches.")
				return nil
			}
			for i, r := range res {
				if i > 0 {
					fmt.Println()
				}
				fmt.Printf("%s (%s)\n", r.Path, r.Surface)
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "  #\tFIRST SEEN\tLAST SEEN\tSIZE\tSHA-256\tSNAPSHOTS")
				for j := len(r.Versions) - 1; j >= 0; j-- {
					v := r.Versions[j]
					last := v.Last.CreatedAt.UTC().Format("2006-01-02 15:04")
					if v.Current {
						last = "(current)"
					}
					sha, size := "-", "-"
					if v.Type == "f" {
						sha, size = v.SHA256[:12], formatBytes(v.Size)
					} else if v.Type == "d" {
						size = "dir"
					} else {
						size = "link"
					}
					count := fmt.Sprint(v.Snapshots)
					if v.Epochs > 1 {
						count += fmt.Sprintf(" (%d epochs)", v.Epochs)
					}
					fmt.Fprintf(w, "  %d\t%s\t%s\t%s\t%s\t%s\n", v.N, v.First.CreatedAt.UTC().Format("2006-01-02 15:04"), last, size, sha, count)
				}
				w.Flush()
				if r.Deleted {
					lv := r.Versions[len(r.Versions)-1]
					fmt.Printf("  Deleted after %s (last in %s).\n", lv.Last.CreatedAt.UTC().Format("2006-01-02 15:04"), lv.Last.SnapshotID)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&surface, "surface", "", "Search this surface only")
	cmd.Flags().BoolVar(&deleted, "deleted", false, "List only files the newest snapshot no longer holds")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the histories as JSON")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to Age private identity file")
	cmd.Flags().StringVar(&privKey, "private-key", "", "Age private identity key string")
	return cmd
}

// resolveVersion turns --path and --version into the newest snapshot that
// holds that version of that path.
func resolveVersion(ctx context.Context, storageCfg config.StorageConfig, key, surface, p string, n int) (snapshotID string, err error) {
	res, err := searchRepos(ctx, storageCfg, key, surface, cleanPatterns([]string{p}), false)
	if err != nil {
		return "", err
	}
	want := strings.Trim(strings.TrimPrefix(p, "/"), "/")
	var hits []findResult
	for _, r := range res {
		if r.Path == want {
			hits = append(hits, r)
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("no kept snapshot holds %s; run 'safegrd find %s'", want, want)
	case 1:
	default:
		return "", fmt.Errorf("%s is in %d surfaces; name one with --surface", want, len(hits))
	}
	for _, v := range hits[0].Versions {
		if v.N == n {
			return v.Last.SnapshotID, nil
		}
	}
	return "", fmt.Errorf("%s has %d kept versions, not %d; run 'safegrd find %s'", want, len(hits[0].Versions), n, want)
}
