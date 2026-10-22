package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

func newCopiesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "copies",
		Short: "Each surface's copies in other buckets: what they lack, and the catch-up",
		Long: `A surface writes every backup to up to two more S3 buckets, each under its own
key, lock and retention: copies: in the config, or the buckets the project
names on the remote server, which replace them.

'copies status' says, for each surface and copy, how many of the snapshots the
surface's own storage holds within the copy's retention the copy lacks.
'copies sync' writes them, from the surface's own storage to the copy, as the
daemon's catch-up does: an archive is checked for first and never written
twice, and a run of an incremental repository is copied object by object.
Each snapshot it writes gets a recovery document naming the copy's bucket.
Reading back out of a bucket costs what its provider charges for egress.`,
	}
	var surfaceID, copyName string
	run := func(dryRun bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			statePath := filepath.Join(resolveStateDir("", cfg), "daemon_state.json")
			state := loadDaemonState(statePath)
			behindAny, ran := false, false
			for _, s := range cfg.Surfaces {
				if surfaceID != "" && s.ID != surfaceID {
					continue
				}
				ran = true
				st := state.Surfaces[s.ID]
				node := s.ID
				if st != nil && st.ServerNodeID != "" {
					node = st.ServerNodeID
				}
				surface := s
				behind, wrote, err := syncCopies(ctx, cfg, &surface, node, copyName, dryRun)
				if err != nil {
					return fmt.Errorf("surface %s: %w", s.ID, err)
				}
				if len(behind) == 0 {
					fmt.Printf("%s: no copies\n", s.ID)
					continue
				}
				if !dryRun {
					reportCopies(ctx, cfg, node, wrote)
					for _, w := range wrote {
						fmt.Printf("%s: copied %s to %s, %s\n", s.ID, w.SnapshotID, w.Bucket, copyLockWords(w))
					}
				}
				for _, b := range behind {
					switch {
					case b.err != nil && b.missing == 0:
						behindAny = true
						fmt.Printf("%s: %s: %v\n", s.ID, b.name, b.err)
					case b.err != nil:
						behindAny = true
						fmt.Printf("%s: %s behind by %d: %v\n", s.ID, b.name, b.missing, b.err)
					case b.missing > 0:
						behindAny = true
						fmt.Printf("%s: %s behind by %d\n", s.ID, b.name, b.missing)
					default:
						fmt.Printf("%s: %s caught up\n", s.ID, b.name)
					}
				}
				if !dryRun && st != nil && copyName == "" {
					st.CopiesBehind = copyBehindOf(st.CopiesBehind, behind, time.Now().UTC())
					st.LastCopySync = time.Now().UTC()
				}
			}
			if !ran {
				if surfaceID != "" {
					return fmt.Errorf("--surface %s: no surface with that id in this config", surfaceID)
				}
				return fmt.Errorf("this config lists no surfaces; copies are written for the surfaces the daemon backs up")
			}
			if !dryRun {
				warnIfStateUnsaved(saveDaemonState(statePath, state), statePath)
			}
			if behindAny {
				if dryRun {
					return fmt.Errorf("a copy is behind; run 'safegrd copies sync' to write what it lacks")
				}
				return fmt.Errorf("a copy is still behind")
			}
			return nil
		}
	}
	status := &cobra.Command{Use: "status", Short: "Say which copies lack snapshots, without writing anything", RunE: run(true)}
	sync := &cobra.Command{Use: "sync", Short: "Write to each copy what it lacks", RunE: run(false)}
	for _, c := range []*cobra.Command{status, sync} {
		c.Flags().StringVar(&surfaceID, "surface", "", "Only this surface")
		c.Flags().StringVar(&copyName, "copy", "", "Only this copy, by its name")
	}
	cmd.AddCommand(status, sync)
	return cmd
}
