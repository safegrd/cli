package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

// pendingNotes are the notes backup --note gives the snapshot this run
// reports.
var pendingNotes map[string]string

// parseNotes reads key=value arguments. A key with an empty value removes
// that note, for safegrd note.
func parseNotes(args []string) (map[string]string, error) {
	if len(args) == 0 {
		return nil, nil
	}
	if len(args) > model.MaxNotes {
		return nil, fmt.Errorf("%d notes; a snapshot holds %d at most", len(args), model.MaxNotes)
	}
	out := map[string]string{}
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not key=value", a)
		}
		k = strings.TrimSpace(k)
		if v != "" {
			if err := model.ValidNote(k, v); err != nil {
				return nil, err
			}
		} else if err := model.ValidNote(k, "x"); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}

func newNoteCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "note <snapshot> key=value...",
		Short: "Add, change or remove notes on a snapshot",
		Long: `Sets notes on a snapshot, such as release=v2.3 or ticket=OPS-12. key= with no
value removes that note. Notes are kept on the remote server, not in the locked
backup, so they can change; 'safegrd list' and the console show them. A host
enrolled with the remote server can note any snapshot of its organization.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !hostIsEnrolled(cfg) {
				return errors.New("notes are kept on the remote server, and this host is not enrolled. Run 'safegrd enroll' first")
			}
			notes, err := parseNotes(args[1:])
			if err != nil {
				return err
			}
			var resp struct {
				SnapshotID string            `json:"snapshot_id"`
				Notes      map[string]string `json:"notes"`
			}
			status, err := postJSON(cmd.Context(), cfg, "/api/v1/snapshots/"+url.PathEscape(args[0])+"/notes", map[string]any{"notes": notes}, &resp)
			if err != nil {
				noteServerStatus(status)
				return fmt.Errorf("the remote server did not take the notes on %s: %w", args[0], err)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(resp)
			}
			if len(resp.Notes) == 0 {
				fmt.Printf("%s has no notes.\n", resp.SnapshotID)
				return nil
			}
			fmt.Printf("%s  %s\n", resp.SnapshotID, noteWords(resp.Notes))
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the snapshot's notes as JSON")
	return cmd
}
