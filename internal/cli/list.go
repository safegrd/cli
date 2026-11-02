package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List snapshots in storage and when each lock ends",
		Long: `Lists the snapshots in this host's storage, with what each holds and when its lock ends.

Shows the newest 100 and says how many older ones it left out. --limit N shows
the newest N, --all every one. Hosted storage holds the whole organization's
snapshots, so a host lists other hosts' backups too, and can restore them.

--json prints a JSON array on stdout, one object per snapshot, and sends every
other line to stderr, so the output can be piped to jq.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if listLimit < 1 {
				return fmt.Errorf("--limit is how many of the newest snapshots to show: 1 or more, or --all for every one")
			}
			listLimitSet = cmd.Flags().Changed("limit")
			// The bucket is listed once for the snapshots, the ones behind
			// a delete marker and the node of each.
			ctx := storage.WithListingMemo(cmd.Context())
			if jsonOut {
				// Routing, credential and deleted-snapshot notices print on
				// stdout. They still matter, so they move to stderr rather
				// than being dropped, and stdout carries the JSON alone.
				stdout := os.Stdout
				os.Stdout = os.Stderr
				defer func() { os.Stdout = stdout }()
				return listJSON(ctx, stdout)
			}
			// Routed and credentialed like backup and restore. A node enrolled
			// with a centrally-managed sink has no bucket or sink secret locally, so reading
			// cfg.Storage directly means this command cannot reach the bucket
			// on hosts configured centrally.
			storageCfg, err := listStorage(ctx)
			if err != nil {
				return err
			}
			storageProvider, err := openStorage(ctx, cfg, storageCfg)
			if err != nil {
				return fmt.Errorf("storage error: %w", err)
			}

			snapshots, err := storageProvider.ListSnapshots(ctx)
			if err != nil {
				return fmt.Errorf("failed to list snapshots: %w", err)
			}
			recorded, err := recordedSnapshots(ctx, listProject)
			if err != nil {
				return err
			}
			snapshots = recorded.keep(snapshots)

			// Checked before the empty case, because "no snapshots" and "your
			// snapshots were deleted and Object Lock saved them" are very
			// different situations that used to print the same sentence.
			shadowed := warnAboutShadowedSnapshots(ctx, storageProvider)

			repoRows := recorded.keepRepo(listRepoSnapshotsKnown(ctx, storageCfg, recorded.lookup(ctx), recorded.known))
			// Cut before any snapshot is described, so a sidecar is read only
			// for a row that is shown.
			older := 0
			if !listAll {
				snapshots, repoRows, older = newestListed(snapshots, repoRows, recorded, listLimit)
			}
			// Last, after both tables: each snapshot's notes, from the
			// remote server.
			shown := map[string]bool{}
			nodeIDs := map[string]bool{cfg.NodeID: true}
			for _, id := range snapshots {
				shown[id] = true
			}
			for _, r := range repoRows {
				shown[r.Meta.SnapshotID] = true
				nodeIDs[r.Meta.NodeID] = true
			}
			defer func() { printNotes(ctx, recorded, shown, nodeIDs) }()
			if older > 0 {
				defer fmt.Printf("\n%d older snapshot%s not shown. Run 'safegrd list --all' for every one, or --limit N for the newest N.\n", older, plural(older))
			}
			if len(repoRows) > 0 {
				defer printRepoTable(repoRows, storageCfg)
			}
			if len(snapshots) == 0 {
				if listProject != "" && len(repoRows) == 0 {
					fmt.Printf("No snapshots of project %s in this storage.\n", listProject)
				} else if shadowed == 0 && len(repoRows) == 0 {
					fmt.Println(noSnapshotsLine(storageCfg))
				}
				return nil
			}

			// The node each snapshot was filed under: restore needs it, and on
			// a machine rebuilding a lost host nothing else says what it is.
			var nodes map[string]string
			if loc, ok := storageProvider.(storage.NodeLocator); ok {
				nodes, _ = loc.SnapshotNodes(ctx)
			}
			setNode, canSetNode := storageProvider.(interface{ SetNodeID(string) })

			recorded.sayUnrecorded(snapshots)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "SNAPSHOT\tNODE\tSURFACE\tCONTENTS\tENC SIZE\tRETENTION\tSTATUS")

			var undescribed int
			for _, snapID := range snapshots {
				node, known := nodes[snapID]
				nodeIDs[node] = true
				if known && canSetNode {
					setNode.SetNodeID(node)
				}
				if node == "" {
					node = "-"
				}
				meta, err := recorded.metadata(ctx, storageProvider, snapID)
				if err != nil {
					// A row of dashes and "[metadata unavailable]" said neither
					// what was missing nor whether the snapshot was still any
					// good, and listing is the one thing a person runs this
					// command for.
					undescribed++
					fmt.Fprintf(w, "%s\t%s\t?\t?\t?\t?\t%s\n", snapID, node, describeMissingMetadata(err))
					continue
				}

				status := string(meta.Status)
				if meta.IsPoisonPillFrozen {
					status = "ANOMALOUS"
				}

				surface := string(meta.SurfaceType)
				if surface == "" {
					surface = "unknown"
				}
				// Two MySQL surfaces read "mysql" and "mysql" and differed
				// only by node id: the database names which is which.
				if meta.DatabaseName != "" {
					surface += " " + meta.DatabaseName
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%.2f MB\t%s\t%s\n",
					meta.SnapshotID,
					node,
					surface,
					describeContents(meta),
					float64(meta.EncryptedSizeBytes)/(1024*1024),
					describeRetention(meta, storageCfg),
					status,
				)
			}

			w.Flush()

			if undescribed > 0 {
				// Said after the table rather than in it, because it is about
				// the sidecar and not about the backup: the manifest itself is
				// sealed inside the encrypted archive, so a snapshot
				// nothing here can describe still restores and still verifies.
				fmt.Fprintf(os.Stderr,
					"\nWarning: %d snapshot(s) above could not be described. The sidecar beside the object is\n"+
						"   what this table reads; it is routing data, not the backup. The manifest is sealed\n"+
						"   inside the encrypted archive, so those snapshots still restore: run\n"+
						"   'safegrd verify --snapshot <id>' with the identity to read what is in them.\n",
					undescribed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&listFromBucket, "from-bucket", "", "List a copy (copies: name, or the name of a bucket the project writes to beside its own) instead of this host's storage")
	cmd.Flags().StringVar(&listFromDir, "from", "", "List an export: the directory 'safegrd export --to-dir' wrote, read without the remote server or this host's storage")
	cmd.Flags().StringVar(&listProject, "project", "", "Only the snapshots of this project (its id, as 'safegrd projects' lists it), as the remote server recorded them")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the snapshots as a JSON array on stdout")
	cmd.Flags().IntVar(&listLimit, "limit", 100, "Show the newest N snapshots. With --json only when given: a script reads every one")
	cmd.Flags().BoolVar(&listAll, "all", false, "Show every snapshot")
	return cmd
}

// listProject is list --project: one project's snapshots.
var listProject string

// listLimit and listAll are list --limit and --all. listLimitSet says
// --limit was given, which --json honors; without it --json prints every
// snapshot, as scripts read it.
var (
	listLimit    = 100
	listAll      bool
	listLimitSet bool
)

// newestListed keeps the newest n of both tables, each in its own order,
// and says how many it left out. Hosted storage holds the whole
// organization's snapshots, and a list of 4,000 rows, oldest first, put the
// ones a person looks for at the bottom of a long scroll. A snapshot's time
// is read from its id, so nothing is downloaded to decide; an id that names
// no time takes the remote server's record of it.
func newestListed(ids []string, rows []repoSnapshot, recorded *recordedList, n int) ([]string, []repoSnapshot, int) {
	if len(ids)+len(rows) <= n {
		return ids, rows, 0
	}
	when := func(id string) time.Time {
		if t, ok := snapshotIDTime(id); ok {
			return t
		}
		if m := recorded.known(id); m != nil {
			return m.CreatedAt
		}
		return time.Time{}
	}
	type entry struct {
		at   time.Time
		repo bool
		i    int
	}
	all := make([]entry, 0, len(ids)+len(rows))
	for i, id := range ids {
		all = append(all, entry{when(id), false, i})
	}
	for i, r := range rows {
		at := time.Time{}
		if r.Meta != nil {
			at = r.Meta.CreatedAt
			if at.IsZero() {
				at = when(r.Meta.SnapshotID)
			}
		}
		all = append(all, entry{at, true, i})
	}
	// Two runs a second apart can share a time: each table lists oldest
	// first, so the later of the two is the newer.
	sort.SliceStable(all, func(a, b int) bool {
		if !all[a].at.Equal(all[b].at) {
			return all[a].at.After(all[b].at)
		}
		return all[a].repo == all[b].repo && all[a].i > all[b].i
	})
	keepID, keepRow := map[int]bool{}, map[int]bool{}
	for _, e := range all[:n] {
		if e.repo {
			keepRow[e.i] = true
		} else {
			keepID[e.i] = true
		}
	}
	var outIDs []string
	for i, id := range ids {
		if keepID[i] {
			outIDs = append(outIDs, id)
		}
	}
	var outRows []repoSnapshot
	for i, r := range rows {
		if keepRow[i] {
			outRows = append(outRows, r)
		}
	}
	return outIDs, outRows, len(all) - n
}

// recordedList is what the remote server recorded of the organization's
// snapshots, by id, read in pages of 200: one request per page in place of
// one sidecar download per snapshot, which took 40 s for 40 snapshots on
// hosted storage. nil when the host is not enrolled, lists an export, or
// the server did not answer, in which case each sidecar is read as before.
// With a project, only that project's, and every snapshot not in it is
// left out of the listing.
type recordedList struct {
	by      map[string]*model.SnapshotMetadata
	project string
}

func recordedSnapshots(ctx context.Context, project string) (*recordedList, error) {
	r := &recordedList{project: project}
	if !hostIsEnrolled(cfg) || listFromDir != "" {
		if project != "" {
			return nil, fmt.Errorf("--project reads which project each snapshot belongs to from the remote server, which this host is not enrolled with")
		}
		return r, nil
	}
	by := map[string]*model.SnapshotMetadata{}
	cursor := ""
	for {
		q := url.Values{"limit": {"200"}}
		if project != "" {
			q.Set("project_id", project)
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page struct {
			Items      []*listedRecord `json:"items"`
			NextCursor string          `json:"next_cursor"`
		}
		if _, err := getJSON(ctx, cfg, "/api/v1/snapshots?"+q.Encode(), &page); err != nil {
			if project != "" {
				return nil, fmt.Errorf("--project: could not read the remote server's record of the snapshots: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Warning: could not read the remote server's record of the snapshots (%v). Each snapshot's sidecar is read instead, which is slower.\n", err)
			return r, nil
		}
		for _, m := range page.Items {
			if m != nil && m.SnapshotID != "" {
				by[m.SnapshotID] = m.metadata()
			}
		}
		if page.NextCursor == "" || len(page.Items) == 0 {
			break
		}
		cursor = page.NextCursor
	}
	r.by = by
	return r, nil
}

// listedRecord is one snapshot as the remote server lists it: the
// record, and when hosted storage deletes it if that is after its lock ends.
// A backup on a plan that locks it a day and keeps it a week carries that
// week here, and nowhere else in the record: the sidecar list read before
// had it.
type listedRecord struct {
	model.SnapshotMetadata
	StorageKeptUntil *time.Time `json:"storage_kept_until,omitempty"`
}

func (r *listedRecord) metadata() *model.SnapshotMetadata {
	m := r.SnapshotMetadata
	if k := r.StorageKeptUntil; k != nil && m.KeptUntil == nil && !m.Unlocked && k.After(m.WORMRetentionUntil) {
		kept := *k
		m.KeptUntil = &kept
	}
	return &m
}

// keep is the snapshot ids to list: all of them, or the project's.
func (r *recordedList) keep(ids []string) []string {
	if r == nil || r.project == "" {
		return ids
	}
	var out []string
	for _, id := range ids {
		if r.by[id] != nil {
			out = append(out, id)
		}
	}
	return out
}

func (r *recordedList) keepRepo(rows []repoSnapshot) []repoSnapshot {
	if r == nil || r.project == "" {
		return rows
	}
	var out []repoSnapshot
	for _, row := range rows {
		if r.by[row.Meta.SnapshotID] != nil {
			out = append(out, row)
		}
	}
	return out
}

// lookup is the remote server's record of one snapshot: from the pages
// read, or asked for when they were not.
func (r *recordedList) lookup(ctx context.Context) func(id string) (*model.SnapshotMetadata, error) {
	return func(id string) (*model.SnapshotMetadata, error) {
		if r != nil && r.by != nil {
			return r.by[id], nil
		}
		return fetchRecordedSnapshot(ctx, cfg, id)
	}
}

// known is the remote server's record of one snapshot, nil when it has none
// or was not read.
func (r *recordedList) known(id string) *model.SnapshotMetadata {
	if r == nil {
		return nil
	}
	return r.by[id]
}

// sayUnrecorded says, before the table, how many snapshots are described
// from their sidecars, one request each. With the remote server unreachable
// that was every snapshot in storage, and list printed nothing until it had
// read them all.
func (r *recordedList) sayUnrecorded(ids []string) {
	n := 0
	for _, id := range ids {
		if r.known(id) == nil {
			n++
		}
	}
	if n >= 20 {
		fmt.Fprintf(os.Stderr, "Reading %d snapshot descriptions from storage, one at a time.\n", n)
	}
}

// metadata describes one snapshot: as the remote server recorded it when
// it did, from its sidecar in storage otherwise.
func (r *recordedList) metadata(ctx context.Context, p storage.StorageProvider, id string) (*model.SnapshotMetadata, error) {
	if r != nil && r.by[id] != nil {
		return r.by[id], nil
	}
	return p.DownloadMetadata(ctx, id)
}

// listedSnapshot is one entry of `list --json`. The field names are the
// output's contract with scripts and hooks; add fields, never rename them.
type listedSnapshot struct {
	SnapshotID string `json:"snapshot_id"`
	// Notes are the snapshot's notes on the remote server.
	Notes     map[string]string `json:"notes,omitempty"`
	NodeID    string            `json:"node_id,omitempty"`
	Surface   string            `json:"surface,omitempty"`
	Database  string            `json:"database,omitempty"`
	Status    string            `json:"status,omitempty"`
	CreatedAt string            `json:"created_at,omitempty"`
	// CompletedAt is when the upload finished.
	CompletedAt        string `json:"completed_at,omitempty"`
	EncryptedSizeBytes int64  `json:"encrypted_size_bytes"`
	TotalItems         int64  `json:"total_items"`
	TotalContainers    int    `json:"total_containers"`
	// WORMMode is COMPLIANCE, GOVERNANCE or NONE; empty when the snapshot
	// predates the field.
	WORMMode    string `json:"worm_mode,omitempty"`
	LockedUntil string `json:"locked_until,omitempty"`
	// Locked is true while Object Lock still holds the snapshot.
	Locked bool `json:"locked"`
	// Unlocked marks a recent run of a project that locks only its kept
	// copies: it carries no lock. KeptUntil is when a snapshot is deleted,
	// for an unlocked run and for a locked one kept past its lock.
	Unlocked  bool   `json:"unlocked,omitempty"`
	KeptUntil string `json:"kept_until,omitempty"`
	Anomalous bool   `json:"anomalous"`
	// MetadataError says why the snapshot could not be described. The
	// snapshot itself may still restore.
	MetadataError string `json:"metadata_error,omitempty"`
	// Format is "repo-v1" for a snapshot in an incremental repository, which
	// is filed under RepoSurface and EpochID. For it EncryptedSizeBytes is
	// what that run uploaded, and LogicalSizeBytes the whole tree's size.
	Format           string `json:"format,omitempty"`
	RepoSurface      string `json:"repo_surface,omitempty"`
	EpochID          string `json:"epoch_id,omitempty"`
	ObjectClass      string `json:"object_class,omitempty"`
	LogicalSizeBytes int64  `json:"logical_size_bytes,omitempty"`
}

// listRepoSnapshots reads every repository snapshot under this storage. A
// failure is said and leaves the rest of the listing in place.
func listRepoSnapshots(ctx context.Context, storageCfg config.StorageConfig) []repoSnapshot {
	return listRepoSnapshotsWith(ctx, storageCfg, func(id string) (*model.SnapshotMetadata, error) {
		return fetchRecordedSnapshot(ctx, cfg, id)
	})
}

// listRepoSnapshotsWith is listRepoSnapshots with the remote server's record
// of a snapshot read through recorded: what list read in one request, in
// place of one request per unlocked run.
func listRepoSnapshotsWith(ctx context.Context, storageCfg config.StorageConfig, recorded func(id string) (*model.SnapshotMetadata, error)) []repoSnapshot {
	return listRepoSnapshotsKnown(ctx, storageCfg, recorded, nil)
}

// listRepoSnapshotsKnown is listRepoSnapshotsWith that takes a row from
// known in place of its sidecar.
func listRepoSnapshotsKnown(ctx context.Context, storageCfg config.StorageConfig, recorded func(id string) (*model.SnapshotMetadata, error), known func(id string) *model.SnapshotMetadata) []repoSnapshot {
	bs, err := repoBackendsAll(ctx, storageCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not list the incremental repositories: %v\n", err)
		return nil
	}
	var out []repoSnapshot
	for _, b := range bs {
		rows, err := repoSnapshotsKnown(ctx, b, known)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not list the repository in %s: %v\n", b.Describe(), err)
			continue
		}
		out = append(out, rows...)
	}
	// This host's own surfaces first, then the rest of the organization's,
	// each oldest first: on a host in a shared organization its own rows
	// were the last of many.
	own := func(r repoSnapshot) bool {
		n := r.Meta.NodeID
		return cfg != nil && cfg.NodeID != "" && (n == cfg.NodeID || strings.HasPrefix(n, cfg.NodeID+"--"))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if oi, oj := own(out[i]), own(out[j]); oi != oj {
			return oi
		}
		return out[i].Meta.CreatedAt.Before(out[j].Meta.CreatedAt)
	})
	// A run written unlocked may since have been kept as the weekly or
	// monthly copy and locked for weeks, which its sidecar, written at
	// backup time, cannot say. The remote server's record can.
	for i := range out {
		if !out[i].Meta.Unlocked {
			continue
		}
		rec, err := recorded(out[i].Meta.SnapshotID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not reach the remote server (%v). Each recent run's lock is shown as it was written; one kept as a weekly or monthly copy since is locked longer.\n", err)
			break
		}
		out[i].Meta = withRecordedLock(out[i].Meta, rec)
	}
	return out
}

// withRecordedLock is meta with the lock the remote server recorded for it,
// when the server says it is locked. The date the run was kept to stays as
// KeptUntil when it is later than the lock.
func withRecordedLock(meta, rec *model.SnapshotMetadata) *model.SnapshotMetadata {
	if rec == nil || rec.Unlocked || rec.WORMRetentionUntil.IsZero() {
		return meta
	}
	m := *meta
	m.Unlocked = false
	m.WORMRetentionUntil = rec.WORMRetentionUntil
	if rec.WORMMode != "" {
		m.WORMMode = rec.WORMMode
	}
	if kept := meta.WORMRetentionUntil; kept.After(rec.WORMRetentionUntil) {
		m.KeptUntil = &kept
	}
	return &m
}

// printRepoTable lists repository snapshots: new is what each run uploaded,
// logical the whole tree it holds.
func printRepoTable(rows []repoSnapshot, storageCfg config.StorageConfig) {
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SNAPSHOT\tNODE\tSURFACE\tEPOCH\tCLASS\tCONTENTS\tLOGICAL\tNEW\tRETENTION\tSTATUS")
	for _, r := range rows {
		m := r.Meta
		status := string(m.Status)
		if m.IsPoisonPillFrozen {
			status = "ANOMALOUS"
		}
		node := m.NodeID
		if node == "" {
			node = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", m.SnapshotID, node, r.SurfaceID, m.EpochID, m.ObjectClass,
			describeContents(m), formatBytes(m.RawSizeBytes), formatBytes(m.EncryptedSizeBytes), describeRetention(m, storageCfg), status)
	}
	w.Flush()
}

// listJSON writes every snapshot as one JSON array to out.
// listFromDir is list --from: an export directory read in place of this
// host's storage. Restore took --from and list did not, so with the remote
// server down nothing said which snapshot IDs an export holds.
var listFromDir string

// listFromBucket is list --from-bucket: one of the surface's copies, listed
// in place of its own storage.
var listFromBucket string

// listStorage is the storage list reads: an export directory with --from,
// otherwise this host's, routed and credentialed like backup and restore.
func listStorage(ctx context.Context) (config.StorageConfig, error) {
	if listFromDir != "" {
		if fi, err := os.Stat(listFromDir); err != nil || !fi.IsDir() {
			return config.StorageConfig{}, fmt.Errorf("--from %s is not a directory 'safegrd export --to-dir' wrote", listFromDir)
		}
		return config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: listFromDir}, nil
	}
	storageCfg, routeErr := storageOrCopy(ctx, listFromBucket)
	if routeErr != nil {
		return storageCfg, routeErr
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

func listJSON(ctx context.Context, out io.Writer) error {
	limit := 0
	if listLimitSet && !listAll {
		limit = listLimit
	}
	entries, err := listedSnapshots(ctx, limit)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

// listedSnapshots reads every snapshot this host's storage holds, or the
// newest limit of them when limit is more than 0, as `list --json`
// describes them. guard reads it too, to find a recent locked snapshot
// instead of taking another.
func listedSnapshots(ctx context.Context, limit int) ([]listedSnapshot, error) {
	storageCfg, err := listStorage(ctx)
	if err != nil {
		return nil, err
	}
	storageProvider, err := openStorage(ctx, cfg, storageCfg)
	if err != nil {
		return nil, fmt.Errorf("storage error: %w", err)
	}
	snapshots, err := storageProvider.ListSnapshots(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list snapshots: %w", err)
	}
	recorded, err := recordedSnapshots(ctx, listProject)
	if err != nil {
		return nil, err
	}
	snapshots = recorded.keep(snapshots)
	warnAboutShadowedSnapshots(ctx, storageProvider)
	repoRows := recorded.keepRepo(listRepoSnapshotsKnown(ctx, storageCfg, recorded.lookup(ctx), recorded.known))
	if limit > 0 {
		snapshots, repoRows, _ = newestListed(snapshots, repoRows, recorded, limit)
	}

	var nodes map[string]string
	if loc, ok := storageProvider.(storage.NodeLocator); ok {
		var locErr error
		if nodes, locErr = loc.SnapshotNodes(ctx); locErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not read which node each snapshot belongs to: %v\n", locErr)
		}
	}
	setNode, canSetNode := storageProvider.(interface{ SetNodeID(string) })

	recorded.sayUnrecorded(snapshots)
	now := time.Now()
	entries := make([]listedSnapshot, 0, len(snapshots))
	for _, snapID := range snapshots {
		e := listedSnapshot{SnapshotID: snapID, NodeID: nodes[snapID]}
		if e.NodeID != "" && canSetNode {
			setNode.SetNodeID(e.NodeID)
		}
		meta, err := recorded.metadata(ctx, storageProvider, snapID)
		if err != nil {
			e.MetadataError = describeMissingMetadata(err)
			entries = append(entries, e)
			continue
		}
		e.Surface = string(meta.SurfaceType)
		e.Database = meta.DatabaseName
		e.Status = string(meta.Status)
		if !meta.CreatedAt.IsZero() {
			e.CreatedAt = meta.CreatedAt.UTC().Format(time.RFC3339)
		}
		if meta.CompletedAt != nil {
			e.CompletedAt = meta.CompletedAt.UTC().Format(time.RFC3339)
		}
		e.EncryptedSizeBytes = meta.EncryptedSizeBytes
		e.TotalItems = meta.TotalItems
		e.TotalContainers = meta.TotalContainers
		e.WORMMode = meta.WORMMode
		e.Anomalous = meta.IsPoisonPillFrozen
		if e.WORMMode != string(config.WORMModeNone) && !meta.WORMRetentionUntil.IsZero() {
			e.LockedUntil = meta.WORMRetentionUntil.UTC().Format(time.RFC3339)
			e.Locked = meta.WORMRetentionUntil.After(now) && storageCfg.Type != config.StorageTypeLocal
			if k := meta.KeptUntil; k != nil && k.After(meta.WORMRetentionUntil) {
				e.KeptUntil = k.UTC().Format(time.RFC3339)
			}
		}
		entries = append(entries, e)
	}

	for _, rs := range repoRows {
		meta := rs.Meta
		e := listedSnapshot{SnapshotID: meta.SnapshotID, NodeID: meta.NodeID, Surface: string(meta.SurfaceType),
			Status: string(meta.Status), EncryptedSizeBytes: meta.EncryptedSizeBytes, TotalItems: meta.TotalItems,
			TotalContainers: meta.TotalContainers, WORMMode: meta.WORMMode, Anomalous: meta.IsPoisonPillFrozen,
			Format: meta.Format, EpochID: meta.EpochID, ObjectClass: meta.ObjectClass, RepoSurface: rs.SurfaceID,
			LogicalSizeBytes: meta.RawSizeBytes}
		if !meta.CreatedAt.IsZero() {
			e.CreatedAt = meta.CreatedAt.UTC().Format(time.RFC3339)
		}
		if meta.CompletedAt != nil {
			e.CompletedAt = meta.CompletedAt.UTC().Format(time.RFC3339)
		}
		if meta.Unlocked {
			e.Unlocked = true
			e.KeptUntil = meta.WORMRetentionUntil.UTC().Format(time.RFC3339)
		} else if e.WORMMode != string(config.WORMModeNone) && !meta.WORMRetentionUntil.IsZero() {
			e.LockedUntil = meta.WORMRetentionUntil.UTC().Format(time.RFC3339)
			e.Locked = meta.WORMRetentionUntil.After(now) && storageCfg.Type != config.StorageTypeLocal
			if k := meta.KeptUntil; k != nil && k.After(meta.WORMRetentionUntil) {
				e.KeptUntil = k.UTC().Format(time.RFC3339)
			}
		}
		entries = append(entries, e)
	}
	nodeIDs := map[string]bool{cfg.NodeID: true}
	for _, e := range entries {
		nodeIDs[e.NodeID] = true
	}
	notes := recorded.notes(ctx, nodeIDs)
	for i := range entries {
		entries[i].Notes = notes[entries[i].SnapshotID]
	}
	return entries, nil
}

// describeContents says what is in a snapshot in the vocabulary of its own
// surface.
//
// It reads TotalItems and TotalContainers (the surface-neutral pair that
// CalculateTotals populates for every surface) rather than TotalTables and TotalRows.
func describeContents(meta *model.SnapshotMetadata) string {
	switch meta.SurfaceType {
	case model.SurfaceTypeFiles:
		return fmt.Sprintf("%d files, %d dirs", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypeEmail:
		return fmt.Sprintf("%d emails, %d folders", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypeMongoDB:
		return fmt.Sprintf("%d documents, %d collections", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypePostgres, model.SurfaceTypeMySQL, model.SurfaceTypeSQLite:
		return fmt.Sprintf("%d rows, %d tables", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypeLaravel:
		if meta.Laravel != nil {
			return fmt.Sprintf("%d rows, %d tables, %d files", meta.TotalItems, meta.TotalContainers, meta.Laravel.TotalFiles)
		}
		return fmt.Sprintf("%d rows, %d tables", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypeWordPress:
		if meta.WordPress != nil {
			return fmt.Sprintf("%d rows, %d tables, %d files", meta.TotalItems, meta.TotalContainers, meta.WordPress.TotalFiles)
		}
		return fmt.Sprintf("%d rows, %d tables", meta.TotalItems, meta.TotalContainers)
	default:
		return fmt.Sprintf("%d items, %d containers", meta.TotalItems, meta.TotalContainers)
	}
}

// describeRetention says what, if anything, retains a snapshot.
//
// The column was previously printed unconditionally. A snapshot written
// at worm_mode NONE has no WORM lock applied.
func describeRetention(meta *model.SnapshotMetadata, storageCfg config.StorageConfig) string {
	if (storageCfg.Type == config.StorageTypeLocal || storageCfg.Type == config.StorageTypeSFTP) && !meta.WORMRetentionUntil.IsZero() {
		// A directory enforces nothing, whatever the sidecar says (older
		// ones say COMPLIANCE, the config's default; newer ones NONE): the
		// date is only safegrd's own refusal to delete before it.
		return "kept until " + meta.WORMRetentionUntil.UTC().Format("2006-01-02 15:04") + " UTC (no Object Lock)"
	}
	mode := meta.WORMMode
	recorded := mode != ""
	if !recorded {
		if resolved, err := storageCfg.ResolveWORMMode(); err == nil {
			mode = string(resolved)
		}
	}
	if mode == string(config.WORMModeNone) {
		if recorded {
			return "none (deletable)"
		}
		return "none (deletable; mode not recorded)"
	}
	if meta.WORMRetentionUntil.IsZero() {
		return "unknown"
	}
	// One clock for every row: archive sidecars carried the host's local
	// time and repository ones UTC, so one table mixed the two unlabelled.
	until := meta.WORMRetentionUntil.UTC().Format("2006-01-02 15:04") + " UTC"
	if meta.Unlocked {
		// A recent run of a project that locks only its kept copies: the
		// date is when it is deleted, and nothing holds it before then.
		return "kept until " + until + ", not locked"
	}
	if !recorded {
		return until + " (mode not recorded)"
	}
	if k := meta.KeptUntil; k != nil && k.After(meta.WORMRetentionUntil) {
		return mode + " until " + until + ", kept until " + k.UTC().Format("2006-01-02 15:04") + " UTC"
	}
	return mode + " until " + until
}

// describeMissingMetadata names why a snapshot could not be described.
//
// "[metadata unavailable]" covered an absent sidecar and an unreadable one
// alike, and the two are different problems: the first is a snapshot written
// before the sidecar existed, or one whose UploadMetadata failed silently; the
// second is a sink that will not answer.
func describeMissingMetadata(err error) string {
	if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "not found") {
		return "no metadata sidecar"
	}
	return "sidecar unreadable: " + err.Error()
}

// noSnapshotsLine says where list looked when it found nothing. A recovery
// config with the wrong prefix printed "No snapshots found in storage" over a
// bucket full of them, and nothing said the prefix was the thing to check.
func noSnapshotsLine(c config.StorageConfig) string {
	switch c.Type {
	case config.StorageTypeS3:
		return fmt.Sprintf("No snapshots under s3://%s/%s. If the bucket holds backups under another prefix, set storage.prefix to it.",
			c.Bucket, strings.Trim(c.Prefix, "/"))
	case config.StorageTypeLocal:
		return fmt.Sprintf("No snapshots in %s.", c.LocalPath)
	case config.StorageTypeSFTP:
		return fmt.Sprintf("No snapshots in %s. If the server holds backups in another directory, set storage.sftp.path to it.", sftpWhere(c))
	}
	return "No snapshots found in storage."
}

// notes is the notes on the snapshots of nodes. The pages of the remote
// server's record carry them, so a list that read those asks nothing more;
// it asked once per node, and the daemon files each surface under a node of
// its own.
func (r *recordedList) notes(ctx context.Context, nodeIDs map[string]bool) map[string]map[string]string {
	if r == nil || r.by == nil {
		return serverNotes(ctx, nodeIDs)
	}
	out := map[string]map[string]string{}
	for id, m := range r.by {
		if len(m.Notes) > 0 && nodeIDs[m.NodeID] {
			out[id] = m.Notes
		}
	}
	return out
}

// serverNotes is the notes on the snapshots of nodes, from the remote server,
// by snapshot id. A host that cannot ask lists without them.
func serverNotes(ctx context.Context, nodeIDs map[string]bool) map[string]map[string]string {
	out := map[string]map[string]string{}
	if !hostIsEnrolled(cfg) {
		return out
	}
	for node := range nodeIDs {
		if node == "" {
			continue
		}
		var resp struct {
			Snapshots map[string]map[string]string `json:"snapshots"`
		}
		if _, err := getJSON(ctx, cfg, "/api/v1/nodes/"+url.PathEscape(node)+"/notes", &resp); err != nil {
			continue
		}
		for id, n := range resp.Snapshots {
			out[id] = n
		}
	}
	return out
}

// printNotes lists the notes on the snapshots shown, one line each.
func printNotes(ctx context.Context, recorded *recordedList, shown, nodeIDs map[string]bool) {
	notes := recorded.notes(ctx, nodeIDs)
	var ids []string
	for id := range notes {
		if shown[id] {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	sort.Strings(ids)
	fmt.Println("\nNotes:")
	for _, id := range ids {
		fmt.Printf("   %s  %s\n", id, noteWords(notes[id]))
	}
}

// noteWords is notes as key=value, by key.
func noteWords(n map[string]string) string {
	keys := make([]string, 0, len(n))
	for k := range n {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+n[k])
	}
	return strings.Join(parts, " ")
}
