package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/runner"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newVerifyCmd() *cobra.Command {
	var fromBucket string
	var (
		snapshotID  string
		sandboxURL  string
		inMemory    bool
		showURL     bool
		keep        bool
		keyPath     string
		privKey     string
		s3Bucket    string
		s3Prefix    string
		s3Region    string
		s3Endpoint  string
		s3AccessKey string
		s3SecretKey string
		checksFile  string
		query       string
		queryOut    string
		queryKeep   bool
		surfaceSel  string
	)

	cmd := &cobra.Command{
		Use: "verify",
		// The attestation check is verify history: "safegrd history" suggests verify.
		SuggestFor: []string{"history"},
		Short:      "Test a backup by restoring it in memory, or into a sandbox database",
		Long: `Reads a snapshot from storage, decrypts it on this host with the private key,
and checks its tables, row counts, columns and extensions.

By default (or with --in-memory) the restore is parsed in memory and needs no
database. With --sandbox-target it is restored into that empty database, which
is the full Fire Drill. Either way the result is reported to the remote server
when this host is enrolled.

--checks names a YAML file of your own checks, the same list a surface's
drill.checks takes, run against the sandbox after the restore:

  - name: orders in the last day
    sql: SELECT count(*) FROM orders WHERE created_at > now() - interval '1 day'
    expect: "> 0"
  - name: app smoke test
    command: ./scripts/smoke.sh   # SAFEGRD_SANDBOX_URL is set; exit 0 passes

A command also gets SAFEGRD_SNAPSHOT_ID, and SAFEGRD_SNAPSHOT_CREATED_AT, when
the backup was taken (RFC 3339, UTC): hold your newest row to it to catch a
backup of data that stopped changing.

--query reads rows out of a database backup without restoring the table they
came from. The snapshot is restored into --sandbox-target, or into a
PostgreSQL cluster started on this host for the run, the query runs in a
read-only transaction, and its rows go to stdout as CSV (or to --out). A
cluster the run started is removed afterwards unless --keep. A query run is
not reported as a drill.

  safegrd verify --snapshot <id> --query "SELECT * FROM orders WHERE id = 4211" --out order.csv`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if surfaceSel != "" {
				if snapshotID != "" {
					return fmt.Errorf("--surface drills a watched surface's newest checked backup; leave out --snapshot")
				}
				if inMemory {
					sandboxURL = ""
				}
				return verifyWatchedSurface(cmd.Context(), surfaceSel, sandboxURL)
			}
			if snapshotID == "" {
				return fmt.Errorf("--snapshot is required")
			}
			checks, err := loadDrillChecks(checksFile)
			if err != nil {
				return err
			}
			if query != "" && (inMemory || len(checks) > 0) {
				return fmt.Errorf("--query restores into a sandbox and reads rows; leave out --in-memory and --checks")
			}
			if query == "" && (queryOut != "" || queryKeep) {
				return fmt.Errorf("--out and --keep go with --query")
			}
			if len(checks) > 0 && (inMemory || sandboxURL == "") {
				return fmt.Errorf("--checks runs against the restored database, so it needs --sandbox-target and no --in-memory")
			}

			// Apply S3 sink overrides if provided
			if s3Bucket != "" {
				cfg.Storage.Type = config.StorageTypeS3
				cfg.Storage.Bucket = s3Bucket
			}
			if s3Prefix != "" {
				cfg.Storage.Prefix = s3Prefix
			}
			if s3Region != "" {
				cfg.Storage.Region = s3Region
			}
			if s3Endpoint != "" {
				cfg.Storage.Endpoint = s3Endpoint
			}
			if s3AccessKey != "" {
				cfg.Storage.AccessKeyID = s3AccessKey
			}
			if s3SecretKey != "" {
				resolved, err := ResolveSecretRef("s3-secret-key", s3SecretKey)
				if err != nil {
					return err
				}
				cfg.Storage.SecretAccessKey = resolved
			}

			// Load private key
			resolvedKey := privKey
			if resolvedKey != "" {
				resolved, err := ResolveSecretRef("private-key", resolvedKey)
				if err != nil {
					return err
				}
				resolvedKey = resolved
			}
			if resolvedKey == "" {
				resolvedKey = cfg.Encryption.PrivateKey
			}
			if resolvedKey == "" {
				path := keyPath
				if path == "" {
					path = cfg.Encryption.KeyPath
				}
				if path != "" {
					loaded, err := crypto.LoadPrivateKey(path)
					if err == nil {
						resolvedKey = loaded
					}
				}
			}

			ctx := cmd.Context()

			// Same key set as restore: the host's own key and a
			// managed-custody organization's keys, fetched for this
			// verification only and never written to disk.
			resolvedKey = withManagedIdentity(ctx, cfg, resolvedKey, heldKeyQuery{snapshotID: snapshotID}, true)

			if resolvedKey == "" {
				return fmt.Errorf("decryption key required for verification: specify --private-key or configure ~/.safegrd/keys/daemon.key")
			}

			storageCfg, routeErr := storageOrCopy(ctx, fromBucket)
			if routeErr != nil {
				return routeErr
			}
			if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, false); err != nil {
				return err
			}
			resolveSinkCredentials(ctx, cfg, &storageCfg)
			if cfg.NodeID != "" && storageCfg.NodeID == "" {
				storageCfg.NodeID = cfg.NodeID
			}
			// A surface the daemon backs up lives under its own node, not the
			// host's, so the bucket is searched under the node the remote
			// server recorded this snapshot for.
			if recorded := recordedNodeID(ctx, cfg, snapshotID); recorded != "" && recorded != storageCfg.NodeID {
				storageCfg.NodeID = recorded
			}
			rs, err := locateRepoSnapshot(ctx, storageCfg, snapshotID)
			if err != nil {
				// Said, and not fatal: the snapshot may be an archive, which
				// does not need the repositories to be readable.
				fmt.Fprintf(os.Stderr, "Warning: could not look among the incremental repositories: %v\n", err)
			}
			if query != "" {
				q := verifyQueryRun{snapshotID: snapshotID, key: resolvedKey, sandboxURL: sandboxURL, query: query, out: queryOut, keep: queryKeep}
				if rs != nil {
					if !runner.IsRepoDatabase(rs.Meta) {
						return fmt.Errorf("snapshot %s is a %s snapshot; --query reads rows from a database backup", snapshotID, rs.Meta.SurfaceType)
					}
					return q.repo(ctx, rs)
				}
				storageProvider, err := openStorage(ctx, cfg, storageCfg)
				if err != nil {
					return storageFailure(fmt.Errorf("storage error: %w", err))
				}
				return q.archive(ctx, storageProvider)
			}
			if rs != nil {
				if runner.IsRepoDatabase(rs.Meta) {
					sandbox := sandboxURL
					if inMemory {
						sandbox = ""
					}
					return verifyRepoDatabase(ctx, rs, resolvedKey, sandbox, checks)
				}
				if sandboxURL != "" && !inMemory {
					return fmt.Errorf("snapshot %s is a %s snapshot; it is proven by restoring it, so leave out --sandbox-target", snapshotID, rs.Meta.SurfaceType)
				}
				return verifyRepoSnapshot(ctx, rs, resolvedKey)
			}
			storageProvider, err := openStorage(ctx, cfg, storageCfg)
			if err != nil {
				return storageFailure(fmt.Errorf("storage error: %w", err))
			}
			// Not where this config looks: a recovery machine rebuilding a lost
			// host does not know the node id its backups were filed under.
			if node := storage.LocateSnapshot(ctx, storageProvider, snapshotID); node != "" {
				fmt.Printf("   Found %s under node %s.\n", snapshotID, node)
			}

			// A snapshot hidden behind a delete marker is a clear signal
			// of attack. Reading past it is not enough; the operator
			// has to be told it happened.
			warnAboutShadowedSnapshots(ctx, storageProvider)

			verifier := runner.NewVerifier(storageProvider, cfg.ServerURL)
			// verify never empties the target it restored into. --keep-sandbox says
			// a person is keeping it to look at, which the report records; a
			// sandbox thrown away after the run is not "kept".
			verifier.KeepFailedSandbox = keep
			verifier.Checks = checks
			if cfg.ServerToken != "" {
				verifier.SetServerToken(cfg.ServerToken)
			}

			// Default to dry restore if --sandbox-target is not explicitly specified or --in-memory is set
			isDryRun := inMemory || sandboxURL == ""

			if isDryRun {
				fmt.Printf("Dry restore of %s: decrypting and reading it in memory\n", snapshotID)
				fmt.Printf("   Snapshot ID:    %s\n", snapshotID)
				// The storage this run reads, after routing: a hosted or
				// console-set bucket is not in cfg.Storage.
				switch storageCfg.Type {
				case config.StorageTypeS3:
					fmt.Printf("   Storage:        s3://%s\n", storageCfg.Bucket)
				case config.StorageTypeHosted:
					fmt.Printf("   Storage:        SafeGrd hosted storage\n")
				default:
					fmt.Printf("   Storage:        %s (a directory on this host)\n", storageCfg.LocalPath)
				}
				fmt.Printf("   Key:            %s\n", identityFingerprint(resolvedKey))
				fmt.Printf("   Method:         schema and COPY data parsed in memory; no database needed\n\n")

				report, dryResult, err := verifier.RunDryRestore(ctx, snapshotID, resolvedKey)
				if err != nil {
					if unknownSnapshot(ctx, err, snapshotID) {
						// A mistyped ID is the caller's, not storage's: it
						// exited 12 with the object path the lookup tried.
						return fmt.Errorf("no snapshot %s in this host's storage or the remote server's records. Run 'safegrd list' for the IDs", snapshotID)
					}
					return fmt.Errorf("dry restore of %s: %w", snapshotID, err)
				}

				if report.Status == model.VerificationStatusPassed {
					fmt.Println("Assertions:")
					for _, a := range report.Assertions {
						fmt.Printf("   [%s] %s (Expected: %s, Actual: %s)%s\n", assertionWord(a), a.Name, a.Expected, a.Actual, notRunWhy(a))
					}

					if report.SurfaceType == model.SurfaceTypeFiles {
						fmt.Println("\nFiles read:")
						fmt.Printf("   Files:       %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Directories: %d\n", report.TablesRestored)
					} else if report.SurfaceType == model.SurfaceTypeEmail {
						fmt.Println("\nMailbox read:")
						fmt.Printf("   Emails:      %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Folders:     %d\n", report.TablesRestored)
					} else if dryResult != nil && len(dryResult.Tables) > 0 {
						fmt.Println("\nTables read:")
						for _, t := range dryResult.Tables {
							colDesc := fmt.Sprintf("%d columns", t.ColumnCount)
							if len(t.Columns) > 0 {
								colNames := make([]string, 0, len(t.Columns))
								for _, c := range t.Columns {
									colNames = append(colNames, c.Name)
								}
								if len(colNames) <= 5 {
									colDesc += " [" + strings.Join(colNames, ", ") + "]"
								} else {
									colDesc += " [" + strings.Join(colNames[:5], ", ") + ", ...]"
								}
							}
							fmt.Printf("   %s.%s: %s rows, %s\n",
								t.Schema, t.TableName,
								formatNumber(t.RowCount),
								colDesc)
						}
					}

					fmt.Printf("\nDry restore verified\n")
					fmt.Printf("   Verification ID: %s\n", report.VerificationID)
					fmt.Printf("   Duration:        %s\n", time.Duration(report.DurationMs*int64(time.Millisecond)).Round(time.Millisecond))
					if report.SurfaceType == model.SurfaceTypeFiles {
						fmt.Printf("   Files:           %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Directories:     %d\n", report.TablesRestored)
					} else if report.SurfaceType == model.SurfaceTypeEmail {
						fmt.Printf("   Emails:          %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Folders:         %d\n", report.TablesRestored)
					} else {
						fmt.Printf("   Tables:          %d\n", report.TablesRestored)
						fmt.Printf("   Rows:            %s\n", formatNumber(report.RowsRestored))
					}
					fmt.Printf("   Certificate:     %s\n", report.CertificateHash)
					return nil
				}

				fmt.Printf("Dry restore failed\n")
				for _, a := range report.Assertions {
					fmt.Printf("   [%s] %s: %s (Expected: %s, Actual: %s)\n", assertionWord(a), a.Name, a.Message, a.Expected, a.Actual)
				}
				return drillFailure(verifier, fmt.Errorf("dry restore of %s failed: %s", snapshotID, report.ErrorMessage))
			}

			// Active Sandbox Fire Drill
			fmt.Printf("Fire Drill: restoring %s into the sandbox database\n", snapshotID)
			fmt.Printf("   Snapshot ID:    %s\n", snapshotID)
			fmt.Printf("   Sandbox:        %s\n\n", dump.RedactURL(sandboxURL))

			report, err := verifier.RunFireDrill(ctx, snapshotID, resolvedKey, sandboxURL)
			if err != nil {
				return fmt.Errorf("fire drill of %s: %w", snapshotID, err)
			}

			if report.Status == model.VerificationStatusPassed {
				fmt.Printf("Fire Drill Passed\n")
				fmt.Printf("   Verification ID: %s\n", report.VerificationID)
				fmt.Printf("   Duration:        %s\n", time.Duration(report.DurationMs*int64(time.Millisecond)).Round(time.Millisecond))
				fmt.Printf("   Tables restored: %d\n", report.TablesRestored)
				fmt.Printf("   Rows restored:   %d\n", report.RowsRestored)
				fmt.Printf("   Certificate:     %s\n", report.CertificateHash)
				fmt.Println("\nAssertions:")
				for _, a := range report.Assertions {
					fmt.Printf("   [%s] %s (Expected: %s, Actual: %s)%s\n", assertionWord(a), a.Name, a.Expected, a.Actual, notRunWhy(a))
				}
			} else {
				fmt.Printf("Fire Drill Failed\n")
				for _, a := range report.Assertions {
					fmt.Printf("   [%s] %s: %s (Expected: %s, Actual: %s)\n", assertionWord(a), a.Name, a.Message, a.Expected, a.Actual)
				}
				shown := dump.RedactURL(sandboxURL)
				if showURL {
					shown = sandboxURL
				}
				if keep {
					fmt.Fprintf(os.Stderr, "Warning: sandbox kept at %s, as the drill left it. Empty it before the next drill into it.\n", shown)
				} else {
					fmt.Fprintf(os.Stderr, "Warning: the sandbox at %s holds what the drill restored. Empty it before the next drill into it.\n", shown)
				}
				return drillFailure(verifier, fmt.Errorf("fire drill of %s failed: %s", snapshotID, report.ErrorMessage))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "Snapshot ID to verify (required)")
	cmd.Flags().StringVar(&surfaceSel, "surface", "", "Drill the backup a watched surface (watch:) last read, where the other tool put it, instead of a snapshot")
	cmd.Flags().BoolVar(&keep, "keep-sandbox", false, "When a sandbox drill fails, record that the sandbox is kept for a person to look at")
	cmd.Flags().BoolVar(&showURL, "show-url", false, "When a sandbox drill fails, print the sandbox's URL with its password")
	cmd.Flags().BoolVar(&inMemory, "in-memory", false, "Restore in memory only, even with --sandbox-target (the default without it)")
	cmd.Flags().StringVar(&fromBucket, "from-bucket", "", "Read the snapshot from this copy (copies: name, or the name of a bucket the project writes to beside its own) instead of the surface's own storage")
	cmd.Flags().StringVar(&sandboxURL, "sandbox-target", "", "An empty database to restore the snapshot into for a full Fire Drill: postgres://…, mysql://…, or sqlite:///path/to/absent.db")
	cmd.Flags().StringVar(&checksFile, "checks", "", "YAML file of your own checks to run against the sandbox after the restore")
	cmd.Flags().StringVar(&query, "query", "", "Restore into a sandbox and print this SQL query's rows as CSV; nothing is reported as a drill")
	cmd.Flags().StringVar(&queryOut, "out", "", "With --query, write the CSV to this file instead of stdout")
	cmd.Flags().BoolVar(&queryKeep, "keep", false, "With --query, leave the PostgreSQL cluster the run started running for a day, and print how to connect")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to the age identity file")
	cmd.Flags().StringVar(&privKey, "private-key", "", "Age identity (AGE-SECRET-KEY-1...), as env:VAR, file:/path or the key")
	cmd.Flags().StringVar(&s3Bucket, "s3-bucket", "", "Read the snapshot from this S3 bucket instead of the configured storage")
	cmd.Flags().StringVar(&s3Prefix, "s3-prefix", "", "Key prefix in the S3 bucket")
	cmd.Flags().StringVar(&s3Region, "s3-region", "", "S3 region of --s3-bucket")
	cmd.Flags().StringVar(&s3Endpoint, "s3-endpoint", "", "S3 endpoint of --s3-bucket, for MinIO, R2 or another S3-compatible store")
	cmd.Flags().StringVar(&s3AccessKey, "s3-access-key", "", "S3 access key ID for --s3-bucket")
	cmd.Flags().StringVar(&s3SecretKey, "s3-secret-key", "", "S3 secret access key, as env:VAR or file:/path")

	cmd.AddCommand(newVerifyHistoryCmd())

	return cmd
}

func newVerifyHistoryCmd() *cobra.Command {
	var (
		nodeID    string
		keyStr    string
		keysFile  string
		localFile string
		saveFile  string
		jsonOut   bool
	)

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Check a node's attestation chain and Ed25519 signatures",
		Long: `Checks a node's attestation records, fetched from the remote server or read from
a file with --file:

1. The first record has PrevHash 'genesis'.
2. Every later record's PrevHash is the certificate hash of the one before it,
   so no record was changed, removed or inserted.
3. Every signed record's Ed25519 signature is valid against the attestation
   key that signed it. Each record names its key; the remote server publishes
   the active key and every retired one, and a record under a retired key is
   refused if it was completed, or chained, after the key retired. --key pins
   one public key for every record instead, as hex or file:/path; --keys-file
   takes the server's published key set, saved for an offline audit. Unsigned
   records are counted and reported.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nodeID == "" {
				nodeID = cfg.NodeID
			}
			if nodeID == "" && localFile == "" {
				return fmt.Errorf("--node is required: this config names no node.id")
			}

			serverURL := resolveServerURL()

			// 1. Load the records: a file (an array of records, or an
			// Evidence Pack), or the remote server's for one node.
			var reports []*model.VerificationReport
			var pack *evidencePackFile
			if localFile != "" {
				data, err := os.ReadFile(localFile)
				if err != nil {
					return fmt.Errorf("failed to read verifications file: %w", err)
				}
				if reports, pack, err = parseAttestationFile(data); err != nil {
					return err
				}
				// --node picks one host's chain out of a file of several.
				if cmd.Flags().Changed("node") {
					kept := reports[:0]
					for _, r := range reports {
						if r.NodeID == nodeID {
							kept = append(kept, r)
						}
					}
					reports = kept
				}
			} else {
				req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, fmt.Sprintf("%s/api/v1/verifications?node_id=%s", serverURL, url.QueryEscape(nodeID)), nil)
				if err != nil {
					return err
				}
				if cfg.ServerToken != "" {
					req.Header.Set("Authorization", "Bearer "+cfg.ServerToken)
				}
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					return fmt.Errorf("failed to fetch verifications from server: %w", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("server returned status %d fetching verifications for node %s", resp.StatusCode, nodeID)
				}
				body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
				if err != nil {
					return fmt.Errorf("failed to read verifications: %w", err)
				}
				if err := json.Unmarshal(body, &reports); err != nil {
					return fmt.Errorf("failed to decode verifications: %w", err)
				}
				// The offline check takes a file of records, and nothing
				// else wrote one: --json prints the summary, not the chain.
				if saveFile != "" {
					if err := os.WriteFile(saveFile, body, 0o644); err != nil {
						return fmt.Errorf("could not save the records to %s: %w", saveFile, err)
					}
					fmt.Fprintf(os.Stderr, "Saved %d records to %s. Check them offline with: safegrd verify history --file %s --keys-file keys.json\n",
						len(reports), saveFile, saveFile)
				}
			}

			// 2. Resolve the attestation keys. A pack carries the keys that
			// signed it; --key or --keys-file checks it against keys from
			// elsewhere instead.
			// A public key is no secret: file:/path is read, with no warning
			// about the value being visible.
			pinned, err := resolveConfigSecret("--key", keyStr)
			if err != nil {
				return err
			}
			var keys *attestationKeySet
			keysFromPack := pack != nil && pinned == "" && keysFile == "" && pack.SigningKey.PublicKeyHex != ""
			if keysFromPack {
				keys, err = keySetFromPublished(pack.published())
			} else {
				keys, err = loadAttestationKeys(cmd.Context(), serverURL, pinned, keysFile)
			}
			if err != nil {
				return err
			}

			if len(reports) == 0 {
				if jsonOut {
					fmt.Println(`{"status":"empty","count":0}`)
				} else {
					fmt.Printf("No attestation records found for node %s.\n", nodeID)
				}
				return nil
			}

			// 3. Each node's records are a chain of their own, from genesis,
			// or for a pack covering a period from the record before it.
			byNode := map[string][]*model.VerificationReport{}
			var nodes []string
			for _, r := range reports {
				if _, ok := byNode[r.NodeID]; !ok {
					nodes = append(nodes, r.NodeID)
				}
				byNode[r.NodeID] = append(byNode[r.NodeID], r)
			}
			sort.Strings(nodes)
			type chainResult struct {
				node, anchor, first, head string
				depth                     int
			}
			var chains []chainResult
			unsigned := 0
			for _, node := range nodes {
				rs := byNode[node]
				// Sort oldest first (started_at ASC) to verify chain forwards from genesis
				sort.Slice(rs, func(i, j int) bool {
					if rs[i].StartedAt.Equal(rs[j].StartedAt) {
						return rs[i].VerificationID < rs[j].VerificationID
					}
					return rs[i].StartedAt.Before(rs[j].StartedAt)
				})
				anchor := "genesis"
				if pack != nil {
					if a, ok := pack.ChainAnchors[node]; ok && a != "" {
						anchor = a
					}
				}
				keys.newest = time.Time{}
				expectedPrev := anchor
				for i, r := range rs {
					// 1. Verify PrevHash chaining
					if r.PrevHash != expectedPrev {
						if len(nodes) > 1 {
							return fmt.Errorf("CHAIN BREAK DETECTED at index %d of node %s (verification %s): expected PrevHash=%q, actual PrevHash=%q",
								i, node, r.VerificationID, expectedPrev, r.PrevHash)
						}
						return fmt.Errorf("CHAIN BREAK DETECTED at index %d (verification %s): expected PrevHash=%q, actual PrevHash=%q",
							i, r.VerificationID, expectedPrev, r.PrevHash)
					}

					// 2. Verify the signature under the key the record names. A
					// record with none is counted and said, never passed as verified.
					if r.Signature == "" {
						unsigned++
					} else if err := keys.verify(i, r); err != nil {
						return err
					}

					// Next link in chain must point to this report's certificate hash
					expectedPrev = r.CertificateHash
				}
				chains = append(chains, chainResult{node: node, anchor: anchor, first: rs[0].CertificateHash, head: rs[len(rs)-1].CertificateHash, depth: len(rs)})
			}

			if jsonOut {
				res := map[string]any{
					"status":        "verified",
					"signatures_ok": unsigned == 0,
					"unsigned":      unsigned,
					"signing_keys":  keys.used(),
				}
				if len(chains) == 1 {
					c := chains[0]
					if nodeID == "" || localFile != "" {
						nodeID = c.node
					}
					res["node_id"], res["chain_depth"], res["genesis_hash"], res["head_hash"] = nodeID, c.depth, c.first, c.head
					if c.anchor != "genesis" {
						res["starts_after"] = c.anchor
					}
				} else {
					var list []map[string]any
					for _, c := range chains {
						list = append(list, map[string]any{"node_id": c.node, "chain_depth": c.depth, "starts_after": c.anchor, "head_hash": c.head})
					}
					res["chains"] = list
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			from := func(c chainResult) string {
				if c.anchor == "genesis" {
					return "from genesis"
				}
				return "from the record before the period (" + c.anchor + ")"
			}
			fmt.Println("Attestation History Verified")
			if len(chains) == 1 {
				c := chains[0]
				if nodeID == "" || localFile != "" {
					// A file names its node in every record; --node is optional with --file.
					nodeID = c.node
				}
				fmt.Printf("   Node ID:         %s\n", nodeID)
				fmt.Printf("   Records:         %d, each linked to the one before it %s\n", c.depth, from(c))
				fmt.Printf("   Genesis hash:    %s\n", c.first)
				fmt.Printf("   Head hash:       %s\n", c.head)
			} else {
				fmt.Printf("   Chains:          %d hosts, %d records, each linked to the one before it\n", len(chains), len(reports))
				for _, c := range chains {
					fmt.Printf("   %s: %d records %s, head %s\n", c.node, c.depth, from(c), c.head)
				}
			}
			if unsigned == 0 {
				fmt.Printf("   Signatures:      %d of %d valid (Ed25519)\n", len(reports), len(reports))
			} else {
				fmt.Printf("   Signatures:      %d of %d valid (Ed25519); %d records carry no signature\n",
					len(reports)-unsigned, len(reports), unsigned)
			}
			if line := keys.usedLine(); line != "" {
				fmt.Printf("   Signing keys:    %s\n", line)
			}
			if keysFromPack {
				fmt.Println("   Keys:            the pack's own. Pass --key or --keys-file to check against keys you got elsewhere.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&nodeID, "node", "", "Node ID to verify history for")
	cmd.Flags().StringVar(&keyStr, "key", "", "Ed25519 attestation public key, hex-encoded, as the key or file:/path")
	cmd.Flags().StringVar(&keysFile, "keys-file", "", "JSON saved from the server's /api/v1/attestations/public-key: the active key and the retired ones, for an offline audit of a chain that spans a key rotation")
	cmd.Flags().StringVar(&localFile, "file", "", "JSON file of verification records to check offline")
	cmd.Flags().StringVar(&saveFile, "save", "", "Also write the records fetched from the remote server to this file, for an offline check with --file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the result as JSON on stdout")

	return cmd
}

// drillFailure is a drill that did not pass: exitStorage when the snapshot
// could not be read, unclassified when it did not restore.
func drillFailure(v *runner.Verifier, err error) error {
	if v.StorageFailed() {
		return storageFailure(err)
	}
	return err
}

func formatNumber(n int64) string {
	in := fmt.Sprintf("%d", n)
	var out []byte
	l := len(in)
	for i, c := range []byte(in) {
		if i > 0 && (l-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// identityFingerprint names an Age identity by its public half's fingerprint,
// the same one enroll prints and the console shows beside each node. The first
// characters of the identity itself are "AGE-SECRET-KEY-1" for every key, so
// they name nothing.
func identityFingerprint(identity string) string {
	// Restore and verify may hold several identities, one per line: the
	// host's own and the ones SafeGrd holds for the organization.
	var prints []string
	for _, line := range strings.Split(strings.TrimSpace(identity), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		recipient, err := recipientFor(line)
		if err != nil {
			return "unreadable identity"
		}
		prints = append(prints, crypto.Fingerprint(recipient))
	}
	if len(prints) > 1 {
		return fmt.Sprintf("%d keys (%s)", len(prints), strings.Join(prints, ", "))
	}
	return strings.Join(prints, "")
}

// attestationKey is one key the remote server signs, or signed, records with.
type attestationKey struct {
	ID        string
	Public    ed25519.PublicKey
	RetiredAt time.Time // zero while the key is active
	Records   int
}

// attestationKeySet is what a chain is checked against: either one pinned key
// for every record (--key), or the server's published set, where
// each record is checked under the key it names.
type attestationKeySet struct {
	pinned *attestationKey
	active *attestationKey
	byID   map[string]*attestationKey
	// newest is the rank of the newest key seen so far in the chain: a record
	// under a key retired before it is out of order. Active ranks above every
	// retired key.
	newest time.Time
	order  []*attestationKey
}

var activeForever = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

func (k *attestationKey) rank() time.Time {
	if k.RetiredAt.IsZero() {
		return activeForever
	}
	return k.RetiredAt
}

// publishedAttestationKeys is the body of GET /api/v1/attestations/public-key.
type publishedAttestationKeys struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Retired   []struct {
		KeyID     string    `json:"key_id"`
		PublicKey string    `json:"public_key"`
		RetiredAt time.Time `json:"retired_at"`
	} `json:"retired"`
}

func parseHexPublicKey(what, s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%s: not hex: %w", what, err)
	}
	// A key of the wrong length used to skip every signature check and
	// still report the signatures verified.
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is %d bytes; an Ed25519 public key is %d", what, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func keySetFromPublished(pk publishedAttestationKeys) (*attestationKeySet, error) {
	activePub, err := parseHexPublicKey("the server's attestation public key", pk.PublicKey)
	if err != nil {
		return nil, err
	}
	set := &attestationKeySet{byID: map[string]*attestationKey{}}
	set.active = &attestationKey{ID: pk.KeyID, Public: activePub}
	set.byID[pk.KeyID] = set.active
	for _, r := range pk.Retired {
		pub, err := parseHexPublicKey("retired attestation key "+r.KeyID, r.PublicKey)
		if err != nil {
			return nil, err
		}
		if r.RetiredAt.IsZero() {
			return nil, fmt.Errorf("retired attestation key %s has no retired_at", r.KeyID)
		}
		set.byID[r.KeyID] = &attestationKey{ID: r.KeyID, Public: pub, RetiredAt: r.RetiredAt.UTC()}
	}
	return set, nil
}

// evidencePackFile is what verify history reads from an Evidence Pack: its
// records, the hash each node's first record links to, and its keys.
type evidencePackFile struct {
	DrillAttestations []*model.VerificationReport `json:"drill_attestations"`
	ChainAnchors      map[string]string           `json:"chain_anchors"`
	SigningKey        struct {
		KeyID        string `json:"key_id"`
		PublicKeyHex string `json:"public_key_hex"`
	} `json:"signing_key"`
	RetiredSigningKeys []struct {
		KeyID     string    `json:"key_id"`
		PublicKey string    `json:"public_key"`
		RetiredAt time.Time `json:"retired_at"`
	} `json:"retired_signing_keys"`
}

// published is the pack's keys in the shape of the public-key route.
func (p *evidencePackFile) published() publishedAttestationKeys {
	pk := publishedAttestationKeys{KeyID: p.SigningKey.KeyID, PublicKey: p.SigningKey.PublicKeyHex}
	for _, r := range p.RetiredSigningKeys {
		pk.Retired = append(pk.Retired, struct {
			KeyID     string    `json:"key_id"`
			PublicKey string    `json:"public_key"`
			RetiredAt time.Time `json:"retired_at"`
		}{r.KeyID, r.PublicKey, r.RetiredAt})
	}
	return pk
}

// parseAttestationFile reads an array of records, or an Evidence Pack.
func parseAttestationFile(data []byte) ([]*model.VerificationReport, *evidencePackFile, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var reports []*model.VerificationReport
		if err := json.Unmarshal(trimmed, &reports); err != nil {
			return nil, nil, fmt.Errorf("failed to parse verifications file: %w", err)
		}
		return reports, nil, nil
	}
	var pack evidencePackFile
	if err := json.Unmarshal(trimmed, &pack); err != nil || pack.DrillAttestations == nil {
		return nil, nil, fmt.Errorf("the file is neither a list of verification records nor an Evidence Pack")
	}
	return pack.DrillAttestations, &pack, nil
}

// loadAttestationKeys resolves the keys from --key, --keys-file or
// the remote server, in that order of precedence.
func loadAttestationKeys(ctx context.Context, serverURL, keyStr, keysFile string) (*attestationKeySet, error) {
	switch {
	case keyStr != "":
		pub, err := parseHexPublicKey("--key", strings.TrimSpace(keyStr))
		if err != nil {
			return nil, err
		}
		return &attestationKeySet{pinned: &attestationKey{ID: "pinned", Public: pub}}, nil
	case keysFile != "":
		data, err := os.ReadFile(keysFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read --keys-file: %w", err)
		}
		var pk publishedAttestationKeys
		if err := json.Unmarshal(data, &pk); err != nil {
			return nil, fmt.Errorf("--keys-file is not the JSON of /api/v1/attestations/public-key: %w", err)
		}
		return keySetFromPublished(pk)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/api/v1/attestations/public-key", nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attestation public key from %s: %w", serverURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d fetching public key", resp.StatusCode)
	}
	var pk publishedAttestationKeys
	if err := json.NewDecoder(resp.Body).Decode(&pk); err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	return keySetFromPublished(pk)
}

// verify checks record i's signature under the key it names.
//
// A pinned key is checked against every record, whatever key id it carries:
// that is the air-gapped audit, where the auditor decides which key to trust.
// Otherwise the record's signing_key_id picks the key. A record that names no
// key was signed before records carried one and is checked under the active
// key. A record under a retired key must have been completed before the key
// retired, and must not follow a record signed under a newer key: the chain
// is append-only, so once the server signs with the new key no honest record
// under the old one can come after it.
func (s *attestationKeySet) verify(i int, r *model.VerificationReport) error {
	sigBytes, err := hex.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("INVALID SIGNATURE at index %d (verification %s): the signature is not hex", i, r.VerificationID)
	}
	key := s.pinned
	if key == nil {
		if r.SigningKeyID == "" {
			key = s.active
		} else if key = s.byID[r.SigningKeyID]; key == nil {
			return fmt.Errorf("UNKNOWN SIGNING KEY at index %d (verification %s): signed under %s, which the remote server publishes as neither active nor retired",
				i, r.VerificationID, r.SigningKeyID)
		}
	}
	if !ed25519.Verify(key.Public, r.CanonicalBytes(), sigBytes) {
		return fmt.Errorf("INVALID SIGNATURE at index %d (verification %s): the Ed25519 signature does not match the record under key %s",
			i, r.VerificationID, key.ID)
	}
	if !key.RetiredAt.IsZero() {
		completed := r.CompletedAt
		if completed.IsZero() {
			completed = r.StartedAt
		}
		if completed.After(key.RetiredAt) {
			return fmt.Errorf("RETIRED KEY at index %d (verification %s): signed under %s, which retired at %s, but completed at %s",
				i, r.VerificationID, key.ID, key.RetiredAt.Format(time.RFC3339), completed.UTC().Format(time.RFC3339))
		}
		if key.rank().Before(s.newest) {
			return fmt.Errorf("RETIRED KEY OUT OF ORDER at index %d (verification %s): signed under %s, which retired at %s, after a record signed under a newer key",
				i, r.VerificationID, key.ID, key.RetiredAt.Format(time.RFC3339))
		}
	}
	if key.rank().After(s.newest) {
		s.newest = key.rank()
	}
	if key.Records == 0 {
		s.order = append(s.order, key)
	}
	key.Records++
	return nil
}

// used lists the keys that signed the chain, for --json.
func (s *attestationKeySet) used() []map[string]any {
	out := make([]map[string]any, 0, len(s.order))
	for _, k := range s.order {
		entry := map[string]any{"key_id": k.ID, "records": k.Records, "status": "active"}
		if k == s.pinned {
			entry["status"] = "pinned"
		} else if !k.RetiredAt.IsZero() {
			entry["status"] = "retired"
			entry["retired_at"] = k.RetiredAt.Format(time.RFC3339)
		}
		out = append(out, entry)
	}
	return out
}

// usedLine is the same, one line for the text output. Empty when a pinned key
// was used: the operator chose it and knows which it is.
func (s *attestationKeySet) usedLine() string {
	if s.pinned != nil {
		return ""
	}
	parts := make([]string, 0, len(s.order))
	for _, k := range s.order {
		records := "records"
		if k.Records == 1 {
			records = "record"
		}
		if k.RetiredAt.IsZero() {
			parts = append(parts, fmt.Sprintf("%s (active, %d %s)", k.ID, k.Records, records))
		} else {
			parts = append(parts, fmt.Sprintf("%s (retired %s, %d %s)", k.ID, k.RetiredAt.Format("2006-01-02"), k.Records, records))
		}
	}
	return strings.Join(parts, "; ")
}

// unknownSnapshot reports whether a failed read means the snapshot does not
// exist: storage said there is no such object, and the remote server, when
// this host can ask it, has no record of the ID either.
func unknownSnapshot(ctx context.Context, err error, snapshotID string) bool {
	msg := err.Error()
	notFound := errors.Is(err, os.ErrNotExist) || errors.Is(err, sink.ErrNotFound) ||
		strings.Contains(msg, "No such object") || strings.Contains(msg, "NoSuchKey") || strings.Contains(msg, "not found")
	if !notFound {
		return false
	}
	return !canReport(cfg) || recordedSnapshot(ctx, cfg, snapshotID) == nil
}

// loadDrillChecks reads a --checks file: a YAML list of checks, as a
// surface's drill.checks holds. An empty path is no checks.
func loadDrillChecks(path string) ([]model.DrillCheck, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--checks: %w", err)
	}
	var checks []model.DrillCheck
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&checks); err != nil {
		return nil, fmt.Errorf("--checks %s: %w. It takes a YAML list of checks, each with a name and either sql and expect, or command", path, err)
	}
	if len(checks) == 0 {
		return nil, fmt.Errorf("--checks %s holds no checks", path)
	}
	if err := model.ValidateDrillChecks(checks); err != nil {
		return nil, fmt.Errorf("--checks %s: %w", path, err)
	}
	return checks, nil
}

// assertionWord is an assertion's state as verify prints it.
func assertionWord(a model.AssertionResult) string {
	switch {
	case a.NotRun:
		return "NOT RUN"
	case a.Passed:
		return "PASS"
	}
	return "FAIL"
}

// notRunWhy is why a check did not run, after its line.
func notRunWhy(a model.AssertionResult) string {
	if !a.NotRun || a.Message == "" {
		return ""
	}
	return ": " + a.Message
}
