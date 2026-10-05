package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

func newEnrollCmd() *cobra.Command {
	var (
		token             string
		apiKey            string
		nodeName          string
		projectID         string
		orgID             string
		nodeIDFlag        string
		keyCustody        string
		storageFlag       string
		allowUnconfigured bool
		claimCode         string
	)

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Register this host with the remote server, using an access token or a node token",
		Long: `Registers this host with the remote server and writes the node token to the config.

Pass a personal access token (sg_pat_...) to register a new node, or a node token
(sg_tok_...) with --node-id to take over one the console already created. With
neither, it uses the login saved by 'safegrd login'. Both flags take env:VAR or
file:/path, which keeps the token out of 'ps' and shell history.`,
		RunE: func(cmd *cobra.Command, args []string) (runErr error) {
			serverURL := resolveServerURL()

			if err := refuseInsecurePersonalToken(serverURL); err != nil {
				return err
			}

			var err error
			if token, err = ResolveSecretRef("token", token); err != nil {
				return err
			}
			if apiKey, err = ResolveSecretRef("api-key", apiKey); err != nil {
				return err
			}

			// Refused before anything is generated. Checked after the local
			// setup, a key made here would be found on the retry and adopted
			// as the operator's own, which silently changes its custody.
			if token == "" && apiKey == "" && (cfg == nil || !strings.HasPrefix(cfg.ServerToken, "sg_pat_")) {
				return fmt.Errorf("no credential to enroll with, and this host is not logged in.\n" +
					"  Run 'safegrd login' first (it prints a URL you can open on any device),\n" +
					"  or pass --token sg_pat_... from Tokens in the console.\n" +
					"  Nothing was changed")
			}

			// Did the operator bring their own key? Decided BEFORE the local
			// setup runs, because that step generates one when none is found;
			// after it, every host looks like it had a key all along.
			//
			// This is the custody decision. A key
			// the operator supplied is theirs and never leaves the host; a key
			// we generate is escrowed, so that losing the host does not lose
			// the backups. --key-custody=local opts out and makes the
			// operator responsible for it.
			keyExistedBeforeEnroll := cfg != nil && cfg.Encryption.PublicKey != ""

			// Whether this host already had an identity of its own, captured
			// before the local setup runs and invents one.
			hostAlreadyHadNodeID := cfg != nil && cfg.NodeID != ""

			// Do the local half if it has not been done. Enrolling used to read
			// cfg.NodeID out of a config LoadCLIConfig had invented from
			// defaults, which registered a node with an empty identity and no
			// keypair: enrolled, and unable to encrypt anything.
			// A claim carries the custody answer given in the console; it is
			// read once the claim is fetched below. An explicit --key-custody
			// wins over it.
			if claimCode != "" {
				if token != "" && !strings.HasPrefix(token, "sg_pat_") {
					return fmt.Errorf("--claim registers a new host, and a node token belongs to one that exists. " +
						"Log in with 'safegrd login' instead. Nothing was changed")
				}
			}

			if storageFlag != "" && storageFlag != string(config.StorageTypeHosted) && storageFlag != string(config.StorageTypeLocal) {
				return fmt.Errorf("--storage %q: enroll can choose hosted or local; configure a bucket in the console "+
					"or with 'safegrd init --storage s3'. Nothing was changed", storageFlag)
			}

			created, adopted, err := ensureLocalSetup(nodeName)
			if err != nil {
				return err
			}
			switch storageFlag {
			case string(config.StorageTypeHosted):
				// The lease supplies the bucket, the prefix, the credential
				// and the plan's retention; nothing about it belongs in the file.
				cfg.Storage = config.StorageConfig{Type: config.StorageTypeHosted, WORMMode: config.WORMModeCompliance}
			case string(config.StorageTypeLocal):
				// A directory on this host, chosen: for a trial or an
				// air-gapped host. It keeps the path the local setup pinned
				// next to the config.
				cfg.Storage.Type = config.StorageTypeLocal
			}
			if created {
				fmt.Printf("No local setup found, so it was created first.\n\n")
			}
			// An identity found on disk is the operator's, whatever wrote it.
			// It reaches here when a previous enrollment generated the key and
			// then failed before writing a config, so this is the retry.
			// A key we did not send stays theirs, and we say so.
			if adopted {
				keyExistedBeforeEnroll = true
			}

			fmt.Printf("Enrolling with %s\n", serverURL)

			// A Personal Access Token passed to --token is registration, not a
			// node token.
			//
			// This is what the documentation, docs.html and the dashboard's own
			// copy-paste command tell an operator to run: all print
			// `enroll --token sg_pat_...`.
			//
			// The prefixes are unambiguous (sg_pat_ for an operator
			// credential, sg_tok_ for a node token), so this routes on the
			// prefix rather than asking the operator to know which flag their
			// token belongs to.
			if apiKey == "" && strings.HasPrefix(token, "sg_pat_") {
				fmt.Printf("Registering a new node with the personal access token.\n")
				apiKey, token = token, ""
			}

			// No credential on the command line: use the one 'safegrd login'
			// saved. Without this, `safegrd login && safegrd enroll` sent the
			// registration with no Authorization header at all and was refused,
			// so the browser login the installer walks you through led nowhere.
			// Only a personal access token counts; a node token already in the
			// config belongs to a node this host enrolled before.
			if token == "" && apiKey == "" && strings.HasPrefix(cfg.ServerToken, "sg_pat_") {
				fmt.Printf("Using the login saved by 'safegrd login'.\n")
				apiKey = cfg.ServerToken
			}

			// Mode 1: Direct Node Token provided
			if token != "" {
				// A node token belongs to a node that already exists, and this
				// host has to adopt that node's identity rather than invent
				// one.
				//
				// It used to invent one: ensureLocalSetup had just generated
				// `node-<random>`, the heartbeat went out for that id, the
				// server answered 403 because the token authenticates a
				// different node, and the command printed a one-line warning
				// and exited 0. The host kept the fabricated node_id, so every
				// later command (such as reporting a snapshot or fetching credentials)
				// spoke about a node the remote server has never heard of.
				switch {
				case nodeIDFlag != "":
					cfg.NodeID = nodeIDFlag
				case !hostAlreadyHadNodeID:
					return fmt.Errorf("a node token authenticates one existing node, and this host "+
						"has no node id of its own yet, so there is nothing to attach the token to.\n"+
						"  Pass --node-id <id> (the console shows it beside the token) or enrol with a\n"+
						"  personal access token (sg_pat_...), which registers a new node and issues its\n"+
						"  own token.\n"+
						"  Nothing was changed: the local key at %s is untouched and no config was written",
						cfg.Encryption.KeyPath)
				}

				cfg.ServerURL = serverURL
				cfg.ServerToken = token
				if projectID != "" {
					cfg.ProjectID = projectID
				}

				// A rejected credential is an error: saving a config with an invalid
				// token would make subsequent commands fail.
				status, err := verifyToken(serverURL, cfg.NodeID, token)
				switch {
				case status == http.StatusUnauthorized || status == http.StatusForbidden:
					return fmt.Errorf("the remote server refused this token for node %s (HTTP %d).\n"+
						"  A node token only authenticates the node it was issued for, so either the id\n"+
						"  is not the one the token belongs to, or the token has been revoked.\n"+
						"  Nothing was changed: no config was written",
						cfg.NodeID, status)
				case err != nil:
					// Could not reach the remote server to check. The token may
					// be perfectly good, so this is written and said out loud
					// rather than refused.
					fmt.Fprintf(os.Stderr, "Warning: could not check the token: %v\n", err)
					fmt.Fprintf(os.Stderr, "   The config is written without that check. Run 'safegrd status' once\n")
					fmt.Fprintf(os.Stderr, "   the remote server is reachable to confirm this node is enrolled.\n")
				default:
					fmt.Printf("Node token accepted\n")
					fmt.Printf("   Node:        %s\n", cfg.NodeID)
				}
			} else {
				// Mode 2: Register node using Organization API key or open registration
				name := nodeName
				if name == "" {
					name = cfg.NodeName
				}
				if name == "" {
					name = "postgres-node"
				}

				generatedNow := !keyExistedBeforeEnroll && cfg.Encryption.PublicKey != ""

				// A key this run generated and never got registered is nobody's
				// yet. Left on disk, the retry adopts it as one the operator
				// supplied and refuses --key-custody=safegrd, so the first
				// refusal made the second one permanent. It goes, and the
				// retry generates a fresh one. Once the server has answered
				// 2xx the key may be registered, and it stays whatever follows.
				registered := false
				if generatedNow && cfg.Encryption.KeyPath != "" {
					generatedKey := cfg.Encryption.KeyPath
					defer func() {
						if runErr == nil || registered {
							return
						}
						if err := os.Remove(generatedKey); err == nil {
							fmt.Fprintf(os.Stderr, "   The key this attempt generated was never sent, so it was removed (%s). Re-running enroll makes a new one.\n", generatedKey)
						}
					}()
				}

				// Two different custody modes, named rather than inferred:
				//
				//   --key-custody=safegrd  generate here, send it, SafeGrd can
				//                          decrypt, losing this host is survivable
				//   --key-custody=local    generate here, write it to key_path,
				//                          send only the recipient, nobody but
				//                          you can ever read these backups
				//
				// A key the operator supplied is always local. Sending an
				// existing key is a decision no flag should make on
				// their behalf; it may be shared with other systems, and its
				// custody was settled before SafeGrd was involved.
				switch keyCustody {
				case "", "safegrd", "local":
				default:
					return fmt.Errorf("--key-custody must be 'safegrd' or 'local', got %q", keyCustody)
				}

				// A claim says where this host goes and what it protects.
				var claim *claimPreview
				claimChoseSafeGrd := false
				if claimCode != "" {
					pv, err := fetchClaim(serverURL, apiKey, claimCode)
					if err != nil {
						return fmt.Errorf("%w. Nothing was changed", err)
					}
					claim, orgID, projectID = pv, pv.OrgID, pv.ProjectID
					fmt.Printf("Claim for project '%s'.\n", pv.ProjectName)
					if pv.StorageKind == string(config.StorageTypeHosted) && storageFlag == "" {
						cfg.Storage = config.StorageConfig{Type: config.StorageTypeHosted, WORMMode: config.WORMModeCompliance}
						storageFlag = string(config.StorageTypeHosted)
					}
					// The console's answer, unless the flag gave one. A server
					// that predates the question answers "local" or nothing,
					// and the key stays on the host as it always did.
					if keyCustody == "" {
						if pv.KeyCustody == "safegrd" {
							keyCustody = "safegrd"
						} else {
							keyCustody = "local"
						}
						// A key already on the host is never sent, whatever the
						// console chose; enrolment says so below.
						claimChoseSafeGrd = keyCustody == "safegrd"
					}
				}

				// A key already here stays here. Refused only when the flag asked
				// for SafeGrd to hold it; a claim's answer covers keys it
				// generates, and enrolment states that this one was not sent.
				if claimChoseSafeGrd && keyExistedBeforeEnroll {
					keyCustody = "local"
				}
				if keyExistedBeforeEnroll && keyCustody == "safegrd" {
					return fmt.Errorf("refusing to send a key you supplied.\n" +
						"  --key-custody=safegrd generates a new key and escrows it; it does not hand over an existing one.\n" +
						"  The key already configured here stays yours. Remove it from the config first if you " +
						"really want SafeGrd to hold a freshly generated one instead")
				}
				escrowRequested := generatedNow && keyCustody != "local"

				// Resolve organization ID for node registration if not provided.
				if orgID == "" {
					resolved, err := resolveEnrollmentOrg(serverURL, apiKey)
					if err != nil {
						return err
					}
					orgID = resolved
					fmt.Printf("Organization: %s\n", orgID)
				}

				// Nothing named a project: ask, or say which one and how to
				// pick another. Hosts landed in Production unannounced, so an
				// agency's client host joined another client's project (M78).
				projectName := ""
				if projectID == "" && claim == nil && !strings.HasPrefix(apiKey, "sg_tok_") {
					projectID, projectName = chooseEnrollProject(serverURL, apiKey, orgID)
				}

				regReq := model.NodeRegisterRequest{
					NodeID:    cfg.NodeID,
					OrgID:     orgID,
					ProjectID: projectID,
					Name:      name,
					// No database is known at enrolment: the first backup
					// names it. Every host was registered as "postgres", and
					// a SQLite host read "SQLITE postgres" in the console.
					DatabaseName:  "",
					StorageBucket: cfg.Storage.Bucket,
					RetentionDays: cfg.Storage.RetentionDays,
					// Where this host's own config sends backups, so the
					// remote server can refuse a host that has nowhere to
					// send them rather than enroll it to back up nothing.
					LocalStorage:      localStorageKind(cfg.Storage, created, storageFlag != ""),
					AllowUnconfigured: allowUnconfigured,
					Claim:             claimCode,
					OS:                runtime.GOOS,
					Arch:              runtime.GOARCH,
					CLIVersion:        Version,

					// The recipient is public and always sent: the remote
					// server needs it to record which key this node uses and to
					// catch a mismatch before a restore fails, not after.
					PublicKey:      cfg.Encryption.PublicKey,
					KeyFingerprint: crypto.Fingerprint(cfg.Encryption.PublicKey),
				}
				if escrowRequested {
					regReq.ManagedIdentity = cfg.Encryption.PrivateKey
				}
				body, _ := json.Marshal(regReq)

				req, err := http.NewRequest("POST", serverURL+"/api/v1/nodes/register", bytes.NewReader(body))
				if err != nil {
					return err
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("User-Agent", UserAgent())
				if apiKey != "" {
					req.Header.Set("Authorization", "Bearer "+apiKey)
				}

				client := &http.Client{Timeout: 5 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					return fmt.Errorf("failed connecting to server: %w", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
					var errResp map[string]string
					_ = json.NewDecoder(resp.Body).Decode(&errResp)
					return fmt.Errorf("server rejected enrollment (HTTP %d): %s", resp.StatusCode, errResp["error"])
				}
				registered = true

				var regResp model.NodeRegisterResponse
				if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
					return fmt.Errorf("invalid server response: %w", err)
				}

				cfg.ServerURL = serverURL
				cfg.ServerToken = regResp.Token
				// The host named no storage and its project backs up to
				// hosted storage, so this host does too.
				if regResp.StorageKind == string(config.StorageTypeHosted) && regReq.LocalStorage == "none" {
					cfg.Storage = config.StorageConfig{Type: config.StorageTypeHosted, WORMMode: config.WORMModeCompliance}
					fmt.Printf("Storage: SafeGrd's hosted storage, as the project is set up.\n")
				}
				if regResp.ProjectID != "" {
					cfg.ProjectID = regResp.ProjectID
				} else if projectID != "" {
					cfg.ProjectID = projectID
				}
				// A key we sent that did not come back confirmed is a
				// data-loss trap, not a warning: the operator would believe it
				// is safe with us, delete their copy, and find out on the day
				// they need it. Fail the command and print the key.
				if escrowRequested && !regResp.KeyEscrowed {
					w := os.Stderr
					fmt.Fprintf(w, "\nError: the remote server did not store the encryption key.\n\n")
					fmt.Fprintf(w, "   This node is enrolled, and the key below is only in this file:\n")
					fmt.Fprintf(w, "   %s\n\n", cfg.Encryption.KeyPath)
					fmt.Fprintf(w, "   Save a copy now. It is the only key that decrypts this node's backups.\n\n")
					fmt.Fprintf(w, "   Public key:  %s\n", cfg.Encryption.PublicKey)
					fmt.Fprintf(w, "   Fingerprint: %s\n", crypto.Fingerprint(cfg.Encryption.PublicKey))
					return fmt.Errorf("enrollment completed but key escrow failed: save the key above before running a backup")
				}

				fmt.Printf("Enrolled node %s as '%s'\n", regResp.NodeID, name)
				// Only enough of the token to tell it apart: the whole of it
				// would stay in terminal scrollback, and in the job log when
				// enrolment runs in CI. The config file below holds it.
				fmt.Printf("   Node token:  %s (saved to the config file)\n", maskToken(regResp.Token))
				fmt.Printf("   Key:         %s\n", crypto.Fingerprint(cfg.Encryption.PublicKey))

				// Report key custody mode.
				switch {
				case regResp.KeyEscrowed:
					fmt.Printf("   Custody:     SafeGrd-managed key\n")
					fmt.Printf("                SafeGrd keeps this key sealed and releases it only to your enrolled hosts,\n")
					fmt.Printf("                so you can restore these backups even after losing this host.\n")
					fmt.Printf("                For a customer-managed key next time, enrol with --key-custody=local.\n")
				case keyExistedBeforeEnroll:
					fmt.Printf("   Custody:     customer-managed key\n")
					fmt.Printf("                Only you can decrypt these backups. SafeGrd has the public half.\n")
					if adopted {
						fmt.Printf("                It was already at %s, so it was not sent: a key we find on a host\n", cfg.Encryption.KeyPath)
						fmt.Printf("                is yours. For a SafeGrd-managed key instead, move that file aside and\n")
						fmt.Printf("                re-run with --key-custody=safegrd.\n")
					}
				default:
					fmt.Printf("   Custody:     customer-managed key (--key-custody=local)\n")
					fmt.Printf("                Only you can decrypt these backups.\n")
					fmt.Printf("                Keep a copy of %s somewhere safe: it is the key that opens them.\n", cfg.Encryption.KeyPath)
				}
				if cfg.ProjectID != "" {
					if projectName != "" {
						fmt.Printf("   Project:     %s (%s)\n", projectName, cfg.ProjectID)
					} else {
						fmt.Printf("   Project ID:  %s\n", cfg.ProjectID)
					}
				}
				if claim != nil {
					addClaimSurfaces(cfg, claim.Surfaces)
					// The same three steps the console's host step shows.
					fmt.Printf("\n   Next: check every surface opens from this host. The console shows the result:\n")
					fmt.Printf("     safegrd doctor\n")
					fmt.Printf("   Take the first backups now, and watch them land in the console:\n")
					fmt.Printf("     safegrd daemon run --once\n")
					fmt.Printf("   Then keep it running as a service that starts at boot:\n")
					fmt.Printf("     sudo safegrd daemon install\n")
				} else if len(cfg.Surfaces) == 0 && cfg.DatabaseURL == "" && os.Getenv("SAFEGRD_DATABASE_URL") == "" {
					fmt.Printf("\n   Next: name what this host protects. Either add a surface to this host in the\n")
					fmt.Printf("   console (Nodes, Add surface on its row) and run:\n")
					fmt.Printf("     safegrd claim\n")
					fmt.Printf("   or give it one database, from the environment so the password stays out of the config:\n")
					fmt.Printf("     export SAFEGRD_DATABASE_URL=\"$DATABASE_URL\"\n")
					fmt.Printf("   Then check it: safegrd doctor\n")
					fmt.Printf("   To restore the organization's backups on this host instead, it needs nothing more:\n")
					fmt.Printf("     safegrd list\n")
					fmt.Printf("     safegrd restore --snapshot <id> --target env:TARGET_URL\n")
				}
			}

			targetConfig, err := saveConfig()
			if err != nil {
				return err
			}

			fmt.Printf("Saved to %s\n", targetConfig)
			return nil
		},
	}

	cmd.Flags().StringVar(&token, "token", "", "Personal access token (sg_pat_...) or node token (sg_tok_...), as env:VAR, file:/path or the token")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Organization API key to register the node with, as env:VAR, file:/path or the key")
	cmd.Flags().StringVar(&nodeName, "node-name", "", "Name this host is shown under (default: the hostname)")
	cmd.Flags().StringVar(&projectID, "project", "", "Project ID or slug to attach this node to (default: the organization's default project)")
	cmd.Flags().StringVar(&nodeIDFlag, "node-id", "",
		"The node this token belongs to, for --token. The console shows it beside the token. "+
			"Not needed with a personal access token, which registers a new node.")
	cmd.Flags().StringVar(&orgID, "org", "",
		"Organization to enrol this node into. Only needed when the credential can see more than one: "+
			"with a single organization it is resolved automatically.")
	cmd.Flags().StringVar(&claimCode, "claim", "",
		"The code the console shows for this host. It names the project and the surfaces to protect; "+
			"log in with 'safegrd login' first")
	cmd.Flags().StringVar(&storageFlag, "storage", "",
		"Where this host's backups go, when the project has no bucket: 'hosted' uses SafeGrd's hosted "+
			"storage, where your plan includes it; 'local' keeps them in a directory on this host")
	cmd.Flags().BoolVar(&allowUnconfigured, "allow-unconfigured", false,
		"Enroll even though neither this host's config nor its project says where backups go. "+
			"Without it enrollment is refused, because the host would back up nothing until storage is set")
	cmd.Flags().StringVar(&keyCustody, "key-custody", "",
		"Who manages the encryption key when this command generates one. "+
			"'safegrd' (default): a SafeGrd-managed key, sealed on the remote server and released only to your enrolled hosts, "+
			"so losing this host never loses the backups. "+
			"'local': a customer-managed key, written to key_path with only the public half sent, so only you can decrypt "+
			"the backups. Keep a copy of the key file somewhere safe. "+
			"Ignored when you supplied your own key (an existing key is never sent).")

	return cmd
}

// verifyToken heartbeats as nodeID and reports the HTTP status separately from
// a transport error, because the caller has to tell "this credential was
// refused" apart from "the remote server could not be reached". They are
// different situations and only one of them is the operator's mistake.
func verifyToken(serverURL, nodeID, token string) (int, error) {
	hb := model.HeartbeatRequest{
		NodeID:      nodeID,
		CLI_Version: Version,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		PostgresUp:  true,
		StorageUp:   true,
	}
	body, _ := json.Marshal(hb)
	req, err := http.NewRequest("POST", serverURL+"/api/v1/nodes/heartbeat", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", UserAgent())

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// resolveEnrollmentOrg finds which organization this credential enrols into.
//
// One organization is the overwhelmingly common case and asking about it would
// be noise, so it is resolved silently and named in the output. More than one
// is refused rather than guessed: enrolling a production database into the wrong
// organization puts it under the wrong quota, the wrong plan and the wrong
// people's console, and none of that is visible from the host afterwards.
func resolveEnrollmentOrg(serverURL, credential string) (string, error) {
	req, err := http.NewRequest("GET", strings.TrimRight(serverURL, "/")+"/api/v1/orgs", nil)
	if err != nil {
		return "", err
	}
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not ask %s which organization to enrol into: %w", serverURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("the remote server rejected this credential (HTTP %d). "+
			"Check the token, or pass --org if it cannot list organizations", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("could not resolve the organization to enrol into (HTTP %d). "+
			"Pass --org <id> to name it", resp.StatusCode)
	}

	var orgs []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return "", fmt.Errorf("could not read the organization list: %w", err)
	}

	switch len(orgs) {
	case 0:
		return "", fmt.Errorf("this credential belongs to no organization, so there is nothing to " +
			"enrol into. Create one in the console first")
	case 1:
		return orgs[0].ID, nil
	default:
		var lines strings.Builder
		for _, o := range orgs {
			lines.WriteString(fmt.Sprintf("\n    %s  %s", o.ID, o.Name))
		}
		return "", fmt.Errorf("this credential can see %d organizations, so which one this node "+
			"belongs to is not ours to choose. Re-run with --org <id>:%s", len(orgs), lines.String())
	}
}

// localStorageKind says where a host's own config sends its backups, for the
// remote server's check that an enrolling host has somewhere to back up to.
// The default local directory counts only when an operator chose it: when
// this enrollment wrote the config itself, those settings are placeholders,
// not a decision, and the answer is "none".
func localStorageKind(st config.StorageConfig, createdByEnroll, chosenByFlag bool) string {
	switch {
	case st.Type == config.StorageTypeHosted:
		return "hosted"
	case st.Type == config.StorageTypeS3 && st.Bucket != "":
		return "s3"
	case st.Type == config.StorageTypeLocal && (!createdByEnroll || chosenByFlag):
		return "local"
	}
	return "none"
}

// maskToken shows a token's prefix and last four characters, enough to match
// it against the console's list without printing anything that authenticates.
func maskToken(tok string) string {
	prefix := ""
	for _, p := range []string{"sg_tok_", "sg_pat_"} {
		if strings.HasPrefix(tok, p) {
			prefix, tok = p, tok[len(p):]
		}
	}
	if len(tok) <= 8 {
		return prefix + "…"
	}
	return prefix + "…" + tok[len(tok)-4:]
}

// chooseEnrollProject picks the project a new host joins when nothing named
// one. One project: that one, said nothing about. More: asked on the
// terminal, defaulting to the organization's default project; with no
// terminal (CI, cloud-init), the default, named, with the flag to choose
// another. A list that cannot be read leaves the choice to the server.
func chooseEnrollProject(serverURL, token, orgID string) (id, name string) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/orgs/%s/projects", strings.TrimRight(serverURL, "/"), orgID), nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	var all []*model.Project
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&all) != nil {
		return "", ""
	}
	var projects []*model.Project
	def := -1
	for _, p := range all {
		if p.ArchivedAt != nil {
			continue
		}
		if def < 0 && (strings.EqualFold(p.Slug, "production") || strings.EqualFold(p.Name, "Production")) {
			def = len(projects)
		}
		projects = append(projects, p)
	}
	if len(projects) == 0 {
		return "", ""
	}
	if def < 0 {
		def = 0
	}
	if len(projects) == 1 {
		return projects[0].ID, projects[0].Name
	}
	// Asked only when a person is watching: stdout a terminal as well, so a
	// script or a test that captures the output is never left waiting.
	var tty *os.File
	if fi, statErr := os.Stdout.Stat(); statErr == nil && fi.Mode()&os.ModeCharDevice != 0 {
		tty, _ = os.OpenFile("/dev/tty", os.O_RDWR, 0)
	}
	if tty == nil {
		var slugs []string
		for _, p := range projects {
			slugs = append(slugs, p.Slug)
		}
		fmt.Printf("Project: %s, the organization's default. To choose another, re-run with --project: %s.\n",
			projects[def].Name, strings.Join(slugs, ", "))
		return projects[def].ID, projects[def].Name
	}
	defer tty.Close()
	fmt.Fprintln(tty, "Which project is this host for?")
	for i, p := range projects {
		fmt.Fprintf(tty, "  %d. %s (%s)\n", i+1, p.Name, p.Slug)
	}
	in := bufio.NewReader(tty)
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(tty, "Project [%d]: ", def+1)
		line, err := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			if err != nil && attempt == 0 {
				break
			}
			return projects[def].ID, projects[def].Name
		}
		if n, convErr := strconv.Atoi(line); convErr == nil && n >= 1 && n <= len(projects) {
			return projects[n-1].ID, projects[n-1].Name
		}
		for _, p := range projects {
			if strings.EqualFold(line, p.Slug) || strings.EqualFold(line, p.Name) {
				return p.ID, p.Name
			}
		}
		fmt.Fprintf(tty, "Type a number from 1 to %d, or press Enter for %s.\n", len(projects), projects[def].Name)
	}
	return projects[def].ID, projects[def].Name
}
