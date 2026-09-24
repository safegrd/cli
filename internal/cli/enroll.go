package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

func newEnrollCmd() *cobra.Command {
	var (
		token      string
		apiKey     string
		nodeName   string
		projectID  string
		orgID      string
		nodeIDFlag string
		keyCustody string
	)

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this node with the SafeGrd Remote Server using an API key or node token",
		Long: `Authenticates the local CLI agent with the SafeGrd remote server.
You can either provide a direct Node Token or an Organization API Key to register this node.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			serverURL := resolveServerURL()

			// Did the operator bring their own key? Decided BEFORE the local
			// setup runs, because that step generates one when none is found —
			// after it, every host looks like it had a key all along.
			//
			// This is the whole of the custody decision. A key
			// the operator supplied is theirs and never leaves the host; a key
			// we just generated is escrowed, so that losing the host is not
			// losing the backups. --key-custody=local opts out and makes the
			// operator responsible for it.
			keyExistedBeforeEnroll := cfg != nil && cfg.Encryption.PublicKey != ""

			// Whether this host already had an identity of its own, captured
			// before the local setup runs and invents one.
			hostAlreadyHadNodeID := cfg != nil && cfg.NodeID != ""

			// Do the local half if it has not been done. Enrolling used to read
			// cfg.NodeID out of a config LoadCLIConfig had invented from
			// defaults, which registered a node with an empty identity and no
			// keypair — enrolled, and unable to encrypt anything.
			created, adopted, err := ensureLocalSetup(nodeName)
			if err != nil {
				return err
			}
			if created {
				fmt.Printf("📁 No local setup found, so it was created before enrolling.\n\n")
			}
			// An identity found on disk is the operator's, whatever wrote it.
			// It reaches here when a previous enrollment generated the key and
			// then failed before writing a config, so this is the retry — and
			// escrowing a key that was already on this host, without being
			// asked in that run, is a custody decision made on somebody's
			// behalf. The conservative half is the one that cannot be undone:
			// a key we did not send stays theirs, and we say so.
			if adopted {
				keyExistedBeforeEnroll = true
			}

			fmt.Printf("🌐 Connecting to SafeGrd Remote Server at %s...\n", serverURL)

			// A Personal Access Token passed to --token is registration, not a
			// node token.
			//
			// This is what the documentation, docs.html and the dashboard's own
			// copy-paste command all tell an operator to run — all three print
			// `enroll --token sg_pat_...`. Before this dispatch that landed in
			// the node-token path below: the PAT was written to server_token, a
			// heartbeat was attempted for a node that did not exist, the 403
			// came back as a one-line warning, and the command printed
			// "Configuration updated" and exited 0 having registered nothing.
			// The operator had a config, a key, and no node in the console.
			//
			// The prefixes are unambiguous — sg_pat_ for an operator
			// credential, sg_tok_ for a node's own — so this routes on the
			// prefix rather than asking the operator to know which flag their
			// token belongs to.
			if apiKey == "" && strings.HasPrefix(token, "sg_pat_") {
				fmt.Printf("🔑 That is a personal access token, so this host will be registered with it.\n")
				apiKey, token = token, ""
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
				// later command — reporting a snapshot, fetching credentials —
				// spoke about a node the remote server has never heard of,
				// while the console showed the real node as never having
				// checked in.
				switch {
				case nodeIDFlag != "":
					cfg.NodeID = nodeIDFlag
				case !hostAlreadyHadNodeID:
					return fmt.Errorf("a node token authenticates one existing node, and this host "+
						"has no node id of its own yet, so there is nothing to attach the token to.\n"+
						"  Pass --node-id <id> — the console shows it beside the token — or enrol with a\n"+
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

				// A rejected credential is not a warning. There is nothing to
				// protect yet on this path — no backup depends on it (protection
				// continuing without the remote server is not enrollment
				// pretending to have happened) — and a config
				// saved with a token the server refuses would make every later
				// command fail somewhere else.
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
					fmt.Printf("⚠️  Could not verify the token: %v\n", err)
					fmt.Printf("   The config below is being written unverified. Run 'safegrd status' once\n")
					fmt.Printf("   the remote server is reachable to confirm this node is enrolled.\n")
				default:
					fmt.Printf("✅ Node token authenticated successfully!\n")
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

				// Two different journeys, named rather than inferred:
				//
				//   --key-custody=safegrd  generate here, send it, SafeGrd can
				//                          decrypt, losing this host is survivable
				//   --key-custody=local    generate here, write it to key_path,
				//                          send only the recipient, nobody but
				//                          you can ever read these backups
				//
				// A key the operator supplied is always local. Sending someone
				// else's existing key is a decision no flag should make on
				// their behalf — it may be shared with other systems, and its
				// custody was settled before SafeGrd was involved.
				switch keyCustody {
				case "", "safegrd", "local":
				default:
					return fmt.Errorf("--key-custody must be 'safegrd' or 'local', got %q", keyCustody)
				}
				if keyExistedBeforeEnroll && keyCustody == "safegrd" {
					return fmt.Errorf("refusing to send a key you supplied.\n" +
						"  --key-custody=safegrd generates a new key and escrows it; it does not hand over an existing one.\n" +
						"  The key already configured here stays yours. Remove it from the config first if you " +
						"really want SafeGrd to hold a freshly generated one instead")
				}
				escrowRequested := generatedNow && keyCustody != "local"

				// org_id is mandatory server-side and is never inferred there:
				// registering without it would bypass the tier quota, which is
				// why the remote server refuses (handlers.go). The CLI never
				// sent it, so every `enroll --api-key` ended in
				// "org_id is required for node registration" — the whole
				// registration path was unreachable.
				if orgID == "" {
					resolved, err := resolveEnrollmentOrg(serverURL, apiKey)
					if err != nil {
						return err
					}
					orgID = resolved
					fmt.Printf("🏢 Organization: %s\n", orgID)
				}

				regReq := model.NodeRegisterRequest{
					NodeID:        cfg.NodeID,
					OrgID:         orgID,
					ProjectID:     projectID,
					Name:          name,
					DatabaseName:  "postgres",
					StorageBucket: cfg.Storage.Bucket,
					RetentionDays: cfg.Storage.RetentionDays,

					// The recipient is public and always sent: the control
					// plane needs it to name which key this node uses and to
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

				var regResp model.NodeRegisterResponse
				if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
					return fmt.Errorf("invalid server response: %w", err)
				}

				cfg.ServerURL = serverURL
				cfg.ServerToken = regResp.Token
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
					fmt.Printf("\n❌ The server did NOT store your encryption key.\n\n")
					fmt.Printf("   This node is enrolled, but the key below exists in exactly one place:\n")
					fmt.Printf("   %s\n\n", cfg.Encryption.KeyPath)
					fmt.Printf("   SAVE IT NOW. Without it every backup this node takes is unreadable,\n")
					fmt.Printf("   by you and by us. Nobody can recover it for you.\n\n")
					fmt.Printf("   Public key:  %s\n", cfg.Encryption.PublicKey)
					fmt.Printf("   Fingerprint: %s\n", crypto.Fingerprint(cfg.Encryption.PublicKey))
					return fmt.Errorf("enrollment completed but key escrow failed — save the key above before running a backup")
				}

				fmt.Printf("✅ Successfully enrolled node '%s'!\n", regResp.NodeID)
				fmt.Printf("   Node Token:  %s\n", regResp.Token)
				fmt.Printf("   Key:         %s\n", crypto.Fingerprint(cfg.Encryption.PublicKey))

				// Say which custody the operator ended up in, every time, in
				// words. A customer must never have to read documentation to
				// find out whether their vendor can read their backups.
				switch {
				case regResp.KeyEscrowed:
					fmt.Printf("   Custody:     SafeGrd holds a copy of this key and CAN decrypt these backups.\n")
					fmt.Printf("                It was generated here just now; --key-custody=local keeps the next one to yourself.\n")
				case keyExistedBeforeEnroll:
					fmt.Printf("   Custody:     you hold this key. SafeGrd has only the public half and CANNOT decrypt these backups.\n")
					if adopted {
						// The key was found on this host rather than named by a
						// config, which is the retry after a failed
						// enrollment. The operator may well have wanted the
						// default — escrow — and silently getting the other
						// answer is the kind of custody surprise this command
						// exists to prevent, so the remedy is stated.
						fmt.Printf("                It was already at %s, so it was not sent: a key we find on a host\n", cfg.Encryption.KeyPath)
						fmt.Printf("                is yours. To have SafeGrd hold one instead, move that file aside and\n")
						fmt.Printf("                re-run with --key-custody=safegrd.\n")
					}
				default:
					fmt.Printf("   Custody:     you hold this key (--key-custody=local). SafeGrd CANNOT decrypt these backups.\n")
					fmt.Printf("                Back up %s — nobody can recover it for you.\n", cfg.Encryption.KeyPath)
				}
				if cfg.ProjectID != "" {
					fmt.Printf("   Project ID:  %s\n", cfg.ProjectID)
				}
			}

			targetConfig := cfgFile
			if targetConfig == "" {
				targetConfig, _ = config.DefaultConfigFile()
			}
			if err := config.SaveCLIConfig(cfg, targetConfig); err != nil {
				return fmt.Errorf("failed updating config: %w", err)
			}

			fmt.Printf("💾 Configuration updated at: %s\n", targetConfig)
			return nil
		},
	}

	cmd.Flags().StringVar(&token, "token", "", "Pre-issued Node Token from dashboard")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Organization/Admin API Key for dynamic registration")
	cmd.Flags().StringVar(&nodeName, "node-name", "", "Human-readable name for this node")
	cmd.Flags().StringVar(&projectID, "project", "", "Project ID or slug to attach this node to (defaults to org default project)")
	cmd.Flags().StringVar(&nodeIDFlag, "node-id", "",
		"The node this token belongs to, for --token. The console shows it beside the token. "+
			"Not needed with a personal access token, which registers a new node.")
	cmd.Flags().StringVar(&orgID, "org", "",
		"Organization to enrol this node into. Only needed when the credential can see more than one: "+
			"with a single organization it is resolved automatically.")
	cmd.Flags().StringVar(&keyCustody, "key-custody", "",
		"Who holds the encryption key when this command generates one: "+
			"'safegrd' (default) sends it to the remote server, so losing this host does not lose the backups, "+
			"and SafeGrd can decrypt them; "+
			"'local' writes it to key_path and sends only the public half, so nobody but you can ever read them "+
			"and nobody can recover it if you lose it. "+
			"Ignored when you supplied your own key — that one is never sent.")

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
