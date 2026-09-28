package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// A claim is the code the console issues for one host: it names the project
// this host joins, where its backups go, and the surfaces it protects, all of
// which were chosen in the browser. The code only says which setup this is;
// the host still authenticates with the login saved by `safegrd login`.

type claimSurface struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	SurfaceType string `json:"surface_type"`
	Config      struct {
		Schedule      string   `json:"schedule"`
		RetentionDays int      `json:"retention_days"`
		CredentialEnv string   `json:"credential_env"`
		Path          string   `json:"path"`
		Roots         []string `json:"roots"`
		Excludes      []string `json:"excludes"`
		Host          string   `json:"host"`
		Port          int      `json:"port"`
		Username      string   `json:"username"`
		Folders       []string `json:"folders"`
	} `json:"config"`
}

type claimPreview struct {
	ClaimID     string         `json:"claim_id"`
	OrgID       string         `json:"org_id"`
	ProjectID   string         `json:"project_id"`
	ProjectName string         `json:"project_name"`
	StorageKind string         `json:"storage_kind"`
	KeyCustody  string         `json:"key_custody"`
	Surfaces    []claimSurface `json:"surfaces"`
}

// fetchClaim asks the remote server what a claim code is for.
func fetchClaim(serverURL, credential, code string) (*claimPreview, error) {
	// In the body, never the URL: a URL is written to access logs, and the
	// code should not be.
	body, _ := json.Marshal(map[string]string{"code": code})
	req, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(serverURL, "/")+"/api/v1/onboarding/claim", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("User-Agent", UserAgent())
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not ask %s about the claim: %w", serverURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if body.Error == "" {
			body.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("the claim was refused: %s", body.Error)
	}
	var pv claimPreview
	if err := json.NewDecoder(resp.Body).Decode(&pv); err != nil {
		return nil, fmt.Errorf("could not read the claim: %w", err)
	}
	if pv.OrgID == "" || pv.ProjectID == "" {
		return nil, fmt.Errorf("the remote server's answer about the claim is incomplete")
	}
	return &pv, nil
}

// surfaceConfigFor is the host's config stanza for a surface named in the
// console. It holds no secret: a credential is the name of an environment
// variable this host sets.
func surfaceConfigFor(s claimSurface) config.SurfaceConfig {
	sc := config.SurfaceConfig{
		ID: s.Key, Type: s.SurfaceType, Name: s.Name,
		Schedule: s.Config.Schedule, RetentionDays: s.Config.RetentionDays,
	}
	switch s.SurfaceType {
	case "postgres", "mysql", "mongodb":
		sc.DatabaseURLEnv = s.Config.CredentialEnv
	case "sqlite":
		sc.DatabaseURL = "sqlite://" + s.Config.Path
	case "files":
		sc.Roots, sc.Excludes = s.Config.Roots, s.Config.Excludes
	case "email":
		sc.Host, sc.Port, sc.Username, sc.Folders = s.Config.Host, s.Config.Port, s.Config.Username, s.Config.Folders
		sc.PasswordEnv = s.Config.CredentialEnv
	}
	return sc
}

// addClaimSurfaces writes the claim's surfaces into the config, keeping any
// the config already has under the same id, and says what the host must
// provide for each.
func addClaimSurfaces(c *config.CLIConfig, surfaces []claimSurface) {
	have := map[string]bool{}
	for _, s := range c.Surfaces {
		have[s.ID] = true
	}
	if len(surfaces) == 0 {
		return
	}
	fmt.Printf("\n📋 Surfaces named for this host in the console:\n")
	for _, s := range surfaces {
		if have[s.Key] {
			fmt.Printf("   %-20s already in this config; left as it is\n", s.Key)
			continue
		}
		c.Surfaces = append(c.Surfaces, surfaceConfigFor(s))
		switch {
		case s.Config.CredentialEnv != "":
			fmt.Printf("   %-20s %s: set %s on this host (the credential never leaves it)\n", s.Key, s.SurfaceType, s.Config.CredentialEnv)
		default:
			fmt.Printf("   %-20s %s\n", s.Key, s.SurfaceType)
		}
	}
}
