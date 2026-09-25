package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
)

// Hosted storage is SafeGrd's own locked bucket. This host never holds a
// credential for it: the remote server signs one request at a time (this part
// of this upload, of this many bytes; this version of this object, to read)
// and sets every object's lock itself. The bytes go straight to the bucket.

// hostedInfo is the remote server's answer to "where does this organization's
// hosted storage stand": the retention to use when the config sets none, the
// quota, and the part size to upload in. It carries no secret.
type hostedInfo struct {
	Bucket         string    `json:"bucket"`
	Prefix         string    `json:"prefix"`
	WORMMode       string    `json:"worm_mode"`
	RetentionDays  int       `json:"retention_days"`
	KeepDaily      int       `json:"keep_daily"`
	KeepWeekly     int       `json:"keep_weekly"`
	KeepMonthly    int       `json:"keep_monthly"`
	MaxRetainUntil time.Time `json:"max_retain_until"`
	QuotaBytes     int64     `json:"quota_bytes"`
	UsedBytes      int64     `json:"used_bytes"`
	PartSize       int64     `json:"part_size"`
	Warning        string    `json:"warning"`
}

// gfs is the plan's retention tiers, used where the config sets none.
func (l *hostedInfo) gfs() gfs {
	if l == nil {
		return gfs{}
	}
	return gfs{Days: l.KeepDaily, Weeks: l.KeepWeekly, Months: l.KeepMonthly}
}

// resolveHostedStorage prepares storage.type: hosted for a command. It asks the
// remote server where the organization stands and fills in the retention the
// config leaves unset. It does nothing for any other storage type.
//
// write is a command about to upload; it is warned when the quota is nearly
// spent. The remote server alone decides whether an upload fits, and refuses
// it at the first request, before any bytes move. Reading never fails for
// quota, so list, verify, restore and export always work.
//
// There is no fallback. The bytes are in SafeGrd's bucket, so without the
// remote server there is nowhere else to reach them; saying so is the only
// honest outcome.
func resolveHostedStorage(ctx context.Context, cfg *config.CLIConfig, storageCfg *config.StorageConfig, write bool) (*hostedInfo, error) {
	if storageCfg.Type != config.StorageTypeHosted {
		return nil, nil
	}
	c, err := newHostedClient(cfg)
	if err != nil {
		return nil, err
	}
	var info hostedInfo
	if err := c.call(ctx, http.MethodGet, "", nil, &info); err != nil {
		return nil, err
	}
	if info.Prefix == "" || info.PartSize <= 0 {
		return nil, fmt.Errorf("hosted storage: the remote server's answer is incomplete")
	}
	// Hosted storage is always locked: the mode is the bucket's, not the host's
	// to choose, and the remote server clamps the date to the plan.
	storageCfg.WORMMode = config.WORMMode(info.WORMMode)
	storageCfg.Prefix = info.Prefix
	if storageCfg.RetentionDays == 0 {
		storageCfg.RetentionDays = info.RetentionDays
	}
	if write && info.Warning != "" {
		fmt.Fprintf(os.Stderr, "⚠️  %s At 100%% new backups are refused; existing ones stay restorable.\n", info.Warning)
	}
	return &info, nil
}

// openStorage returns the provider a command reads and writes through: the
// hosted provider for storage.type: hosted, the ordinary one otherwise.
func openStorage(ctx context.Context, cfg *config.CLIConfig, storageCfg config.StorageConfig) (storage.StorageProvider, error) {
	if storageCfg.Type != config.StorageTypeHosted {
		return storage.NewProvider(ctx, storageCfg)
	}
	c, err := newHostedClient(cfg)
	if err != nil {
		return nil, err
	}
	nodeID := storageCfg.NodeID
	if nodeID == "" {
		nodeID = cfg.NodeID
	}
	return &hostedProvider{client: c, nodeID: nodeID, retentionDays: storageCfg.RetentionDays}, nil
}

// --- talking to the remote server ------------------------------------------------

type hostedClient struct {
	base  string // <server>/api/v1/nodes/<node>/hosted
	token string
	api   *http.Client
	// bucket uploads and downloads parts; no overall timeout, because a part
	// on a slow link takes as long as it takes. A stalled one still fails.
	bucket *http.Client
}

func newHostedClient(cfg *config.CLIConfig) (*hostedClient, error) {
	if cfg.ServerURL == "" || cfg.NodeID == "" || cfg.ServerToken == "" {
		return nil, fmt.Errorf("storage.type is hosted, which needs this host enrolled with the remote server " +
			"(node_id and server_token): run `safegrd enroll`")
	}
	if err := refuseInsecureServerURL(cfg.ServerURL); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 2 * time.Minute
	return &hostedClient{
		base:   fmt.Sprintf("%s/api/v1/nodes/%s/hosted", strings.TrimRight(cfg.ServerURL, "/"), cfg.NodeID),
		token:  cfg.ServerToken,
		api:    &http.Client{Timeout: 60 * time.Second},
		bucket: &http.Client{Transport: transport},
	}, nil
}

// hostedError is a refusal from the remote server, in its own words.
type hostedError struct {
	Status int
	Msg    string
}

func (e *hostedError) Error() string { return "hosted storage: " + e.Msg }

func (c *hostedClient) call(ctx context.Context, method, sub string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+sub, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.api.Do(req)
	if err != nil {
		return fmt.Errorf("hosted storage: the remote server could not be reached: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return &hostedError{Status: resp.StatusCode, Msg: e.Error}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("hosted storage: unreadable answer from the remote server: %w", err)
	}
	return nil
}

// --- the provider ----------------------------------------------------------------

type hostedProvider struct {
	client        *hostedClient
	nodeID        string
	retentionDays int

	mu      sync.Mutex
	objects []hostedObject // cached listing, for one command
}

type hostedObject struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	VersionID string `json:"version_id"`
	Hidden    bool   `json:"hidden"`
}

func (p *hostedProvider) Type() string { return "hosted" }

// SetNodeID points the provider at the node a snapshot was filed under, for
// restoring on a new host (storage.LocateSnapshot).
func (p *hostedProvider) SetNodeID(nodeID string) { p.nodeID = strings.TrimSpace(nodeID) }

func (p *hostedProvider) objectPath(name string) string {
	if p.nodeID == "" {
		return name
	}
	return p.nodeID + "/" + name
}

func (p *hostedProvider) UploadSnapshot(ctx context.Context, snapshotID string, stream io.Reader, _ int64, retentionUntil time.Time) (string, error) {
	if retentionUntil.IsZero() && p.retentionDays > 0 {
		retentionUntil = time.Now().UTC().AddDate(0, 0, p.retentionDays)
	}
	uri, err := p.upload(ctx, snapshotID+".safegrd", stream, retentionUntil)
	if err != nil {
		return "", err
	}
	p.forget()
	return uri, nil
}

func (p *hostedProvider) UploadMetadata(ctx context.Context, snapshotID string, meta *model.SnapshotMetadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	retain := meta.WORMRetentionUntil
	if retain.IsZero() && p.retentionDays > 0 {
		retain = time.Now().UTC().AddDate(0, 0, p.retentionDays)
	}
	if _, err := p.upload(ctx, snapshotID+".meta.json", bytes.NewReader(data), retain); err != nil {
		return err
	}
	p.forget()
	return nil
}

type hostedUpload struct {
	UploadID    string    `json:"upload_id"`
	PartSize    int64     `json:"part_size"`
	RetainUntil time.Time `json:"retain_until"`
	StorageURI  string    `json:"storage_uri"`
}

type hostedPartURL struct {
	PartNumber int32  `json:"part_number"`
	Size       int64  `json:"size"`
	URL        string `json:"url"`
}

// hostedBufferBudget bounds the memory part buffers may take. With 16 MiB
// parts that is four in flight; with 64 MiB parts, two.
const hostedBufferBudget = 128 << 20

// upload streams r to hosted storage as a multipart upload: it reads a part,
// asks the remote server for a URL signed for exactly that part's length, and
// PUTs it, with several parts in flight at once. Any failure aborts the upload,
// so nothing half-written is left to be billed or mistaken for a backup.
func (p *hostedProvider) upload(ctx context.Context, name string, r io.Reader, retainUntil time.Time) (string, error) {
	var up hostedUpload
	if err := p.client.call(ctx, http.MethodPost, "/uploads", map[string]any{
		"node_id": p.nodeID, "name": name, "retain_until": retainUntil,
	}, &up); err != nil {
		return "", err
	}
	if up.PartSize <= 0 {
		return "", fmt.Errorf("hosted storage: the remote server gave no part size")
	}
	concurrency := int(hostedBufferBudget / up.PartSize)
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 4 {
		concurrency = 4
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
		slots    = make(chan struct{}, concurrency)
	)
	fail := func(err error) {
		errOnce.Do(func() { firstErr = err; cancel() })
	}
	var total int64
	for part := int32(1); ; part++ {
		buf := make([]byte, up.PartSize)
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
			total += int64(n)
			wg.Add(1)
			go func(part int32, data []byte) {
				defer wg.Done()
				defer func() { <-slots }()
				if err := p.putPart(ctx, up.UploadID, part, data); err != nil {
					fail(fmt.Errorf("hosted storage: part %d of %s: %w", part, name, err))
				}
			}(part, buf[:n])
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			fail(fmt.Errorf("reading the stream for %s: %w", name, rerr))
			break
		}
		if part >= 10000 {
			fail(fmt.Errorf("hosted storage: %s is larger than 10,000 parts of %s", name, formatBytes(up.PartSize)))
			break
		}
	}
	wg.Wait()
	if firstErr == nil && total == 0 {
		firstErr = fmt.Errorf("hosted storage: %s is empty", name)
	}
	if firstErr != nil {
		p.abort(up.UploadID)
		return "", firstErr
	}
	var done struct {
		StorageURI string `json:"storage_uri"`
		Bytes      int64  `json:"bytes"`
	}
	if err := p.client.call(context.WithoutCancel(ctx), http.MethodPost, "/uploads/"+up.UploadID+"/complete", nil, &done); err != nil {
		return "", err
	}
	if done.Bytes != total {
		return "", fmt.Errorf("hosted storage: %s was stored as %d bytes, %d were sent", name, done.Bytes, total)
	}
	return done.StorageURI, nil
}

// abort tells the remote server to abandon an upload. Said out loud when it
// fails: the server's sweeper will abort it later, but the operator should
// know an upload is dangling.
func (p *hostedProvider) abort(uploadID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.client.call(ctx, http.MethodPost, "/uploads/"+uploadID+"/abort", nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  hosted storage: could not abort the failed upload (%v); the remote server will clean it up\n", err)
	}
}

// putPart asks for a URL signed for exactly this part and uploads it, retrying
// a transient failure with a fresh URL.
func (p *hostedProvider) putPart(ctx context.Context, uploadID string, part int32, data []byte) error {
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt*attempt) * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		var grant struct {
			Parts []hostedPartURL `json:"parts"`
		}
		err := p.client.call(ctx, http.MethodPost, "/uploads/"+uploadID+"/parts", map[string]any{
			"parts": []map[string]any{{"part_number": part, "size": len(data)}},
		}, &grant)
		if err != nil {
			var he *hostedError
			if errors.As(err, &he) && (he.Status/100 == 4 || he.Status == http.StatusInsufficientStorage) {
				return err // a refusal (quota, a closed upload) is not transient
			}
			last = err
			continue
		}
		if len(grant.Parts) != 1 {
			return fmt.Errorf("the remote server granted %d URLs for one part", len(grant.Parts))
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, grant.Parts[0].URL, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.ContentLength = int64(len(data))
		resp, err := p.client.bucket.Do(req)
		if err != nil {
			last = err
			continue
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			return nil
		}
		last = fmt.Errorf("the bucket answered %s: %s", resp.Status, strings.TrimSpace(string(msg)))
		if resp.StatusCode/100 == 4 && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusRequestTimeout {
			return last // a 403 may be an expired URL, worth a fresh one; other 4xx will not change
		}
	}
	return last
}

func (p *hostedProvider) download(ctx context.Context, path string) (io.ReadCloser, error) {
	var d struct {
		URL string `json:"url"`
	}
	if err := p.client.call(ctx, http.MethodPost, "/downloads", map[string]string{"path": path}, &d); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.bucket.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hosted storage: downloading %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		return nil, fmt.Errorf("hosted storage: downloading %s: the bucket answered %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp.Body, nil
}

// fetch reads an object from the node's folder, or from the flat prefix where
// a host without a node id filed it.
func (p *hostedProvider) fetch(ctx context.Context, name string) (io.ReadCloser, error) {
	rc, err := p.download(ctx, p.objectPath(name))
	if err == nil || p.nodeID == "" {
		return rc, err
	}
	var he *hostedError
	if errors.As(err, &he) && he.Status == http.StatusNotFound {
		if flat, ferr := p.download(ctx, name); ferr == nil {
			return flat, nil
		}
	}
	return nil, err
}

func (p *hostedProvider) DownloadSnapshot(ctx context.Context, snapshotID string) (io.ReadCloser, error) {
	return p.fetch(ctx, snapshotID+".safegrd")
}

func (p *hostedProvider) DownloadMetadata(ctx context.Context, snapshotID string) (*model.SnapshotMetadata, error) {
	rc, err := p.fetch(ctx, snapshotID+".meta.json")
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var meta model.SnapshotMetadata
	if err := json.NewDecoder(rc).Decode(&meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	return &meta, nil
}

func (p *hostedProvider) list(ctx context.Context) ([]hostedObject, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.objects != nil {
		return p.objects, nil
	}
	var out struct {
		Objects []hostedObject `json:"objects"`
	}
	if err := p.client.call(ctx, http.MethodGet, "/objects", nil, &out); err != nil {
		return nil, err
	}
	if out.Objects == nil {
		out.Objects = []hostedObject{}
	}
	p.objects = out.Objects
	return p.objects, nil
}

func (p *hostedProvider) forget() {
	p.mu.Lock()
	p.objects = nil
	p.mu.Unlock()
}

// ListSnapshots returns every snapshot in the organization's hosted storage,
// hidden ones included: they are intact and restorable.
func (p *hostedProvider) ListSnapshots(ctx context.Context) ([]string, error) {
	objs, err := p.list(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var ids []string
	for _, o := range objs {
		if !strings.HasSuffix(o.Path, ".safegrd") {
			continue
		}
		id := strings.TrimSuffix(path.Base(o.Path), ".safegrd")
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func (p *hostedProvider) SnapshotExists(ctx context.Context, snapshotID string) (bool, error) {
	objs, err := p.list(ctx)
	if err != nil {
		return false, err
	}
	for _, o := range objs {
		if o.Path == p.objectPath(snapshotID+".safegrd") || o.Path == snapshotID+".safegrd" {
			return true, nil
		}
	}
	return false, nil
}

// SnapshotNodes maps each snapshot to the node folder it is filed under.
func (p *hostedProvider) SnapshotNodes(ctx context.Context) (map[string]string, error) {
	objs, err := p.list(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, o := range objs {
		if !strings.HasSuffix(o.Path, ".safegrd") {
			continue
		}
		id := strings.TrimSuffix(path.Base(o.Path), ".safegrd")
		node := ""
		if dir := path.Dir(o.Path); dir != "." {
			node = dir
		}
		out[id] = node
	}
	return out, nil
}

// DeleteSnapshot never deletes. Hosted snapshots are removed by the remote
// server once their locks expire; no host holds a credential that could.
func (p *hostedProvider) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	return fmt.Errorf("hosted storage: snapshot %s cannot be deleted from this host; the remote server removes "+
		"hosted snapshots once their locks expire", snapshotID)
}

// formatBytes renders a byte count in binary units, for quota messages.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
