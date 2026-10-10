package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/sink"
)

// hostedRepo is an incremental repository on SafeGrd's hosted storage. The
// remote server opens every epoch and decides its locks, names every key and
// signs every request; this host PUTs and GETs the bytes directly, and holds
// no storage credential.
type hostedRepo struct {
	c *hostedClient
	// node is the node the repository is filed under: the host's own, or
	// the surface's when the daemon registered one for it.
	node string
	// allNodes lists every node's repositories in the organization, for
	// list, find and export: the daemon files a surface under its own node
	// (host--surface), and a host restoring after a lost one has another id
	// again, so a list scoped to this host's id found nothing. Writes stay
	// on node: a host never appends to another node's epoch.
	allNodes bool

	// run is the run this backend is writing, once StartRun named it.
	run string

	mu       sync.Mutex
	prefixes map[string]string // epoch id -> key prefix
	uris     map[string]string // epoch id -> the location a snapshot record carries
	gets     map[string]signedGet
	// signing serialises the signing of one key, so concurrent reads of
	// one pack ask the remote server once; every signed download counts
	// against the day's budget.
	signing sink.PerKey
}

// Transfers to the bucket are tried a few times: a dropped connection or a
// 5xx from the bucket is the ordinary weather of a two-hour upload, and a
// run that dies on one is resumed only at its next schedule.
const hostedTransferAttempts = 4

// hostedTransferBackoff is the first pause between attempts; each later one
// is twice the one before. A variable so tests do not wait.
var hostedTransferBackoff = time.Second

// retryTransfer runs try until it succeeds, says the failure is final, or
// the attempts run out, with a growing pause between attempts.
func retryTransfer(ctx context.Context, try func() (final bool, err error)) error {
	var err error
	for attempt := 0; attempt < hostedTransferAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(hostedTransferBackoff << (attempt - 1)):
			}
		}
		var final bool
		if final, err = try(); err == nil || final {
			return err
		}
	}
	return err
}

// transient reports whether a bucket's answer is one worth trying again:
// a server-side failure, or a request it asked to have slowed down.
func transient(status int) bool { return status/100 == 5 || status == http.StatusTooManyRequests }

type signedGet struct {
	url     string
	size    int64
	expires time.Time
}

func newHostedRepo(c *config.CLIConfig, storageCfg config.StorageConfig) (sink.Backend, error) {
	hc, err := newHostedClient(c)
	if err != nil {
		return nil, err
	}
	node := strings.TrimSpace(storageCfg.NodeID)
	if node == "" {
		node = c.NodeID
	}
	return &hostedRepo{c: hc, node: node, prefixes: map[string]string{}, uris: map[string]string{}, gets: map[string]signedGet{}}, nil
}

func (h *hostedRepo) Describe() string { return "SafeGrd hosted storage" }

// EpochURI names an epoch the way the remote server records a snapshot's
// location: the name it gave the epoch, which carries no bucket.
func (h *hostedRepo) EpochURI(e format.Epoch) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.uris[e.EpochID]
}

type hostedEpochView struct {
	Epoch       json.RawMessage `json:"epoch"`
	Prefix      string          `json:"prefix"`
	StorageURI  string          `json:"storage_uri"`
	NodeID      string          `json:"node_id"`
	SurfaceID   string          `json:"surface_id"`
	State       string          `json:"state"`
	New         bool            `json:"new"`
	OpeningDone bool            `json:"opening_done"`
}

func (h *hostedRepo) remember(v hostedEpochView) (format.Epoch, error) {
	var e format.Epoch
	if err := format.Unmarshal(v.Epoch, &e); err != nil {
		return e, fmt.Errorf("the remote server's epoch does not parse: %w", err)
	}
	if err := e.Validate(); err != nil {
		return e, err
	}
	h.mu.Lock()
	h.prefixes[e.EpochID] = v.Prefix
	h.uris[e.EpochID] = v.StorageURI
	h.mu.Unlock()
	return e, nil
}

func (h *hostedRepo) prefix(epochID string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.prefixes[epochID]
	if !ok {
		return "", fmt.Errorf("epoch %s was not opened or listed in this run", epochID)
	}
	return p, nil
}

// callRetry is the client's callRetry: listings and signed reads wait out a
// 429 instead of failing a restore started in a burst.
func (h *hostedRepo) callRetry(ctx context.Context, method, sub string, in, out any) error {
	return h.c.callRetry(ctx, method, sub, in, out)
}

func (h *hostedRepo) OpenEpoch(ctx context.Context, req sink.OpenRequest) (sink.Opened, error) {
	// The month and a retention increase are the remote server's to decide:
	// it knows the plan's clamps (a trial's locks end with the trial), and a
	// host deciding them from its own settings would open an epoch on every
	// run the clamp applies to. The host asks for a new epoch only for what
	// it alone knows: no cache, a lost one, --new-epoch, another format.
	open, reason := req.Decision.Open, req.Decision.Reason
	if reason == format.ReasonMonth || reason == format.ReasonRetentionIncreased {
		open, reason = false, ""
	}
	body := map[string]any{
		"node_id": h.node, "surface_id": req.SurfaceID, "open": open, "reason": reason,
		"opening_tier": req.OpeningTier, "recipient": req.Recipient, "format": format.Version,
		"retention": map[string]int{"days": req.Retention.Days, "keep_daily": req.Retention.KeepDaily,
			"keep_weekly": req.Retention.KeepWeekly, "keep_monthly": req.Retention.KeepMonthly},
	}
	if req.Current != nil {
		body["current_epoch_id"] = req.Current.Epoch.EpochID
	}
	if req.Chunker != nil {
		body["chunker"] = req.Chunker
	}
	var v hostedEpochView
	if err := h.c.call(ctx, http.MethodPost, "/repo/epochs", body, &v); err != nil {
		return sink.Opened{}, err
	}
	e, err := h.remember(v)
	if err != nil {
		return sink.Opened{}, err
	}
	return sink.Opened{Epoch: e, New: v.New, OpeningDone: v.OpeningDone}, nil
}

type hostedSlot struct {
	Kind        string            `json:"kind"`
	Key         string            `json:"key"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Class       string            `json:"class"`
	RetainUntil time.Time         `json:"retain_until"`
	Locked      *bool             `json:"locked"`
}

type hostedRunView struct {
	RunID     string    `json:"run_id"`
	Mode      string    `json:"mode"`
	Scheduled bool      `json:"scheduled"`
	Locked    bool      `json:"locked"`
	LockUntil time.Time `json:"lock_until"`
	KeptUntil time.Time `json:"kept_until"`
	Slot      string    `json:"slot"`
}

// StartRun tells the remote server a run begins and learns whether its
// objects are locked when written: in a project that locks only the copies
// it keeps, the first run of each day is, the rest are kept unlocked.
func (h *hostedRepo) StartRun(ctx context.Context, e format.Epoch, runID string) (sink.RunDecision, error) {
	var v hostedRunView
	if err := h.callRetry(ctx, http.MethodPost, "/repo/epochs/"+url.PathEscape(e.EpochID)+"/runs", map[string]any{"run_id": runID}, &v); err != nil {
		return sink.RunDecision{}, err
	}
	h.mu.Lock()
	h.run = runID
	h.mu.Unlock()
	if v.Mode != "kept" {
		return sink.RunDecision{}, nil
	}
	return sink.RunDecision{Known: true, Scheduled: v.Scheduled, Locked: v.Locked, LockUntil: v.LockUntil, KeptUntil: v.KeptUntil, Slot: v.Slot}, nil
}

func (h *hostedRepo) runID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.run
}

func (h *hostedRepo) Reserve(ctx context.Context, e format.Epoch, class string, objs []sink.ObjectSpec) ([]sink.Slot, error) {
	type spec struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
		Size int64  `json:"size"`
		MD5  string `json:"md5"`
	}
	in := struct {
		RunID   string `json:"run_id,omitempty"`
		Objects []spec `json:"objects"`
	}{RunID: h.runID()}
	for _, o := range objs {
		in.Objects = append(in.Objects, spec{Kind: string(o.Kind), Name: o.Name, Size: o.Size, MD5: base64.StdEncoding.EncodeToString(o.MD5[:])})
	}
	var out struct {
		Objects []hostedSlot `json:"objects"`
	}
	if err := h.callRetry(ctx, http.MethodPost, "/repo/epochs/"+url.PathEscape(e.EpochID)+"/sign", in, &out); err != nil {
		return nil, err
	}
	if len(out.Objects) != len(objs) {
		return nil, fmt.Errorf("hosted storage signed %d of %d objects", len(out.Objects), len(objs))
	}
	slots := make([]sink.Slot, len(out.Objects))
	for i, s := range out.Objects {
		if s.Class != class {
			return nil, fmt.Errorf("epoch %s takes %s objects now, and this run writes %s ones; run the backup again", e.EpochID, s.Class, class)
		}
		slots[i] = sink.Slot{Kind: objs[i].Kind, Key: s.Key, EpochID: e.EpochID, Class: s.Class, RetainUntil: s.RetainUntil, URL: s.URL, Headers: s.Headers,
			Unlocked: s.Locked != nil && !*s.Locked}
	}
	return slots, nil
}

// Put sends the body to the signed URL with exactly the headers the
// signature covers: its length, its MD5 and its lock. A refusal from the
// bucket is final; a 5xx is tried again. A connection that drops before an
// answer arrives may or may not have delivered the object, and a second PUT
// of a delivered one writes a second version, which is billed: so the
// remote server is asked whether the bucket holds the key, and the body is
// sent again only when it does not.
func (h *hostedRepo) Put(ctx context.Context, slot sink.Slot, body []byte) error {
	for k, v := range slot.Headers {
		if strings.EqualFold(k, "Content-Length") && v != strconv.Itoa(len(body)) {
			return fmt.Errorf("%s was signed for %s bytes, the object is %d", slot.Key, v, len(body))
		}
	}
	return retryTransfer(ctx, func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, slot.URL, bytes.NewReader(body))
		if err != nil {
			return true, err
		}
		req.ContentLength = int64(len(body))
		for k, v := range slot.Headers {
			if !strings.EqualFold(k, "Content-Length") {
				req.Header.Set(k, v)
			}
		}
		resp, err := h.c.bucket.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return true, ctx.Err()
			}
			landed, perr := h.landed(ctx, slot)
			switch {
			case perr != nil:
				return true, fmt.Errorf("uploading %s: %w (and whether it arrived could not be checked: %v)", slot.Key, err, perr)
			case landed:
				return true, nil
			}
			return false, fmt.Errorf("uploading %s: %w", slot.Key, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			return true, nil
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return !transient(resp.StatusCode), fmt.Errorf("hosted storage refused %s: HTTP %d %s", slot.Key, resp.StatusCode, strings.TrimSpace(string(msg)))
	})
}

// landed asks the remote server whether the bucket holds the slot's object,
// by confirming it: the answer records it, which the run does next anyway.
// Only the answer that the bucket does not hold it yet means the body may be
// sent again; any other refusal (the epoch closed meanwhile) is final.
func (h *hostedRepo) landed(ctx context.Context, slot sink.Slot) (bool, error) {
	err := h.uploaded(ctx, slot.EpochID, []string{slot.Key})
	var he *hostedError
	if errors.As(err, &he) && he.Status == http.StatusConflict && strings.Contains(he.Msg, "does not hold") {
		return false, nil
	}
	return err == nil, err
}

func (h *hostedRepo) Uploaded(ctx context.Context, e format.Epoch, keys []string) error {
	return h.uploaded(ctx, e.EpochID, keys)
}

func (h *hostedRepo) uploaded(ctx context.Context, epochID string, keys []string) error {
	return h.callRetry(ctx, http.MethodPost, "/repo/epochs/"+url.PathEscape(epochID)+"/uploaded", map[string]any{"keys": keys}, nil)
}

// Commit names every object the run wrote and every earlier one its
// snapshot reads, so the remote server knows what a kept copy of this run
// holds and can lock it.
func (h *hostedRepo) Commit(ctx context.Context, e format.Epoch, c sink.RunCommit) error {
	return h.callRetry(ctx, http.MethodPost, "/repo/epochs/"+url.PathEscape(e.EpochID)+"/commit", map[string]any{
		"snapshot_id": c.SnapshotID, "run_id": c.RunID, "class": c.Class, "keys": c.Keys, "refs": c.Refs, "retain_until": c.RetainUntil,
	}, nil)
}

func (h *hostedRepo) listEpochs(ctx context.Context, surfaceID string) ([]hostedEpochView, error) {
	q := url.Values{}
	if !h.allNodes {
		q.Set("node_id", h.node)
	}
	if surfaceID != "" {
		q.Set("surface_id", surfaceID)
	}
	var out struct {
		Epochs []hostedEpochView `json:"epochs"`
	}
	if err := h.callRetry(ctx, http.MethodGet, "/repo/epochs?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return out.Epochs, nil
}

func (h *hostedRepo) Epochs(ctx context.Context, surfaceID string) ([]sink.EpochInfo, error) {
	views, err := h.listEpochs(ctx, surfaceID)
	if err != nil {
		return nil, err
	}
	var out []sink.EpochInfo
	for _, v := range views {
		e, err := h.remember(v)
		if err != nil {
			return nil, err
		}
		out = append(out, sink.EpochInfo{Epoch: e, Prefix: v.Prefix})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Epoch.OpenedAt.Before(out[j].Epoch.OpenedAt) })
	return out, nil
}

// Surfaces lists the surfaces with a repository under this node.
func (h *hostedRepo) Surfaces(ctx context.Context) ([]string, error) {
	views, err := h.listEpochs(ctx, "")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range views {
		if !seen[v.SurfaceID] {
			seen[v.SurfaceID] = true
			out = append(out, v.SurfaceID)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (h *hostedRepo) List(ctx context.Context, e sink.EpochInfo, sub string) ([]sink.ObjectInfo, error) {
	var out struct {
		Objects []struct {
			Key  string `json:"key"`
			Size int64  `json:"size"`
		} `json:"objects"`
	}
	q := ""
	if sub != "" {
		q = "?sub=" + url.QueryEscape(sub)
	}
	if err := h.callRetry(ctx, http.MethodGet, "/repo/epochs/"+url.PathEscape(e.Epoch.EpochID)+"/objects"+q, nil, &out); err != nil {
		return nil, err
	}
	objs := make([]sink.ObjectInfo, len(out.Objects))
	for i, o := range out.Objects {
		objs[i] = sink.ObjectInfo{Key: o.Key, Size: o.Size}
	}
	return objs, nil
}

// signed returns a GET URL for key, asking the remote server for it once per
// URL lifetime.
func (h *hostedRepo) signed(ctx context.Context, key string) (signedGet, error) {
	defer h.signing.Lock(key)()
	h.mu.Lock()
	if g, ok := h.gets[key]; ok && time.Until(g.expires) > 15*time.Second {
		h.mu.Unlock()
		return g, nil
	}
	h.mu.Unlock()
	var out struct {
		Objects []struct {
			Key       string    `json:"key"`
			URL       string    `json:"url"`
			Size      int64     `json:"size"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"objects"`
	}
	if err := h.callRetry(ctx, http.MethodPost, "/repo/download", map[string]any{"keys": []string{key}}, &out); err != nil {
		var he *hostedError
		if errors.As(err, &he) && he.Status == http.StatusNotFound {
			return signedGet{}, fmt.Errorf("%s: %w", key, sink.ErrNotFound)
		}
		return signedGet{}, err
	}
	if len(out.Objects) != 1 {
		return signedGet{}, fmt.Errorf("hosted storage signed %d downloads for one key", len(out.Objects))
	}
	g := signedGet{url: out.Objects[0].URL, size: out.Objects[0].Size, expires: out.Objects[0].ExpiresAt}
	h.mu.Lock()
	h.gets[key] = g
	h.mu.Unlock()
	return g, nil
}

// fetch reads key, or a range of it, from its signed URL. A read is
// harmless to repeat, so a dropped connection or a 5xx is tried again.
func (h *hostedRepo) fetch(ctx context.Context, key string, rng string) ([]byte, error) {
	g, err := h.signed(ctx, key)
	if err != nil {
		return nil, err
	}
	var body []byte
	err = retryTransfer(ctx, func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.url, nil)
		if err != nil {
			return true, err
		}
		if rng != "" {
			req.Header.Set("Range", rng)
		}
		resp, err := h.c.bucket.Do(req)
		if err != nil {
			return ctx.Err() != nil, fmt.Errorf("downloading %s: %w", key, err)
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
			body = nil
			return true, nil
		case resp.StatusCode/100 != 2:
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			return !transient(resp.StatusCode), fmt.Errorf("hosted storage refused the download of %s: HTTP %d %s", key, resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		body, err = io.ReadAll(resp.Body)
		return err == nil, err
	})
	return body, err
}

func (h *hostedRepo) Get(ctx context.Context, key string) ([]byte, error) {
	return h.fetch(ctx, key, "")
}

func (h *hostedRepo) GetRange(ctx context.Context, key string, off, n int64) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	b, err := h.fetch(ctx, key, fmt.Sprintf("bytes=%d-%d", off, off+n-1))
	if int64(len(b)) > n {
		b = b[:n]
	}
	return b, err
}
