package cli

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/wal"
)

// walHostedSmall is the largest object written with one signed PUT; a larger
// bundle or base backup goes up in parts.
const walHostedSmall = 32 << 20

// walHostedStore is a WAL archive on hosted storage. The remote server signs
// every request and chooses every lock; the bytes go straight to the bucket.
// Keys are the ones the host's own bucket would hold, from wal/ down.
type walHostedStore struct {
	p             *hostedProvider
	baseEveryDays int
	// readNode reads another host's archive of the organization; "" reads
	// this host's.
	readNode string
}

func newWALHostedStore(c *config.CLIConfig, s *config.SurfaceConfig) (wal.Store, error) {
	client, err := newHostedClient(c)
	if err != nil {
		return nil, err
	}
	every := 0
	if s.WAL != nil {
		every = s.WAL.BaseEveryDays
	}
	return &walHostedStore{p: &hostedProvider{client: client, nodeID: c.NodeID}, baseEveryDays: every}, nil
}

func (h *walHostedStore) Root() string     { return "" }
func (h *walHostedStore) Describe() string { return "hosted storage" }
func (h *walHostedStore) Locks() bool      { return true }

// walHostedErr turns the remote server's 404 into the archive's ErrNotFound.
func walHostedErr(key string, err error) error {
	var he *hostedError
	if errors.As(err, &he) && he.Status == http.StatusNotFound {
		return fmt.Errorf("%s: %w", key, wal.ErrNotFound)
	}
	return err
}

func (h *walHostedStore) Put(ctx context.Context, key string, body io.Reader, _ time.Time) (time.Time, error) {
	head := make([]byte, walHostedSmall+1)
	n, err := io.ReadFull(body, head)
	switch {
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		return h.putSmall(ctx, key, head[:n])
	case err != nil:
		return time.Time{}, err
	}
	if !strings.HasSuffix(key, ".bundle") && !strings.HasSuffix(key, "/base.tar.zst.age") {
		return time.Time{}, fmt.Errorf("%s is larger than %d MiB, which hosted storage takes in one piece only for a bundle or a base backup", key, walHostedSmall>>20)
	}
	var up hostedUpload
	if err := h.p.client.callRetry(ctx, http.MethodPost, "/wal/uploads", map[string]any{"key": key, "base_every_days": h.baseEveryDays}, &up); err != nil {
		return time.Time{}, err
	}
	if _, err := h.p.sendUpload(ctx, up, key, io.MultiReader(bytes.NewReader(head[:n]), body)); err != nil {
		return time.Time{}, err
	}
	return up.RetainUntil, nil
}

func (h *walHostedStore) putSmall(ctx context.Context, key string, data []byte) (time.Time, error) {
	if len(data) == 0 {
		return time.Time{}, fmt.Errorf("%s is empty", key)
	}
	sum := md5.Sum(data)
	var signed struct {
		Objects []struct {
			Key         string            `json:"key"`
			URL         string            `json:"url"`
			Headers     map[string]string `json:"headers"`
			LockedUntil time.Time         `json:"locked_until"`
		} `json:"objects"`
	}
	if err := h.p.client.callRetry(ctx, http.MethodPost, "/wal/sign", map[string]any{
		"objects":         []map[string]any{{"key": key, "size": len(data), "md5": base64.StdEncoding.EncodeToString(sum[:])}},
		"base_every_days": h.baseEveryDays,
	}, &signed); err != nil {
		return time.Time{}, err
	}
	if len(signed.Objects) != 1 {
		return time.Time{}, fmt.Errorf("the remote server signed %d uploads for one object", len(signed.Objects))
	}
	slot := signed.Objects[0]
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, slot.URL, bytes.NewReader(data))
	if err != nil {
		return time.Time{}, err
	}
	req.ContentLength = int64(len(data))
	for k, v := range slot.Headers {
		req.Header.Set(k, v)
	}
	resp, err := h.p.client.bucket.Do(req)
	if err != nil {
		return time.Time{}, storageFailure(fmt.Errorf("hosted storage: writing %s: %w", key, err))
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return time.Time{}, storageFailure(fmt.Errorf("hosted storage: writing %s: %w", key, bucketError(resp.Status, msg)))
	}
	if err := h.p.client.callRetry(ctx, http.MethodPost, "/wal/uploaded", map[string]any{"keys": []string{key}}, nil); err != nil {
		return time.Time{}, err
	}
	return slot.LockedUntil, nil
}

// signedGet asks for a GET of key and sends it, with a byte range when n > 0.
func (h *walHostedStore) signedGet(ctx context.Context, key string, off, n int64) (*http.Response, error) {
	var signed struct {
		Objects []struct {
			URL string `json:"url"`
		} `json:"objects"`
	}
	if err := h.p.client.callRetry(ctx, http.MethodPost, "/wal/download", map[string]any{"node_id": h.readNode, "keys": []string{key}}, &signed); err != nil {
		return nil, walHostedErr(key, err)
	}
	if len(signed.Objects) != 1 {
		return nil, fmt.Errorf("the remote server signed %d downloads for one object", len(signed.Objects))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signed.Objects[0].URL, nil)
	if err != nil {
		return nil, err
	}
	if n > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+n-1))
	}
	resp, err := h.p.client.bucket.Do(req)
	if err != nil {
		return nil, storageFailure(fmt.Errorf("hosted storage: reading %s: %w", key, err))
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%s: %w", key, wal.ErrNotFound)
		}
		return nil, storageFailure(fmt.Errorf("hosted storage: reading %s: %w", key, bucketError(resp.Status, msg)))
	}
	return resp, nil
}

func (h *walHostedStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := h.signedGet(ctx, key, 0, 0)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (h *walHostedStore) GetRange(ctx context.Context, key string, off, n int64) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	resp, err := h.signedGet(ctx, key, off, n)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		// The bucket ignored the range: skip to it.
		if _, err := io.CopyN(io.Discard, resp.Body, off); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(resp.Body, n))
}

func (h *walHostedStore) GetCurrent(ctx context.Context, key string) (io.ReadCloser, error) {
	return h.Get(ctx, key)
}

func (h *walHostedStore) list(ctx context.Context, prefix string, current bool) ([]wal.Object, error) {
	var listed struct {
		Objects []wal.Object `json:"objects"`
	}
	if err := h.p.client.callRetry(ctx, http.MethodPost, "/wal/list", map[string]any{"node_id": h.readNode, "prefix": prefix, "current": current}, &listed); err != nil {
		return nil, err
	}
	sort.Slice(listed.Objects, func(i, j int) bool { return listed.Objects[i].Key < listed.Objects[j].Key })
	return listed.Objects, nil
}

func (h *walHostedStore) List(ctx context.Context, prefix string) ([]wal.Object, error) {
	return h.list(ctx, prefix, false)
}

func (h *walHostedStore) ListCurrent(ctx context.Context, prefix string) ([]wal.Object, error) {
	return h.list(ctx, prefix, true)
}

func (h *walHostedStore) Children(ctx context.Context, prefix string) ([]string, error) {
	prefix = strings.Trim(prefix, "/") + "/"
	objs, err := h.list(ctx, prefix, false)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, o := range objs {
		name, _, ok := strings.Cut(strings.TrimPrefix(o.Key, prefix), "/")
		if ok && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

// Delete is the remote server's: a bundle's files are retired through it.
func (h *walHostedStore) Delete(context.Context, string) error { return wal.ErrDeleteDenied }

// Retire asks the remote server to delete WAL files a bundle holds. It
// checks each against a bundle's index before it deletes any.
func (h *walHostedStore) Retire(ctx context.Context, keys []string) (int, error) {
	var out struct {
		Deleted int `json:"deleted"`
	}
	if err := h.p.client.callRetry(ctx, http.MethodPost, "/wal/retire", map[string]any{"keys": keys}, &out); err != nil {
		return 0, err
	}
	return out.Deleted, nil
}
