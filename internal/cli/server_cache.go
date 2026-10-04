package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/repo/cache"
)

// serverCache keeps a repository writer's cache on the remote server between
// runs, for a backup that runs on a machine deleted after each run. Without
// it every run would open a new epoch and upload everything again. The cache
// is encrypted here to a key the remote server holds for this surface and
// gives only to the surface's backup runs; the server stores the encrypted
// bytes and cannot read them without that key.
type serverCache struct {
	c         *hostedClient
	surfaceID string
	dir       string
	identity  *age.X25519Identity
}

// serverCacheMaxBytes bounds what is read back, as the remote server bounds
// what it signs.
const serverCacheMaxBytes = 2 << 30

// fetchServerCache gets the surface's cache key and, when the remote server
// holds one, the cache, unpacked into the state directory where the writer
// looks for it. A cache that cannot be read is left out: the run opens a new
// epoch, as on a rebuilt host.
func fetchServerCache(ctx context.Context, c *config.CLIConfig, surfaceID, stateDir string) (*serverCache, string, error) {
	hc, err := newHostedClient(c)
	if err != nil {
		return nil, "", err
	}
	var resp struct {
		Identity string `json:"identity"`
		URL      string `json:"url"`
		Size     int64  `json:"size"`
	}
	if err := hc.call(ctx, http.MethodGet, "/repo/cache?surface_id="+url.QueryEscape(surfaceID), nil, &resp); err != nil {
		return nil, "", err
	}
	id, err := age.ParseX25519Identity(resp.Identity)
	if err != nil {
		return nil, "", fmt.Errorf("the remote server's cache key does not parse")
	}
	sc := &serverCache{c: hc, surfaceID: surfaceID, dir: cache.Dir(stateDir, surfaceID), identity: id}
	if resp.URL == "" {
		return sc, "no cache is kept for this surface yet", nil
	}
	if resp.Size > serverCacheMaxBytes {
		return sc, fmt.Sprintf("the kept cache is %s, over the %s this reads", formatBytes(resp.Size), formatBytes(serverCacheMaxBytes)), nil
	}
	var body []byte
	err = retryTransfer(ctx, func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, resp.URL, nil)
		if err != nil {
			return true, err
		}
		r, err := hc.bucket.Do(req)
		if err != nil {
			return ctx.Err() != nil, err
		}
		defer r.Body.Close()
		if r.StatusCode/100 != 2 {
			return !transient(r.StatusCode), fmt.Errorf("HTTP %d", r.StatusCode)
		}
		body, err = io.ReadAll(io.LimitReader(r.Body, serverCacheMaxBytes+1))
		return false, err
	})
	if err != nil {
		return sc, "the kept cache could not be downloaded (" + err.Error() + ")", nil
	}
	if err := sc.unpack(body); err != nil {
		_ = os.RemoveAll(sc.dir)
		return sc, "the kept cache could not be read (" + err.Error() + ")", nil
	}
	return sc, "", nil
}

func (s *serverCache) unpack(body []byte) error {
	plain, err := age.Decrypt(bytes.NewReader(body), s.identity)
	if err != nil {
		return err
	}
	zr, err := zstd.NewReader(plain)
	if err != nil {
		return err
	}
	defer zr.Close()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || h.Name == "" || strings.ContainsAny(h.Name, "/\\") || h.Name == "." || h.Name == ".." {
			return fmt.Errorf("the cache holds %q, which is not a cache file", h.Name)
		}
		f, err := os.OpenFile(filepath.Join(s.dir, h.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, serverCacheMaxBytes))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
}

// save packs the cache directory, encrypts it to the surface's cache key and
// writes it to the remote server's storage, replacing the one kept before.
func (s *serverCache) save(ctx context.Context) (int64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	var buf bytes.Buffer
	enc, err := age.Encrypt(&buf, s.identity.Recipient())
	if err != nil {
		return 0, err
	}
	zw, err := zstd.NewWriter(enc)
	if err != nil {
		return 0, err
	}
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		f, err := os.Open(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return 0, err
		}
		fi, err := f.Stat()
		if err == nil {
			err = tw.WriteHeader(&tar.Header{Name: e.Name(), Mode: 0o600, Size: fi.Size(), Typeflag: tar.TypeReg})
		}
		if err == nil {
			_, err = io.CopyN(tw, f, fi.Size())
		}
		f.Close()
		if err != nil {
			return 0, err
		}
	}
	if err := tw.Close(); err != nil {
		return 0, err
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	if err := enc.Close(); err != nil {
		return 0, err
	}
	body := buf.Bytes()
	sum := md5.Sum(body)
	var signed struct {
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	}
	if err := s.c.call(ctx, http.MethodPost, "/repo/cache", map[string]any{"surface_id": s.surfaceID, "size": len(body),
		"md5": base64.StdEncoding.EncodeToString(sum[:])}, &signed); err != nil {
		return 0, err
	}
	err = retryTransfer(ctx, func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, signed.URL, bytes.NewReader(body))
		if err != nil {
			return true, err
		}
		req.ContentLength = int64(len(body))
		for k, v := range signed.Headers {
			if !strings.EqualFold(k, "Content-Length") {
				req.Header.Set(k, v)
			}
		}
		r, err := s.c.bucket.Do(req)
		if err != nil {
			return ctx.Err() != nil, err
		}
		defer r.Body.Close()
		if r.StatusCode/100 != 2 {
			msg, _ := io.ReadAll(io.LimitReader(r.Body, 2048))
			return !transient(r.StatusCode), fmt.Errorf("HTTP %d %s", r.StatusCode, strings.TrimSpace(string(msg)))
		}
		return true, nil
	})
	if err != nil {
		return 0, err
	}
	if err := s.c.call(ctx, http.MethodPost, "/repo/cache/done", map[string]any{"surface_id": s.surfaceID}, nil); err != nil {
		return 0, err
	}
	return int64(len(body)), nil
}
