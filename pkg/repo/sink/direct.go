package sink

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
)

// Direct is a backend that writes straight to a store the host holds a
// credential for: the customer's own bucket, or a directory. The writer's
// policy decides epochs and lock dates.
type Direct struct {
	S Store
}

// NewDirect returns a backend over s.
func NewDirect(s Store) *Direct { return &Direct{S: s} }

func (d *Direct) Describe() string { return d.S.Describe() }

func (d *Direct) OpenEpoch(ctx context.Context, req OpenRequest) (Opened, error) {
	if !req.Decision.Open {
		if req.Current == nil {
			return Opened{}, fmt.Errorf("no epoch to continue")
		}
		return Opened{Epoch: req.Current.Epoch, OpeningDone: req.Current.OpeningDone}, nil
	}
	e, err := policy.NewEpoch(req.Now, req.SurfaceID, req.Decision.Reason, req.OpeningTier, req.Retention, req.Recipient)
	if err != nil {
		return Opened{}, err
	}
	if req.PackTargetBytes > 0 {
		e.PackTargetBytes = req.PackTargetBytes
	}
	if req.Chunker != nil {
		e.Chunker = *req.Chunker
		if err := e.Validate(); err != nil {
			return Opened{}, err
		}
	}
	body, err := format.Marshal(e)
	if err != nil {
		return Opened{}, err
	}
	key, _ := ObjectKey(EpochPrefix(d.S.Root(), e.SurfaceID, e.EpochID), KindEpoch, "")
	if err := d.S.Put(ctx, key, body, md5.Sum(body), e.OpeningRetainUntil); err != nil {
		return Opened{}, fmt.Errorf("writing epoch %s: %w", e.EpochID, err)
	}
	return Opened{Epoch: e, New: true}, nil
}

func (d *Direct) Reserve(_ context.Context, e format.Epoch, class string, objs []ObjectSpec) ([]Slot, error) {
	prefix := EpochPrefix(d.S.Root(), e.SurfaceID, e.EpochID)
	out := make([]Slot, len(objs))
	for i, o := range objs {
		key, err := ObjectKey(prefix, o.Kind, o.Name)
		if err != nil {
			return nil, err
		}
		out[i] = Slot{Kind: o.Kind, Key: key, EpochID: e.EpochID, Class: class, RetainUntil: e.RetainUntil(class)}
	}
	return out, nil
}

func (d *Direct) Put(ctx context.Context, slot Slot, body []byte) error {
	return d.S.Put(ctx, slot.Key, body, md5.Sum(body), slot.RetainUntil)
}

func (d *Direct) Uploaded(context.Context, format.Epoch, []string) error { return nil }

func (d *Direct) Commit(context.Context, format.Epoch, RunCommit) error { return nil }

// Epochs lists a surface's epochs by their descriptors. A store that can
// list the names under a prefix is asked for the epoch directories and then
// for each descriptor by key, which is one listing and one small read per
// epoch; any other store is listed whole, which on a bucket walks every
// pack of every epoch.
func (d *Direct) Epochs(ctx context.Context, surfaceID string) ([]EpochInfo, error) {
	base := path.Join(d.S.Root(), "repo", surfaceID) + "/"
	var ids []string
	if c, ok := d.S.(Children); ok {
		names, err := c.Children(ctx, base)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if format.ValidEpochID(n) {
				ids = append(ids, n)
			}
		}
	} else {
		objs, err := d.S.List(ctx, base)
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			parts := strings.Split(strings.TrimPrefix(o.Key, base), "/")
			if len(parts) == 2 && parts[1] == "epoch.json" && format.ValidEpochID(parts[0]) {
				ids = append(ids, parts[0])
			}
		}
	}
	var out []EpochInfo
	for _, id := range ids {
		key := path.Join(base, id, "epoch.json")
		body, err := d.Get(ctx, key)
		if errors.Is(err, ErrNotFound) {
			continue // a directory with no descriptor is not an epoch
		}
		if err != nil {
			return nil, fmt.Errorf("epoch %s: %w", id, err)
		}
		var e format.Epoch
		if err := format.Unmarshal(body, &e); err != nil {
			return nil, fmt.Errorf("epoch %s: epoch.json does not parse: %w", id, err)
		}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		if e.EpochID != id || e.SurfaceID != surfaceID {
			return nil, fmt.Errorf("epoch %s: epoch.json names epoch %s of surface %s", id, e.EpochID, e.SurfaceID)
		}
		out = append(out, EpochInfo{Epoch: e, Prefix: path.Join(base, id)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Epoch.OpenedAt.Before(out[j].Epoch.OpenedAt) })
	return out, nil
}

// Children is a store that can list the names directly under a prefix.
type Children interface {
	Children(ctx context.Context, prefix string) ([]string, error)
}

// Surfaces lists the surface ids that have a repository in this store.
func (d *Direct) Surfaces(ctx context.Context) ([]string, error) {
	base := path.Join(d.S.Root(), "repo")
	if c, ok := d.S.(Children); ok {
		names, err := c.Children(ctx, base)
		if err != nil {
			return nil, err
		}
		sort.Strings(names)
		return names, nil
	}
	objs, err := d.S.List(ctx, base+"/")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, o := range objs {
		parts := strings.Split(strings.TrimPrefix(o.Key, base+"/"), "/")
		if len(parts) == 3 && parts[2] == "epoch.json" && !seen[parts[0]] {
			seen[parts[0]] = true
			out = append(out, parts[0])
		}
	}
	sort.Strings(out)
	return out, nil
}

func (d *Direct) List(ctx context.Context, e EpochInfo, sub string) ([]ObjectInfo, error) {
	prefix := e.Prefix + "/"
	if sub != "" {
		prefix = path.Join(e.Prefix, sub) + "/"
	}
	return d.S.List(ctx, prefix)
}

func (d *Direct) Get(ctx context.Context, key string) ([]byte, error) {
	rc, err := d.S.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (d *Direct) GetRange(ctx context.Context, key string, off, n int64) ([]byte, error) {
	return d.S.GetRange(ctx, key, off, n)
}
