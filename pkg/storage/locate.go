package storage

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// NodeLocator reports which node each stored snapshot was filed under: the
// path segment between the prefix and the object, "" for a snapshot written
// flat, before node segmentation.
//
// It exists for disaster recovery. Snapshots are stored under
// <prefix>/<node_id>/, and restore searches under the node configured.
// A machine rebuilding a lost host (holding the key and read access to
// the bucket) may not know the original node ID, so NodeLocator discovers it.
type NodeLocator interface {
	SnapshotNodes(ctx context.Context) (map[string]string, error)
}

// LocateSnapshot points p at the node snapshotID was stored under when it is
// not where p already looks, and returns that node ("" when unchanged or not
// found). Providers that cannot enumerate are left alone.
func LocateSnapshot(ctx context.Context, p StorageProvider, snapshotID string) string {
	if ok, err := p.SnapshotExists(ctx, snapshotID); err == nil && ok {
		return ""
	}
	loc, ok := p.(NodeLocator)
	if !ok {
		return ""
	}
	nodes, err := loc.SnapshotNodes(ctx)
	if err != nil {
		return ""
	}
	node, found := nodes[snapshotID]
	if !found || node == "" {
		return ""
	}
	if setter, ok := p.(interface{ SetNodeID(string) }); ok {
		setter.SetNodeID(node)
		return node
	}
	return ""
}

// nodeOfKey returns the node segment of key under prefix, and whether key is
// a snapshot object at all.
func nodeOfKey(prefix, key string) (id, node string, ok bool) {
	if !strings.HasSuffix(key, ".safegrd") {
		return "", "", false
	}
	rel := strings.TrimPrefix(key, strings.TrimSuffix(prefix, "/")+"/")
	id = strings.TrimSuffix(path.Base(rel), ".safegrd")
	if dir := path.Dir(rel); dir != "." {
		node = path.Base(dir)
	}
	return id, node, true
}

func (s *S3StorageProvider) SnapshotNodes(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	versions, err := s.listVersions(ctx, s.prefix+"/")
	if err == nil {
		for _, v := range versions {
			if v.IsMarker {
				continue
			}
			if id, node, ok := nodeOfKey(s.prefix, v.Key); ok {
				out[id] = node
			}
		}
		return out, nil
	}
	// A provider without versioning (DigitalOcean Spaces): list current keys.
	prefix := s.prefix + "/"
	pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			if id, node, ok := nodeOfKey(s.prefix, *obj.Key); ok {
				out[id] = node
			}
		}
	}
	return out, nil
}

func (l *LocalStorageProvider) SnapshotNodes(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.Walk(l.baseDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(l.baseDir, p)
		if rerr != nil {
			return nil
		}
		if id, node, ok := nodeOfKey("", filepath.ToSlash(rel)); ok {
			out[id] = node
		}
		return nil
	})
	return out, err
}
