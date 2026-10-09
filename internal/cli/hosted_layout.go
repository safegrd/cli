package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/storage"
)

// storage.layout: hosted reads hosted storage's bucket with the bucket's own
// key, for when the remote server cannot sign a request: list, restore and
// verify work from it with no server.url. The bucket files an organization's
// objects under orgs/<org-id>/safegrd/ (the config's prefix):
//
//	snapshots/<node>/<snapshot>.safegrd, .meta.json   one archive per backup
//	repo/<node>/<surface>/<epoch>/...                 an incremental repository
//
// A customer's own bucket puts the repository under <node>/repo/<surface>, so
// the archive half is the ordinary S3 provider one folder down and the
// repository half needs its keys moved. Nothing here writes: an object
// written past the remote server is one it never locked or counted.

var errHostedLayoutReadOnly = errors.New("storage.layout: hosted only reads hosted storage's bucket; " +
	"back up with storage.type: hosted, through the remote server")

func hostedLayout(s config.StorageConfig) bool { return s.Layout == config.StorageLayoutHosted }

func checkHostedLayout(s config.StorageConfig) error {
	switch {
	case s.Layout == "":
		return nil
	case s.Layout != config.StorageLayoutHosted:
		return fmt.Errorf("storage.layout %q is not a layout; the one value is hosted", s.Layout)
	case s.Type != config.StorageTypeS3:
		return fmt.Errorf("storage.layout: hosted reads a bucket, so it needs storage.type: s3, not %q", s.Type)
	case !strings.HasPrefix(strings.Trim(s.Prefix, "/"), "orgs/"):
		return fmt.Errorf("storage.layout: hosted needs storage.prefix set to the organization's folder, orgs/<org-id>/safegrd")
	}
	return nil
}

// hostedLayoutArchives opens the archive half: snapshots/<node>/ under the
// organization's folder, which is where the S3 provider files a node's
// archives when its prefix is snapshots.
func hostedLayoutArchives(ctx context.Context, s config.StorageConfig) (storage.StorageProvider, error) {
	if err := checkHostedLayout(s); err != nil {
		return nil, err
	}
	s.Prefix = path.Join(strings.Trim(s.Prefix, "/"), "snapshots")
	p, err := storage.NewS3Storage(ctx, s)
	if err != nil {
		return nil, err
	}
	return &readOnlyArchives{p}, nil
}

// readOnlyArchives is the S3 provider with every write refused.
type readOnlyArchives struct{ *storage.S3StorageProvider }

func (readOnlyArchives) UploadSnapshot(context.Context, string, io.Reader, int64, time.Time) (string, error) {
	return "", errHostedLayoutReadOnly
}
func (readOnlyArchives) UploadMetadata(context.Context, string, *model.SnapshotMetadata) error {
	return errHostedLayoutReadOnly
}
func (readOnlyArchives) UploadRecoveryDoc(context.Context, string, []byte, bool, time.Time) error {
	return errHostedLayoutReadOnly
}
func (readOnlyArchives) DeleteSnapshot(context.Context, string) error { return errHostedLayoutReadOnly }
func (readOnlyArchives) ExtendRetention(context.Context, string, time.Time) error {
	return errHostedLayoutReadOnly
}
func (readOnlyArchives) UndeleteSnapshot(context.Context, string) (int, error) {
	return 0, errHostedLayoutReadOnly
}
func (readOnlyArchives) DeleteVersion(context.Context, string, string) error {
	return errHostedLayoutReadOnly
}

// DeleteProbe writes an object to see whether it can delete it.
func (readOnlyArchives) DeleteProbe(context.Context) (bool, bool, string, error) {
	return false, false, "", errHostedLayoutReadOnly
}

// hostedLayoutRepos opens the repository half: one backend per node with a
// repository, or only node's when it is set.
func hostedLayoutRepos(ctx context.Context, s config.StorageConfig, node string) ([]sink.Backend, error) {
	if err := checkHostedLayout(s); err != nil {
		return nil, err
	}
	org := strings.Trim(s.Prefix, "/")
	s.Prefix = org
	s.NodeID = ""
	p, err := storage.NewS3Storage(ctx, s)
	if err != nil {
		return nil, err
	}
	client, bucket, _, _ := p.ObjectStore()
	nodes := []string{node}
	if node == "" {
		all := &sink.S3{Client: client, Bucket: bucket, Prefix: org}
		if nodes, err = all.Children(ctx, path.Join(org, "repo")); err != nil {
			return nil, err
		}
	}
	out := make([]sink.Backend, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, sink.NewDirect(&hostedRepoStore{S3: &sink.S3{Client: client, Bucket: bucket, Prefix: path.Join(org, "repo", n)}}))
	}
	return out, nil
}

// hostedRepoStore is one node's repositories in hosted storage's bucket,
// shown to the repository reader in a customer bucket's layout: its root is
// orgs/<org>/safegrd/repo/<node>, and the reader's <root>/repo/<surface>
// is <root>/<surface> there.
type hostedRepoStore struct{ *sink.S3 }

func (h *hostedRepoStore) in(key string) string {
	root := h.Root()
	if key == root+"/repo" {
		return root
	}
	if rest, ok := strings.CutPrefix(key, root+"/repo/"); ok {
		return root + "/" + rest
	}
	return key
}

func (h *hostedRepoStore) Put(context.Context, string, []byte, [16]byte, time.Time) error {
	return errHostedLayoutReadOnly
}

func (h *hostedRepoStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return h.S3.Get(ctx, h.in(key))
}

func (h *hostedRepoStore) GetRange(ctx context.Context, key string, off, n int64) ([]byte, error) {
	return h.S3.GetRange(ctx, h.in(key), off, n)
}

func (h *hostedRepoStore) List(ctx context.Context, prefix string) ([]sink.ObjectInfo, error) {
	objs, err := h.S3.List(ctx, h.in(prefix))
	if err != nil {
		return nil, err
	}
	root := h.Root()
	for i := range objs {
		if rest, ok := strings.CutPrefix(objs[i].Key, root+"/"); ok {
			objs[i].Key = root + "/repo/" + rest
		}
	}
	return objs, nil
}

func (h *hostedRepoStore) Children(ctx context.Context, prefix string) ([]string, error) {
	return h.S3.Children(ctx, h.in(prefix))
}

func (h *hostedRepoStore) DeleteVersion(context.Context, string, string) error {
	return errHostedLayoutReadOnly
}
