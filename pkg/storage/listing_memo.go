package storage

import (
	"context"
	"sync"
)

// listingMemo keeps one bucket listing for the command that asked for it.
// list reads the snapshots, the ones behind a delete marker and the node of
// each, and each paged through every version under the prefix, the
// repository's packs included.
type listingMemo struct {
	mu sync.Mutex
	m  map[string][]objectVersion
}

type listingMemoKey struct{}

// WithListingMemo returns ctx carrying a memo for bucket listings. Only the
// read-only listings consult it; a command that writes should not attach
// one, since its own writes would not show in a listing it kept.
func WithListingMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, listingMemoKey{}, &listingMemo{m: map[string][]objectVersion{}})
}

// snapshotVersions is listVersions of the provider's prefix, shared through
// ctx's memo when it carries one. A failure is not kept.
func (s *S3StorageProvider) snapshotVersions(ctx context.Context) ([]objectVersion, error) {
	prefix := s.prefix + "/"
	m, _ := ctx.Value(listingMemoKey{}).(*listingMemo)
	if m == nil {
		return s.listVersions(ctx, prefix)
	}
	key := s.bucket + "\x00" + prefix
	m.mu.Lock()
	if v, ok := m.m[key]; ok {
		m.mu.Unlock()
		return v, nil
	}
	m.mu.Unlock()
	v, err := s.listVersions(ctx, prefix)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.m[key] = v
	m.mu.Unlock()
	return v, nil
}
