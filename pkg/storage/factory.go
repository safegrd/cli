package storage

import (
	"context"
	"fmt"

	"github.com/safegrd/cli/pkg/config"
)

// NewProvider constructs the appropriate StorageProvider based on configuration.
func NewProvider(ctx context.Context, cfg config.StorageConfig) (StorageProvider, error) {
	switch cfg.Type {
	case config.StorageTypeLocal:
		path := cfg.LocalPath
		if path == "" {
			path = "./safegrd-storage"
		}
		prov, err := NewLocalStorage(path)
		if err != nil {
			return nil, err
		}
		if cfg.NodeID != "" {
			prov.SetNodeID(cfg.NodeID)
		}
		return prov, nil
	case config.StorageTypeS3:
		return NewS3Storage(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported storage provider type: %s", cfg.Type)
	}
}
