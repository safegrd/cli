package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
)

// uploadSidecars writes what sits beside an archive in storage once it is
// uploaded: the manifest, and the recovery document that says how to restore
// the snapshot with the bucket and the key alone. Neither failure fails the
// backup, and neither is quiet: the ciphertext is in the sink, so the backup
// is a backup, but a sidecar that is missing is said on stderr. sealTo is the
// recipient the recovery document is sealed to, or "" to write it as text.
func uploadSidecars(ctx context.Context, provider storage.StorageProvider, storageCfg config.StorageConfig, snapshotID string, meta *model.SnapshotMetadata, sealTo string) {
	warnIfManifestFailed(provider.UploadMetadata(ctx, snapshotID, meta), snapshotID)
	doc := dump.RenderRecoveryDoc(meta, recoveryLocation(storageCfg, meta.NodeID))
	sealed := false
	if sealTo != "" {
		var out bytes.Buffer
		if _, err := crypto.EncryptStream(bytes.NewReader(doc), &out, sealTo); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: the recovery document for %s was not sealed (%v) and was not written.\n", snapshotID, err)
			return
		}
		doc, sealed = out.Bytes(), true
	}
	if err := provider.UploadRecoveryDoc(ctx, snapshotID, doc, sealed, meta.WORMRetentionUntil); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: the recovery document for %s was not written: %v\n"+
			"   The backup and its manifest are in storage; RECOVERY.md beside them is not.\n", snapshotID, err)
	}
}

// recoveryLocation is where a snapshot sits, for its recovery document: the
// storage's kind, bucket, endpoint, region and prefix, and nothing that
// opens it.
func recoveryLocation(c config.StorageConfig, nodeID string) dump.Location {
	switch c.Type {
	case config.StorageTypeHosted:
		return dump.Location{Kind: "hosted"}
	case config.StorageTypeLocal, "":
		p := c.LocalPath
		if p == "" {
			p = "./safegrd-storage"
		}
		if nodeID != "" {
			p = path.Join(p, nodeID)
		}
		return dump.Location{Kind: "local", Prefix: p}
	}
	prefix := strings.Trim(c.Prefix, "/")
	if nodeID != "" && !strings.Contains(prefix, nodeID) {
		prefix = path.Join(prefix, nodeID)
	}
	return dump.Location{Kind: "s3", Bucket: c.Bucket, Endpoint: c.Endpoint, Region: c.Region, Prefix: prefix}
}

// recoveryDocSealTo is the recipient a surface's recovery document is sealed
// to, or "" when it is written as text, the default.
func recoveryDocSealTo(s *config.SurfaceConfig, recipient string) string {
	if s != nil && s.RecoveryDocSealed {
		return recipient
	}
	return ""
}
