package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// maxUnsentPerSurface caps the records a surface keeps waiting to be sent. A
// host offline for months at an hourly schedule would otherwise grow its state
// file without bound; past the cap the oldest is dropped, and said. Its
// snapshot is still in the bucket and 'safegrd list' still shows it.
const maxUnsentPerSurface = 500

// UnsentRecord is a backup the remote server has not recorded because it could
// not be reached, or failed in a way worth trying again. It is kept in the
// daemon's state and sent, oldest first, once a heartbeat gets an answer.
type UnsentRecord struct {
	Meta          model.SnapshotMetadata `json:"meta"`
	FirstFailedAt time.Time              `json:"first_failed_at"`
	Reason        string                 `json:"reason"`
}

// reportSnapshot sends a finished backup's record and, when the failure is
// one worth retrying, keeps it to send again. It returns what notRecorded
// holds for this run.
func reportSnapshot(ctx context.Context, c *config.CLIConfig, st *SurfaceState, meta *model.SnapshotMetadata) string {
	reason, retry := deliverSnapshotRecord(ctx, c.ServerURL, c.ServerToken, meta, false)
	if reason == "" || !retry {
		return reason
	}
	keepUnsent(st, meta, reason)
	return reason + "; sent again when the remote server answers"
}

func keepUnsent(st *SurfaceState, meta *model.SnapshotMetadata, reason string) {
	st.Unsent = append(st.Unsent, UnsentRecord{Meta: *meta, FirstFailedAt: time.Now().UTC(), Reason: reason})
	if over := len(st.Unsent) - maxUnsentPerSurface; over > 0 {
		for _, dropped := range st.Unsent[:over] {
			fmt.Fprintf(os.Stderr, "⚠️  Surface %s: %d backup records are waiting to be sent; dropping the oldest, %s. "+
				"Its snapshot is in your storage and 'safegrd list' shows it.\n",
				st.SurfaceID, maxUnsentPerSurface, dropped.Meta.SnapshotID)
		}
		st.Unsent = append([]UnsentRecord(nil), st.Unsent[over:]...)
	}
}

// resendUnsent sends the records a surface kept, oldest first, and stops at
// the first that still cannot be delivered so their order holds. A record the
// remote server now refuses outright is dropped with the reason, since sending
// it again would be refused again. It returns how many were recorded.
func resendUnsent(ctx context.Context, c *config.CLIConfig, st *SurfaceState) int {
	sent := 0
	for len(st.Unsent) > 0 {
		rec := st.Unsent[0]
		reason, retry := deliverSnapshotRecord(ctx, c.ServerURL, c.ServerToken, &rec.Meta, false)
		if reason != "" && retry {
			break
		}
		st.Unsent = st.Unsent[1:]
		if reason != "" {
			fmt.Fprintf(os.Stderr, "❌ Surface %s: the record of %s was refused when sent again: %s\n",
				st.SurfaceID, rec.Meta.SnapshotID, reason)
			continue
		}
		sent++
	}
	if len(st.Unsent) == 0 {
		st.Unsent = nil
		// The last backup's "not recorded" is no longer true once its record
		// is in.
		if strings.HasPrefix(st.LastError, "not recorded: ") && strings.Contains(st.LastError, "sent again") {
			st.LastError = ""
		}
	}
	if sent > 0 {
		fmt.Printf("📨 Surface %s: sent %d backup record(s) the remote server had not received.\n", st.SurfaceID, sent)
	}
	return sent
}
