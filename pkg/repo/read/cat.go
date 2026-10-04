package read

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/sink"
)

// catRangeBytes bounds one range request of a Cat: consecutive blobs of a
// file that lie end to end in one pack are fetched together up to this size.
const catRangeBytes = 16 << 20

// Cat writes one file of a snapshot to w in order, and fails if what it wrote
// does not match the file's size and SHA-256. A database restore reads a run
// this way, table by table, without a copy on disk.
func (r *Repo) Cat(ctx context.Context, idx Index, n format.Node, w io.Writer) error {
	if n.Type != format.NodeFile {
		return fmt.Errorf("%s is not a file", n.Name)
	}
	h := sha256.New()
	out := io.MultiWriter(w, h)
	var size int64
	for i := 0; i < len(n.Content); {
		first, ok := idx[n.Content[i]]
		if !ok {
			return fmt.Errorf("%s: blob %s is in no index the snapshot lists", n.Name, n.Content[i])
		}
		if format.BlobKind(first.Entry.Type) != format.BlobData {
			return fmt.Errorf("%s: blob %s is stored as a tree", n.Name, n.Content[i])
		}
		// The run of blobs that follow each other in the same pack.
		j, end := i+1, first.Entry.Offset+first.Entry.Length
		for j < len(n.Content) {
			loc, ok := idx[n.Content[j]]
			if !ok || loc.Pack != first.Pack || loc.Entry.Offset != end || end-first.Entry.Offset+loc.Entry.Length > catRangeBytes {
				break
			}
			end += loc.Entry.Length
			j++
		}
		o, hdr, err := r.opener(ctx, first.Pack)
		if err != nil {
			return err
		}
		if first.Entry.Offset < int64(hdr) {
			return fmt.Errorf("pack %s: a blob starts inside the header", first.Pack)
		}
		data, err := r.B.GetRange(ctx, r.key(sink.KindPack, first.Pack), first.Entry.Offset, end-first.Entry.Offset)
		if err != nil {
			return fmt.Errorf("pack %s: %w", first.Pack, err)
		}
		if int64(len(data)) != end-first.Entry.Offset {
			return fmt.Errorf("pack %s is shorter than its index says", first.Pack)
		}
		for k := i; k < j; k++ {
			e := idx[n.Content[k]].Entry
			rec := data[e.Offset-first.Entry.Offset : e.Offset-first.Entry.Offset+e.Length]
			plain, err := o.Blob(rec, e)
			if err != nil {
				return fmt.Errorf("%s: pack %s: %w", n.Name, first.Pack, err)
			}
			if format.Hash(plain) != n.Content[k] {
				return fmt.Errorf("%s: blob %s does not hash to its id", n.Name, n.Content[k])
			}
			if _, err := out.Write(plain); err != nil {
				return err
			}
			size += int64(len(plain))
		}
		i = j
	}
	if size != n.Size {
		return fmt.Errorf("%s is %d bytes, its tree says %d", n.Name, size, n.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != n.SHA256 {
		return fmt.Errorf("%s does not match its SHA-256: %s, recorded %s", n.Name, got, n.SHA256)
	}
	return nil
}
