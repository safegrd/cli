package dump

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ObjectRestoreResult is what a restore into a bucket wrote.
type ObjectRestoreResult struct {
	// Root is the bucket and prefix written to, as s3://bucket/prefix.
	Root string `json:"root"`
	// ObjectsWritten counts the files uploaded, one object each.
	ObjectsWritten int64 `json:"objects_written"`
	BytesWritten   int64 `json:"bytes_written"`
	// Directories counts the archive's directories, which a bucket has no
	// object for: their keys imply them.
	Directories int `json:"directories"`
	// WithContentType counts the objects uploaded with the content type the
	// backup sealed for them.
	WithContentType int64 `json:"with_content_type"`
}

// objectRestorePartSize is the size of each part of a large object's upload,
// and so the most of one file held in memory at a time.
const objectRestorePartSize = 16 << 20

// RestoreArchiveToObjectStore uploads a files archive into a bucket: each
// file to the key prefix/path, with the content type sealed in the archive's
// manifest. It is the reverse of a bucket backup, and also takes a snapshot of
// a directory on a host.
//
// Every file's bytes are hashed as they are uploaded and held to the sealed
// manifest. A file whose hash differs fails before its upload completes: the
// transfer reads the whole of a small file before it sends it, and aborts a
// multipart upload of a large one, so the object is never created. The
// archive's symlinks are refused by name before anything is written, since a
// bucket has no link to restore one as.
//
// Objects already at a key are replaced. A restore that fails part way has
// written the files before the one it names, and the error says how many.
func RestoreArchiveToObjectStore(ctx context.Context, src io.Reader, dst ObjectStoreSource) (*ObjectRestoreResult, error) {
	client, err := dst.client(ctx)
	if err != nil {
		return nil, err
	}
	res := &ObjectRestoreResult{Root: dst.Root()}
	prefix := strings.Trim(dst.Prefix, "/")
	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		u.PartSize = objectRestorePartSize
		u.Concurrency = 2
	})

	tr := tar.NewReader(src)
	var sealed map[string]FileEntryManifest
	failed := func(err error) error {
		if res.ObjectsWritten == 0 {
			return fmt.Errorf("%w. Nothing was written to %s", err, res.Root)
		}
		return fmt.Errorf("%w. %d files were written to %s before this one; the rest were not", err, res.ObjectsWritten, res.Root)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, failed(err)
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, failed(fmt.Errorf("reading the archive: %w", err))
		}
		name := path.Clean(strings.ReplaceAll(hdr.Name, "\\", "/"))
		if name == ".safegrd-manifest.json" {
			var m SealedFileManifest
			if err := json.NewDecoder(tr).Decode(&m); err != nil {
				return nil, failed(fmt.Errorf("the archive's sealed manifest does not parse: %w", err))
			}
			sealed = map[string]FileEntryManifest{}
			var links []string
			for _, e := range m.Entries {
				sealed[path.Clean(strings.ReplaceAll(e.Path, "\\", "/"))] = e
				if e.IsSymlink {
					links = append(links, e.Path)
				}
			}
			if len(links) > 0 {
				sort.Strings(links)
				return nil, failed(fmt.Errorf("the snapshot holds %d symlinks, which a bucket has no object for: %s. Restore it to a directory with --target-dir",
					len(links), strings.Join(firstN(links, 5), ", ")))
			}
			continue
		}
		if name == "." || name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) {
			return nil, failed(fmt.Errorf("the archive entry %s points outside the restore", hdr.Name))
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			res.Directories++
			continue
		case tar.TypeReg:
		case tar.TypeSymlink:
			return nil, failed(fmt.Errorf("the archive entry %s is a symlink, which a bucket has no object for. Restore it to a directory with --target-dir", hdr.Name))
		default:
			return nil, failed(fmt.Errorf("the archive entry %s has tar type %q, which a SafeGrd file backup never writes", hdr.Name, string(hdr.Typeflag)))
		}
		if sealed == nil {
			return nil, failed(fmt.Errorf("the archive entry %s comes before any sealed manifest; refusing to upload unverified files", hdr.Name))
		}
		want, ok := sealed[name]
		if !ok || want.IsDir || want.IsSymlink {
			return nil, failed(fmt.Errorf("the archive entry %s is not a file in the sealed manifest", hdr.Name))
		}
		key := name
		if prefix != "" {
			key = prefix + "/" + name
		}
		body := &digestReader{r: io.LimitReader(tr, hdr.Size), h: sha256.New(), want: want.Sha256, size: hdr.Size, name: name}
		in := &s3.PutObjectInput{Bucket: aws.String(dst.Bucket), Key: aws.String(key), Body: body}
		if want.ContentType != "" {
			in.ContentType = aws.String(want.ContentType)
		}
		if _, err := uploader.Upload(ctx, in); err != nil {
			var digest *digestMismatch
			if errors.As(err, &digest) {
				return nil, failed(digest)
			}
			return nil, failed(fmt.Errorf("uploading %s to s3://%s/%s: %w", name, dst.Bucket, key, err))
		}
		res.ObjectsWritten++
		res.BytesWritten += body.read
		if want.ContentType != "" {
			res.WithContentType++
		}
	}
	if sealed == nil {
		return nil, failed(errors.New("the archive has no sealed manifest"))
	}
	return res, nil
}

// digestMismatch is a file whose bytes are not the ones the backup sealed.
type digestMismatch struct{ name, got, want string }

func (d *digestMismatch) Error() string {
	return fmt.Sprintf("%s does not match the sealed manifest (SHA-256 %s, sealed %s), so it was not uploaded", d.name, d.got, d.want)
}

// digestReader hashes what it passes on and, at the end, returns the
// mismatch in place of io.EOF, so the upload reading it fails instead of
// completing.
type digestReader struct {
	r    io.Reader
	h    hash.Hash
	want string
	size int64
	read int64
	name string
}

func (d *digestReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	d.h.Write(p[:n])
	d.read += int64(n)
	if err == io.EOF {
		if d.read != d.size {
			return n, fmt.Errorf("%s ends after %d of its %d bytes", d.name, d.read, d.size)
		}
		if got := hex.EncodeToString(d.h.Sum(nil)); d.want != "" && got != d.want {
			return n, &digestMismatch{name: d.name, got: got, want: d.want}
		}
	}
	return n, err
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("and %d more", len(s)-n))
	}
	return s
}
