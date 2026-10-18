package wal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/crypto"
)

// lockSlack is how long past the recovery window a locked object stays, so a
// late bundle or a slow clock never leaves the window's oldest moment
// unlocked.
const lockSlack = 3 * 24 * time.Hour

// Archive is one cluster's WAL archive.
type Archive struct {
	Store     Store
	SurfaceID string
	SystemID  string
	// Recipient is the age recipient WAL and base backups are encrypted to.
	Recipient string
	// Identity is the age identity a fetch or a restore decrypts with.
	Identity string
	// Window is how far back a restore can reach.
	Window time.Duration
	// BaseEvery is how often a base backup is taken.
	BaseEvery time.Duration
	Now       func() time.Time
	// IndexCache, when set, is a directory bundle indexes are kept in once
	// read. An index is locked and never changes, so a restore's thousands
	// of fetches each read only the bundle listing and not every index.
	IndexCache string
}

func (a *Archive) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *Archive) prefix() string { return Prefix(a.Store.Root(), a.SurfaceID, a.SystemID) }

// Describe names where the archive is.
func (a *Archive) Describe() string {
	return strings.TrimSuffix(a.Store.Describe(), "/"+a.Store.Root()) + "/" + a.prefix()
}

func randomHex() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Push archives one WAL file. It returns only once the object is stored:
// PostgreSQL recycles the file as soon as archive_command exits 0. A file
// already archived with the same contents is not written again; the same
// name with other contents is refused.
func (a *Archive) Push(ctx context.Context, name string, src io.Reader) error {
	if err := ValidName(name); err != nil {
		return err
	}
	plain, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	sum := sha256.Sum256(plain)
	sha := hex.EncodeToString(sum[:])
	have, err := a.Store.ListCurrent(ctx, path.Join(a.prefix(), "segments", name+"-"))
	if err != nil {
		return err
	}
	for _, o := range have {
		p, ok := parseSegmentKey(o.Key)
		if !ok || p.Name != name {
			continue
		}
		if p.Sha16 == sha[:16] {
			return nil
		}
		return fmt.Errorf("%s is already archived with different contents (%s, this file %s). Check that only one cluster archives to this surface", name, p.Sha16, sha[:16])
	}
	var buf bytes.Buffer
	if _, err := crypto.EncryptStream(bytes.NewReader(plain), &buf, a.Recipient); err != nil {
		return fmt.Errorf("encrypting %s: %w", name, err)
	}
	_, err = a.Store.Put(ctx, segmentKey(a.prefix(), name, a.now(), sha), &buf, time.Time{})
	return err
}

// Pushed lists the WAL files that sit unlocked in the archive, by name and
// then push time. Keys that are not WAL files are left out.
func (a *Archive) Pushed(ctx context.Context) ([]Pushed, error) {
	objs, err := a.Store.ListCurrent(ctx, path.Join(a.prefix(), "segments")+"/")
	if err != nil {
		return nil, err
	}
	var out []Pushed
	for _, o := range objs {
		if p, ok := parseSegmentKey(o.Key); ok {
			p.Size = o.Size
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].PushedAt.Before(out[j].PushedAt)
	})
	return out, nil
}

// BundledFile is one WAL file inside a bundle.
type BundledFile struct {
	Name     string    `json:"name"`
	PushedAt time.Time `json:"pushed_at"`
	// PlainSha16 is the first 16 hex digits of the SHA-256 of the
	// uncompressed file, as its push recorded it.
	PlainSha16   string `json:"plain_sha16"`
	CipherSha256 string `json:"cipher_sha256"`
	Offset       int64  `json:"offset"`
	Length       int64  `json:"length"`
}

// BundleIndex says what a bundle holds and where.
type BundleIndex struct {
	Version     int           `json:"version"`
	BundleID    string        `json:"bundle_id"`
	SurfaceID   string        `json:"surface_id"`
	SystemID    string        `json:"system_id"`
	CreatedAt   time.Time     `json:"created_at"`
	LockedUntil time.Time     `json:"locked_until,omitzero"`
	Bytes       int64         `json:"bytes"`
	Files       []BundledFile `json:"files"`
}

func (a *Archive) bundleKey(id string) string { return path.Join(a.prefix(), "bundles", id+".bundle") }
func (a *Archive) indexKey(id string) string  { return path.Join(a.prefix(), "bundles", id+".json") }

// Bundles reads every bundle's index, oldest first.
func (a *Archive) Bundles(ctx context.Context) ([]BundleIndex, error) {
	objs, err := a.Store.List(ctx, path.Join(a.prefix(), "bundles")+"/")
	if err != nil {
		return nil, err
	}
	var out []BundleIndex
	for _, o := range objs {
		id, ok := strings.CutSuffix(path.Base(o.Key), ".json")
		if !ok || !bundleRe.MatchString(id) {
			continue
		}
		body, err := a.readIndex(ctx, id, o.Key)
		if err != nil {
			return nil, err
		}
		var ix BundleIndex
		if err := json.Unmarshal(body, &ix); err != nil {
			return nil, fmt.Errorf("%s does not parse: %w", o.Key, err)
		}
		if ix.BundleID != id || ix.SystemID != a.SystemID {
			return nil, fmt.Errorf("%s names bundle %s of system %s", o.Key, ix.BundleID, ix.SystemID)
		}
		out = append(out, ix)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BundleID < out[j].BundleID })
	return out, nil
}

// readIndex reads a bundle's index from the cache, or from the store and
// then into the cache. The cache only saves requests: one that cannot be
// read or written is passed over.
func (a *Archive) readIndex(ctx context.Context, id, key string) ([]byte, error) {
	var cached string
	if a.IndexCache != "" {
		cached = filepath.Join(a.IndexCache, a.SurfaceID, a.SystemID, id+".json")
		if body, err := os.ReadFile(cached); err == nil && json.Valid(body) {
			return body, nil
		}
	}
	body, err := a.readAll(ctx, key)
	if err != nil || cached == "" {
		return body, err
	}
	if err := os.MkdirAll(filepath.Dir(cached), 0o700); err == nil {
		if tmp, err := os.CreateTemp(filepath.Dir(cached), ".index-*"); err == nil {
			_, werr := tmp.Write(body)
			if cerr := tmp.Close(); werr == nil && cerr == nil {
				werr = os.Rename(tmp.Name(), cached)
			}
			if werr != nil {
				os.Remove(tmp.Name())
			}
		}
	}
	return body, nil
}

func (a *Archive) readAll(ctx context.Context, key string) ([]byte, error) {
	rc, err := a.Store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// BundleResult is what one bundle run did.
type BundleResult struct {
	BundleID string
	Files    int
	Bytes    int64
	// LockedUntil is zero in a store that locks nothing.
	LockedUntil time.Time
	// Deleted counts the unlocked WAL files removed, bundled now or before.
	Deleted int
	// Kept counts the unlocked WAL files that are bundled but could not be
	// deleted, and KeptWhy says why.
	Kept    int
	KeptWhy error
	// Conflicts are names archived twice with different contents, left
	// unlocked and unbundled for a person to look at.
	Conflicts []string
}

// Bundle joins every unlocked WAL file's ciphertext into one locked object,
// reads it back, and deletes the files it holds. It needs no private key.
func (a *Archive) Bundle(ctx context.Context) (BundleResult, error) {
	var res BundleResult
	pushed, err := a.Pushed(ctx)
	if err != nil {
		return res, err
	}
	if len(pushed) == 0 {
		return res, nil
	}
	earlier, err := a.Bundles(ctx)
	if err != nil {
		return res, err
	}
	inBundle := map[string]map[string]bool{}
	for _, ix := range earlier {
		for _, f := range ix.Files {
			if inBundle[f.Name] == nil {
				inBundle[f.Name] = map[string]bool{}
			}
			inBundle[f.Name][f.PlainSha16] = true
		}
	}

	byName := map[string][]Pushed{}
	var names []string
	for _, p := range pushed {
		if byName[p.Name] == nil {
			names = append(names, p.Name)
		}
		byName[p.Name] = append(byName[p.Name], p)
	}
	var take, retire []Pushed
	for _, n := range names {
		group := byName[n]
		shas := map[string]bool{}
		for _, p := range group {
			shas[p.Sha16] = true
		}
		for s := range inBundle[n] {
			shas[s] = true
		}
		if len(shas) > 1 {
			res.Conflicts = append(res.Conflicts, n)
			continue
		}
		if len(inBundle[n]) == 0 {
			take = append(take, group[0])
			retire = append(retire, group[1:]...)
		} else {
			retire = append(retire, group...)
		}
	}

	if len(take) > 0 {
		newest := take[0].PushedAt
		for _, p := range take {
			if p.PushedAt.After(newest) {
				newest = p.PushedAt
			}
		}
		now := a.now()
		id := newID("w", now, randomHex())
		ix := BundleIndex{Version: 1, BundleID: id, SurfaceID: a.SurfaceID, SystemID: a.SystemID, CreatedAt: now}
		if a.Store.Locks() {
			ix.LockedUntil = newest.Add(a.Window + lockSlack)
			// A bundle of WAL pushed long ago still has to be locked when it
			// is written, and a lock date in the past cannot be.
			if !ix.LockedUntil.After(now) {
				ix.LockedUntil = now.Add(lockSlack)
			}
		}
		files, n, lock, err := a.writeBundle(ctx, id, take, ix.LockedUntil)
		if err != nil {
			return res, err
		}
		ix.LockedUntil = lock
		ix.Files, ix.Bytes = files, n
		if err := a.verifyBundle(ctx, id, files); err != nil {
			return res, err
		}
		body, err := json.MarshalIndent(ix, "", "  ")
		if err != nil {
			return res, err
		}
		if _, err := a.Store.Put(ctx, a.indexKey(id), bytes.NewReader(body), ix.LockedUntil); err != nil {
			return res, fmt.Errorf("writing the index of bundle %s: %w", id, err)
		}
		res.BundleID, res.Files, res.Bytes, res.LockedUntil = id, len(files), n, ix.LockedUntil
		retire = append(take, retire...)
	}

	if r, ok := a.Store.(Retirer); ok {
		for start := 0; start < len(retire); start += 64 {
			end := min(start+64, len(retire))
			keys := make([]string, 0, end-start)
			for _, p := range retire[start:end] {
				keys = append(keys, p.Key)
			}
			n, err := r.Retire(ctx, keys)
			res.Deleted += n
			if err != nil {
				res.Kept, res.KeptWhy = len(retire)-res.Deleted, err
				break
			}
		}
		return res, nil
	}
	for i, p := range retire {
		// ErrDeleteDenied, or any other failure: the rest stay unlocked
		// beside the bundle, and the next run tries again.
		if err := a.Store.Delete(ctx, p.Key); err != nil {
			res.Kept, res.KeptWhy = len(retire)-i, err
			break
		}
		res.Deleted++
	}
	return res, nil
}

// writeBundle streams the files' ciphertext into one object, in order.
func (a *Archive) writeBundle(ctx context.Context, id string, take []Pushed, lockUntil time.Time) ([]BundledFile, int64, time.Time, error) {
	pr, pw := io.Pipe()
	files := make([]BundledFile, 0, len(take))
	var off int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, p := range take {
			body, err := a.readCurrent(ctx, p.Key)
			if err != nil {
				pw.CloseWithError(fmt.Errorf("reading %s: %w", p.Key, err))
				return
			}
			sum := sha256.Sum256(body)
			if _, err := pw.Write(body); err != nil {
				return
			}
			files = append(files, BundledFile{Name: p.Name, PushedAt: p.PushedAt, PlainSha16: p.Sha16,
				CipherSha256: hex.EncodeToString(sum[:]), Offset: off, Length: int64(len(body))})
			off += int64(len(body))
		}
		pw.Close()
	}()
	lock, err := a.Store.Put(ctx, a.bundleKey(id), pr, lockUntil)
	// A Put that failed part way leaves the reader mid-file; closing the
	// pipe ends it, and files is read only once it has stopped appending.
	pr.CloseWithError(io.ErrClosedPipe)
	<-done
	if err != nil {
		return nil, 0, lock, fmt.Errorf("writing bundle %s: %w", id, err)
	}
	if len(files) != len(take) {
		return nil, 0, lock, fmt.Errorf("bundle %s holds %d of %d WAL files", id, len(files), len(take))
	}
	return files, off, lock, nil
}

func (a *Archive) readCurrent(ctx context.Context, key string) ([]byte, error) {
	rc, err := a.Store.GetCurrent(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// verifyBundle reads a bundle back whole and checks each file's ciphertext
// against what was written.
func (a *Archive) verifyBundle(ctx context.Context, id string, files []BundledFile) error {
	rc, err := a.Store.Get(ctx, a.bundleKey(id))
	if err != nil {
		return fmt.Errorf("reading bundle %s back: %w", id, err)
	}
	defer rc.Close()
	for _, f := range files {
		h := sha256.New()
		if _, err := io.CopyN(h, rc, f.Length); err != nil {
			return fmt.Errorf("reading bundle %s back at %s: %w", id, f.Name, err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != f.CipherSha256 {
			return fmt.Errorf("bundle %s holds %s with other bytes than were written (%s, wrote %s); the unlocked files are kept", id, f.Name, got[:16], f.CipherSha256[:16])
		}
	}
	if n, _ := io.Copy(io.Discard, rc); n != 0 {
		return fmt.Errorf("bundle %s is %d bytes longer than was written", id, n)
	}
	return nil
}

// Fetch writes one WAL file to dst, from the unlocked files or a bundle. A
// file the archive does not hold returns ErrNotFound, which is how a restore
// learns it has replayed everything there is.
func (a *Archive) Fetch(ctx context.Context, name string, dst io.Writer) error {
	if err := ValidName(name); err != nil {
		return err
	}
	have, err := a.Store.ListCurrent(ctx, path.Join(a.prefix(), "segments", name+"-"))
	if err != nil {
		return err
	}
	for _, o := range have {
		p, ok := parseSegmentKey(o.Key)
		if !ok || p.Name != name {
			continue
		}
		body, err := a.readCurrent(ctx, o.Key)
		if errors.Is(err, ErrNotFound) {
			break // bundled and deleted since the listing
		}
		if err != nil {
			return err
		}
		return a.decryptTo(name, body, p.Sha16, dst)
	}
	bundles, err := a.Bundles(ctx)
	if err != nil {
		return err
	}
	for i := len(bundles) - 1; i >= 0; i-- {
		for _, f := range bundles[i].Files {
			if f.Name != name {
				continue
			}
			body, err := a.Store.GetRange(ctx, a.bundleKey(bundles[i].BundleID), f.Offset, f.Length)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != f.CipherSha256 {
				return fmt.Errorf("%s in bundle %s does not match its index", name, bundles[i].BundleID)
			}
			return a.decryptTo(name, body, f.PlainSha16, dst)
		}
	}
	return fmt.Errorf("%s: %w", name, ErrNotFound)
}

func (a *Archive) decryptTo(name string, body []byte, sha16 string, dst io.Writer) error {
	var plain bytes.Buffer
	m, err := crypto.DecryptStream(bytes.NewReader(body), &plain, a.Identity)
	if err != nil {
		return fmt.Errorf("decrypting %s: %w", name, err)
	}
	if !strings.HasPrefix(m.RawSha256, sha16) {
		return fmt.Errorf("%s decrypts to other bytes than were pushed (%s, pushed %s)", name, m.RawSha256[:16], sha16)
	}
	_, err = dst.Write(plain.Bytes())
	return err
}
