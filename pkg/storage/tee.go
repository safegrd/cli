package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// NamedCopy is a bucket a backup is copied to beside the primary.
type NamedCopy struct {
	Name     string
	Provider StorageProvider
	// WORMMode is the copy's lock mode, as its config states it.
	WORMMode string
	// RetentionDays locks the copy for this many days from the backup; zero
	// keeps the primary's date.
	RetentionDays int
	// Config is the copy's storage, for what is said about where it is.
	Config config.StorageConfig
}

// CopyResult is what one copy of one snapshot came to.
type CopyResult struct {
	Name        string
	StorageURI  string
	WORMMode    string
	RetainUntil time.Time
	Err         error
	// DocErr is why the recovery document beside the copy was not written;
	// the copy holds the snapshot either way.
	DocErr error
}

// Tee writes each snapshot to the primary and to every copy at once, from one
// stream: nothing is read back out of the primary. A copy that fails is
// dropped from that snapshot (its upload aborted) and said in its result; the
// snapshot succeeds or fails on the primary alone. Everything that reads goes
// to the primary.
type Tee struct {
	StorageProvider
	copies []NamedCopy
	// copyDoc, when set, renders the recovery document beside one copy,
	// naming that copy's own bucket. Without it a copy gets the primary's.
	copyDoc func(name string, r CopyResult) ([]byte, error)

	mu      sync.Mutex
	results map[string][]CopyResult // by snapshot id
}

// NewTee wraps primary so each snapshot is also written to copies.
func NewTee(primary StorageProvider, copies ...NamedCopy) *Tee {
	return &Tee{StorageProvider: primary, copies: copies, results: map[string][]CopyResult{}}
}

// Primary is the provider every read goes to.
func (t *Tee) Primary() StorageProvider { return t.StorageProvider }

// Results are the copies of a snapshot, in the order the copies were given.
func (t *Tee) Results(snapshotID string) []CopyResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]CopyResult(nil), t.results[snapshotID]...)
}

// copyUntil is the lock date of a copy: its own retention from now, or the
// primary's date when it sets none.
func (c NamedCopy) copyUntil(primary time.Time) time.Time {
	if c.RetentionDays > 0 {
		return time.Now().UTC().AddDate(0, 0, c.RetentionDays)
	}
	return primary
}

// errCopyDropped closes a copy's stream when the primary fails, so its upload
// stops and is aborted rather than completed into a locked object.
var errCopyDropped = errors.New("the backup to the surface's own storage failed, so this copy was stopped")

// UploadSnapshot streams the snapshot to the primary and every copy.
func (t *Tee) UploadSnapshot(ctx context.Context, snapshotID string, stream io.Reader, size int64, retentionUntil time.Time) (string, error) {
	if len(t.copies) == 0 {
		return t.StorageProvider.UploadSnapshot(ctx, snapshotID, stream, size, retentionUntil)
	}
	type live struct {
		w    *io.PipeWriter
		dead bool
	}
	writers := make([]*live, len(t.copies))
	results := make([]CopyResult, len(t.copies))
	var wg sync.WaitGroup
	for i, c := range t.copies {
		pr, pw := io.Pipe()
		writers[i] = &live{w: pw}
		until := c.copyUntil(retentionUntil)
		results[i] = CopyResult{Name: c.Name, WORMMode: c.WORMMode, RetainUntil: until}
		wg.Add(1)
		go func(i int, c NamedCopy, pr *io.PipeReader) {
			defer wg.Done()
			uri, err := c.Provider.UploadSnapshot(ctx, snapshotID, pr, -1, until)
			results[i].StorageURI, results[i].Err = uri, err
			// Whatever is left is drained by nobody: closing the reader makes
			// the tee's next write to it fail, which drops this copy.
			_ = pr.CloseWithError(errCopyDone(err))
		}(i, c, pr)
	}
	tee := &teeReader{src: stream, write: func(p []byte) {
		for _, l := range writers {
			if l.dead {
				continue
			}
			if _, err := l.w.Write(p); err != nil {
				l.dead = true
			}
		}
	}}
	uri, err := t.StorageProvider.UploadSnapshot(ctx, snapshotID, tee, size, retentionUntil)
	for _, l := range writers {
		if err != nil {
			_ = l.w.CloseWithError(errCopyDropped)
		} else {
			_ = l.w.Close()
		}
	}
	wg.Wait()
	if err == nil {
		for i := range results {
			if results[i].Err == nil && writers[i].dead {
				results[i].Err = fmt.Errorf("the copy stopped reading part way")
			}
		}
		t.mu.Lock()
		t.results[snapshotID] = results
		t.mu.Unlock()
	}
	return uri, err
}

func errCopyDone(err error) error {
	if err != nil {
		return err
	}
	return io.ErrClosedPipe
}

// teeReader hands every byte read from src to write, as it is read.
type teeReader struct {
	src   io.Reader
	write func([]byte)
}

func (r *teeReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.write(p[:n])
	}
	return n, err
}

// UploadMetadata writes the manifest to the primary, then to every copy
// that took the snapshot. A copy that cannot take it is marked failed.
func (t *Tee) UploadMetadata(ctx context.Context, snapshotID string, meta *model.SnapshotMetadata) error {
	if err := t.StorageProvider.UploadMetadata(ctx, snapshotID, meta); err != nil {
		return err
	}
	t.eachHeld(snapshotID, func(c NamedCopy, r *CopyResult) {
		m := *meta
		m.StorageURI = r.StorageURI
		if c.WORMMode != "" {
			m.WORMMode = c.WORMMode
		}
		if !r.RetainUntil.IsZero() {
			m.WORMRetentionUntil = r.RetainUntil
		}
		if err := c.Provider.UploadMetadata(ctx, snapshotID, &m); err != nil {
			r.Err = fmt.Errorf("writing the manifest: %w", err)
		}
	})
	return nil
}

// SetCopyRecoveryDoc renders the recovery document beside each copy, so it
// names the bucket it sits in. The render returns the document sealed as
// the primary's is.
func (t *Tee) SetCopyRecoveryDoc(render func(name string, r CopyResult) ([]byte, error)) {
	t.copyDoc = render
}

// UploadRecoveryDoc writes the recovery document beside each copy as beside
// the primary. A copy that cannot take it keeps its snapshot; the document
// is a convenience, and the copy still restores. Its failure is kept in
// DocErrs.
func (t *Tee) UploadRecoveryDoc(ctx context.Context, snapshotID string, doc []byte, sealed bool, retainUntil time.Time) error {
	if err := t.StorageProvider.UploadRecoveryDoc(ctx, snapshotID, doc, sealed, retainUntil); err != nil {
		return err
	}
	t.eachHeld(snapshotID, func(c NamedCopy, r *CopyResult) {
		body := doc
		if t.copyDoc != nil {
			own, err := t.copyDoc(c.Name, *r)
			if err != nil {
				r.DocErr = err
				return
			}
			body = own
		}
		if err := c.Provider.UploadRecoveryDoc(ctx, snapshotID, body, sealed, r.RetainUntil); err != nil {
			r.DocErr = err
		}
	})
	return nil
}

func (t *Tee) eachHeld(snapshotID string, f func(NamedCopy, *CopyResult)) {
	t.mu.Lock()
	rs := t.results[snapshotID]
	t.mu.Unlock()
	for i := range rs {
		if rs[i].Err != nil || i >= len(t.copies) {
			continue
		}
		f(t.copies[i], &rs[i])
	}
	t.mu.Lock()
	t.results[snapshotID] = rs
	t.mu.Unlock()
}

// SetNodeID points the primary and every copy at the node a snapshot is
// filed under.
func (t *Tee) SetNodeID(node string) {
	for _, p := range append([]StorageProvider{t.StorageProvider}, providersOf(t.copies)...) {
		if s, ok := p.(interface{ SetNodeID(string) }); ok {
			s.SetNodeID(node)
		}
	}
}

func providersOf(cs []NamedCopy) []StorageProvider {
	out := make([]StorageProvider, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Provider)
	}
	return out
}

// CopyConfigs is each copy's storage, by name.
func (t *Tee) CopyConfigs() map[string]config.StorageConfig {
	out := map[string]config.StorageConfig{}
	for _, c := range t.copies {
		out[c.Name] = c.Config
	}
	return out
}
