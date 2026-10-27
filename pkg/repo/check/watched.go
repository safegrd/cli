package check

import (
	"context"
	"errors"
	"sync"

	"github.com/safegrd/cli/pkg/repo/sink"
)

// watched is the backend a check reads through. It keeps the first read that
// failed for any reason but the object being absent: storage that answered
// 503, a connection that dropped, a cancelled context. Such a read says
// nothing about the bytes in storage, so a check that met one has checked
// nothing and must not report the snapshot as damaged.
type watched struct {
	sink.Backend
	mu  sync.Mutex
	err error
}

func (w *watched) note(err error) {
	if err == nil || errors.Is(err, sink.ErrNotFound) {
		return
	}
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
}

// failed is the first read that failed, or nil.
func (w *watched) failed() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *watched) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := w.Backend.Get(ctx, key)
	w.note(err)
	return b, err
}

func (w *watched) GetRange(ctx context.Context, key string, off, n int64) ([]byte, error) {
	b, err := w.Backend.GetRange(ctx, key, off, n)
	w.note(err)
	return b, err
}

func (w *watched) List(ctx context.Context, e sink.EpochInfo, sub string) ([]sink.ObjectInfo, error) {
	objs, err := w.Backend.List(ctx, e, sub)
	w.note(err)
	return objs, err
}
