package cli

import (
	"context"
	"sync"
)

// nodeMemo keeps the remote server's answers about nodes for one daemon
// pass or one command. A pass asked for the node's bucket and credentials
// again for each surface, for its erasures and for its drill, and the
// credentials route allows 30 a minute. A failure is never kept: the next
// caller asks again and reports its own error.
type nodeMemo struct {
	mu sync.Mutex
	m  map[string]any
}

type nodeMemoKey struct{}

// withNodeMemo returns ctx carrying a fresh memo. Lookups under a context
// without one ask the remote server every time, as before.
func withNodeMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, nodeMemoKey{}, &nodeMemo{m: map[string]any{}})
}

// memoized returns the answer kept under key in ctx's memo, or fetches it
// and keeps it when it succeeds.
func memoized[T any](ctx context.Context, key string, fetch func() (*T, error)) (*T, error) {
	n, _ := ctx.Value(nodeMemoKey{}).(*nodeMemo)
	if n == nil {
		return fetch()
	}
	n.mu.Lock()
	if v, ok := n.m[key].(*T); ok {
		n.mu.Unlock()
		cp := *v
		return &cp, nil
	}
	n.mu.Unlock()
	v, err := fetch()
	if err != nil || v == nil {
		return v, err
	}
	n.mu.Lock()
	n.m[key] = v
	n.mu.Unlock()
	cp := *v
	return &cp, nil
}
