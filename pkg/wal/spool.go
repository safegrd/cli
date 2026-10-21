package wal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// A spool is a directory on the database's host that WAL files wait in
// between archive_command and the archive. archive_command returns once a
// file is in the spool and synced to disk, so a busy cluster is not held up
// by one upload per segment; the daemon uploads the spool several files at
// a time. PostgreSQL recycles a file once archive_command returns, so the
// spool's copy, synced, is what stands for it until it is uploaded.

// Spool is one surface's spool: Dir/<system id>/<WAL file name>.
type Spool struct{ Dir string }

// Spooled is one file waiting in a spool.
type Spooled struct {
	System, Name, Path string
	Size               int64
}

// Add writes body into the spool and syncs it, and the directory, before
// it returns.
func (s Spool) Add(system, name string, body []byte) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if err := ValidSystemID(system); err != nil {
		return err
	}
	dir := filepath.Join(s.Dir, system)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(dir, name)
	if have, err := os.ReadFile(dst); err == nil {
		if bytes.Equal(have, body) {
			return nil
		}
		return fmt.Errorf("%s is already spooled with different contents. Check that only one cluster archives to this surface", name)
	}
	f, err := os.CreateTemp(dir, ".spool-*")
	if err != nil {
		return err
	}
	_, werr := f.Write(body)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(f.Name(), dst)
	}
	if werr != nil {
		os.Remove(f.Name())
		return fmt.Errorf("spooling %s: %w", name, werr)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

// List returns the spooled files, oldest WAL first.
func (s Spool) List() ([]Spooled, error) {
	systems, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Spooled
	for _, sys := range systems {
		if !sys.IsDir() || ValidSystemID(sys.Name()) != nil {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.Dir, sys.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.IsDir() || ValidName(f.Name()) != nil {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			out = append(out, Spooled{System: sys.Name(), Name: f.Name(), Path: filepath.Join(s.Dir, sys.Name(), f.Name()), Size: info.Size()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Bytes is how much the spool holds.
func (s Spool) Bytes() (int64, error) {
	l, err := s.List()
	var n int64
	for _, f := range l {
		n += f.Size
	}
	return n, err
}

// Drain uploads the spooled files through a copy of a for each one's
// system, n at a time, and removes each once it is stored. It returns how
// many it uploaded and the first failure; a file that failed stays.
func Drain(ctx context.Context, a *Archive, s Spool, n int) (int, error) {
	files, err := s.List()
	if err != nil || len(files) == 0 {
		return 0, err
	}
	if n < 1 {
		n = 1
	}
	var mu sync.Mutex
	pushed := 0
	var first error
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(f Spooled) {
			defer wg.Done()
			defer func() { <-sem }()
			err := func() error {
				body, err := os.ReadFile(f.Path)
				if err != nil {
					return err
				}
				b := *a
				b.SystemID = f.System
				if err := b.Push(ctx, f.Name, bytes.NewReader(body)); err != nil {
					return fmt.Errorf("%s: %w", f.Name, err)
				}
				return os.Remove(f.Path)
			}()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if first == nil {
					first = err
				}
				return
			}
			pushed++
		}(f)
	}
	wg.Wait()
	return pushed, first
}

// Dropped is a WAL file let go without being archived, because the WAL
// waiting to leave the host passed queue_max. The archive has a gap from
// it, and a restore's window starts after it.
type Dropped struct {
	System string    `json:"system"`
	Name   string    `json:"name"`
	At     time.Time `json:"at"`
}

// droppedFile is where a surface's dropped WAL is recorded, beside its
// spool.
func (s Spool) droppedFile() string { return filepath.Join(s.Dir, "dropped.json") }

// RecordDropped adds names to the record of WAL let go.
func (s Spool) RecordDropped(d ...Dropped) error {
	have, _ := s.Dropped()
	have = append(have, d...)
	if len(have) > 1000 {
		have = have[len(have)-1000:]
	}
	body, err := json.MarshalIndent(have, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	tmp := s.droppedFile() + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.droppedFile())
}

// Dropped is the record of WAL let go, oldest first.
func (s Spool) Dropped() ([]Dropped, error) {
	body, err := os.ReadFile(s.droppedFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Dropped
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%s does not parse: %w", s.droppedFile(), err)
	}
	return out, nil
}

// DropOldest removes spooled files, oldest first, until the spool and
// incoming bytes fit under max. It returns what it removed.
func (s Spool) DropOldest(max, incoming int64) ([]Dropped, error) {
	files, err := s.List()
	if err != nil {
		return nil, err
	}
	var total int64
	for _, f := range files {
		total += f.Size
	}
	var out []Dropped
	for _, f := range files {
		if total+incoming <= max {
			break
		}
		if err := os.Remove(f.Path); err != nil {
			return out, err
		}
		total -= f.Size
		out = append(out, Dropped{System: f.System, Name: f.Name, At: time.Now().UTC()})
	}
	return out, nil
}

// ReadyBytes is how much WAL PostgreSQL holds that archive_command has not
// archived yet: each .ready file in pg_wal/archive_status counted at
// segSize.
func ReadyBytes(pgdata string, segSize int64) (int64, error) {
	ents, err := os.ReadDir(filepath.Join(pgdata, "pg_wal", "archive_status"))
	if err != nil {
		return 0, err
	}
	var n int64
	for _, e := range ents {
		if name, ok := strings.CutSuffix(e.Name(), ".ready"); ok && IsSegment(name) {
			n += segSize
		}
	}
	return n, nil
}
