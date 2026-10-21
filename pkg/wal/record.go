package wal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// A base's record (base.json) and a bundle's index (<id>.json) are what make
// the objects beside them usable: without the index, every WAL file in the
// bundle is unreachable. Each is written twice, at its key and at key.copy,
// and each copy carries the SHA-256 of the record it holds, so a reader
// tells a damaged copy from a good one and reads the other.

// recordEnvelope is one copy of a record: the record's bytes and their
// SHA-256.
type recordEnvelope struct {
	Sha256 string          `json:"sha256"`
	Record json.RawMessage `json:"record"`
}

// copySuffix names a record's second copy.
const copySuffix = ".copy"

// SealRecord is v as one copy's bytes: the record and its SHA-256.
func SealRecord(v any) ([]byte, error) {
	rec, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(rec)
	return json.Marshal(recordEnvelope{Sha256: hex.EncodeToString(sum[:]), Record: rec})
}

// OpenRecord checks one copy of a base record or bundle index and returns
// the record it holds.
func OpenRecord(body []byte) (json.RawMessage, error) {
	var env recordEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("does not parse: %w", err)
	}
	if len(env.Record) == 0 {
		return nil, errors.New("holds no record")
	}
	// The checksum is over the record's compact form, which is how it was
	// written.
	var compact bytes.Buffer
	if err := json.Compact(&compact, env.Record); err != nil {
		return nil, fmt.Errorf("holds a record that does not parse: %w", err)
	}
	sum := sha256.Sum256(compact.Bytes())
	if hex.EncodeToString(sum[:]) != env.Sha256 {
		return nil, errors.New("does not match its own checksum")
	}
	return env.Record, nil
}

// writeRecord writes v at key and at key.copy, each locked until lock, and
// returns the lock the first was given.
func (a *Archive) writeRecord(ctx context.Context, key string, v any, lock time.Time) (time.Time, error) {
	body, err := SealRecord(v)
	if err != nil {
		return time.Time{}, err
	}
	got, err := a.Store.Put(ctx, key, bytes.NewReader(body), lock)
	if err != nil {
		return got, err
	}
	if _, err := a.Store.Put(ctx, key+copySuffix, bytes.NewReader(body), lock); err != nil {
		return got, fmt.Errorf("writing its second copy: %w", err)
	}
	return got, nil
}

// readRecordRaw reads the record at key, or at key.copy when the first is
// missing or damaged.
func (a *Archive) readRecordRaw(ctx context.Context, key string) (json.RawMessage, error) {
	var firstErr error
	for _, k := range []string{key, key + copySuffix} {
		body, err := a.readAll(ctx, k)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", k, err)
			}
			continue
		}
		rec, err := OpenRecord(body)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s %w", k, err)
			}
			continue
		}
		return rec, nil
	}
	return nil, fmt.Errorf("neither copy of the record can be read: %w", firstErr)
}

// RecordProblem is a record whose two copies are not both whole and alike.
type RecordProblem struct {
	Key, Problem string
}

// checkRecordPair reads both copies of the record at key and says what is
// wrong with the pair, or "".
func (a *Archive) checkRecordPair(ctx context.Context, key string) string {
	var recs [2]json.RawMessage
	var errs [2]error
	for i, k := range []string{key, key + copySuffix} {
		body, err := a.readAll(ctx, k)
		if err == nil {
			recs[i], err = OpenRecord(body)
		}
		errs[i] = err
	}
	switch {
	case errs[0] != nil && errs[1] != nil:
		return fmt.Sprintf("both copies are unreadable (%v; %v)", errs[0], errs[1])
	case errs[0] != nil:
		return fmt.Sprintf("the first copy is unreadable (%v); the second is whole and is read instead", errs[0])
	case errs[1] != nil:
		return fmt.Sprintf("the second copy is unreadable (%v); the first is whole", errs[1])
	case !bytes.Equal(recs[0], recs[1]):
		return "the two copies are whole and hold different records; the first is read"
	}
	return ""
}

// CheckRecords reads both copies of every base's record and every bundle's
// index and returns the pairs that are not whole and alike.
func (a *Archive) CheckRecords(ctx context.Context) ([]RecordProblem, error) {
	ids, err := a.recordIDs(ctx)
	if err != nil {
		return nil, err
	}
	var out []RecordProblem
	for _, key := range ids {
		if p := a.checkRecordPair(ctx, key); p != "" {
			out = append(out, RecordProblem{Key: key, Problem: p})
		}
	}
	return out, nil
}

// recordIDs is the key of every base record and bundle index the archive
// holds, by its first copy's key.
func (a *Archive) recordIDs(ctx context.Context) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, dir := range []string{"base", "bundles"} {
		objs, err := a.Store.List(ctx, path.Join(a.prefix(), dir)+"/")
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			k := strings.TrimSuffix(o.Key, copySuffix)
			if !strings.HasSuffix(k, ".json") || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}
