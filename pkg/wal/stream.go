package wal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/safegrd/cli/pkg/crypto"
)

// A MySQL binary log and a MongoDB oplog are followed by the daemon into
// the same archive PostgreSQL's WAL goes to, as segments named for the
// place in the log they cover. A run of segments is unbroken when each
// starts where the one before ended (stream.go), so a gap shows in the
// names without the key.

// Stream engines.
const (
	StreamMySQL = "mysql"
	StreamMongo = "mongodb"
)

// StreamPos is a place in a MySQL binary log or a MongoDB oplog, as a base
// or a restore point records it.
type StreamPos struct {
	Engine string `json:"engine"`
	// Database is the surface's database, which a restore replays.
	Database string `json:"database"`
	// MariaDB marks a MariaDB server, whose binary log a restore reads
	// with MariaDB's mysqlbinlog.
	MariaDB bool `json:"mariadb,omitempty"`
	// File and FileNum are the binary log file; Pos the byte offset in it,
	// or for MongoDB the oplog timestamp (seconds << 32 | ordinal) after
	// which a replay starts.
	File    string `json:"file,omitempty"`
	FileNum uint32 `json:"file_num,omitempty"`
	Pos     uint64 `json:"pos"`
	// Until is, for a MongoDB base, the oplog timestamp the dump ended at:
	// no restore from it stops earlier.
	Until uint64 `json:"until,omitempty"`
	// GTIDs is the GTID state at the position, for a person to read.
	GTIDs string `json:"gtids,omitempty"`
}

// MongoTS is an oplog timestamp as one number: seconds, then ordinal.
func MongoTS(t, i uint32) uint64 { return uint64(t)<<32 | uint64(i) }

// MongoTSTime is the moment an oplog timestamp names, to the second.
func MongoTSTime(ts uint64) time.Time { return time.Unix(int64(ts>>32), 0).UTC() }

// StreamSeg is a segment's place in its log. For MySQL, File is the binary
// log's number and Start and End byte offsets in it; for MongoDB, File is 0
// and Start and End oplog timestamps (the segment holds Start < ts <= End).
type StreamSeg struct {
	Name       string
	File       uint32
	Start, End uint64
	// Rotates marks the last segment of a binary log file.
	Rotates bool
	// Idle, on an empty segment, is when the follower was caught up with
	// nothing new (Unix seconds), which makes each such name new.
	Idle uint32
}

// mongoSegRe is an oplog segment's name: the timestamp after which it
// starts and the one it reaches.
var mongoSegRe = regexp.MustCompile(`^mo-[0-9a-f]{16}-[0-9a-f]{16}$`)

func mongoSegName(after, last uint64) string { return fmt.Sprintf("mo-%016x-%016x", after, last) }

func parseMongoSegment(name string) (StreamSeg, bool) {
	if !mongoSegRe.MatchString(name) {
		return StreamSeg{}, false
	}
	a, _ := strconv.ParseUint(name[3:19], 16, 64)
	b, _ := strconv.ParseUint(name[20:36], 16, 64)
	return StreamSeg{Name: name, Start: a, End: b}, true
}

func streamSegName(name string) bool {
	return mysqlSegRe.MatchString(name) || mongoSegRe.MatchString(name)
}

func parseStreamSeg(engine, name string) (StreamSeg, bool) {
	if engine == StreamMongo {
		return parseMongoSegment(name)
	}
	return parseMySQLSegment(name)
}

// follows says next continues the run prev ends.
func (prev StreamSeg) follows(next StreamSeg) bool {
	if next.File == prev.File && next.Start == prev.End {
		return true
	}
	return prev.Rotates && next.File == prev.File+1 && next.Start == 4
}

// covers says the segment holds, or starts at, position pos of file.
func (s StreamSeg) covers(file uint32, pos uint64) bool {
	return s.File == file && s.Start <= pos && pos <= s.End
}

// streamEntry is one segment the archive holds, unlocked or bundled.
type streamEntry struct {
	StreamSeg
	PushedAt      time.Time
	Key           string
	Bundle        string
	Offset, Len   int64
	Sha16, Cipher string
}

// streamCatalog lists every segment of the engine once, in log order.
func (a *Archive) streamCatalog(ctx context.Context, engine string) ([]streamEntry, error) {
	var out []streamEntry
	seen := map[string]bool{}
	bundles, err := a.Bundles(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range bundles {
		for _, f := range b.Files {
			seg, ok := parseStreamSeg(engine, f.Name)
			if !ok || seen[f.Name] {
				continue
			}
			seen[f.Name] = true
			out = append(out, streamEntry{StreamSeg: seg, PushedAt: f.PushedAt, Bundle: b.BundleID, Offset: f.Offset, Len: f.Length,
				Sha16: f.PlainSha16, Cipher: f.CipherSha256})
		}
	}
	pushed, err := a.Pushed(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pushed {
		seg, ok := parseStreamSeg(engine, p.Name)
		if !ok || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		out = append(out, streamEntry{StreamSeg: seg, PushedAt: p.PushedAt, Key: p.Key, Sha16: p.Sha16})
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.File != y.File {
			return x.File < y.File
		}
		if x.Start != y.Start {
			return x.Start < y.Start
		}
		if x.End != y.End {
			return x.End < y.End
		}
		return x.Idle < y.Idle
	})
	return out, nil
}

// streamRun is the unbroken run of segments from position (file, pos):
// the first that covers it, then each that follows. gap names the first
// segment out of place, or "" when the run reaches the newest segment; a
// run that cannot start names the position.
func streamRun(es []streamEntry, file uint32, pos uint64) (run []streamEntry, gap string) {
	i := 0
	for ; i < len(es); i++ {
		if es[i].covers(file, pos) {
			break
		}
	}
	if i == len(es) {
		return nil, fmt.Sprintf("the log at %d:%d", file, pos)
	}
	run = append(run, es[i])
	for _, e := range es[i+1:] {
		if !run[len(run)-1].follows(e.StreamSeg) {
			return run, e.Name
		}
		run = append(run, e)
	}
	return run, ""
}

// readStreamEntry reads and decrypts one segment.
func (a *Archive) readStreamEntry(ctx context.Context, e streamEntry) ([]byte, error) {
	var body []byte
	var err error
	if e.Bundle != "" {
		body, err = a.Store.GetRange(ctx, a.bundleKey(e.Bundle), e.Offset, e.Len)
		if err == nil {
			if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != e.Cipher {
				return nil, fmt.Errorf("%s in bundle %s does not match its index", e.Name, e.Bundle)
			}
		}
	} else {
		body, err = a.readCurrent(ctx, e.Key)
	}
	if err != nil {
		return nil, err
	}
	var plain bytes.Buffer
	if err := a.decryptTo(e.Name, body, e.Sha16, &plain); err != nil {
		return nil, err
	}
	return plain.Bytes(), nil
}

// StreamStatus is the window a MySQL or MongoDB archive restores: from the
// end of the oldest base whose run reaches as far as any, to the newest
// segment of that run.
func (a *Archive) StreamStatus(ctx context.Context, engine string) (Status, error) {
	var st Status
	bases, inc, err := a.Bases(ctx)
	if err != nil {
		return st, err
	}
	st.Incomplete = inc
	cat, err := a.streamCatalog(ctx, engine)
	if err != nil {
		return st, err
	}
	pushed, err := a.Pushed(ctx)
	if err != nil {
		return st, err
	}
	for _, p := range pushed {
		st.Unlocked++
		st.UnlockedBytes += p.Size
		if p.PushedAt.After(st.NewestPush) {
			st.NewestPush = p.PushedAt
		}
	}
	bundles, err := a.Bundles(ctx)
	if err != nil {
		return st, err
	}
	for _, b := range bundles {
		st.Bundles++
		st.BundledBytes += b.Bytes
		for _, f := range b.Files {
			if f.PushedAt.After(st.LockedTo) {
				st.LockedTo = f.PushedAt
			}
			if f.PushedAt.After(st.NewestPush) {
				st.NewestPush = f.PushedAt
			}
		}
	}
	st.Files = len(cat)
	gaps := map[string]*Gap{}
	for _, b := range bases {
		if b.Stream == nil || b.Stream.Engine != engine {
			continue
		}
		st.Bases = append(st.Bases, b)
		run, gap := streamRun(cat, b.Stream.FileNum, b.Stream.Pos)
		if gap != "" {
			if g, ok := gaps[gap]; ok {
				g.Breaks = append(g.Breaks, b.BaseID)
			} else {
				g := &Gap{First: gap, Last: gap, Breaks: []string{b.BaseID}}
				if n := len(run); n > 0 {
					g.Before = run[n-1].PushedAt
				}
				gaps[gap] = g
			}
		}
		if len(run) == 0 {
			continue
		}
		to := newestPush(run)
		if engine == StreamMongo && !reaches(run, b.Stream.Until) {
			continue // the dump's last read is not archived yet
		}
		if to.Before(b.EndedAt) {
			to = b.EndedAt
		}
		if !st.HasWindow || to.After(st.WindowTo) {
			st.HasWindow, st.WindowFrom, st.WindowTo = true, b.EndedAt, to
		} else if to.Equal(st.WindowTo) && b.EndedAt.Before(st.WindowFrom) {
			st.WindowFrom = b.EndedAt
		}
	}
	for _, g := range gaps {
		st.Gaps = append(st.Gaps, *g)
	}
	sort.Slice(st.Gaps, func(i, j int) bool { return st.Gaps[i].First < st.Gaps[j].First })
	return st, nil
}

func newestPush(run []streamEntry) time.Time {
	var t time.Time
	for _, e := range run {
		if e.PushedAt.After(t) {
			t = e.PushedAt
		}
	}
	return t
}

// reaches says an oplog run gets to timestamp ts.
func reaches(run []streamEntry, ts uint64) bool {
	return len(run) > 0 && run[len(run)-1].End >= ts
}

// StreamCatalogEnd is the newest segment's end, for a follower resuming:
// zero ok when the archive holds none of the engine's segments.
func (a *Archive) StreamCatalogEnd(ctx context.Context, engine string) (StreamSeg, bool, error) {
	cat, err := a.streamCatalog(ctx, engine)
	if err != nil || len(cat) == 0 {
		return StreamSeg{}, false, err
	}
	return cat[len(cat)-1].StreamSeg, true, nil
}

// putStreamBase streams a base's dump, compressed and encrypted, into the
// archive as one locked object and writes its record. dump writes the
// dump; it returns the base's place in the log once the dump is done.
func (a *Archive) putStreamBase(ctx context.Context, info BaseInfo, dump func(io.Writer) (*StreamPos, error)) (BaseInfo, error) {
	started := a.now()
	info.Version, info.SurfaceID, info.SystemID = 1, a.SurfaceID, a.SystemID
	info.BaseID, info.StartedAt = newID("b", started, randomHex()), started
	if a.Store.Locks() {
		info.LockedUntil = started.Add(a.Window + a.BaseEvery + lockSlack)
	}
	pr, pw := io.Pipe()
	var pos *StreamPos
	var dumpErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		pos, dumpErr = dump(pw)
		pw.CloseWithError(dumpErr)
	}()
	er, ew := io.Pipe()
	var m *crypto.StreamMetrics
	var encErr error
	encDone := make(chan struct{})
	counted := &countWriter{w: ew}
	go func() {
		defer close(encDone)
		m, encErr = crypto.EncryptStream(pr, counted, a.Recipient)
		pr.CloseWithError(encErr)
		ew.CloseWithError(encErr)
	}()
	lock, err := a.Store.Put(ctx, a.baseKey(info.BaseID, "base.tar.zst.age"), er, info.LockedUntil)
	er.CloseWithError(io.ErrClosedPipe)
	<-encDone
	<-done
	switch {
	case dumpErr != nil && (err == nil || !errors.Is(dumpErr, io.ErrClosedPipe)):
		return info, dumpErr
	case err != nil:
		return info, err
	case encErr != nil:
		return info, fmt.Errorf("encrypting the base: %w", encErr)
	}
	info.LockedUntil = lock
	info.Stream = pos
	info.TarBytes, info.TarSha256, info.StoredBytes = m.RawBytes, m.RawSha256, counted.n
	info.EndedAt = a.now()
	if _, err := a.writeRecord(ctx, a.baseKey(info.BaseID, "base.json"), info, info.LockedUntil); err != nil {
		return info, fmt.Errorf("writing the record of base %s: %w", info.BaseID, err)
	}
	return info, nil
}

// readStreamBase decrypts a base's dump into w and checks it is what was
// written.
func (a *Archive) readStreamBase(ctx context.Context, b BaseInfo, w io.Writer) error {
	rc, err := a.Store.Get(ctx, a.baseKey(b.BaseID, "base.tar.zst.age"))
	if err != nil {
		return fmt.Errorf("reading base %s: %w", b.BaseID, err)
	}
	defer rc.Close()
	m, err := crypto.DecryptStream(rc, w, a.Identity)
	if err != nil {
		return fmt.Errorf("decrypting base %s: %w", b.BaseID, err)
	}
	if m.RawSha256 != b.TarSha256 {
		return fmt.Errorf("base %s decrypts to other bytes than were written", b.BaseID)
	}
	return nil
}

// recordStreamPoint writes a restore point's record, locked as a bundle is.
func (a *Archive) recordStreamPoint(ctx context.Context, rp RestorePoint) error {
	body, err := jsonIndent(rp)
	if err != nil {
		return err
	}
	var lock time.Time
	if a.Store.Locks() {
		lock = rp.At.Add(a.Window + lockSlack)
	}
	_, err = a.Store.Put(ctx, a.pointKey(rp.Name), bytes.NewReader(body), lock)
	return err
}

// pickStreamBase is the newest base of the engine that a restore to target
// (zero: the end of the archive) or to point can start from.
func pickStreamBase(bases []BaseInfo, engine string, target time.Time, point *RestorePoint) *BaseInfo {
	var pick *BaseInfo
	for i := range bases {
		b := bases[i]
		if b.Stream == nil || b.Stream.Engine != engine {
			continue
		}
		switch {
		case point != nil && point.Stream != nil:
			if b.Stream.FileNum < point.Stream.FileNum || (b.Stream.FileNum == point.Stream.FileNum && b.Stream.Pos <= point.Stream.Pos && b.Stream.Until <= point.Stream.Pos) {
				pick = &bases[i]
			}
		case target.IsZero() || !b.EndedAt.After(target):
			pick = &bases[i]
		}
	}
	return pick
}

func jsonIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
