package wal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/safegrd/cli/pkg/dump"
)

// MongoServer is what the follower and a base read about a replica set
// before they start.
type MongoServer struct {
	SetName  string
	SystemID string
	Database string
	// Oldest and Newest are the oplog's first and last timestamps.
	Oldest, Newest uint64
}

func tsOf(v bson.RawValue) (uint64, bool) {
	t, i, ok := v.TimestampOK()
	return MongoTS(t, i), ok
}

func mongoNotAuthorized(err error) bool {
	var ce mongo.CommandError
	if errors.As(err, &ce) && (ce.Code == 13 || ce.Name == "Unauthorized") {
		return true
	}
	return err != nil && strings.Contains(err.Error(), "not authorized")
}

// oplogEdge reads the oplog's oldest (first) or newest timestamp.
func oplogEdge(ctx context.Context, client *mongo.Client, first bool) (uint64, error) {
	dir := -1
	if first {
		dir = 1
	}
	raw, err := client.Database("local").Collection("oplog.rs").FindOne(ctx, bson.D{},
		options.FindOne().SetSort(bson.D{{Key: "$natural", Value: dir}}).SetProjection(bson.D{{Key: "ts", Value: 1}})).Raw()
	if err != nil {
		if mongoNotAuthorized(err) {
			return 0, errors.New("this user may not read the oplog (local.oplog.rs). Grant it: db.getSiblingDB(\"admin\").grantRolesToUser(\"<user>\", [{role: \"read\", db: \"local\"}])")
		}
		return 0, fmt.Errorf("reading the oplog: %w", err)
	}
	ts, ok := tsOf(raw.Lookup("ts"))
	if !ok {
		return 0, errors.New("an oplog entry with no timestamp")
	}
	return ts, nil
}

// InspectMongo checks the server is a replica set whose oplog this user
// may read, and reads its name and the oplog's span.
func InspectMongo(ctx context.Context, databaseURL string) (MongoServer, error) {
	var s MongoServer
	client, db, err := dump.OpenMongo(ctx, databaseURL)
	if err != nil {
		return s, err
	}
	defer client.Disconnect(context.Background()) //nolint:errcheck
	s.Database = db.Name()
	var hello bson.M
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello); err != nil {
		return s, fmt.Errorf("connecting: %w", err)
	}
	if hello["msg"] == "isdbgrid" {
		return s, errors.New("this is a sharded cluster (mongos): each shard keeps its own oplog, and point-in-time recovery reads one replica set's")
	}
	name, _ := hello["setName"].(string)
	if name == "" {
		return s, errors.New("this server is standalone and has no oplog to follow. Run it as a one-member replica set (--replSet rs0, then rs.initiate()) for point-in-time recovery")
	}
	s.SetName = name
	sum := sha256.Sum256([]byte("mongodb:" + name))
	s.SystemID = strconv.FormatUint(binary.BigEndian.Uint64(sum[:8])>>1|1<<62, 10)
	if s.Newest, err = oplogEdge(ctx, client, false); err != nil {
		return s, err
	}
	if s.Oldest, err = oplogEdge(ctx, client, true); err != nil {
		return s, err
	}
	return s, nil
}

// mongoFilter is the oplog query for database db after ts after and at or
// before ts last: its own entries, and transactions that touch it.
func mongoFilter(db string, after, last uint64) bson.D {
	re := bson.Regex{Pattern: "^" + regexp.QuoteMeta(db) + `\.`}
	return bson.D{
		{Key: "ts", Value: bson.D{{Key: "$gt", Value: bsonTS(after)}, {Key: "$lte", Value: bsonTS(last)}}},
		{Key: "$or", Value: bson.A{
			bson.D{{Key: "ns", Value: re}},
			bson.D{{Key: "ns", Value: "admin.$cmd"}, {Key: "o.applyOps.ns", Value: re}},
		}},
	}
}

func bsonTS(ts uint64) bson.Timestamp { return bson.Timestamp{T: uint32(ts >> 32), I: uint32(ts)} }

// keepOwnOps drops a transaction's operations on other databases, so the
// archive holds only the surface's. Any other entry is kept as it is.
func keepOwnOps(raw bson.Raw, db string) (bson.Raw, error) {
	if ns, _ := raw.Lookup("ns").StringValueOK(); ns != "admin.$cmd" {
		return raw, nil
	}
	var doc bson.D
	if err := bson.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	for i, e := range doc {
		if e.Key != "o" {
			continue
		}
		o, ok := e.Value.(bson.D)
		if !ok {
			return raw, nil
		}
		for j, f := range o {
			if f.Key != "applyOps" {
				continue
			}
			ops, ok := f.Value.(bson.A)
			if !ok {
				return raw, nil
			}
			var keep bson.A
			for _, op := range ops {
				if d, ok := op.(bson.D); ok && strings.HasPrefix(nsOf(d), db+".") {
					keep = append(keep, op)
				}
			}
			o[j].Value = keep
		}
		doc[i].Value = o
	}
	return bson.Marshal(doc)
}

func nsOf(d bson.D) string {
	for _, e := range d {
		if e.Key == "ns" {
			s, _ := e.Value.(string)
			return s
		}
	}
	return ""
}

// MongoFollowerStatus is what the follower last did.
type MongoFollowerStatus struct {
	Following bool
	Last      uint64
	LastPush  time.Time
	LastError string
}

// MongoFollower follows one database's entries in a replica set's oplog
// into an archive. Each interval it reads the oplog's newest timestamp, then
// the database's entries up to it, and pushes them as one segment; with
// none for a minute it pushes an empty one, so the archive says it was
// caught up then.
type MongoFollower struct {
	Archive     *Archive
	URL         string
	Interval    time.Duration
	Logf, Warnf func(format string, args ...any)
	OnGap       func()

	mu     sync.Mutex
	status MongoFollowerStatus
}

// Status is what the follower last did.
func (f *MongoFollower) Status() MongoFollowerStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *MongoFollower) note(fn func(*MongoFollowerStatus)) {
	f.mu.Lock()
	fn(&f.status)
	f.mu.Unlock()
}

// Run follows until ctx ends, starting again 30 seconds after a failure.
func (f *MongoFollower) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := f.Follow(ctx)
		if ctx.Err() != nil {
			return
		}
		f.note(func(s *MongoFollowerStatus) { s.Following, s.LastError = false, err.Error() })
		if f.Warnf != nil {
			f.Warnf("following the oplog: %v. Starting again in 30s", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

// Follow follows until ctx ends or a read fails.
func (f *MongoFollower) Follow(ctx context.Context) error {
	srv, err := InspectMongo(ctx, f.URL)
	if err != nil {
		return err
	}
	f.Archive.SystemID = srv.SystemID
	last := srv.Newest
	if end, ok, err := f.Archive.StreamCatalogEnd(ctx, StreamMongo); err != nil {
		return err
	} else if ok {
		if end.End >= srv.Oldest {
			last = end.End
		} else {
			if f.Warnf != nil {
				f.Warnf("the oplog no longer holds %s, where the archive ends (it rolled over while nothing followed). "+
					"The archive has a gap from there, and restores reach past it only from the next base backup, which the daemon takes now",
					MongoTSTime(end.End).Format("2006-01-02 15:04:05 UTC"))
			}
			if f.OnGap != nil {
				f.OnGap()
			}
		}
	}
	client, _, err := dump.OpenMongo(ctx, f.URL)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.Background()) //nolint:errcheck
	oplog := client.Database("local").Collection("oplog.rs")
	f.note(func(s *MongoFollowerStatus) { s.Following, s.Last, s.LastError = true, last, "" })
	if f.Logf != nil {
		f.Logf("following the oplog of %s from %s", srv.SetName, MongoTSTime(last).Format("2006-01-02 15:04:05 UTC"))
	}
	interval := f.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	lastPush := time.Now()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		newest, err := oplogEdge(ctx, client, false)
		if err != nil {
			return err
		}
		if newest <= last {
			continue
		}
		// The oplog still has last: nothing between it and newest is lost.
		if oldest, err := oplogEdge(ctx, client, true); err != nil {
			return err
		} else if oldest > last {
			return fmt.Errorf("the oplog rolled over past %s while it was being read", MongoTSTime(last).Format("2006-01-02 15:04:05 UTC"))
		}
		cur, err := oplog.Find(ctx, mongoFilter(srv.Database, last, newest), options.Find().SetSort(bson.D{{Key: "$natural", Value: 1}}))
		if err != nil {
			return fmt.Errorf("reading the oplog: %w", err)
		}
		var body bytes.Buffer
		n := 0
		for cur.Next(ctx) {
			doc, err := keepOwnOps(cur.Current, srv.Database)
			if err != nil {
				cur.Close(ctx)
				return err
			}
			body.Write(doc)
			n++
		}
		err = cur.Err()
		cur.Close(ctx)
		if err != nil {
			return fmt.Errorf("reading the oplog: %w", err)
		}
		if n == 0 && time.Since(lastPush) < time.Minute {
			continue
		}
		name := mongoSegName(last, newest)
		if err := f.Archive.PushNew(ctx, name, body.Bytes()); err != nil {
			return fmt.Errorf("pushing %s: %w", name, err)
		}
		last, lastPush = newest, time.Now()
		f.note(func(s *MongoFollowerStatus) { s.Last, s.LastPush, s.LastError = last, time.Now().UTC(), "" })
	}
}

// MongoBase dumps the surface's database between two reads of the oplog's
// newest timestamp: a restore replays every entry after the first over the
// dump, and stops no earlier than the second.
func (a *Archive) MongoBase(ctx context.Context, databaseURL string) (BaseInfo, error) {
	srv, err := InspectMongo(ctx, databaseURL)
	if err != nil {
		return BaseInfo{}, err
	}
	a.SystemID = srv.SystemID
	d := dump.NewMongoDumper(databaseURL)
	info := BaseInfo{Kind: StreamMongo, Source: srv.SetName}
	return a.putStreamBase(ctx, info, func(w io.Writer) (*StreamPos, error) {
		if _, err := d.Dump(ctx, srv.Database, w); err != nil {
			return nil, err
		}
		after, err := InspectMongo(ctx, databaseURL)
		if err != nil {
			return nil, err
		}
		return &StreamPos{Engine: StreamMongo, Database: srv.Database, Pos: srv.Newest, Until: after.Newest}, nil
	})
}

// MongoRestorePoint counts every collection of the database in one
// snapshot read at the oplog's newest timestamp, which the point records:
// the counts are exact there.
func (a *Archive) MongoRestorePoint(ctx context.Context, databaseURL string) (RestorePoint, error) {
	var rp RestorePoint
	srv, err := InspectMongo(ctx, databaseURL)
	if err != nil {
		return rp, err
	}
	a.SystemID = srv.SystemID
	client, db, err := dump.OpenMongo(ctx, databaseURL)
	if err != nil {
		return rp, err
	}
	defer client.Disconnect(context.Background()) //nolint:errcheck
	names, err := db.ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}})
	if err != nil {
		return rp, err
	}
	// The counts are read at the oplog's newest entry, and hold from the
	// database's own newest entry on, since nothing of its came between.
	// The point is that entry, which the archive already holds.
	at := srv.Newest
	var own bson.Raw
	own, err = client.Database("local").Collection("oplog.rs").FindOne(ctx, mongoFilter(srv.Database, 0, srv.Newest),
		options.FindOne().SetSort(bson.D{{Key: "$natural", Value: -1}}).SetProjection(bson.D{{Key: "ts", Value: 1}})).Raw()
	if err == nil {
		if ts, ok := tsOf(own.Lookup("ts")); ok {
			at = ts
		}
	} else if !errors.Is(err, mongo.ErrNoDocuments) {
		return rp, fmt.Errorf("reading the database's newest oplog entry: %w", err)
	}
	now := a.now()
	rp = RestorePoint{Version: 1, Name: newID("r", now, randomHex()), SurfaceID: a.SurfaceID, SystemID: a.SystemID, At: MongoTSTime(at),
		LSN:    fmt.Sprintf("%d:%d", at>>32, uint32(at)),
		Stream: &StreamPos{Engine: StreamMongo, Database: srv.Database, Pos: at}}
	sortStrings(names)
	for _, n := range names {
		if strings.HasPrefix(n, "system.") {
			continue
		}
		c, err := mongoCountAt(ctx, db, n, srv.Newest)
		if err != nil {
			return rp, fmt.Errorf("counting %s at the point: %w", n, err)
		}
		if c > pointCountCap {
			rp.Skipped = append(rp.Skipped, n)
			continue
		}
		rp.Tables = append(rp.Tables, TableCount{Table: n, Before: c, After: c})
	}
	if err := a.recordStreamPoint(ctx, rp); err != nil {
		return rp, fmt.Errorf("recording restore point %s: %w", rp.Name, err)
	}
	return rp, nil
}

func mongoCountAt(ctx context.Context, db *mongo.Database, coll string, ts uint64) (int64, error) {
	cmd := bson.D{
		{Key: "aggregate", Value: coll},
		{Key: "pipeline", Value: bson.A{bson.D{{Key: "$count", Value: "n"}}}},
		{Key: "cursor", Value: bson.D{}},
		{Key: "readConcern", Value: bson.D{{Key: "level", Value: "snapshot"}, {Key: "atClusterTime", Value: bsonTS(ts)}}},
	}
	var out struct {
		Cursor struct {
			FirstBatch []struct {
				N int64 `bson:"n"`
			} `bson:"firstBatch"`
		} `bson:"cursor"`
	}
	if err := db.RunCommand(ctx, cmd).Decode(&out); err != nil {
		return 0, err
	}
	if len(out.Cursor.FirstBatch) == 0 {
		return 0, nil
	}
	return out.Cursor.FirstBatch[0].N, nil
}

// MongoCounts counts every collection of a restored database.
func MongoCounts(ctx context.Context, databaseURL string) (map[string]int64, error) {
	client, db, err := dump.OpenMongo(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(context.Background()) //nolint:errcheck
	names, err := db.ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}})
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, n := range names {
		c, err := db.Collection(n).CountDocuments(ctx, bson.D{})
		if err != nil {
			return nil, err
		}
		out[n] = c
	}
	return out, nil
}

// RestoreMongo loads the base into an empty database and replays the
// oplog to the target with mongorestore.
func (a *Archive) RestoreMongo(ctx context.Context, o StreamRestoreOptions) (StreamRestoreResult, error) {
	var res StreamRestoreResult
	base, run, err := a.planStream(ctx, StreamMongo, o)
	if err != nil {
		return res, err
	}
	bp := base.Stream
	limit := uint64(1<<63 - 1)
	switch {
	case o.Point != nil && o.Point.Stream != nil:
		limit = o.Point.Stream.Pos
	case !o.Target.IsZero():
		// An oplog timestamp is to the second: an entry stamped in the
		// target's own second may be after it, so the replay stops before.
		limit = MongoTS(uint32(o.Target.Add(-time.Second).Unix()), 1<<32-1)
	}
	if limit < bp.Until {
		return res, fmt.Errorf("base %s's dump ended at %s; a restore from it reaches no earlier moment", base.BaseID,
			MongoTSTime(bp.Until).Format("2006-01-02 15:04:05 UTC"))
	}
	if !reaches(run, bp.Until) {
		return res, fmt.Errorf("the archive's oplog does not yet reach the end of base %s's dump", base.BaseID)
	}
	targetDB, err := dump.MongoDatabaseName(o.TargetURL)
	if err != nil {
		return res, err
	}
	res.Base, res.ArchiveEnd, res.ReachedAt = *base, newestPush(run), base.EndedAt
	if err := a.loadBase(ctx, *base, dump.NewMongoRestorer(o.TargetURL)); err != nil {
		return res, err
	}
	dir, err := os.MkdirTemp(o.WorkDir, "oplog-replay-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "oplog.bson")
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return res, err
	}
	var lastTS uint64
	for _, e := range run {
		if e.End <= bp.Pos {
			continue
		}
		if e.Start >= limit {
			break
		}
		body, err := a.readStreamEntry(ctx, e)
		if err != nil {
			out.Close()
			return res, err
		}
		for len(body) > 0 {
			if len(body) < 4 {
				out.Close()
				return res, fmt.Errorf("%s ends inside a document", e.Name)
			}
			n := int(binary.LittleEndian.Uint32(body))
			if n < 5 || n > len(body) {
				out.Close()
				return res, fmt.Errorf("%s ends inside a document", e.Name)
			}
			doc := bson.Raw(body[:n])
			body = body[n:]
			ts, ok := tsOf(doc.Lookup("ts"))
			if !ok || ts <= bp.Pos || ts > limit {
				continue
			}
			if targetDB != bp.Database {
				if doc, err = renameOplogNS(doc, bp.Database, targetDB); err != nil {
					out.Close()
					return res, err
				}
			}
			if _, err := out.Write(doc); err != nil {
				out.Close()
				return res, err
			}
			res.Transactions++
			lastTS = ts
		}
	}
	if err := out.Close(); err != nil {
		return res, err
	}
	if res.Transactions == 0 {
		return res, nil
	}
	res.ReachedAt = MongoTSTime(lastTS)
	// --oplogLimit stops before the timestamp it names, so one past the
	// last entry kept.
	next := lastTS + 1
	if err := dump.MongoOplogReplay(ctx, o.TargetURL, path, uint32(next>>32), uint32(next)); err != nil {
		return res, fmt.Errorf("replaying the oplog over base %s: %w. The target holds the base and part of the oplog; empty it before trying again", base.BaseID, err)
	}
	return res, nil
}

// renameOplogNS moves an entry's namespace, and those inside a
// transaction's applyOps, from database from to database to.
func renameOplogNS(raw bson.Raw, from, to string) (bson.Raw, error) {
	var doc bson.D
	if err := bson.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	move := func(ns string) string {
		if rest, ok := strings.CutPrefix(ns, from+"."); ok {
			return to + "." + rest
		}
		return ns
	}
	for i, e := range doc {
		switch e.Key {
		case "ns":
			if s, ok := e.Value.(string); ok {
				doc[i].Value = move(s)
			}
		case "o":
			o, ok := e.Value.(bson.D)
			if !ok {
				continue
			}
			for j, f := range o {
				ops, ok := f.Value.(bson.A)
				if f.Key != "applyOps" || !ok {
					continue
				}
				for k, op := range ops {
					d, ok := op.(bson.D)
					if !ok {
						continue
					}
					for m, g := range d {
						if g.Key == "ns" {
							if s, ok := g.Value.(string); ok {
								d[m].Value = move(s)
							}
						}
					}
					ops[k] = d
				}
				o[j].Value = ops
			}
			doc[i].Value = o
		}
	}
	return bson.Marshal(doc)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
