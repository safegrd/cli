package dump

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/crc64"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// A MongoDB snapshot is mongodump's own archive, which the
// database tools restore without SafeGrd, in chunks, then a manifest:
//
//	mongo/dump.archive[.N]  mongodump --archive, as written
//	manifest.json           every collection's exact document count
//
// The counts are read from the archive as it streams past, never counted
// beside the dump, so they always agree with it. mongodump without --oplog
// (which only a whole-server dump may use) reads each collection
// consistently but not all of them at one instant: a document written to one
// collection during the dump may be in the archive while a related one in
// another is not. The docs say so.
const mongoDumpEntry = "mongo/dump.archive"

// mongoArchiveMagic opens every mongodump archive.
const mongoArchiveMagic = 0x8199e26d

// IsMongoURL reports whether a connection string names a MongoDB database.
func IsMongoURL(u string) bool {
	return strings.HasPrefix(u, "mongodb://") || strings.HasPrefix(u, "mongodb+srv://")
}

// mongoDatabase is the database a mongodb:// URL names.
func mongoDatabase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a mongodb:// URL: %w", err)
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" || strings.ContainsAny(db, "/. \"$") {
		return "", fmt.Errorf("the URL names no database: mongodb://user:password@host:27017/<database>?authSource=admin")
	}
	return db, nil
}

// SameMongoDatabase reports whether two mongodb:// URLs name one database on
// one set of hosts.
func SameMongoDatabase(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	hosts := func(u *url.URL) string {
		hs := strings.Split(strings.ToLower(u.Host), ",")
		for i, h := range hs {
			h = strings.Replace(h, "localhost", "127.0.0.1", 1)
			if !strings.Contains(h, ":") {
				h += ":27017"
			}
			hs[i] = h
		}
		sort.Strings(hs)
		return strings.Join(hs, ",")
	}
	return hosts(ua) == hosts(ub) && strings.Trim(ua.Path, "/") == strings.Trim(ub.Path, "/")
}

// OpenMongo connects with the Go driver and returns the named database.
func OpenMongo(ctx context.Context, raw string) (*mongo.Client, *mongo.Database, error) {
	name, err := mongoDatabase(raw)
	if err != nil {
		return nil, nil, err
	}
	client, err := mongo.Connect(options.Client().ApplyURI(raw).SetServerSelectionTimeout(15 * time.Second))
	if err != nil {
		return nil, nil, err
	}
	return client, client.Database(name), nil
}

// MongoTool is a located mongodump or mongorestore.
type MongoTool struct{ Path, Version string }

func (t *MongoTool) String() string { return filepath.Base(t.Path) + " " + t.Version }

var mongoToolVersionRe = regexp.MustCompile(`version:\s*r?(\d+\.\d+\.\d+)`)

func findMongoTool(ctx context.Context, name string) (*MongoTool, error) {
	env := "SAFEGRD_" + strings.ToUpper(name)
	var candidates []string
	if p := os.Getenv(env); p != "" {
		candidates = []string{p}
	} else {
		if p, err := exec.LookPath(name); err == nil {
			candidates = append(candidates, p)
		}
		dirs := []string{"/usr/bin", "/usr/local/bin"}
		if runtime.GOOS == "darwin" {
			dirs = append(dirs, "/opt/homebrew/bin", "/opt/homebrew/opt/mongodb-database-tools/bin")
		}
		for _, d := range dirs {
			candidates = append(candidates, filepath.Join(d, name))
		}
	}
	for _, p := range candidates {
		out, err := exec.CommandContext(ctx, p, "--version").CombinedOutput()
		if err != nil {
			continue
		}
		v := ""
		if m := mongoToolVersionRe.FindStringSubmatch(string(out)); m != nil {
			v = m[1]
		}
		return &MongoTool{Path: p, Version: v}, nil
	}
	if p := os.Getenv(env); p != "" {
		return nil, fmt.Errorf("%s=%s is not a working %s", env, p, name)
	}
	return nil, fmt.Errorf("no %s found: install the MongoDB Database Tools (mongodb-database-tools), or set %s", name, env)
}

// mongoToolConfig writes the connection string, password and all, to a 0600
// file in a private directory for --config. On the command line it would be
// readable by every user on the host.
func mongoToolConfig(uri string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "safegrd-mongo-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "tool.yaml")
	quoted, _ := json.Marshal(uri) // a JSON string is a valid YAML string
	if err := os.WriteFile(path, []byte("uri: "+string(quoted)+"\n"), 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// mongoArchiveStats is what reading a mongodump archive found.
type mongoArchiveStats struct {
	ServerVersion, ToolVersion string
	// Collections in the order the archive declares them; views are left out,
	// since a view holds no documents of its own.
	Collections []string
	Views       []string
	Docs        map[string]int64
	// DocBytes is each collection's documents in BSON bytes: its size in the
	// snapshot, reported as the table's size the way the SQL engines report theirs.
	DocBytes  map[string]int64
	Ended     map[string]bool // namespace -> its EOF block arrived
	CRCFailed []string
	Bytes     int64
}

// readMongoArchive reads a whole mongodump archive: the prelude, then the
// interleaved namespace blocks, counting each collection's documents and
// checking each namespace's CRC as it ends.
func readMongoArchive(r io.Reader) (*mongoArchiveStats, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	st := &mongoArchiveStats{Docs: map[string]int64{}, DocBytes: map[string]int64{}, Ended: map[string]bool{}}
	var magic [4]byte
	if _, err := io.ReadFull(br, magic[:]); err != nil {
		return st, fmt.Errorf("the archive is empty: %w", err)
	}
	st.Bytes += 4
	if binary.LittleEndian.Uint32(magic[:]) != mongoArchiveMagic {
		return st, fmt.Errorf("not a mongodump archive")
	}
	next := func() (bson.Raw, bool, error) {
		var lenb [4]byte
		if _, err := io.ReadFull(br, lenb[:]); err != nil {
			return nil, false, err
		}
		n := int32(binary.LittleEndian.Uint32(lenb[:]))
		st.Bytes += 4
		if n == -1 {
			return nil, true, nil
		}
		if n < 5 || n > 64<<20 {
			return nil, false, fmt.Errorf("corrupt archive: a document of %d bytes", n)
		}
		doc := make([]byte, n)
		copy(doc, lenb[:])
		if _, err := io.ReadFull(br, doc[4:]); err != nil {
			return nil, false, fmt.Errorf("the archive ends inside a document: %w", err)
		}
		st.Bytes += int64(n) - 4
		return bson.Raw(doc), false, nil
	}
	str := func(d bson.Raw, key string) string {
		v, err := d.LookupErr(key)
		if err != nil {
			return ""
		}
		s, _ := v.StringValueOK()
		return s
	}

	// Prelude: the header, then one metadata document per namespace.
	header, term, err := next()
	if err != nil || term {
		return st, fmt.Errorf("the archive has no header")
	}
	st.ServerVersion, st.ToolVersion = str(header, "server_version"), str(header, "tool_version")
	for {
		d, term, err := next()
		if err != nil {
			return st, fmt.Errorf("the archive's prelude is cut short: %w", err)
		}
		if term {
			break
		}
		ns := str(d, "db") + "." + str(d, "collection")
		meta := str(d, "metadata")
		if strings.Contains(meta, `"viewOn"`) || str(d, "type") == "view" {
			st.Views = append(st.Views, ns)
			continue
		}
		st.Collections = append(st.Collections, ns)
		st.Docs[ns] = 0
	}

	// Body: blocks of one namespace's documents, each opened by a header and
	// closed by a terminator; a namespace ends with a header whose EOF is set.
	table := crc64.MakeTable(crc64.ECMA)
	crcs := map[string]hash.Hash64{}
	for {
		h, term, err := next()
		if errors.Is(err, io.EOF) {
			return st, nil
		}
		if err != nil {
			return st, err
		}
		if term {
			continue
		}
		ns := str(h, "db") + "." + str(h, "collection")
		if eof, _ := h.Lookup("EOF").BooleanOK(); eof {
			st.Ended[ns] = true
			want, _ := h.Lookup("CRC").Int64OK()
			if c, ok := crcs[ns]; ok && int64(c.Sum64()) != want {
				st.CRCFailed = append(st.CRCFailed, ns)
			}
			continue
		}
		if crcs[ns] == nil {
			crcs[ns] = crc64.New(table)
		}
		for {
			d, term, err := next()
			if err != nil {
				return st, fmt.Errorf("the archive ends inside %s: %w", ns, err)
			}
			if term {
				break
			}
			_, _ = crcs[ns].Write(d)
			st.Docs[ns]++
			st.DocBytes[ns] += int64(len(d))
		}
	}
}

// Complete reports whether every declared namespace reached its end.
func (st *mongoArchiveStats) missingEnds() []string {
	var out []string
	for _, ns := range append(append([]string{}, st.Collections...), st.Views...) {
		if !st.Ended[ns] {
			out = append(out, ns)
		}
	}
	return out
}

// MongoDumper streams a MongoDB database into a snapshot archive.
type MongoDumper struct {
	databaseURL string
	Warn        func(string)
}

// NewMongoDumper creates a dumper for a mongodb:// URL.
func NewMongoDumper(databaseURL string) *MongoDumper {
	return &MongoDumper{databaseURL: databaseURL, Warn: func(msg string) { fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg) }}
}

// Dump runs mongodump and streams its archive into the snapshot, counting
// every collection's documents as they pass.
func (d *MongoDumper) Dump(ctx context.Context, databaseName string, dst io.Writer) (*model.SnapshotMetadata, error) {
	// When the snapshot was taken. The file and mail collectors always set it;
	// the database engines did not, so every database meta.json carried the
	// zero time and the remote server ordered those snapshots as year 1.
	started := time.Now().UTC()
	start := time.Now()
	dbName, err := mongoDatabase(d.databaseURL)
	if err != nil {
		return nil, err
	}
	tool, err := findMongoTool(ctx, "mongodump")
	if err != nil {
		return nil, err
	}
	cfgPath, cleanup, err := mongoToolConfig(d.databaseURL)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	cmd := exec.CommandContext(ctx, tool.Path, "--config="+cfgPath, "--archive", "--quiet")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", tool, err)
	}
	tw := tar.NewWriter(dst)
	cw := &chunkWriter{tw: tw, name: mongoChunkName}
	pr, pw := io.Pipe()
	statsCh := make(chan *mongoArchiveStats, 1)
	parseErrCh := make(chan error, 1)
	go func() {
		st, err := readMongoArchive(pr)
		_, _ = io.Copy(io.Discard, pr)
		statsCh <- st
		parseErrCh <- err
	}()
	_, copyErr := io.Copy(io.MultiWriter(cw, pw), stdout)
	_ = pw.Close()
	waitErr := cmd.Wait()
	st, parseErr := <-statsCh, <-parseErrCh
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return nil, fmt.Errorf("%s failed: %v: %s", tool, waitErr, msg)
	}
	if copyErr != nil {
		return nil, fmt.Errorf("writing the dump to the archive: %w", copyErr)
	}
	if parseErr != nil {
		return nil, fmt.Errorf("%s wrote an archive SafeGrd cannot read: %w", tool, parseErr)
	}
	if missing := st.missingEnds(); len(missing) > 0 {
		return nil, fmt.Errorf("%s exited cleanly but the archive never finished %s: the dump is incomplete", tool, strings.Join(missing, ", "))
	}
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		d.Warn(fmt.Sprintf("%s said, while succeeding: %s", tool, msg))
	}
	if err := cw.Close(); err != nil {
		return nil, err
	}

	meta := &model.SnapshotMetadata{
		SurfaceType:   model.SurfaceTypeMongoDB,
		CreatedAt:     started,
		DatabaseName:  dbName,
		ServerVersion: st.ServerVersion,
		SchemaSource:  tool.String(),
	}
	if databaseName != "" {
		meta.DatabaseName = databaseName
	}
	for _, ns := range st.Collections {
		db, coll, _ := strings.Cut(ns, ".")
		meta.TableStats = append(meta.TableStats, model.TableStat{Schema: db, TableName: coll, RowCount: st.Docs[ns], SizeBytes: st.DocBytes[ns]})
	}
	meta.CalculateTotals()
	meta.DurationMs = elapsedMilliseconds(start)
	manifest, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeTarEntry(tw, entryManifest, manifest); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return meta, nil
}

func mongoChunkName(part int) string {
	if part == 0 {
		return mongoDumpEntry
	}
	return mongoDumpEntry + "." + strconv.Itoa(part)
}

func parseMongoChunk(name string) (string, string, int, bool) {
	if name == mongoDumpEntry {
		return "", "dump", 0, true
	}
	rest, ok := strings.CutPrefix(name, mongoDumpEntry+".")
	if !ok {
		return "", "", 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 1 {
		return "", "", 0, false
	}
	return "", "dump", n, true
}

// mongoArchive reads a MongoDB snapshot, handing the archive to consume as one
// stream and returning the manifest.
func mongoArchive(src io.Reader, consume func(io.Reader) error) (*model.SnapshotMetadata, bool, error) {
	var manifest *model.SnapshotMetadata
	saw := false
	streams := &tableStreams{
		parse: parseMongoChunk,
		consume: func(_, _ string, r io.Reader) error {
			saw = true
			return consume(r)
		},
		other: func(hdr *tar.Header, r io.Reader) error {
			if hdr.Name != entryManifest {
				return nil
			}
			data, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			var m model.SnapshotMetadata
			if err := json.Unmarshal(data, &m); err != nil {
				return fmt.Errorf("the archive's manifest is unreadable: %w", err)
			}
			manifest = &m
			return nil
		},
	}
	err := streams.Run(tar.NewReader(src))
	return manifest, saw, err
}

// InspectMongoArchive is the in-memory Fire Drill for a MongoDB snapshot:
// every namespace in the archive reached its end with a matching CRC, and
// every collection holds exactly the documents the manifest recorded.
func InspectMongoArchive(ctx context.Context, src io.Reader) (*DryRestoreResult, error) {
	start := time.Now()
	result := &DryRestoreResult{Passed: true}
	var st *mongoArchiveStats
	var readErr error
	manifest, saw, err := mongoArchive(src, func(r io.Reader) error {
		st, readErr = readMongoArchive(r)
		_, _ = io.Copy(io.Discard, r)
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		result.Passed = false
		result.ErrorMessage = fmt.Sprintf("failed reading the snapshot: %v", err)
		return result, nil
	}
	add := func(a model.AssertionResult) {
		result.Assertions = append(result.Assertions, a)
		if !a.Passed {
			result.Passed = false
		}
	}
	add(model.AssertionResult{Name: "Manifest Catalog Integrity", Passed: manifest != nil,
		Expected: "manifest.json present", Actual: fmt.Sprintf("present: %v", manifest != nil)})
	add(model.AssertionResult{Name: "Archive Readable", Passed: saw && readErr == nil,
		Expected: "a complete mongodump archive", Actual: fmt.Sprintf("present: %v, error: %v", saw, readErr)})
	if manifest == nil || st == nil {
		result.ErrorMessage = "the snapshot is missing its manifest or its archive"
		return result, nil
	}
	result.Manifest = manifest
	result.DatabaseName = manifest.DatabaseName
	missing := st.missingEnds()
	add(model.AssertionResult{Name: "Every Namespace Complete", Passed: len(missing) == 0,
		Expected: "every collection and view reaches its end", Actual: fmt.Sprintf("unfinished: %v", missing)})
	add(model.AssertionResult{Name: "Archive CRCs", Passed: len(st.CRCFailed) == 0,
		Expected: "each collection's documents match the CRC mongodump wrote", Actual: fmt.Sprintf("mismatched: %v", st.CRCFailed)})
	add(SchemaFidelity(manifest))
	for _, ns := range st.Collections {
		db, coll, _ := strings.Cut(ns, ".")
		result.Tables = append(result.Tables, TableDryStats{Schema: db, TableName: coll, RowCount: st.Docs[ns]})
		result.TotalRows += st.Docs[ns]
	}
	result.TotalTables = len(result.Tables)
	result.TotalDataBytes = st.Bytes
	add(model.AssertionResult{Name: "Table Count Match", Passed: result.TotalTables == manifest.TotalTables,
		Expected: fmt.Sprintf("%d collections", manifest.TotalTables), Actual: fmt.Sprintf("%d collections", result.TotalTables)})
	add(model.AssertionResult{Name: "Total Row Count Match", Passed: result.TotalRows == manifest.TotalRows,
		Expected: fmt.Sprintf("%d documents", manifest.TotalRows), Actual: fmt.Sprintf("%d documents", result.TotalRows)})
	for _, t := range manifest.TableStats {
		got, ok := st.Docs[t.Schema+"."+t.TableName]
		if !ok {
			add(model.AssertionResult{Name: "Collection Existence: " + t.TableName, Expected: "in the archive", Actual: "missing"})
			continue
		}
		add(model.AssertionResult{Name: "Document Count: " + t.TableName, Passed: got == t.RowCount,
			Expected: fmt.Sprintf("%d documents", t.RowCount), Actual: fmt.Sprintf("%d documents", got)})
	}
	result.DurationMs = elapsedMilliseconds(start)
	return result, nil
}

// MongoRestorer loads a MongoDB snapshot into an empty database.
type MongoRestorer struct {
	targetURL string
	Warn      func(string)
}

// NewMongoRestorer creates a restorer for a mongodb:// URL.
func NewMongoRestorer(targetURL string) *MongoRestorer {
	return &MongoRestorer{targetURL: targetURL, Warn: func(msg string) { fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg) }}
}

// Restore pipes the archive into mongorestore, renaming the source database
// to the target's, then holds every collection's document count to the
// manifest. mongorestore writes as it goes, so a failure part way leaves part
// of the database behind; the error says so.
func (r *MongoRestorer) Restore(ctx context.Context, src io.Reader) (*model.SnapshotMetadata, error) {
	targetDB, err := mongoDatabase(r.targetURL)
	if err != nil {
		return nil, err
	}
	client, db, err := OpenMongo(ctx, r.targetURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	if err := MongoCheckEmpty(ctx, db); err != nil {
		return nil, err
	}
	tool, err := findMongoTool(ctx, "mongorestore")
	if err != nil {
		return nil, err
	}
	// mongorestore reads a database in the URI as a filter on the archive's
	// namespaces, which here name the source database, so nothing would be
	// restored at all. The target is given by --nsTo instead; the URI keeps
	// only where to connect and which database to authenticate against.
	cfgPath, cleanup, err := mongoToolConfig(withoutDatabase(r.targetURL))
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// The source database's name is in the archive's manifest, which comes
	// after the archive; the archive's own prelude names it first.
	var stderr bytes.Buffer
	var st *mongoArchiveStats
	manifest, saw, err := mongoArchive(src, func(archive io.Reader) error {
		br := bufio.NewReaderSize(archive, 1<<20)
		sourceDB, err := peekMongoDatabase(br)
		if err != nil {
			return err
		}
		pr, pw := io.Pipe()
		statsCh := make(chan *mongoArchiveStats, 1)
		go func() {
			s, _ := readMongoArchive(pr)
			_, _ = io.Copy(io.Discard, pr)
			statsCh <- s
		}()
		cmd := exec.CommandContext(ctx, tool.Path, "--config="+cfgPath, "--archive", "--stopOnError", "--quiet",
			"--nsFrom="+sourceDB+".*", "--nsTo="+targetDB+".*")
		cmd.Stdin = io.TeeReader(br, pw)
		cmd.Stderr = &stderr
		runErr := cmd.Run()
		_, _ = io.Copy(pw, br) // what the tool did not read
		_ = pw.Close()
		st = <-statsCh
		if runErr != nil {
			msg := strings.TrimSpace(stderr.String())
			if len(msg) > 500 {
				msg = msg[:500] + "..."
			}
			return fmt.Errorf("%s failed: %v: %s. The target may now hold part of the snapshot; drop its collections before retrying", tool, runErr, msg)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !saw || manifest == nil || st == nil {
		return nil, fmt.Errorf("the archive is not a MongoDB snapshot: no archive or no manifest")
	}
	if missing := st.missingEnds(); len(missing) > 0 || len(st.CRCFailed) > 0 {
		return nil, fmt.Errorf("the snapshot's archive is damaged: unfinished %v, CRC mismatch %v", missing, st.CRCFailed)
	}
	counts, err := MongoCountDocuments(ctx, db, manifest)
	if err != nil {
		return nil, err
	}
	for _, t := range manifest.TableStats {
		if counts[t.TableName] != t.RowCount {
			return nil, fmt.Errorf("%s loaded %d documents; the snapshot recorded %d", t.TableName, counts[t.TableName], t.RowCount)
		}
	}
	return manifest, nil
}

// peekMongoDatabase reads the archive's first namespace from its prelude
// without consuming anything.
func peekMongoDatabase(br *bufio.Reader) (string, error) {
	head, err := br.Peek(8)
	if err != nil || binary.LittleEndian.Uint32(head[:4]) != mongoArchiveMagic {
		return "", fmt.Errorf("not a mongodump archive")
	}
	hdrLen := int(int32(binary.LittleEndian.Uint32(head[4:8])))
	if hdrLen < 5 || hdrLen > 1<<20 {
		return "", fmt.Errorf("corrupt archive header")
	}
	buf, err := br.Peek(4 + hdrLen + 4)
	if err != nil {
		return "", err
	}
	n := int(int32(binary.LittleEndian.Uint32(buf[4+hdrLen:])))
	if n < 5 || n > 1<<20 {
		return "", fmt.Errorf("the archive declares no collections")
	}
	buf, err = br.Peek(4 + hdrLen + n)
	if err != nil {
		return "", err
	}
	v, err := bson.Raw(buf[4+hdrLen:]).LookupErr("db")
	if err != nil {
		return "", fmt.Errorf("the archive's first namespace has no database")
	}
	s, _ := v.StringValueOK()
	return s, nil
}

// MongoCheckEmpty refuses a database that already holds collections.
func MongoCheckEmpty(ctx context.Context, db *mongo.Database) error {
	names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: bson.D{{Key: "$not", Value: bson.Regex{Pattern: "^system\\."}}}}})
	if err != nil {
		return fmt.Errorf("could not inspect the target database: %w", err)
	}
	if len(names) > 0 {
		return fmt.Errorf("the target database already holds %d collection(s); restore into a new, empty database", len(names))
	}
	return nil
}

// MongoCountDocuments counts every manifest collection exactly.
func MongoCountDocuments(ctx context.Context, db *mongo.Database, m *model.SnapshotMetadata) (map[string]int64, error) {
	out := map[string]int64{}
	for _, t := range m.TableStats {
		n, err := db.Collection(t.TableName).CountDocuments(ctx, bson.D{})
		if err != nil {
			return nil, fmt.Errorf("counting %s: %w", t.TableName, err)
		}
		out[t.TableName] = n
	}
	return out, nil
}

// MongoResetDatabase drops every collection and view a drill restored into
// its sandbox. Only ever called after MongoCheckEmpty passed.
func MongoResetDatabase(ctx context.Context, db *mongo.Database) error {
	specs, err := db.ListCollectionSpecifications(ctx, bson.D{})
	if err != nil {
		return err
	}
	// Views first: a view over a collection is dropped before the collection.
	sort.SliceStable(specs, func(i, j int) bool { return specs[i].Type == "view" && specs[j].Type != "view" })
	for _, s := range specs {
		if strings.HasPrefix(s.Name, "system.") {
			continue
		}
		if err := db.Collection(s.Name).Drop(ctx); err != nil {
			return fmt.Errorf("dropping %s: %w", s.Name, err)
		}
	}
	return nil
}

// MongoToolsFor finds mongodump and mongorestore for a database, for doctor.
func MongoToolsFor(ctx context.Context, databaseURL string) (dumpTool, restoreTool *MongoTool, server string, err error) {
	client, db, err := OpenMongo(ctx, databaseURL)
	if err != nil {
		return nil, nil, "", err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	var info bson.M
	if err := db.RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&info); err != nil {
		return nil, nil, "", fmt.Errorf("could not reach the server: %w", err)
	}
	server, _ = info["version"].(string)
	if dumpTool, err = findMongoTool(ctx, "mongodump"); err != nil {
		return nil, nil, server, err
	}
	if restoreTool, err = findMongoTool(ctx, "mongorestore"); err != nil {
		return nil, nil, server, err
	}
	return dumpTool, restoreTool, server, nil
}

// withoutDatabase removes the database from a mongodb:// URL, naming it as
// authSource when none was given, since that is what the driver defaulted to.
func withoutDatabase(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	db := strings.TrimPrefix(u.Path, "/")
	q := u.Query()
	if db != "" && q.Get("authSource") == "" && u.User != nil {
		q.Set("authSource", db)
		u.RawQuery = q.Encode()
	}
	u.Path = "/"
	return u.String()
}
