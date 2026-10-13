package dump

import (
	"archive/tar"
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"io"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// A MongoDB run takes mongodump's archive apart by namespace, so a
// collection nothing wrote since the last run stores no new chunks and the
// console can show each collection's bytes:
//
//	mongo/prelude.bson                    the archive's header and one
//	                                      metadata document per namespace
//	                                      (options, indexes), as written
//	mongo/collections/<collection>.bson[.N]  the collection's documents, in
//	                                      the order the dump read them, with
//	                                      no block framing
//	manifest.json
//
// A view has metadata and no file. The archive's body is blocks of one
// namespace's documents, each opened by a header and closed by a
// terminator, cut where mongodump's buffers happened to fill, so the blocks
// are not what is stored: a block boundary that moved would make an
// unchanged collection look changed. A restore and a drill rebuild the
// archive from the documents, one block per namespace, and hand it to the
// mongorestore and inspector the archive format already uses.
//
// mongodump's directory form (one .bson file per collection) was not used:
// it writes every document to the host's disk in plaintext first.
const (
	// MongoPreludeEntry and MongoCollectionsDir name a run's entries.
	MongoPreludeEntry   = "mongo/prelude.bson"
	MongoCollectionsDir = "mongo/collections/"
	mongoBSONSuffix     = ".bson"
)

// MongoCollectionEntry is the run entry a collection's documents are stored
// in.
func MongoCollectionEntry(collection string) string {
	return MongoCollectionsDir + runEntryName(collection) + mongoBSONSuffix
}

// IsMongoRunEntry reports whether an archive entry is part of a
// per-collection MongoDB dump: the prelude or a collection.
func IsMongoRunEntry(name string) bool {
	base, _, ok := parseChunkedEntry(name)
	return ok && (base == MongoPreludeEntry || strings.HasPrefix(base, MongoCollectionsDir))
}

// MongoRunCollection is the collection a run entry under mongo/collections/
// holds, or "" for the prelude.
func MongoRunCollection(name string) string {
	base, _, ok := parseChunkedEntry(name)
	if !ok || !strings.HasPrefix(base, MongoCollectionsDir) {
		return ""
	}
	return unescapeRunEntryName(strings.TrimSuffix(strings.TrimPrefix(base, MongoCollectionsDir), mongoBSONSuffix))
}

// mongoRunWriter is the sink that writes a run's entries as the archive
// streams past: the prelude when it ends, each collection's documents
// through a chunkWriter of its own, closed when its namespace ends or when
// another namespace's documents start.
type mongoRunWriter struct {
	tw      *tar.Writer
	views   map[string]bool
	open    map[string]*chunkWriter
	closed  map[string]bool
	current string
	order   []string
}

func newMongoRunWriter(tw *tar.Writer) *mongoRunWriter {
	return &mongoRunWriter{tw: tw, views: map[string]bool{}, open: map[string]*chunkWriter{}, closed: map[string]bool{}}
}

func (w *mongoRunWriter) prelude(raw []byte, collections, views []string) error {
	for _, v := range views {
		w.views[v] = true
	}
	return writeTarEntry(w.tw, MongoPreludeEntry, raw)
}

func (w *mongoRunWriter) writer(ns string) (*chunkWriter, error) {
	if cw, ok := w.open[ns]; ok {
		return cw, nil
	}
	if w.closed[ns] {
		// Its documents would land in a second entry of the same name, and
		// a reader would take the first for the whole collection.
		return nil, fmt.Errorf("mongodump wrote %s in two parts with another collection between them: the run cannot be written", ns)
	}
	if w.current != "" && w.current != ns {
		// mongodump was told to dump one collection at a time, so documents
		// of another namespace mean this one is complete.
		if err := w.close(w.current); err != nil {
			return nil, err
		}
	}
	_, coll, _ := strings.Cut(ns, ".")
	entry := MongoCollectionEntry(coll)
	cw := &chunkWriter{tw: w.tw, name: func(part int) string { return chunkedName(entry, part) }}
	w.open[ns], w.current = cw, ns
	w.order = append(w.order, ns)
	return cw, nil
}

func (w *mongoRunWriter) doc(ns string, raw []byte) error {
	cw, err := w.writer(ns)
	if err != nil {
		return err
	}
	_, err = cw.Write(raw)
	return err
}

func (w *mongoRunWriter) end(ns string) error {
	if w.views[ns] || w.closed[ns] {
		// A view has no file. A collection whose end arrives after another
		// collection's documents was closed when they started.
		return nil
	}
	if _, ok := w.open[ns]; !ok {
		// A collection with no documents still gets its file, so a reader
		// can tell "empty" from "missing".
		if _, err := w.writer(ns); err != nil {
			return err
		}
	}
	return w.close(ns)
}

func (w *mongoRunWriter) close(ns string) error {
	cw, ok := w.open[ns]
	if !ok {
		return nil
	}
	delete(w.open, ns)
	w.closed[ns] = true
	if w.current == ns {
		w.current = ""
	}
	return cw.Close()
}

// Write is the archive bytes mongodump produced; the run keeps only what the
// parser hands the sink, so they are dropped here.
func (w *mongoRunWriter) Write(p []byte) (int, error) { return len(p), nil }

// Close finishes any collection the archive never ended.
func (w *mongoRunWriter) Close() error {
	for ns := range w.open {
		if err := w.close(ns); err != nil {
			return err
		}
	}
	return nil
}

// MongoRunPart is one collection's documents as a run holds them.
type MongoRunPart struct {
	Collection string
	Size       int64
	// Open streams the documents to w.
	Open func(w io.Writer) error
}

// mongoRunNamespace is one namespace the prelude declares.
type mongoRunNamespace struct {
	db, collection string
}

// mongoPreludeNamespaces reads the namespaces a run's prelude declares, in
// order, and the archive header.
func mongoPreludeNamespaces(prelude []byte) (header bson.Raw, nss []mongoRunNamespace, err error) {
	rest := prelude
	first := true
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, nil, fmt.Errorf("the run's prelude ends inside a document")
		}
		n := int(int32(binary.LittleEndian.Uint32(rest[:4])))
		if n < 5 || n > len(rest) {
			return nil, nil, fmt.Errorf("the run's prelude holds a document of %d bytes", n)
		}
		d := bson.Raw(rest[:n])
		rest = rest[n:]
		if first {
			header, first = d, false
			continue
		}
		db, _ := d.Lookup("db").StringValueOK()
		coll, _ := d.Lookup("collection").StringValueOK()
		if db == "" || coll == "" {
			return nil, nil, fmt.Errorf("the run's prelude names a namespace with no database or collection")
		}
		nss = append(nss, mongoRunNamespace{db: db, collection: coll})
	}
	if header == nil {
		return nil, nil, fmt.Errorf("the run's prelude has no header")
	}
	return header, nss, nil
}

// mongoNamespaceHeader is the header that opens or closes a namespace's
// block, in the field order mongodump writes.
func mongoNamespaceHeader(ns mongoRunNamespace, eof bool, crc uint64) ([]byte, error) {
	return bson.Marshal(bson.D{{Key: "db", Value: ns.db}, {Key: "collection", Value: ns.collection}, {Key: "EOF", Value: eof}, {Key: "CRC", Value: int64(crc)}})
}

// mongoRunLayout is the order a rebuilt archive writes namespaces in: every
// namespace the prelude declares, then any collection the run holds that the
// prelude does not name, each with the part holding its documents or nil.
func mongoRunLayout(prelude []byte, parts []MongoRunPart) ([]mongoRunNamespace, []*MongoRunPart, error) {
	_, nss, err := mongoPreludeNamespaces(prelude)
	if err != nil {
		return nil, nil, err
	}
	byColl := map[string]*MongoRunPart{}
	for i := range parts {
		byColl[parts[i].Collection] = &parts[i]
	}
	var out []*MongoRunPart
	seen := map[string]bool{}
	for _, ns := range nss {
		out = append(out, byColl[ns.collection])
		seen[ns.collection] = true
	}
	db := ""
	if len(nss) > 0 {
		db = nss[0].db
	}
	for i := range parts {
		if seen[parts[i].Collection] {
			continue
		}
		if db == "" {
			return nil, nil, fmt.Errorf("the run holds collection %s and its prelude names no database", parts[i].Collection)
		}
		nss = append(nss, mongoRunNamespace{db: db, collection: parts[i].Collection})
		out = append(out, &parts[i])
	}
	return nss, out, nil
}

// MongoRunArchiveSize is the size of the archive WriteMongoRunArchive writes
// for a run, so it can be one entry of a tar stream.
func MongoRunArchiveSize(prelude []byte, parts []MongoRunPart) (int64, error) {
	nss, layout, err := mongoRunLayout(prelude, parts)
	if err != nil {
		return 0, err
	}
	size := int64(4 + len(prelude) + 4)
	for i, ns := range nss {
		h, err := mongoNamespaceHeader(ns, false, 0)
		if err != nil {
			return 0, err
		}
		// The opening header, the documents, a terminator, the closing
		// header (the same size, whatever its CRC) and a terminator.
		size += int64(len(h)) + 4 + int64(len(h)) + 4
		if layout[i] != nil {
			size += layout[i].Size
		}
	}
	return size, nil
}

// mongoTerminator closes a block of the archive.
var mongoTerminator = []byte{0xff, 0xff, 0xff, 0xff}

// WriteMongoRunArchive writes a run back as the mongodump archive it was
// taken from, one block per namespace: the magic, the prelude as stored, a
// terminator, then for each namespace its opening header, its documents, a
// terminator, its closing header with the CRC-64 of the documents, and a
// terminator. mongorestore reads it as it reads mongodump's own.
func WriteMongoRunArchive(prelude []byte, parts []MongoRunPart, w io.Writer) error {
	nss, layout, err := mongoRunLayout(prelude, parts)
	if err != nil {
		return err
	}
	var magic [4]byte
	binary.LittleEndian.PutUint32(magic[:], mongoArchiveMagic)
	if _, err := w.Write(magic[:]); err != nil {
		return err
	}
	if _, err := w.Write(prelude); err != nil {
		return err
	}
	if _, err := w.Write(mongoTerminator); err != nil {
		return err
	}
	table := crc64.MakeTable(crc64.ECMA)
	for i, ns := range nss {
		h, err := mongoNamespaceHeader(ns, false, 0)
		if err != nil {
			return err
		}
		if _, err := w.Write(h); err != nil {
			return err
		}
		crc := crc64.New(table)
		if p := layout[i]; p != nil {
			cw := &countingWriter{w: io.MultiWriter(w, crc)}
			if err := p.Open(cw); err != nil {
				return fmt.Errorf("reading %s: %w", p.Collection, err)
			}
			if cw.n != p.Size {
				return fmt.Errorf("%s holds %d bytes, the run recorded %d", p.Collection, cw.n, p.Size)
			}
		}
		if _, err := w.Write(mongoTerminator); err != nil {
			return err
		}
		if h, err = mongoNamespaceHeader(ns, true, crc.Sum64()); err != nil {
			return err
		}
		if _, err := w.Write(h); err != nil {
			return err
		}
		if _, err := w.Write(mongoTerminator); err != nil {
			return err
		}
	}
	return nil
}

// countingWriter counts what passes through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
