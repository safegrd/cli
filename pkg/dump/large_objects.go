package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/safegrd/cli/pkg/model"
)

// Large objects live in pg_largeobject, outside every table a COPY reads,
// and pg_dump leaves them out of the sections the backup asks it for. They
// are read here, under the backup's snapshot, into two kinds of entry:
//
//	large-objects.json         each object's oid, owner and size, before them
//	large-objects/<oid>.lo     an object's bytes
//
// both after the tables' rows and before post-data. The manifest records how
// many there were, how many the role could not read, and one digest over
// every object, which a restore and a drill hold what they read to.
const (
	entryLargeObjects = "large-objects.json"
	largeObjectPrefix = "large-objects/"
	largeObjectSuffix = ".lo"

	loReadMode  = 0x40000 // INV_READ: reads see the transaction's snapshot
	loWriteMode = 0x20000 // INV_WRITE
	loChunk     = 1 << 20
)

// largeObject is one object as large-objects.json lists it.
type largeObject struct {
	OID   uint32 `json:"oid"`
	Owner string `json:"owner"`
	Size  int64  `json:"size"`
}

// largeObjectEntry is the archive entry an object's bytes are in. The oid is
// zero-padded so entries sort in oid order.
func largeObjectEntry(oid uint32) string {
	return fmt.Sprintf("%s%010d%s", largeObjectPrefix, oid, largeObjectSuffix)
}

// parseLargeObjectEntry is the oid an entry name holds an object's bytes for.
func parseLargeObjectEntry(name string) (uint32, bool) {
	if !strings.HasPrefix(name, largeObjectPrefix) || !strings.HasSuffix(name, largeObjectSuffix) {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, largeObjectPrefix), largeObjectSuffix), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// IsLargeObjectEntry reports whether an archive entry or a run's file is one
// of a PostgreSQL snapshot's large objects or their list.
func IsLargeObjectEntry(name string) bool {
	_, ok := parseLargeObjectEntry(name)
	return ok || name == entryLargeObjects
}

// loDigest folds each object's oid, size and SHA-256 into one digest. Objects
// are added in oid order, as the dump writes them.
type loDigest struct {
	h     hash.Hash
	n     int64
	bytes int64
}

func newLODigest() *loDigest { return &loDigest{h: sha256.New()} }

func (d *loDigest) add(oid uint32, size int64, sum []byte) {
	var b [12]byte
	binary.BigEndian.PutUint32(b[:4], oid)
	binary.BigEndian.PutUint64(b[4:], uint64(size))
	d.h.Write(b[:])
	d.h.Write(sum)
	d.n++
	d.bytes += size
}

func (d *loDigest) hex() string { return hex.EncodeToString(d.h.Sum(nil)) }

// loObjects collects what an archive's objects hashed to, in any order, and
// digests them in oid order.
type loObjects map[uint32]struct {
	size int64
	sum  []byte
}

func (o loObjects) digest() *loDigest {
	oids := make([]uint32, 0, len(o))
	for oid := range o {
		oids = append(oids, oid)
	}
	sort.Slice(oids, func(i, j int) bool { return oids[i] < oids[j] })
	d := newLODigest()
	for _, oid := range oids {
		d.add(oid, o[oid].size, o[oid].sum)
	}
	return d
}

// hashLargeObject reads one object's entry and records its size and digest.
func (o loObjects) hashLargeObject(oid uint32, r io.Reader) error {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return err
	}
	o[oid] = struct {
		size int64
		sum  []byte
	}{n, h.Sum(nil)}
	return nil
}

// dumpLargeObjects writes every large object the backup's role may read into
// the archive, under the backup's snapshot, and records them in meta. One the
// role may not read is counted and said, not a reason to stop the backup.
func dumpLargeObjects(ctx context.Context, tx pgx.Tx, tw *tar.Writer, meta *model.SnapshotMetadata, warn func(string)) error {
	rows, err := tx.Query(ctx, `SELECT l.oid::int8, coalesce(pg_get_userbyid(l.lomowner)::text, '') FROM pg_largeobject_metadata l ORDER BY l.oid`)
	if err != nil {
		return fmt.Errorf("failed to list large objects: %w", err)
	}
	var all []largeObject
	for rows.Next() {
		var oid int64
		var lo largeObject
		if err := rows.Scan(&oid, &lo.Owner); err != nil {
			rows.Close()
			return fmt.Errorf("failed to list large objects: %w", err)
		}
		lo.OID = uint32(oid)
		all = append(all, lo)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to list large objects: %w", err)
	}
	meta.LargeObjects = int64(len(all))
	if len(all) == 0 {
		return nil
	}

	// First the ones this role may open, with their sizes: the list goes
	// in ahead of the bytes so a restore knows each object's owner.
	var readable []largeObject
	var refused []string
	for _, lo := range all {
		size, err := largeObjectSize(ctx, tx, lo.OID)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "42501" {
				refused = append(refused, strconv.FormatUint(uint64(lo.OID), 10))
				continue
			}
			return fmt.Errorf("failed to open large object %d: %w", lo.OID, err)
		}
		lo.Size = size
		readable = append(readable, lo)
	}
	list, err := json.Marshal(readable)
	if err != nil {
		return err
	}
	if err := writeTarEntry(tw, entryLargeObjects, list); err != nil {
		return err
	}
	digest := newLODigest()
	for _, lo := range readable {
		sum, err := copyLargeObject(ctx, tx, tw, lo)
		if err != nil {
			return fmt.Errorf("failed to read large object %d: %w", lo.OID, err)
		}
		digest.add(lo.OID, lo.Size, sum)
	}
	meta.LargeObjectsLeftOut = int64(len(refused))
	meta.LargeObjectBytes = digest.bytes
	meta.LargeObjectsDigest = digest.hex()
	if len(refused) > 0 {
		shown := refused
		if len(shown) > 10 {
			shown = append(shown[:10:10], "...")
		}
		warn(fmt.Sprintf("This backup's role may not read %d of the database's %d large objects (%s), so the snapshot does not hold them, "+
			"and its Fire Drill fails. Back up as their owner, or GRANT SELECT ON LARGE OBJECT ... TO the backup role.",
			len(refused), len(all), strings.Join(shown, ", ")))
	}
	return nil
}

// largeObjectSize opens an object for reading under a savepoint and returns
// its size, so a refusal leaves the transaction usable.
func largeObjectSize(ctx context.Context, tx pgx.Tx, oid uint32) (int64, error) {
	if _, err := tx.Exec(ctx, "SAVEPOINT safegrd_lo"); err != nil {
		return 0, err
	}
	var fd int32
	var size int64
	err := tx.QueryRow(ctx, "SELECT lo_open($1::int8::oid, $2)", int64(oid), loReadMode).Scan(&fd)
	if err == nil {
		err = tx.QueryRow(ctx, "SELECT lo_lseek64($1, 0, 2)", fd).Scan(&size)
	}
	if err == nil {
		_, err = tx.Exec(ctx, "SELECT lo_close($1)", fd)
	}
	if err != nil {
		if _, rerr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT safegrd_lo; RELEASE SAVEPOINT safegrd_lo"); rerr != nil {
			return 0, rerr
		}
		return 0, err
	}
	_, err = tx.Exec(ctx, "RELEASE SAVEPOINT safegrd_lo")
	return size, err
}

// copyLargeObject writes one object's bytes to the archive and returns their
// SHA-256.
func copyLargeObject(ctx context.Context, tx pgx.Tx, tw *tar.Writer, lo largeObject) ([]byte, error) {
	if err := tw.WriteHeader(&tar.Header{Name: largeObjectEntry(lo.OID), Mode: 0o600, Size: lo.Size, ModTime: time.Now()}); err != nil {
		return nil, err
	}
	var fd int32
	if err := tx.QueryRow(ctx, "SELECT lo_open($1::int8::oid, $2)", int64(lo.OID), loReadMode).Scan(&fd); err != nil {
		return nil, err
	}
	h := sha256.New()
	var read int64
	for read < lo.Size {
		var chunk []byte
		if err := tx.QueryRow(ctx, "SELECT loread($1, $2)", fd, loChunk).Scan(&chunk); err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			return nil, fmt.Errorf("ended at %d of %d bytes", read, lo.Size)
		}
		if int64(len(chunk)) > lo.Size-read {
			return nil, fmt.Errorf("grew past the %d bytes it had when the backup began", lo.Size)
		}
		h.Write(chunk)
		if _, err := tw.Write(chunk); err != nil {
			return nil, err
		}
		read += int64(len(chunk))
	}
	if _, err := tx.Exec(ctx, "SELECT lo_close($1)", fd); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// loadLargeObject creates one object under its own oid and writes its bytes
// into it, returning their SHA-256. The target is empty, so the oid is free.
func loadLargeObject(ctx context.Context, conn *pgx.Conn, oid uint32, r io.Reader) (int64, []byte, error) {
	if _, err := conn.Exec(ctx, "SELECT lo_create($1::int8::oid)", int64(oid)); err != nil {
		return 0, nil, fmt.Errorf("creating large object %d: %w", oid, err)
	}
	var fd int32
	if err := conn.QueryRow(ctx, "SELECT lo_open($1::int8::oid, $2)", int64(oid), loWriteMode).Scan(&fd); err != nil {
		return 0, nil, fmt.Errorf("opening large object %d: %w", oid, err)
	}
	h := sha256.New()
	buf := make([]byte, loChunk)
	var n int64
	for {
		k, err := io.ReadFull(r, buf)
		if k > 0 {
			h.Write(buf[:k])
			if _, werr := conn.Exec(ctx, "SELECT lowrite($1, $2)", fd, buf[:k]); werr != nil {
				return 0, nil, fmt.Errorf("writing large object %d: %w", oid, werr)
			}
			n += int64(k)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return 0, nil, err
		}
	}
	if _, err := conn.Exec(ctx, "SELECT lo_close($1)", fd); err != nil {
		return 0, nil, fmt.Errorf("closing large object %d: %w", oid, err)
	}
	return n, h.Sum(nil), nil
}

// largeObjectsAssertion is a drill's check of the objects an archive held
// against the manifest, and false when the database held none.
func largeObjectsAssertion(m *model.SnapshotMetadata, got loObjects) (model.AssertionResult, bool) {
	if m == nil || m.LargeObjects == 0 {
		return model.AssertionResult{}, false
	}
	a := model.AssertionResult{
		Name:     "Large Objects Included",
		Expected: fmt.Sprintf("%s, digest %s", largeObjectsWords(m.LargeObjects), shortDigest(m.LargeObjectsDigest)),
	}
	d := got.digest()
	a.Actual = fmt.Sprintf("%s, digest %s", largeObjectsWords(d.n), shortDigest(d.hex()))
	switch {
	case m.LargeObjectsLeftOut > 0:
		a.Message = fmt.Sprintf("The backup's role could not read %s of the database's %d, so the snapshot does not hold them",
			largeObjectsWords(m.LargeObjectsLeftOut), m.LargeObjects)
	case d.n != m.LargeObjects || d.hex() != m.LargeObjectsDigest:
		a.Message = "The archive's large objects are not the ones the backup read"
	default:
		a.Passed = true
		a.Message = fmt.Sprintf("Every large object is in the archive, %d bytes, matching the backup's digest", d.bytes)
	}
	return a, true
}

func shortDigest(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// largeObjectSQL is one object as SQL psql can run: created under its oid
// and written in chunks, so a load.sql restores it without SafeGrd.
func largeObjectSQL(oid uint32, r io.Reader) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "SELECT pg_catalog.lo_create(%d);\n", oid)
	buf := make([]byte, loChunk)
	var off int64
	for {
		k, err := io.ReadFull(r, buf)
		if k > 0 {
			fmt.Fprintf(&b, "SELECT pg_catalog.lo_put(%d, %d, '\\x%s');\n", oid, off, hex.EncodeToString(buf[:k]))
			off += int64(k)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return b.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
	}
}
