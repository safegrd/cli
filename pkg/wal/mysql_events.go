package wal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Binary log events, as far as the follower and a restore read them: each
// event's 19-byte header, the format description, GTID events' commit
// times, query events' default database and statement, and table maps'
// database. Row images are never decoded.

const (
	evQuery          = 2
	evStop           = 3
	evRotate         = 4
	evIntvar         = 5
	evRand           = 13
	evUserVar        = 14
	evFormatDesc     = 15
	evXID            = 16
	evTableMap       = 19
	evWriteRowsV1    = 23
	evDeleteRowsV1   = 25
	evHeartbeat      = 27
	evIncident       = 26
	evWriteRowsV2    = 30
	evDeleteRowsV2   = 32
	evGTID           = 33
	evAnonymousGTID  = 34
	evPreviousGTIDs  = 35
	evXAPrepare      = 38
	evPartialUpdate  = 39
	evTxPayload      = 40
	evHeartbeatV2    = 41
	evMariaAnnotate  = 160
	evMariaCkpt      = 161
	evMariaGTID      = 162
	evMariaGTIDList  = 163
	evMariaQueryComp = 165
	evMariaWriteComp = 166
	evMariaDelComp   = 171
	evHeaderLen      = 19
	binlogMagic      = "\xfebin"
	flagArtificial   = 0x20
)

// binlogEvent is one event as read: its bytes and its header.
type binlogEvent struct {
	Raw      []byte
	At       uint32 // header timestamp, seconds
	Type     byte
	ServerID uint32
	// LogPos is where the event ends in its file. MariaDB leaves it 0 on
	// the events inside a transaction.
	LogPos uint32
	Flags  uint16
}

func (e binlogEvent) start() uint32 { return e.LogPos - uint32(len(e.Raw)) }

func parseEventHeader(raw []byte) (binlogEvent, error) {
	if len(raw) < evHeaderLen {
		return binlogEvent{}, fmt.Errorf("a binary log event of %d bytes", len(raw))
	}
	e := binlogEvent{Raw: raw, At: binary.LittleEndian.Uint32(raw), Type: raw[4],
		ServerID: binary.LittleEndian.Uint32(raw[5:]), LogPos: binary.LittleEndian.Uint32(raw[13:]),
		Flags: binary.LittleEndian.Uint16(raw[17:])}
	if size := binary.LittleEndian.Uint32(raw[9:]); int(size) != len(raw) {
		return e, fmt.Errorf("a binary log event says it is %d bytes and is %d", size, len(raw))
	}
	return e, nil
}

// formatDesc is what a file's format description event says.
type formatDesc struct {
	Raw []byte
	// PostHeader is each event type's post-header length, by type - 1.
	PostHeader []byte
	// Checksum says each event ends in a CRC32.
	Checksum bool
	Server   string
}

func parseFormatDesc(raw []byte) (formatDesc, error) {
	fd := formatDesc{Raw: raw}
	b := raw[evHeaderLen:]
	if len(b) < 2+50+4+1 {
		return fd, errors.New("a short format description event")
	}
	fd.Server = strings.TrimRight(string(b[2:52]), "\x00")
	b = b[57:]
	// Servers since MySQL 5.6.1 and MariaDB 5.3 end the event with the
	// checksum algorithm (one byte) and the event's own CRC32.
	alg := byte(0)
	if len(b) >= 5 {
		alg = b[len(b)-5]
		fd.PostHeader = b[:len(b)-5]
	} else {
		fd.PostHeader = b
	}
	fd.Checksum = alg == 1
	return fd, nil
}

func (fd formatDesc) postHeader(t byte) int {
	if int(t) >= 1 && int(t) <= len(fd.PostHeader) {
		return int(fd.PostHeader[t-1])
	}
	return 0
}

// body is an event's bytes after its header, without its checksum.
func (fd formatDesc) body(e binlogEvent) []byte {
	b := e.Raw[evHeaderLen:]
	if fd.Checksum && len(b) >= 4 {
		b = b[:len(b)-4]
	}
	return b
}

func (fd formatDesc) checkCRC(e binlogEvent) error {
	if !fd.Checksum || e.Type == evFormatDesc {
		return nil
	}
	n := len(e.Raw)
	if n < evHeaderLen+4 {
		return errors.New("an event too short for its checksum")
	}
	if crc32.ChecksumIEEE(e.Raw[:n-4]) != binary.LittleEndian.Uint32(e.Raw[n-4:]) {
		return fmt.Errorf("an event at %d fails its checksum", e.start())
	}
	return nil
}

// queryParts reads a query event's default database and statement. A
// compressed MariaDB query's statement is not read: stmt is "".
func (fd formatDesc) queryParts(e binlogEvent) (db, stmt string) {
	b := fd.body(e)
	ph := fd.postHeader(e.Type)
	if e.Type == evMariaQueryComp {
		ph = fd.postHeader(evQuery)
	}
	if ph < 13 || len(b) < ph {
		return "", ""
	}
	dbLen := int(b[8])
	varsLen := int(binary.LittleEndian.Uint16(b[11:13]))
	i := ph + varsLen
	if len(b) < i+dbLen+1 {
		return "", ""
	}
	db = string(b[i : i+dbLen])
	if e.Type == evQuery {
		stmt = string(b[i+dbLen+1:])
	}
	return db, stmt
}

// tableID reads the table id a table map or rows event names.
func (fd formatDesc) tableID(e binlogEvent) (uint64, bool) {
	b := fd.body(e)
	n := 6
	if fd.postHeader(e.Type) == 6 {
		n = 4
	}
	if len(b) < n {
		return 0, false
	}
	var id uint64
	for i := n - 1; i >= 0; i-- {
		id = id<<8 | uint64(b[i])
	}
	return id, true
}

// tableMapDB reads the database a table map event's table is in.
func (fd formatDesc) tableMapDB(e binlogEvent) (string, bool) {
	b := fd.body(e)
	ph := fd.postHeader(evTableMap)
	if ph == 0 {
		ph = 8
	}
	if len(b) < ph+1 {
		return "", false
	}
	n := int(b[ph])
	if len(b) < ph+1+n {
		return "", false
	}
	return string(b[ph+1 : ph+1+n]), true
}

// commitMicros is a MySQL GTID event's immediate_commit_timestamp, when the
// event carries one.
func (fd formatDesc) commitMicros(e binlogEvent) (int64, bool) {
	b := fd.body(e)
	const fixed = 1 + 16 + 8 + 1 + 8 + 8
	if len(b) < fixed+7 || b[25] != 2 {
		return 0, false
	}
	var v uint64
	for i := 6; i >= 0; i-- {
		v = v<<8 | uint64(b[fixed+i])
	}
	v &^= 1 << 55
	return int64(v), v != 0
}

// gtidString names a GTID event's transaction: MySQL's uuid:gno, MariaDB's
// domain-server-seq.
func (fd formatDesc) gtidString(e binlogEvent) string {
	b := fd.body(e)
	switch e.Type {
	case evGTID:
		if len(b) < 25 {
			return ""
		}
		u := b[1:17]
		return fmt.Sprintf("%x-%x-%x-%x-%x:%d", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16], binary.LittleEndian.Uint64(b[17:25]))
	case evMariaGTID:
		if len(b) < 12 {
			return ""
		}
		return fmt.Sprintf("%d-%d-%d", binary.LittleEndian.Uint32(b[8:12]), e.ServerID, binary.LittleEndian.Uint64(b[0:8]))
	}
	return ""
}

func mariaStandalone(fd formatDesc, e binlogEvent) bool {
	b := fd.body(e)
	return len(b) >= 13 && b[12]&1 != 0
}

// binlogTx is one transaction, or one event outside any.
type binlogTx struct {
	Events []binlogEvent
	// At is when it committed: MySQL's commit timestamp to the
	// microsecond, else the last event's header to the second.
	At time.Time
	// Exact says At is to the microsecond.
	Exact bool
	GTID  string
}

// end is where the transaction ends in its file, counted on from the last
// event that says where it ends.
func (t *binlogTx) end() uint32 {
	var after uint32
	for i := len(t.Events) - 1; i >= 0; i-- {
		if p := t.Events[i].LogPos; p != 0 {
			return p + after
		}
		after += uint32(len(t.Events[i].Raw))
	}
	return 0
}

// begin is where the transaction starts in its file.
func (t *binlogTx) begin() uint32 {
	var size uint32
	for _, e := range t.Events {
		size += uint32(len(e.Raw))
	}
	return t.end() - size
}

// txGrouper cuts a run of events into transactions.
type txGrouper struct {
	fd   formatDesc
	cur  *binlogTx
	open bool // inside BEGIN, or a MariaDB transactional GTID
}

// add takes the next event and returns the transaction it completes, if it
// completes one.
func (g *txGrouper) add(e binlogEvent) *binlogTx {
	if g.cur == nil {
		g.cur = &binlogTx{}
	}
	t := g.cur
	t.Events = append(t.Events, e)
	at := time.Unix(int64(e.At), 0).UTC()
	if !t.Exact && at.After(t.At) {
		t.At = at
	}
	switch e.Type {
	case evGTID, evAnonymousGTID:
		t.GTID = g.fd.gtidString(e)
		if us, ok := g.fd.commitMicros(e); ok {
			t.At, t.Exact = time.UnixMicro(us).UTC(), true
		}
		return nil
	case evMariaGTID:
		t.GTID = g.fd.gtidString(e)
		g.open = !mariaStandalone(g.fd, e)
		return nil
	case evMariaAnnotate, evIntvar, evRand, evUserVar:
		return nil // these lead into the statement after them
	case evQuery:
		_, stmt := g.fd.queryParts(e)
		word := strings.ToUpper(strings.TrimSpace(stmt))
		switch {
		case word == "BEGIN" || strings.HasPrefix(word, "XA START"):
			g.open = true
			return nil
		case word == "COMMIT" || word == "ROLLBACK" || strings.HasPrefix(word, "XA COMMIT") || strings.HasPrefix(word, "XA ROLLBACK"):
			g.open = false
		}
	case evXID, evXAPrepare:
		g.open = false
	}
	if g.open {
		return nil
	}
	g.cur = nil
	return t
}

// pending says events have been taken that no transaction has closed.
func (g *txGrouper) pending() bool { return g.cur != nil && len(g.cur.Events) > 0 }

// mysqlSegRe is a binary log segment's name: the file's number, the byte
// range it covers, and r when it ends with the server's rotate to the next
// file. An empty range with a time after it marks that the follower was
// caught up then, with nothing to push.
var mysqlSegRe = regexp.MustCompile(`^my-[0-9a-f]{8}-[0-9a-f]{12}-[0-9a-f]{12}(?:r|-[0-9a-f]{8})?$`)

func mysqlSegName(s StreamSeg) string {
	n := fmt.Sprintf("my-%08x-%012x-%012x", s.File, s.Start, s.End)
	switch {
	case s.Rotates:
		n += "r"
	case s.Idle != 0:
		n += fmt.Sprintf("-%08x", s.Idle)
	}
	return n
}

// parseMySQLSegment reads a segment name back.
func parseMySQLSegment(name string) (StreamSeg, bool) {
	if !mysqlSegRe.MatchString(name) {
		return StreamSeg{}, false
	}
	f, _ := strconv.ParseUint(name[3:11], 16, 32)
	st, _ := strconv.ParseUint(name[12:24], 16, 64)
	en, _ := strconv.ParseUint(name[25:37], 16, 64)
	s := StreamSeg{Name: name, File: uint32(f), Start: st, End: en, Rotates: strings.HasSuffix(name, "r")}
	if len(name) > 38 && name[37] == '-' {
		t, _ := strconv.ParseUint(name[38:], 16, 32)
		s.Idle = uint32(t)
	}
	return s, true
}

// binlogFileNumber is the number a binary log file's name ends in.
func binlogFileNumber(name string) (uint32, error) {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return 0, fmt.Errorf("%q is not a binary log file name", name)
	}
	n, err := strconv.ParseUint(name[i+1:], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not a binary log file name", name)
	}
	return uint32(n), nil
}

// binlogFileName is the file with number n beside base's.
func binlogFileName(base string, n uint32) string {
	i := strings.LastIndexByte(base, '.')
	width := len(base) - i - 1
	return fmt.Sprintf("%s.%0*d", base[:i], width, n)
}

// segmentBody is a segment as a binary log file mysqlbinlog reads: the
// magic, the format description, and the events.
func segmentBody(fd formatDesc, events []binlogEvent) []byte {
	var b bytes.Buffer
	b.WriteString(binlogMagic)
	b.Write(fd.Raw)
	for _, e := range events {
		b.Write(e.Raw)
	}
	return b.Bytes()
}

// readSegmentBody splits a segment back into its format description and
// events.
func readSegmentBody(body []byte) (formatDesc, []binlogEvent, error) {
	var fd formatDesc
	if !bytes.HasPrefix(body, []byte(binlogMagic)) {
		return fd, nil, errors.New("not a binary log segment")
	}
	b := body[len(binlogMagic):]
	var out []binlogEvent
	first := true
	for len(b) > 0 {
		if len(b) < evHeaderLen {
			return fd, nil, errors.New("a binary log segment ends inside an event header")
		}
		size := int(binary.LittleEndian.Uint32(b[9:]))
		if size < evHeaderLen || size > len(b) {
			return fd, nil, errors.New("a binary log segment ends inside an event")
		}
		e, err := parseEventHeader(b[:size])
		if err != nil {
			return fd, nil, err
		}
		if first {
			if e.Type != evFormatDesc {
				return fd, nil, errors.New("a binary log segment does not start with a format description")
			}
			if fd, err = parseFormatDesc(e.Raw); err != nil {
				return fd, nil, err
			}
			first = false
		} else {
			out = append(out, e)
		}
		b = b[size:]
	}
	if first {
		return fd, nil, errors.New("an empty binary log segment")
	}
	return fd, out, nil
}

// filterTx keeps what a restore of database db replays from one
// transaction: statements whose default database is db (and BEGIN, COMMIT,
// ROLLBACK), db's table maps and the row events behind them, and the events
// that frame them. ok is false when nothing of db's is left.
func filterTx(fd formatDesc, t *binlogTx, db string) (kept []binlogEvent, ok bool) {
	tables := map[uint64]bool{}
	for _, e := range t.Events {
		switch {
		case e.Type == evQuery || e.Type == evMariaQueryComp:
			qdb, stmt := fd.queryParts(e)
			word := strings.ToUpper(strings.TrimSpace(stmt))
			if word == "BEGIN" || word == "COMMIT" || word == "ROLLBACK" || strings.HasPrefix(word, "XA ") {
				kept = append(kept, e)
				continue
			}
			if qdb == db {
				kept, ok = append(kept, e), true
			}
		case e.Type == evTableMap:
			id, idOK := fd.tableID(e)
			tdb, dbOK := fd.tableMapDB(e)
			if idOK && dbOK && tdb == db {
				tables[id] = true
				kept, ok = append(kept, e), true
			}
		case isRowsEvent(e.Type):
			if id, idOK := fd.tableID(e); idOK && tables[id] {
				kept = append(kept, e)
			}
		case e.Type == evMariaAnnotate, e.Type == evIntvar, e.Type == evRand, e.Type == evUserVar:
			// Framing for a statement; harmless when the statement is gone.
			kept = append(kept, e)
		case e.Type == evGTID, e.Type == evAnonymousGTID, e.Type == evMariaGTID, e.Type == evXID, e.Type == evXAPrepare:
			kept = append(kept, e)
		}
	}
	return kept, ok
}

func isRowsEvent(t byte) bool {
	return (t >= evWriteRowsV1 && t <= evDeleteRowsV1) || (t >= evWriteRowsV2 && t <= evDeleteRowsV2) ||
		t == evPartialUpdate || (t >= evMariaWriteComp && t <= evMariaDelComp)
}
