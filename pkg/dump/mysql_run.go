package dump

import (
	"archive/tar"
	"regexp"
	"strconv"
	"strings"
)

// A MySQL run splits the dump tool's one stream into the sections it is
// written in, so a table nothing wrote since the last run stores no new
// chunks and the console can show each table's bytes:
//
//	mysql/head.sql[.N]            everything before the first table: the
//	                              header and the session settings
//	mysql/tables/<table>.sql[.N]  one table, view stub or sequence: its
//	                              structure, its rows and its triggers
//	mysql/tail.sql[.N]            routines, events, the final view
//	                              definitions, the closing settings and
//	                              "-- Dump completed"
//	manifest.json
//
// Concatenated in that order (head, the tables as the dump wrote them, tail)
// the sections are the dump byte for byte, so a restore and a drill read the
// stream the archive's readers already read. The split is on the comment
// block the dump tool puts before each object:
//
//	--
//	-- Table structure for table `orders`
//	--
//
// The tail starts at the first block that is not an object's (routines,
// events, a final view) or at the closing settings, whichever comes first.
//
// `mysqldump --tab` was not used: it has the server write one file per
// table on its own disk (FILE privilege, secure_file_priv), which a managed
// server refuses and a backup machine cannot read.
const (
	// MySQLHeadEntry, MySQLTablesDir and MySQLTailEntry name a run's
	// sections.
	MySQLHeadEntry   = "mysql/head.sql"
	MySQLTablesDir   = "mysql/tables/"
	MySQLTailEntry   = "mysql/tail.sql"
	mysqlCommentLine = "--"
)

// mysqlObjectHeader is the comment line that opens a table's, a view stub's
// or a sequence's section, with its name in backticks (doubled inside).
var mysqlObjectHeader = regexp.MustCompile("^-- (?:Table structure for table|Temporary (?:view|table) structure for view|Sequence structure for) `((?:[^`]|``)+)`$")

// mysqlTailStarts are the lines after which nothing belongs to a table: the
// comment blocks for routines, events and the final view definitions, and
// the first of the closing session settings, which is how the tail starts
// when the database has none of those.
var mysqlTailStarts = []string{
	"-- Dumping routines for database",
	"-- Dumping events for database",
	"-- Final view structure for view",
	"-- Dump completed",
	"/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;",
}

// MySQLTableEntry is the run entry a table's section is stored in.
func MySQLTableEntry(table string) string { return MySQLTablesDir + runEntryName(table) + ".sql" }

// mysqlSectionWriter is the io.Writer a per-table dump streams into. It
// cuts the stream at object boundaries and writes each section through its
// own chunkWriter, so a table larger than copyChunkSize is still written in
// parts and nothing is held in memory beyond one line and one chunk.
type mysqlSectionWriter struct {
	tw      *tar.Writer
	cur     *chunkWriter
	head    *chunkWriter
	tail    *chunkWriter
	inTail  bool
	line    []byte
	pending []byte
	// Tables are the object sections, in the dump's order.
	Tables []string
	err    error
}

func newMySQLSectionWriter(tw *tar.Writer) *mysqlSectionWriter {
	head := &chunkWriter{tw: tw, name: func(part int) string { return chunkedName(MySQLHeadEntry, part) }}
	return &mysqlSectionWriter{tw: tw, cur: head, head: head}
}

// chunkedName is part N of a stream written in parts.
func chunkedName(base string, part int) string {
	if part == 0 {
		return base
	}
	return base + "." + strconv.Itoa(part)
}

func (w *mysqlSectionWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n := len(p)
	for len(p) > 0 {
		i := strings.IndexByte(string(p), '\n')
		if i < 0 {
			w.line = append(w.line, p...)
			break
		}
		w.line = append(w.line, p[:i+1]...)
		p = p[i+1:]
		if err := w.endLine(); err != nil {
			w.err = err
			return 0, err
		}
	}
	return n, nil
}

// endLine routes one complete line. A bare "--" is held back until the next
// line says whether it opens a new section.
func (w *mysqlSectionWriter) endLine() error {
	line := w.line
	w.line = nil
	text := strings.TrimRight(string(line), "\r\n")
	if text == mysqlCommentLine {
		if err := w.flushPending(); err != nil {
			return err
		}
		w.pending = line
		return nil
	}
	if !w.inTail {
		if m := mysqlObjectHeader.FindStringSubmatch(text); m != nil {
			name := strings.ReplaceAll(m[1], "``", "`")
			w.Tables = append(w.Tables, name)
			entry := MySQLTableEntry(name)
			if err := w.closeCurrent(); err != nil {
				return err
			}
			w.cur = &chunkWriter{tw: w.tw, name: func(part int) string { return chunkedName(entry, part) }}
		} else if w.cur != w.head && mysqlStartsTail(text) {
			if err := w.closeCurrent(); err != nil {
				return err
			}
			w.inTail = true
			w.tail = &chunkWriter{tw: w.tw, name: func(part int) string { return chunkedName(MySQLTailEntry, part) }}
			w.cur = w.tail
		}
	}
	if err := w.flushPending(); err != nil {
		return err
	}
	_, err := w.cur.Write(line)
	return err
}

func mysqlStartsTail(text string) bool {
	for _, s := range mysqlTailStarts {
		if strings.HasPrefix(text, s) {
			return true
		}
	}
	return false
}

func (w *mysqlSectionWriter) flushPending() error {
	if w.pending == nil {
		return nil
	}
	_, err := w.cur.Write(w.pending)
	w.pending = nil
	return err
}

// closeCurrent finishes the section being written. The head is closed when
// the first object starts, every table when the next section starts.
func (w *mysqlSectionWriter) closeCurrent() error {
	return w.cur.Close()
}

// Close writes what is left: a partial last line, a held-back "--", the
// section being written. A dump with no object has only a head; one with
// objects and no tail has none, and the sections still concatenate to the
// dump.
func (w *mysqlSectionWriter) Close() error {
	if w.err != nil {
		return w.err
	}
	if len(w.line) > 0 {
		line := w.line
		w.line = nil
		if err := w.flushPending(); err != nil {
			return err
		}
		if _, err := w.cur.Write(line); err != nil {
			return err
		}
	}
	if err := w.flushPending(); err != nil {
		return err
	}
	return w.closeCurrent()
}

// IsMySQLRunEntry reports whether an archive entry is a section of a
// per-table MySQL dump: the head, a table or the tail.
func IsMySQLRunEntry(name string) bool {
	base, _, ok := parseChunkedEntry(name)
	return ok && (base == MySQLHeadEntry || base == MySQLTailEntry || strings.HasPrefix(base, MySQLTablesDir))
}

// MySQLRunTable is the table a run entry under mysql/tables/ holds, or ""
// for the head and the tail.
func MySQLRunTable(name string) string {
	base, _, ok := parseChunkedEntry(name)
	if !ok || !strings.HasPrefix(base, MySQLTablesDir) {
		return ""
	}
	return unescapeRunEntryName(strings.TrimSuffix(strings.TrimPrefix(base, MySQLTablesDir), ".sql"))
}
