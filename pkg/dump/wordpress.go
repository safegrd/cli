package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// A WordPress snapshot is one archive holding the site's database and its
// files, written by the WordPress plugin. In order:
//
//	mysql/dump.sql[.N]  the database, in mysqldump's shape, in chunks
//	files/<path>        wp-config.php, .htaccess and wp-content, relative to the site root
//	files.json          every files/ entry: path, size, SHA-256
//	manifest.json       the snapshot metadata, with a wordpress section
//
// The dump is read by the MySQL code: the same counter, the same client on
// restore. Nothing else may be in the archive.
const (
	wpFilesPrefix   = "files/"
	wpFileListEntry = "files.json"
	// WordPressSchemaSource is how the plugin names itself in SchemaSource,
	// followed by its version.
	WordPressSchemaSource = "safegrd-wordpress"
	// wpAttachedFileKey is the postmeta key that names an attachment's
	// file, relative to the uploads directory.
	wpAttachedFileKey = "_wp_attached_file"
	// wpListMissing is how many missing or mismatched names an assertion
	// spells out before it gives a count.
	wpListMissing = 10
)

// WordPressFileEntry is one file the archive holds, as files.json lists it.
type WordPressFileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Sha256 string `json:"sha256"`
}

// wordpressParts is what reading a WordPress archive found besides the dump.
type wordpressParts struct {
	manifest   *model.SnapshotMetadata
	fileList   []WordPressFileEntry
	sawList    bool
	sawDump    bool
	unexpected []string
}

// readWordPressArchive reads the archive once: the dump to consume as one
// stream, each file to onFile with its path relative to the site root, and
// files.json and manifest.json into parts.
func readWordPressArchive(src io.Reader, consume func(io.Reader) error, onFile func(rel string, hdr *tar.Header, r io.Reader) error) (*wordpressParts, error) {
	parts := &wordpressParts{}
	streams := &tableStreams{
		parse: parseMySQLChunk,
		consume: func(_, _ string, r io.Reader) error {
			parts.sawDump = true
			return consume(r)
		},
		other: func(hdr *tar.Header, r io.Reader) error {
			switch {
			case hdr.Name == entryManifest:
				data, err := io.ReadAll(io.LimitReader(r, 64<<20))
				if err != nil {
					return err
				}
				var m model.SnapshotMetadata
				if err := json.Unmarshal(data, &m); err != nil {
					return fmt.Errorf("the archive's manifest is unreadable: %w", err)
				}
				parts.manifest = &m
			case hdr.Name == wpFileListEntry:
				data, err := io.ReadAll(io.LimitReader(r, 256<<20))
				if err != nil {
					return err
				}
				if err := json.Unmarshal(data, &parts.fileList); err != nil {
					return fmt.Errorf("the archive's file list is unreadable: %w", err)
				}
				parts.sawList = true
			case strings.HasPrefix(hdr.Name, wpFilesPrefix) && hdr.Typeflag == tar.TypeReg:
				rel := strings.TrimPrefix(hdr.Name, wpFilesPrefix)
				if err := safeRelPath(rel); err != nil {
					return err
				}
				return onFile(rel, hdr, r)
			default:
				parts.unexpected = append(parts.unexpected, hdr.Name)
			}
			return nil
		},
	}
	err := streams.Run(tar.NewReader(src))
	return parts, err
}

// safeRelPath refuses a path that would leave the directory it is joined to.
func safeRelPath(rel string) error {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") || strings.ContainsRune(rel, 0) {
		return fmt.Errorf("the archive names a file outside the site: %q", rel)
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return fmt.Errorf("the archive names a file outside the site: %q", rel)
		}
	}
	return nil
}

// seenFile is a file as the archive held it.
type seenFile struct {
	size   int64
	sha256 string
}

// InspectWordPressArchive is the in-memory Fire Drill for a WordPress site.
// It checks the site as one thing: the database half as a MySQL drill does,
// every file against the list written beside it, and every attachment the
// database names (read out of the dump, not from a list the plugin wrote)
// against the files the archive holds.
func InspectWordPressArchive(ctx context.Context, src io.Reader) (*DryRestoreResult, error) {
	start := time.Now()
	result := &DryRestoreResult{Passed: true}
	counter := newMySQLDumpCounter()
	attachments := newWPAttachmentScanner()
	var dumpBytes int64
	seen := map[string]seenFile{}
	parts, err := readWordPressArchive(src, func(r io.Reader) error {
		n, err := io.Copy(io.MultiWriter(counter, attachments), r)
		dumpBytes = n
		return err
	}, func(rel string, _ *tar.Header, r io.Reader) error {
		h := sha256.New()
		n, err := io.Copy(h, r)
		if err != nil {
			return err
		}
		seen[rel] = seenFile{size: n, sha256: hex.EncodeToString(h.Sum(nil))}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		result.Passed = false
		result.ErrorMessage = fmt.Sprintf("failed reading the archive: %v", err)
		return result, nil
	}
	add := func(a model.AssertionResult) {
		result.Assertions = append(result.Assertions, a)
		if !a.Passed {
			result.Passed = false
		}
	}
	manifest := parts.manifest
	add(model.AssertionResult{Name: "Manifest Catalog Integrity", Passed: manifest != nil && manifest.WordPress != nil,
		Expected: "manifest.json with a wordpress section", Actual: fmt.Sprintf("present: %v", manifest != nil && manifest.WordPress != nil)})
	add(model.AssertionResult{Name: "Dump Present", Passed: parts.sawDump,
		Expected: mysqlDumpEntry + " present", Actual: fmt.Sprintf("present: %v", parts.sawDump)})
	add(model.AssertionResult{Name: "Dump Complete", Passed: counter.Completed,
		Expected: "the dump ends with its completion line", Actual: fmt.Sprintf("complete: %v", counter.Completed)})
	add(model.AssertionResult{Name: "Only Site Entries", Passed: len(parts.unexpected) == 0,
		Expected: "the dump, files/, files.json and manifest.json", Actual: describeNames("unexpected", parts.unexpected)})
	if manifest == nil || manifest.WordPress == nil {
		result.ErrorMessage = "archive is missing manifest.json or its wordpress section"
		return result, nil
	}
	wp := manifest.WordPress
	result.Manifest = manifest
	result.DatabaseName = manifest.DatabaseName
	add(SchemaFidelity(manifest))

	// The database half.
	for _, t := range counter.Tables() {
		result.Tables = append(result.Tables, TableDryStats{Schema: manifest.DatabaseName, TableName: t, RowCount: counter.Rows[t]})
		result.TotalRows += counter.Rows[t]
	}
	result.TotalTables = len(result.Tables)
	result.TotalDataBytes = dumpBytes
	add(model.AssertionResult{Name: "Table Count Match", Passed: result.TotalTables == manifest.TotalTables,
		Expected: fmt.Sprintf("%d tables", manifest.TotalTables), Actual: fmt.Sprintf("%d tables", result.TotalTables)})
	add(model.AssertionResult{Name: "Total Row Count Match", Passed: result.TotalRows == manifest.TotalRows,
		Expected: fmt.Sprintf("%d rows", manifest.TotalRows), Actual: fmt.Sprintf("%d rows", result.TotalRows)})
	for _, t := range manifest.TableStats {
		got, ok := counter.Rows[t.TableName]
		if !ok {
			add(model.AssertionResult{Name: "Table Existence: " + t.TableName, Expected: "table in the dump", Actual: "missing"})
			continue
		}
		add(model.AssertionResult{Name: "Row Count: " + t.TableName, Passed: got == t.RowCount,
			Expected: fmt.Sprintf("%d rows", t.RowCount), Actual: fmt.Sprintf("%d rows", got)})
	}

	// The files half: every file against its list, both ways.
	add(model.AssertionResult{Name: "File List Present", Passed: parts.sawList,
		Expected: wpFileListEntry + " present", Actual: fmt.Sprintf("present: %v", parts.sawList)})
	var missing, mismatched, unlisted []string
	listed := map[string]bool{}
	var listedBytes int64
	for _, f := range parts.fileList {
		listed[f.Path] = true
		listedBytes += f.Size
		got, ok := seen[f.Path]
		switch {
		case !ok:
			missing = append(missing, f.Path)
		case got.size != f.Size || !strings.EqualFold(got.sha256, f.Sha256):
			mismatched = append(mismatched, f.Path)
		}
	}
	for p := range seen {
		if !listed[p] {
			unlisted = append(unlisted, p)
		}
	}
	add(model.AssertionResult{Name: "Files Present", Passed: len(missing) == 0,
		Expected: fmt.Sprintf("%d files", len(parts.fileList)), Actual: describeNames("missing", missing)})
	add(model.AssertionResult{Name: "File Contents Match", Passed: len(mismatched) == 0,
		Expected: "every file's size and SHA-256 as listed", Actual: describeNames("differ", mismatched)})
	add(model.AssertionResult{Name: "No Unlisted Files", Passed: len(unlisted) == 0,
		Expected: "every file in the list", Actual: describeNames("unlisted", unlisted)})
	add(model.AssertionResult{Name: "File Count Match", Passed: int64(len(parts.fileList)) == wp.TotalFiles,
		Expected: fmt.Sprintf("%d files", wp.TotalFiles), Actual: fmt.Sprintf("%d files", len(parts.fileList))})
	if wp.FileBytes > 0 {
		add(model.AssertionResult{Name: "File Bytes Match", Passed: listedBytes == wp.FileBytes,
			Expected: fmt.Sprintf("%d bytes", wp.FileBytes), Actual: fmt.Sprintf("%d bytes", listedBytes)})
	}

	// The two halves against each other: every attachment the database
	// names is a file in the archive.
	named := attachments.Files(wp.TablePrefix + "postmeta")
	uploads := strings.Trim(wp.UploadsPath, "/")
	var absent []string
	for _, f := range named {
		rel := path.Join(uploads, f)
		if _, ok := seen[rel]; !ok {
			absent = append(absent, rel)
		}
	}
	add(model.AssertionResult{Name: "Attachments Present", Passed: len(absent) == 0 && attachments.Err() == nil,
		Expected: fmt.Sprintf("%d attachments the database names, under %s", len(named), uploads),
		Actual:   describeAttachments(len(named), absent, attachments.Err())})
	result.DurationMs = elapsedMilliseconds(start)
	return result, nil
}

func describeNames(what string, names []string) string {
	if len(names) == 0 {
		return "none " + what
	}
	sort.Strings(names)
	shown := names
	if len(shown) > wpListMissing {
		shown = shown[:wpListMissing]
	}
	s := fmt.Sprintf("%d %s: %s", len(names), what, strings.Join(shown, ", "))
	if len(names) > len(shown) {
		s += ", ..."
	}
	return s
}

func describeAttachments(named int, absent []string, err error) string {
	if err != nil {
		return "the dump's attachment rows could not be read: " + err.Error()
	}
	if len(absent) == 0 {
		return fmt.Sprintf("%d of %d present", named, named)
	}
	return fmt.Sprintf("%d of %d present; %s", named-len(absent), named, describeNames("missing", absent))
}

// wpAttachmentScanner reads a dump as it streams past and collects, for
// every table with meta_key and meta_value columns, the meta_value of each
// row whose meta_key is _wp_attached_file. The columns come from the table's
// CREATE TABLE, since mysqldump's INSERTs name none.
type wpAttachmentScanner struct {
	columns map[string][]string
	files   map[string][]string

	state     int
	line      []byte
	creating  string
	inRoutine bool

	table          string
	keyCol, valCol int
	fields         []string
	field          []byte
	fieldTooLong   bool
	quoted         bool
	quote          byte
	escape         bool
	err            error
}

const (
	wsLine   = iota // collecting the start of a line
	wsSkip          // ignoring the rest of a line
	wsTuples        // inside the VALUES of a meta table's INSERT
)

// wpMaxField bounds the bytes kept of one value: a file name is short, and
// a meta_value can be megabytes of serialized PHP.
const wpMaxField = 4096

func newWPAttachmentScanner() *wpAttachmentScanner {
	return &wpAttachmentScanner{columns: map[string][]string{}, files: map[string][]string{}}
}

// Files is every attachment file the named table's rows name, sorted.
func (s *wpAttachmentScanner) Files(table string) []string {
	out := append([]string(nil), s.files[table]...)
	sort.Strings(out)
	return out
}

// Err says when a meta table's rows were not shaped as expected, so the
// attachment check cannot be trusted.
func (s *wpAttachmentScanner) Err() error { return s.err }

func (s *wpAttachmentScanner) Write(p []byte) (int, error) {
	for _, b := range p {
		switch s.state {
		case wsLine:
			if b == '\n' {
				s.endLine()
				continue
			}
			s.line = append(s.line, b)
			if s.inRoutine {
				if len(s.line) > 512 {
					s.state, s.line = wsSkip, s.line[:0]
				}
				continue
			}
			if name, ok := insertTable(s.line); ok {
				cols := s.columns[name]
				k, v := indexOf(cols, "meta_key"), indexOf(cols, "meta_value")
				if k >= 0 && v >= 0 {
					s.table, s.keyCol, s.valCol = name, k, v
					s.state = wsTuples
					s.fields, s.field, s.quoted = nil, s.field[:0], false
				} else {
					s.state = wsSkip
				}
				s.line = s.line[:0]
				continue
			}
			if len(s.line) > 512 {
				s.state, s.line = wsSkip, s.line[:0]
			}
		case wsSkip:
			if b == '\n' {
				s.state = wsLine
			}
		case wsTuples:
			s.tupleByte(b)
		}
	}
	return len(p), nil
}

func (s *wpAttachmentScanner) tupleByte(b byte) {
	if s.quote != 0 {
		if s.escape {
			s.escape = false
			s.appendField(unescapeMySQL(b))
			return
		}
		switch b {
		case '\\':
			s.escape = true
		case s.quote:
			s.quote = 0
		default:
			s.appendField(b)
		}
		return
	}
	switch {
	case b == '\'' || b == '"':
		s.quote, s.quoted = b, true
	case b == '(' && s.fields == nil:
		s.fields = []string{}
		s.field, s.fieldTooLong, s.quoted = s.field[:0], false, false
	case s.fields == nil:
		// Between tuples: a comma, VALUES, the statement's end.
		if b == ';' {
			s.state = wsSkip
		}
	case b == ',':
		s.pushField()
	case b == ')':
		s.pushField()
		s.endTuple()
		s.fields = nil
	case b == ' ' || b == '\n' || b == '\r' || b == '\t':
		if s.quoted {
			return
		}
		s.appendField(b)
	default:
		s.appendField(b)
	}
}

func (s *wpAttachmentScanner) appendField(b byte) {
	if len(s.field) >= wpMaxField {
		s.fieldTooLong = true
		return
	}
	s.field = append(s.field, b)
}

func (s *wpAttachmentScanner) pushField() {
	v := string(s.field)
	if !s.quoted {
		v = strings.TrimSpace(v)
	}
	if s.fieldTooLong {
		v = "\x00too long"
	}
	s.fields = append(s.fields, v)
	s.field, s.fieldTooLong, s.quoted = s.field[:0], false, false
}

func (s *wpAttachmentScanner) endTuple() {
	if len(s.fields) <= s.keyCol || len(s.fields) <= s.valCol {
		if s.err == nil {
			s.err = fmt.Errorf("a row of %s has %d values, fewer than its columns", s.table, len(s.fields))
		}
		return
	}
	if s.fields[s.keyCol] != wpAttachedFileKey {
		return
	}
	v := s.fields[s.valCol]
	if v == "" || v == "NULL" {
		return
	}
	if strings.HasPrefix(v, "\x00") {
		if s.err == nil {
			s.err = fmt.Errorf("an attachment's file name in %s is longer than %d bytes", s.table, wpMaxField)
		}
		return
	}
	s.files[s.table] = append(s.files[s.table], strings.TrimPrefix(v, "/"))
}

func (s *wpAttachmentScanner) endLine() {
	line := string(s.line)
	s.line = s.line[:0]
	if strings.HasPrefix(line, "DELIMITER ") {
		s.inRoutine = strings.TrimSpace(line) != "DELIMITER ;"
		return
	}
	if m := createTableRe.FindStringSubmatch(line); m != nil {
		s.creating = strings.ReplaceAll(m[1], "``", "`")
		s.columns[s.creating] = nil
		return
	}
	if s.creating == "" {
		return
	}
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, ")") {
		s.creating = ""
		return
	}
	if strings.HasPrefix(trimmed, "`") {
		if end := strings.Index(trimmed[1:], "`"); end >= 0 {
			s.columns[s.creating] = append(s.columns[s.creating], trimmed[1:1+end])
		}
	}
}

func indexOf(list []string, want string) int {
	for i, v := range list {
		if v == want {
			return i
		}
	}
	return -1
}

// unescapeMySQL is the character a backslash escape in a mysqldump string
// stands for.
func unescapeMySQL(b byte) byte {
	switch b {
	case '0':
		return 0
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'b':
		return '\b'
	case 'Z':
		return 0x1a
	}
	return b
}

// WordPressRestoreResult is what a WordPress restore wrote.
type WordPressRestoreResult struct {
	Manifest     *model.SnapshotMetadata
	FilesWritten int64
	BytesWritten int64
}

// RestoreWordPress loads a WordPress snapshot's database into an empty MySQL
// or MariaDB database and writes its files under dir, which must be empty or
// not exist. Every file is held to its listed size and digest, and every
// table's rows to the manifest.
func RestoreWordPress(ctx context.Context, src io.Reader, targetURL, dir string) (*WordPressRestoreResult, error) {
	if err := emptyDir(dir); err != nil {
		return nil, err
	}
	target, err := parseMySQLURL(targetURL)
	if err != nil {
		return nil, err
	}
	db, err := target.open()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := MySQLCheckEmpty(ctx, db); err != nil {
		return nil, err
	}
	_, mariaDB, err := mysqlServer(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the restore target: %w", err)
	}
	tool, err := findMySQLTool(ctx, "client", mariaDB)
	if err != nil {
		return nil, err
	}
	cnf, cleanup, err := target.defaultsFile()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	counter := newMySQLDumpCounter()
	written := map[string]seenFile{}
	res := &WordPressRestoreResult{}
	var stderr bytes.Buffer
	parts, err := readWordPressArchive(src, func(dump io.Reader) error {
		cmd := exec.CommandContext(ctx, tool.Path, "--defaults-extra-file="+cnf,
			"--binary-mode", "--default-character-set=utf8mb4", "--database="+target.Database)
		cmd.Stdin = newDefinerRewriter(io.TeeReader(dump, counter))
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := toolMessage(stderr.String())
			if len(msg) > 500 {
				msg = msg[:500] + "..."
			}
			return fmt.Errorf("%s failed: %v: %s. The target may now hold part of the snapshot; drop and recreate it before retrying", tool, err, msg)
		}
		_, err := io.Copy(counter, dump)
		return err
	}, func(rel string, hdr *tar.Header, r io.Reader) error {
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(hdr.Mode).Perm() & 0o755
		if mode == 0 {
			mode = 0o644
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode|0o600)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, h), r)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("writing %s: %w", rel, err)
		}
		if !hdr.ModTime.IsZero() {
			_ = os.Chtimes(dst, hdr.ModTime, hdr.ModTime) // a file's time is a convenience, not its contents
		}
		written[rel] = seenFile{size: n, sha256: hex.EncodeToString(h.Sum(nil))}
		res.FilesWritten++
		res.BytesWritten += n
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !parts.sawDump || parts.manifest == nil || parts.manifest.WordPress == nil {
		return nil, errors.New("the archive is not a WordPress snapshot: no dump or no manifest")
	}
	if len(parts.unexpected) > 0 {
		return nil, fmt.Errorf("the archive holds entries a WordPress snapshot does not: %s", strings.Join(parts.unexpected, ", "))
	}
	if !counter.Completed {
		return nil, fmt.Errorf("the snapshot's dump is incomplete: it ends before %q", mysqlDumpDone)
	}
	if !parts.sawList {
		return nil, errors.New("the archive has no file list, so the files written cannot be checked")
	}
	for _, f := range parts.fileList {
		got, ok := written[f.Path]
		if !ok {
			return nil, fmt.Errorf("%s is in the snapshot's file list but not in the archive", f.Path)
		}
		if got.size != f.Size || !strings.EqualFold(got.sha256, f.Sha256) {
			return nil, fmt.Errorf("%s was restored with %d bytes and a different digest from the %d the snapshot listed", f.Path, got.size, f.Size)
		}
	}
	if len(written) != len(parts.fileList) {
		return nil, fmt.Errorf("the archive holds %d files and lists %d", len(written), len(parts.fileList))
	}
	counts, err := MySQLCountRows(ctx, db, parts.manifest)
	if err != nil {
		return nil, err
	}
	for _, t := range parts.manifest.TableStats {
		if counts[t.TableName] != t.RowCount {
			return nil, fmt.Errorf("%s loaded %d rows; the snapshot recorded %d", t.TableName, counts[t.TableName], t.RowCount)
		}
	}
	res.Manifest = parts.manifest
	return res, nil
}

// emptyDir refuses a directory that holds anything: a restore never
// writes over files.
func emptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s is not empty; restore a site into an empty directory", dir)
	}
	return nil
}
