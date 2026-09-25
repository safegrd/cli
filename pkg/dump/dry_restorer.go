package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

var (
	pgCopySignature = []byte{0x50, 0x47, 0x43, 0x4F, 0x50, 0x59, 0x0A, 0xFF, 0x0D, 0x0A, 0x00}

	// Regex to match CREATE TABLE statements
	tableDDLRegex = regexp.MustCompile(`(?s)CREATE TABLE (?:IF NOT EXISTS )?"?([^".\s]+)"?\."?([^"(\s]+)"?\s*\((.*?)\);`)
	// Regex to match CREATE EXTENSION statements
	extensionRegex = regexp.MustCompile(`CREATE EXTENSION (?:IF NOT EXISTS )?"?([^";\s]+)"?`)
)

// TableColumnInfo holds column name and type extracted from schema DDL.
type TableColumnInfo struct {
	Name     string `json:"name"`
	DataType string `json:"data_type"`
}

// TableDryStats holds verified table statistics from archive inspection.
type TableDryStats struct {
	Schema      string            `json:"schema"`
	TableName   string            `json:"table_name"`
	RowCount    int64             `json:"row_count"`
	ColumnCount int               `json:"column_count"`
	Columns     []TableColumnInfo `json:"columns"`
	DataBytes   int64             `json:"data_bytes"`
}

// DryRestoreResult contains comprehensive integrity assertions from the in-memory dry restore.
type DryRestoreResult struct {
	Manifest       *model.SnapshotMetadata `json:"manifest,omitempty"`
	DatabaseName   string                  `json:"database_name"`
	TotalTables    int                     `json:"total_tables"`
	TotalRows      int64                   `json:"total_rows"`
	TotalDataBytes int64                   `json:"total_data_bytes"`
	Tables         []TableDryStats         `json:"tables"`
	Extensions     []string                `json:"extensions"`
	DurationMs     int64                   `json:"duration_ms"`
	Passed         bool                    `json:"passed"`
	Assertions     []model.AssertionResult `json:"assertions"`
	ErrorMessage   string                  `json:"error_message,omitempty"`
}

// DryRestorer inspects decrypted backup archive streams without a running PostgreSQL instance.
type DryRestorer struct{}

// NewDryRestorer creates an in-memory dry restore inspector.
func NewDryRestorer() *DryRestorer {
	return &DryRestorer{}
}

// InspectArchive parses a decrypted tar archive stream in memory and asserts structural integrity.
func (d *DryRestorer) InspectArchive(ctx context.Context, src io.Reader) (*DryRestoreResult, error) {
	startTime := time.Now()

	result := &DryRestoreResult{
		Passed: true,
	}

	var (
		manifestFound bool
		schemaFound   bool
		sequencesSeen bool
		schemaTables  = make(map[string][]TableColumnInfo) // "schema.table" -> columns
		tableRows     = make(map[string]int64)             // "schema.table" -> rows parsed
		tableCols     = make(map[string]int)
		tableBytes    = make(map[string]int64)
		copyErrors    []model.AssertionResult
	)

	// 1. Read the archive in order, each table's chunks as one stream, so no
	// table is ever held in memory whole.
	streams := &tableStreams{
		consume: func(schema, table string, rd io.Reader) error {
			key := fmt.Sprintf("%s.%s", schema, table)
			counted := &countingReader{r: rd}
			rows, cols, parseErr := parseBinaryCopyStream(counted)
			// Whatever follows the trailer is still part of the entry.
			_, _ = io.Copy(io.Discard, counted)
			tableRows[key] = rows
			tableCols[key] = cols
			tableBytes[key] = counted.n
			if parseErr != nil {
				copyErrors = append(copyErrors, model.AssertionResult{
					Name:     fmt.Sprintf("Binary COPY Stream: %s", key),
					Passed:   false,
					Expected: "valid PostgreSQL binary COPY wire stream",
					Actual:   fmt.Sprintf("parse error: %v", parseErr),
					Message:  parseErr.Error(),
				})
			}
			return nil
		},
		other: func(hdr *tar.Header, rd io.Reader) error {
			switch hdr.Name {
			case entryManifest:
				manifestFound = true
				data, err := io.ReadAll(rd)
				if err != nil {
					return fmt.Errorf("failed reading manifest.json: %w", err)
				}
				var m model.SnapshotMetadata
				if err := json.Unmarshal(data, &m); err != nil {
					return fmt.Errorf("failed parsing manifest.json: %w", err)
				}
				result.Manifest = &m
				result.DatabaseName = m.DatabaseName
			case entrySchema, entryPreData:
				schemaFound = true
				schemaBytes, err := io.ReadAll(rd)
				if err != nil {
					return fmt.Errorf("failed reading %s: %w", hdr.Name, err)
				}
				schemaTables, result.Extensions = parseSchemaDDL(string(schemaBytes))
			case entrySequences:
				sequencesSeen = true
			}
			return nil
		},
	}
	if err := streams.Run(tar.NewReader(src)); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		result.Passed = false
		result.ErrorMessage = fmt.Sprintf("failed reading archive tar stream: %v", err)
		return result, nil
	}
	if len(copyErrors) > 0 {
		result.Assertions = append(result.Assertions, copyErrors...)
		result.Passed = false
	}

	// 2. Validate manifest presence
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "Manifest Catalog Integrity",
		Passed:   manifestFound,
		Expected: "manifest.json present in root of archive",
		Actual:   fmt.Sprintf("manifest.json found: %v", manifestFound),
	})
	if !manifestFound {
		result.Passed = false
		result.ErrorMessage = "archive is missing manifest.json metadata"
		return result, nil
	}

	// 3. Validate schema DDL presence
	result.Assertions = append(result.Assertions, model.AssertionResult{
		Name:     "Schema DDL Integrity",
		Passed:   schemaFound,
		Expected: "pre-data.sql (or schema.sql) present in root of archive",
		Actual:   fmt.Sprintf("schema found: %v", schemaFound),
	})
	if !schemaFound {
		result.Passed = false
		result.ErrorMessage = "archive is missing its schema"
		return result, nil
	}

	// 3b. The schema must be one a restore can rebuild the database from.
	fidelity := SchemaFidelity(result.Manifest)
	result.Assertions = append(result.Assertions, fidelity)
	if !fidelity.Passed {
		result.Passed = false
	}
	if result.Manifest.SchemaSource != "" {
		result.Assertions = append(result.Assertions, model.AssertionResult{
			Name:     "Sequence Positions Recorded",
			Passed:   sequencesSeen,
			Expected: "sequences.sql present",
			Actual:   fmt.Sprintf("present: %v", sequencesSeen),
		})
		if !sequencesSeen {
			result.Passed = false
		}
	}

	// 4. Collect per-table volume stats. The tables are the manifest's and
	// the archive's: the schema can name tables with no rows of their own,
	// such as a partitioned table's parent.
	var totalRows int64
	var totalBytes int64
	tableKeySet := make(map[string]bool)
	for _, ts := range result.Manifest.TableStats {
		tableKeySet[fmt.Sprintf("%s.%s", ts.Schema, ts.TableName)] = true
	}
	for k := range tableRows {
		tableKeySet[k] = true
	}
	keys := make([]string, 0, len(tableKeySet))
	for k := range tableKeySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		schema, tableName, _ := strings.Cut(key, ".")
		cols := schemaTables[key]
		colCount := len(cols)
		if colCount == 0 {
			colCount = tableCols[key]
		}
		result.Tables = append(result.Tables, TableDryStats{
			Schema:      schema,
			TableName:   tableName,
			RowCount:    tableRows[key],
			ColumnCount: colCount,
			Columns:     cols,
			DataBytes:   tableBytes[key],
		})
		totalRows += tableRows[key]
		totalBytes += tableBytes[key]
	}

	result.TotalTables = len(result.Tables)
	result.TotalRows = totalRows
	result.TotalDataBytes = totalBytes

	// 5. Assert Table Counts against Manifest
	if result.Manifest != nil {
		expectedTables := result.Manifest.TotalTables
		if expectedTables == 0 && len(result.Manifest.TableStats) > 0 {
			expectedTables = len(result.Manifest.TableStats)
		}
		tablesMatch := result.TotalTables == expectedTables
		result.Assertions = append(result.Assertions, model.AssertionResult{
			Name:     "Table Count Match",
			Passed:   tablesMatch,
			Expected: fmt.Sprintf("%d tables", expectedTables),
			Actual:   fmt.Sprintf("%d tables", result.TotalTables),
		})
		if !tablesMatch {
			result.Passed = false
		}

		// 6. Assert Total Rows against Manifest
		expectedRows := result.Manifest.TotalRows
		rowsMatch := result.TotalRows == expectedRows
		result.Assertions = append(result.Assertions, model.AssertionResult{
			Name:     "Total Row Count Match",
			Passed:   rowsMatch,
			Expected: fmt.Sprintf("%d rows", expectedRows),
			Actual:   fmt.Sprintf("%d rows", result.TotalRows),
		})
		if !rowsMatch {
			result.Passed = false
		}

		// 7. Assert per-table row match
		for _, expTable := range result.Manifest.TableStats {
			key := fmt.Sprintf("%s.%s", expTable.Schema, expTable.TableName)
			var foundStat *TableDryStats
			for _, t := range result.Tables {
				if t.Schema == expTable.Schema && t.TableName == expTable.TableName {
					foundStat = &t
					break
				}
			}

			if foundStat == nil {
				result.Assertions = append(result.Assertions, model.AssertionResult{
					Name:     fmt.Sprintf("Table Existence: %s", key),
					Passed:   false,
					Expected: "table exists in archive",
					Actual:   "table missing",
				})
				result.Passed = false
			} else {
				match := foundStat.RowCount == expTable.RowCount
				result.Assertions = append(result.Assertions, model.AssertionResult{
					Name:     fmt.Sprintf("Row Count: %s", key),
					Passed:   match,
					Expected: fmt.Sprintf("%d rows", expTable.RowCount),
					Actual:   fmt.Sprintf("%d rows", foundStat.RowCount),
				})
				if !match {
					result.Passed = false
				}
			}
		}

		// 8. Assert Extensions match
		if len(result.Manifest.Extensions) > 0 {
			extSet := make(map[string]bool)
			for _, e := range result.Extensions {
				extSet[e] = true
			}
			for _, expExt := range result.Manifest.Extensions {
				present := extSet[expExt]
				result.Assertions = append(result.Assertions, model.AssertionResult{
					Name:     fmt.Sprintf("Extension: %s", expExt),
					Passed:   present,
					Expected: "extension declared in schema DDL",
					Actual:   fmt.Sprintf("present: %v", present),
				})
				if !present {
					result.Passed = false
				}
			}
		}
	}

	result.DurationMs = elapsedMilliseconds(startTime)
	return result, nil
}

// parseBinaryCopyStream reads PostgreSQL binary COPY wire format tuples and counts rows and columns.
func parseBinaryCopyStream(r io.Reader) (int64, int, error) {
	// 1. Signature (11 bytes)
	sig := make([]byte, 11)
	if _, err := io.ReadFull(r, sig); err != nil {
		return 0, 0, fmt.Errorf("failed reading PGCOPY signature: %w", err)
	}
	if !bytes.Equal(sig, pgCopySignature) {
		return 0, 0, fmt.Errorf("invalid PGCOPY signature")
	}

	// 2. Flags (4 bytes)
	var flags uint32
	if err := binary.Read(r, binary.BigEndian, &flags); err != nil {
		return 0, 0, fmt.Errorf("failed reading PGCOPY flags: %w", err)
	}

	// 3. Header Extension Area Length (4 bytes)
	var extLen uint32
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		return 0, 0, fmt.Errorf("failed reading PGCOPY header extension length: %w", err)
	}
	if extLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(extLen)); err != nil {
			return 0, 0, fmt.Errorf("failed skipping PGCOPY header extension: %w", err)
		}
	}

	// 4. Tuples Loop
	var rowCount int64
	var colCount int

	for {
		var numFields int16
		if err := binary.Read(r, binary.BigEndian, &numFields); err != nil {
			if err == io.EOF {
				break
			}
			return rowCount, colCount, fmt.Errorf("failed reading tuple field count: %w", err)
		}

		// -1 (0xFFFF) is the standard PGCOPY file trailer signifying end of data
		if numFields == -1 {
			break
		}
		if numFields < 0 {
			return rowCount, colCount, fmt.Errorf("corrupt tuple field count: %d", numFields)
		}

		if rowCount == 0 {
			colCount = int(numFields)
		}
		rowCount++

		// Read each field
		for i := 0; i < int(numFields); i++ {
			var fieldLen int32
			if err := binary.Read(r, binary.BigEndian, &fieldLen); err != nil {
				return rowCount, colCount, fmt.Errorf("failed reading field length in row %d: %w", rowCount, err)
			}
			if fieldLen == -1 {
				// NULL field, 0 bytes follow
				continue
			}
			if fieldLen < -1 {
				return rowCount, colCount, fmt.Errorf("corrupt field length %d in row %d", fieldLen, rowCount)
			}
			if fieldLen > 0 {
				if _, err := io.CopyN(io.Discard, r, int64(fieldLen)); err != nil {
					return rowCount, colCount, fmt.Errorf("failed skipping field data in row %d: %w", rowCount, err)
				}
			}
		}
	}

	return rowCount, colCount, nil
}

// parseSchemaDDL extracts tables, columns, and extensions from schema DDL SQL.
func parseSchemaDDL(ddl string) (map[string][]TableColumnInfo, []string) {
	tables := make(map[string][]TableColumnInfo)
	var extensions []string

	// Extract extensions
	extMatches := extensionRegex.FindAllStringSubmatch(ddl, -1)
	for _, m := range extMatches {
		if len(m) >= 2 {
			extensions = append(extensions, strings.TrimSpace(m[1]))
		}
	}

	// Extract tables
	tableMatches := tableDDLRegex.FindAllStringSubmatch(ddl, -1)
	for _, m := range tableMatches {
		if len(m) < 4 {
			continue
		}
		schema := strings.Trim(strings.TrimSpace(m[1]), `"`)
		tableName := strings.Trim(strings.TrimSpace(m[2]), `"`)
		body := m[3]

		var cols []TableColumnInfo
		lines := strings.Split(body, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "--") {
				continue
			}
			// Remove trailing comma
			line = strings.TrimSuffix(line, ",")
			lineUpper := strings.ToUpper(line)

			// Skip table constraints
			if strings.HasPrefix(lineUpper, "CONSTRAINT ") ||
				strings.HasPrefix(lineUpper, "PRIMARY KEY ") ||
				strings.HasPrefix(lineUpper, "FOREIGN KEY ") ||
				strings.HasPrefix(lineUpper, "UNIQUE ") ||
				strings.HasPrefix(lineUpper, "CHECK ") {
				continue
			}

			// Parse column definition
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				colName := strings.Trim(parts[0], `"`)
				colType := parts[1]
				cols = append(cols, TableColumnInfo{
					Name:     colName,
					DataType: colType,
				})
			}
		}

		key := fmt.Sprintf("%s.%s", schema, tableName)
		tables[key] = cols
	}

	return tables, extensions
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// SchemaFidelity is the Fire Drill's verdict on how a snapshot's schema was
// captured. A schema re-derived without pg_dump restores without foreign
// keys, views, triggers or enum types, and could not restore an array column
// at all, so a drill that passed it would be proving a restore we cannot do.
func SchemaFidelity(m *model.SnapshotMetadata) model.AssertionResult {
	if m != nil && m.SurfaceType == model.SurfaceTypeMySQL {
		return model.AssertionResult{Name: "Schema Captured By The Server's Dump Tool", Expected: "mysqldump or mariadb-dump",
			Actual: m.SchemaSource, Passed: strings.HasPrefix(m.SchemaSource, "mysqldump") || strings.HasPrefix(m.SchemaSource, "mariadb-dump")}
	}
	if m != nil && m.SurfaceType == model.SurfaceTypeSQLite {
		return model.AssertionResult{Name: "Copied By The SQLite Engine", Expected: "sqlite VACUUM INTO",
			Actual: m.SchemaSource, Passed: strings.HasPrefix(m.SchemaSource, "sqlite VACUUM INTO")}
	}
	if m != nil && m.SurfaceType == model.SurfaceTypeMongoDB {
		return model.AssertionResult{Name: "Captured By mongodump", Expected: "mongodump",
			Actual: m.SchemaSource, Passed: strings.HasPrefix(m.SchemaSource, "mongodump")}
	}
	a := model.AssertionResult{Name: "Schema Captured By pg_dump", Expected: "schema from pg_dump"}
	switch {
	case m == nil:
		a.Actual = "no manifest"
	case strings.HasPrefix(m.SchemaSource, "pg_dump "):
		a.Passed = true
		a.Actual = m.SchemaSource
	case m.SchemaSource == SchemaSourceNative:
		a.Actual = "re-derived without pg_dump"
		a.Message = "the host had no pg_dump that could dump this server, so the schema restores without foreign keys, " +
			"views, triggers or enum types; install the PostgreSQL client on the host"
	default:
		a.Actual = "taken before SafeGrd used pg_dump"
		a.Message = "snapshots taken before CLI v0.0.3 re-derived the schema: an array column does not restore, and " +
			"foreign keys, views, triggers, enum types and sequence positions are lost; take a new backup"
	}
	return a
}
